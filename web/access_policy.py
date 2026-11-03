"""主机与容器共享的访问模式；只有主机能够原子修改策略。"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid

MAX_BYTES = 4096
MODES = ('lan', 'public')


class PolicyConflict(ValueError):
    pass


def validate_policy(value):
    if (not isinstance(value, dict) or set(value) != {'mode', 'revision'}
            or value['mode'] not in MODES or not isinstance(value['revision'], str)
            or not re.fullmatch(r'[0-9a-f]{32}', value['revision'])):
        raise ValueError('访问策略格式无效')
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('访问策略字段重复')
        result[key] = value
    return result


@contextlib.contextmanager
def _directory(path, owner_uid):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.name in ('', '.', '..'):
        raise ValueError('访问策略路径无效')
    fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o027:
            raise ValueError('访问策略目录权限无效')
        yield fd, path.name
    finally:
        os.close(fd)


def _regular(info, owner_uid, modes=(0o600, 0o640)):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) not in modes or info.st_nlink != 1):
        raise ValueError('访问策略文件权限无效')


def _read(directory, name, owner_uid):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        _regular(info, owner_uid)
        if info.st_size > MAX_BYTES:
            raise ValueError('访问策略文件过大')
        with os.fdopen(fd, 'rb') as handle:
            fd = None
            data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('访问策略文件过大')
        try:
            value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, RecursionError):
            raise ValueError('访问策略编码或结构无效') from None
        return validate_policy(value)
    finally:
        if fd is not None:
            os.close(fd)


def read_policy(path, owner_uid=0):
    with _directory(path, owner_uid) as (directory, name):
        return _read(directory, name, owner_uid)


@contextlib.contextmanager
def _locked(directory, owner_uid):
    fd = os.open('.policy.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                 0o600, dir_fd=directory)
    try:
        _regular(os.fstat(fd), owner_uid, (0o600,))
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write(directory, name, value, owner_uid, gid):
    validate_policy(value)
    temporary = '.policy-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        os.fchown(fd, owner_uid, gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, 'wb') as handle:
            fd = None
            handle.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        return value
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def initialize_policy(path, mode='lan', owner_uid=0, gid=10100):
    if mode not in MODES:
        raise ValueError('访问模式无效')
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('访问策略路径无效')
    try:
        path.parent.mkdir(mode=0o750)
    except FileExistsError:
        pass
    else:
        os.chown(str(path.parent), owner_uid, gid)
        os.chmod(str(path.parent), 0o750)
    with _directory(path, owner_uid) as (directory, name), _locked(directory, owner_uid):
        try:
            return _read(directory, name, owner_uid)
        except FileNotFoundError:
            return _write(directory, name, {'mode': mode, 'revision': uuid.uuid4().hex}, owner_uid, gid)


def write_policy(path, mode, expected_revision, owner_uid=0, gid=10100):
    validate_policy({'mode': mode, 'revision': expected_revision})
    with _directory(path, owner_uid) as (directory, name), _locked(directory, owner_uid):
        current = _read(directory, name, owner_uid)
        if current['revision'] != expected_revision:
            raise PolicyConflict('访问策略已更新，请重新读取')
        if current['mode'] == mode:
            return current
        return _write(directory, name, {'mode': mode, 'revision': uuid.uuid4().hex}, owner_uid, gid)


def write_applied(path, policy, owner_uid=0, gid=10100):
    validate_policy(policy)
    with _directory(path, owner_uid) as (directory, _):
        try:
            if _read(directory, 'applied.json', owner_uid) == policy:
                return policy
        except FileNotFoundError:
            pass
        return _write(directory, 'applied.json', policy, owner_uid, gid)
