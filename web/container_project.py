"""生成 Container Manager 可导入的独立项目配置，不执行容器启停。"""
from collections.abc import Mapping
import functools
import json
import os
from pathlib import Path
import re
import secrets
import stat
from types import MappingProxyType
from typing import NamedTuple, Optional

DOCKER = '/usr/local/bin/docker'
PROJECT_FILE = 'docker-compose.yml'
PROJECT_STATE = 'container-project.json'
PROJECT_MARKER = 'x-certweb-project'
ERROR = '项目配置无效或权限不安全，请检查项目名称、目录及私有部署配置'
IMAGE_ERROR = '无法确认本机 synology-cert-web:local 镜像，请先修复 Docker 或按原部署配置构建镜像'


class ProjectImageError(ValueError):
    pass


class _ProjectSnapshot(NamedTuple):
    home: str
    name: str
    directory: str
    directory_existed: bool
    manifest_before: Optional[bytes]
    metadata_before: Optional[bytes]
    manifest_after: bytes
    metadata_after: bytes


def safe_errors(method):
    @functools.wraps(method)
    def invoke(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ProjectImageError:
            raise
        except Exception:
            raise ValueError(ERROR) from None
    return invoke


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', value):
        raise ValueError(ERROR)
    return value


def _directory(path, uid, private=False):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path != path.resolve() or info.st_uid != uid
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError(ERROR)


def _regular(path, uid):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path != path.resolve()
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError(ERROR)


def _overlap(first, second):
    return first == second or first in second.parents or second in first.parents


def _location(home, directory, uid):
    home, directory = Path(home), Path(directory)
    _directory(home, uid, private=True)
    if not directory.is_absolute() or directory != directory.resolve():
        raise ValueError(ERROR)
    protected = [home / name for name in ('code', 'data', 'bridge', 'tls', 'access', 'upgrades')]
    configuration = home / 'deployment.json'
    if configuration.exists() or configuration.is_symlink():
        _regular(configuration, uid)
        native = json.loads(configuration.read_text()).get('native_home')
        if native is not None:
            if not isinstance(native, str) or not Path(native).is_absolute():
                raise ValueError(ERROR)
            protected.append(Path(native).resolve())
    if any(_overlap(directory, root) for root in protected):
        raise ValueError(ERROR)
    if directory.exists() or directory.is_symlink():
        _directory(directory, uid)
    else:
        _directory(directory.parent, uid)
    return directory


def _marker(home, name):
    return {'version': 1, 'home': str(home), 'name': name}


def _service(home, content):
    if not isinstance(content, dict) or set(content.get('services', {})) != {'certweb'}:
        raise ValueError(ERROR)
    service = content['services']['certweb']
    if (not isinstance(service, dict) or service.get('image') != 'synology-cert-web:local'
            or service.get('container_name') != 'synology-cert-web'
            or service.get('labels', {}).get('io.github.784933671.certweb.managed') != 'true'
            or not isinstance(service.get('environment'), dict)):
        raise ValueError(ERROR)
    if (service.get('network_mode') != 'host' or service.get('user') != '10100:10100'
            or service.get('read_only') is not True or service.get('init') is not True
            or service.get('restart') != 'no' or service.get('cap_drop') != ['ALL']
            or service.get('security_opt') != ['no-new-privileges:true']
            or service.get('privileged', False) is not False
            or any(key in service for key in ('entrypoint', 'command', 'pid', 'ipc', 'devices',
                                              'volumes_from', 'cap_add', 'group_add', 'use_api_socket',
                                              'post_start', 'pre_stop'))):
        raise ValueError(ERROR)
    mounts = service.get('volumes')
    expected = {'/' + name: str(home / name) for name in ('data', 'bridge', 'tls', 'access')}
    if not isinstance(mounts, list) or len(mounts) != len(expected):
        raise ValueError(ERROR)
    targets = set()
    for mount in mounts:
        if (not isinstance(mount, dict) or mount.get('type') != 'bind'
                or mount.get('target') not in expected or mount['target'] in targets
                or mount.get('source') != expected[mount['target']]
                or mount.get('read_only', False) is not (mount['target'] != '/data')):
            raise ValueError(ERROR)
        targets.add(mount['target'])
    return service


def _manifest(home, name, content):
    if (not isinstance(content, dict) or content.get(PROJECT_MARKER) != _marker(home, name)
            or type(content[PROJECT_MARKER].get('version')) is not int):
        raise ValueError(ERROR)
    service = _service(home, content)
    if ('build' in service or service['environment'].get('CERTWEB_PROJECT_MODE') != '1'
            or '$' in json.dumps(content)):
        raise ValueError(ERROR)
    return content


def _read_manifest(home, directory, name, uid):
    path = directory / PROJECT_FILE
    _regular(path, uid)
    return _manifest(home, name, json.loads(path.read_text()))


def _sync_directory(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic(path, content):
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        _sync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


@safe_errors
def load_project(home, uid=0):
    home = Path(home)
    state = home / PROJECT_STATE
    if not state.exists() and not state.is_symlink():
        return None
    _regular(state, uid)
    project = json.loads(state.read_text())
    if (not isinstance(project, dict) or set(project) != {'version', 'name', 'directory'}
            or type(project['version']) is not int or project['version'] != 1
            or not isinstance(project['directory'], str)):
        raise ValueError(ERROR)
    _name(project['name'])
    directory = _location(home, project['directory'], uid)
    _directory(directory, uid)
    _read_manifest(home, directory, project['name'], uid)
    return project


@safe_errors
def render_project(home, name, runner, code=None):
    home, name = Path(home), _name(name)
    code = Path(code) if code is not None else home / 'code'
    if not home.is_absolute() or home != home.resolve() or not code.is_absolute() or code != code.resolve():
        raise ValueError(ERROR)
    arguments = [DOCKER, 'compose', '--project-name', name, '--env-file', str(home / 'deployment.env'),
                 '-f', str(code / 'compose.yaml'), 'config', '--format', 'json']
    content = json.loads(runner(arguments, timeout=90))
    service = _service(home, content)
    content.pop('name', None)
    service.pop('build', None)
    service['environment']['CERTWEB_PROJECT_MODE'] = '1'
    content[PROJECT_MARKER] = _marker(home, name)
    result = (json.dumps(content, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    _manifest(home, name, json.loads(result))
    return result


def _destination(home, directory, name, uid):
    name = _name(name)
    directory = _location(home, directory, uid)
    project = {'version': 1, 'name': name, 'directory': str(directory)}
    previous = load_project(home, uid)
    if previous is not None and previous != project:
        raise ValueError(ERROR)
    if previous is None and directory.exists() and any(directory.iterdir()):
        # 文件已落盘而元数据未提交的中断导出，可使用同一参数继续。
        if {path.name for path in directory.iterdir()} != {PROJECT_FILE}:
            raise ValueError(ERROR)
        _read_manifest(home, directory, name, uid)
    return project


@safe_errors
def prepare_project(home, directory, name, runner, uid=0):
    home = Path(home)
    project = _destination(home, directory, name, uid)
    try:
        image = runner([DOCKER, 'image', 'inspect', 'synology-cert-web:local', '--format', '{{.Id}}'], timeout=30).strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise ValueError()
    except Exception:
        raise ProjectImageError(IMAGE_ERROR) from None
    return MappingProxyType(project), render_project(home, project['name'], runner)


def _prepared(home, prepared, uid):
    if not isinstance(prepared, tuple) or len(prepared) != 2:
        raise ValueError(ERROR)
    requested, content = prepared
    if (not isinstance(requested, Mapping) or set(requested) != {'version', 'name', 'directory'}
            or type(requested['version']) is not int or requested['version'] != 1
            or not isinstance(requested['directory'], str) or not isinstance(content, bytes)):
        raise ValueError(ERROR)
    project = _destination(home, requested['directory'], requested['name'], uid)
    if project != requested:
        raise ValueError(ERROR)
    _manifest(home, project['name'], json.loads(content))
    return project, content


def _metadata(project):
    return (json.dumps(project, ensure_ascii=False) + '\n').encode()


def _optional_bytes(path, uid):
    if not path.exists() and not path.is_symlink():
        return None
    _regular(path, uid)
    return path.read_bytes()


@safe_errors
def capture_project_state(home, prepared, uid=0):
    """只读快照；由持有部署锁的调用方覆盖提交及监督启动事务。"""
    home = Path(home)
    project, content = _prepared(home, prepared, uid)
    directory = Path(project['directory'])
    return _ProjectSnapshot(str(home), project['name'], str(directory), directory.exists(),
                            _optional_bytes(directory / PROJECT_FILE, uid),
                            _optional_bytes(home / PROJECT_STATE, uid), content, _metadata(project))


@safe_errors
def restore_project_state(home, snapshot, uid=0):
    """仅回退本次事务写入；拒绝覆盖事务期间出现的陌生文件或内容。"""
    home = Path(home)
    if not isinstance(snapshot, _ProjectSnapshot) or snapshot.home != str(home):
        raise ValueError(ERROR)
    _name(snapshot.name)
    directory = _location(home, snapshot.directory, uid)
    if snapshot.directory_existed and not directory.exists():
        raise ValueError(ERROR)
    manifest, metadata = directory / PROJECT_FILE, home / PROJECT_STATE
    current_manifest, current_metadata = _optional_bytes(manifest, uid), _optional_bytes(metadata, uid)
    if (current_manifest not in (snapshot.manifest_before, snapshot.manifest_after)
            or current_metadata not in (snapshot.metadata_before, snapshot.metadata_after)):
        raise ValueError(ERROR)
    # 首次切换回滚先撤销项目模式，避免中断后留下指向缺失配置的元数据。
    if snapshot.metadata_before is None and current_metadata is not None:
        metadata.unlink()
        _sync_directory(home)
    if snapshot.manifest_before is None:
        if current_manifest is not None:
            manifest.unlink()
            _sync_directory(directory)
    elif current_manifest != snapshot.manifest_before:
        _atomic(manifest, snapshot.manifest_before)
    if snapshot.metadata_before is not None and current_metadata != snapshot.metadata_before:
        _atomic(metadata, snapshot.metadata_before)
    if not snapshot.directory_existed and directory.exists() and not any(directory.iterdir()):
        directory.rmdir()
        _sync_directory(directory.parent)


@safe_errors
def commit_project(home, prepared, uid=0):
    home = Path(home)
    project, content = _prepared(home, prepared, uid)
    directory = Path(project['directory'])
    if not directory.exists():
        directory.mkdir(mode=0o700)
        _directory(directory, uid)
        _sync_directory(directory.parent)
    _atomic(directory / PROJECT_FILE, content)
    _atomic(home / PROJECT_STATE, _metadata(project))
    return project


@safe_errors
def export_project(home, directory, name, runner, uid=0):
    prepared = prepare_project(home, directory, name, runner, uid)
    return commit_project(home, prepared, uid)


@safe_errors
def refresh_project(home, runner, uid=0):
    project = load_project(home, uid)
    if project is None:
        return None
    return export_project(home, project['directory'], project['name'], runner, uid)


@safe_errors
def project_compose(home, project, *args):
    _name(project['name'])
    return [DOCKER, 'compose', '--project-name', project['name'], '-f',
            str(Path(project['directory']) / PROJECT_FILE)] + list(args)
