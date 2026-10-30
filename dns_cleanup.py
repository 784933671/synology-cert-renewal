#!/usr/bin/env python3
"""DNS 验证记录的私有日志，以及腾讯云响应的严格校验。"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

EMPTY_GRACE = 300
PAGE_SIZE = 100


class CleanupError(Exception):
    pass


def validate_pair(name, value):
    suffix = name[len('_acme-challenge.'):] if isinstance(name, str) and name.startswith('_acme-challenge.') else ''
    labels = suffix.split('.')
    if (len(labels) < 2 or len(name) > 253 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels) or
            not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', value)):
        raise CleanupError('DNS 清理记录的名称或验证值无效。')


def check_private(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise CleanupError('DNS 清理文件必须属于当前运行用户，且禁止其他用户访问。')


def write_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.dns-cleanup-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, separators=(',', ':'))
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def journal(home):
    state = home / 'state'
    check_private(home, directory=True)
    check_private(state, directory=True)
    lock = state / 'dns-cleanup.lock'
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        check_private(lock)
        fcntl.flock(fd, fcntl.LOCK_EX)
        path = state / 'dns-cleanup.json'
        data = {'version': 1, 'entries': []}
        if os.path.lexists(path):
            check_private(path)
            data = json.loads(path.read_text())
        if (not isinstance(data, dict) or data.get('version') != 1 or
                not isinstance(data.get('entries'), list) or len(data['entries']) > 256):
            raise CleanupError('DNS 清理日志格式无效。')
        seen = set()
        for entry in data['entries']:
            if not isinstance(entry, dict):
                raise CleanupError('DNS 清理日志格式无效。')
            validate_pair(entry.get('name'), entry.get('value'))
            created = entry.get('created_at')
            pair = (entry['name'], entry['value'])
            if (type(created) not in (int, float) or not 0 < created <= time.time() + 60 or pair in seen):
                raise CleanupError('DNS 清理日志时间或条目无效。')
            seen.add(pair)
        yield path, data
    finally:
        os.close(fd)


def journal_command(home, action, arguments):
    with journal(home) as (path, data):
        entries = data['entries']
        if action == 'count':
            print(len(entries))
            return
        if action == 'list':
            for entry in entries:
                print(entry['name'] + ' ' + entry['value'])
            return
        name, value = arguments[:2]
        validate_pair(name, value)
        entry = next((item for item in entries if item['name'] == name and item['value'] == value), None)
        if action == 'track':
            if entry is None:
                if len(entries) >= 256:
                    raise CleanupError('待清理 DNS 记录过多，停止新增。')
                entries.append({'name': name, 'value': value, 'created_at': time.time()})
                write_json(path, data)
        elif action == 'done':
            if entry is not None:
                # 创建请求可能已到达云端但响应丢失；短暂空列表不能证明未创建。
                confirmed_delete = len(arguments) == 3 and arguments[2] == 'deleted'
                if not confirmed_delete and time.time() - entry['created_at'] < EMPTY_GRACE:
                    raise CleanupError('DNS 创建结果尚未确认，保留清理记录等待下次重试。')
                entries.remove(entry)
                write_json(path, data)
        else:
            raise CleanupError('未知 DNS 清理操作。')


def response_data(raw, allow_empty=False):
    data = json.loads(raw)
    response = data.get('Response') if isinstance(data, dict) else None
    if not isinstance(response, dict) or not isinstance(response.get('RequestId'), str) or not response['RequestId']:
        raise CleanupError('腾讯云返回了无法确认成功的响应。')
    error = response.get('Error')
    if error is not None:
        if allow_empty and isinstance(error, dict) and error.get('Code') == 'ResourceNotFound.NoDataOfRecord':
            return {'RecordList': []}
        raise CleanupError('腾讯云 DNS 请求失败，保留待清理记录。')
    return response


def record_page(raw, subdomain, value):
    response = response_data(raw, allow_empty=True)
    records = response.get('RecordList')
    if not isinstance(records, list) or len(records) > PAGE_SIZE:
        raise CleanupError('腾讯云 DNS 列表格式异常。')
    ids = []
    for record in records:
        if not isinstance(record, dict) or any(key not in record for key in ('Name', 'Value', 'Type', 'RecordId')):
            raise CleanupError('腾讯云 DNS 记录格式异常。')
        record_id = record['RecordId']
        if type(record_id) is not int or record_id <= 0:
            raise CleanupError('腾讯云 DNS 记录 ID 无效。')
        if record['Name'] == subdomain and record['Value'] == value and record['Type'] == 'TXT':
            ids.append(record_id)
    return len(records), ids


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        home, action, arguments = Path(argv[0]), argv[1], argv[2:]
        if action == 'response':
            response_data(sys.stdin.read())
        elif action == 'created':
            response = response_data(sys.stdin.read())
            if type(response.get('RecordId')) is not int or response['RecordId'] <= 0:
                raise CleanupError('腾讯云未返回已创建的 DNS 记录 ID。')
        elif action == 'records':
            count, ids = record_page(sys.stdin.read(), arguments[0], arguments[1])
            print(' '.join(map(str, [count] + ids)))
        else:
            journal_command(home, action, arguments)
        return 0
    except (CleanupError, OSError, ValueError, IndexError, TypeError):
        # 不输出响应内容、验证值或密钥。
        print('DNS 清理操作未完成，待清理记录已保留；请检查权限、网络及本机日志。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
