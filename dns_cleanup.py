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
DIAGNOSTIC_LIMIT = 64 * 1024
API_ACTIONS = {'DescribeRecordList', 'CreateRecord', 'DescribeRecordFilterList', 'DeleteRecord'}
ERROR_ROOTS = {'AuthFailure', 'FailedOperation', 'InternalError', 'InvalidAction', 'InvalidParameter',
               'InvalidParameterValue', 'LimitExceeded', 'MissingParameter', 'OperationDenied',
               'RequestLimitExceeded', 'ResourceInUse', 'ResourceInsufficient', 'ResourceNotFound',
               'ResourceUnavailable', 'UnauthorizedOperation', 'UnknownParameter', 'UnsupportedOperation'}
ERROR_CODES = {'AuthFailure.SecretIdNotFound', 'AuthFailure.SignatureFailure', 'AuthFailure.SignatureExpire',
               'AuthFailure.InvalidAuthorization', 'AuthFailure.TokenFailure',
               'AuthFailure.UnauthorizedOperation', 'UnauthorizedOperation.CamNoPermission',
               'UnauthorizedOperation.PermissionDenied', 'ResourceNotFound.NoDataOfDomain',
               'ResourceNotFound.NoDataOfRecord', 'InvalidParameter.DomainInvalid',
               'InvalidParameterValue.DomainInvalid', 'FailedOperation.DomainIsLocked'}
LOCAL_CODES = {'NetworkError', 'InvalidResponse', 'MissingCredentials', 'StateError',
               'UnknownError', 'RecordStillPresent', 'IndexNotReady'}


class CleanupError(Exception):
    pass


class DiagnosticError(CleanupError):
    pass


def safe_error_code(value):
    if not isinstance(value, str):
        return 'UnknownError'
    if value in ERROR_CODES or value in ERROR_ROOTS:
        return value
    if value.split('.', 1)[0] in ERROR_ROOTS:
        return value.split('.', 1)[0]
    return 'UnknownError'


def diagnostic(home, stage, action, category, code):
    destination = os.environ.get('CERTCTL_DIAGNOSTIC_FILE')
    if not destination:
        return
    try:
        if (stage not in ('dns_query', 'dns_create', 'dns_cleanup') or
                action not in API_ACTIONS | {'Credentials', 'Journal'} or
                category not in ('api', 'network', 'invalid_response', 'credentials', 'local_state') or
                code not in ERROR_CODES | ERROR_ROOTS | LOCAL_CODES):
            raise DiagnosticError()
        state = home / 'state'
        path = Path(destination)
        relative = path.relative_to(state)
        if not path.is_absolute() or len(relative.parts) < 2 or '..' in relative.parts:
            raise DiagnosticError()
        check_private(home, directory=True)
        check_private(state, directory=True)
        parent = state
        for part in relative.parts[:-1]:
            parent = parent / part
            check_private(parent, directory=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise DiagnosticError()
            fcntl.flock(fd, fcntl.LOCK_EX)
            data = (json.dumps({'stage': stage, 'action': action, 'code': code,
                                'category': category}, separators=(',', ':')) + '\n').encode()
            if os.fstat(fd).st_size + len(data) > DIAGNOSTIC_LIMIT:
                raise DiagnosticError()
            if os.write(fd, data) != len(data):
                raise DiagnosticError()
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError, CleanupError):
        raise DiagnosticError('DNS_DIAGNOSTIC_WRITE_FAILED')


def api_response(home, stage, action, mode, transport_ok, raw):
    if action not in API_ACTIONS or mode not in ('normal', 'root'):
        raise CleanupError('未知 DNS API 操作。')
    try:
        payload = json.loads(raw)
        response = payload.get('Response') if isinstance(payload, dict) else None
    except ValueError:
        response = None
    if isinstance(response, dict) and isinstance(response.get('Error'), dict):
        code = safe_error_code(response['Error'].get('Code'))
        if transport_ok and action == 'DescribeRecordList' and mode == 'root':
            # 探测不存在的子域是正常过程，只在最终没有找到根域时报告。
            print(code)
            return 2
        if transport_ok and action == 'DescribeRecordFilterList' and code == 'ResourceNotFound.NoDataOfRecord':
            return 0
        diagnostic(home, stage, action, 'api', code)
        return 1
    if not transport_ok:
        diagnostic(home, stage, action, 'network', 'NetworkError')
        return 1
    valid = (isinstance(response, dict) and isinstance(response.get('RequestId'), str)
             and bool(response['RequestId']) and 'Error' not in response)
    if valid and action == 'CreateRecord':
        valid = type(response.get('RecordId')) is int and response['RecordId'] > 0
    elif valid and action == 'DescribeRecordList':
        counts = response.get('RecordCountInfo')
        total = counts.get('TotalCount') if isinstance(counts, dict) else response.get('TotalCount')
        valid = type(total) is int and total >= 0 and isinstance(response.get('RecordList'), list)
    elif valid and action == 'DescribeRecordFilterList':
        records = response.get('RecordList')
        valid = isinstance(records, list) and len(records) <= PAGE_SIZE
        if valid:
            valid = all(isinstance(item, dict) and type(item.get('RecordId')) is int
                        and item['RecordId'] > 0 and all(isinstance(item.get(key), str)
                        for key in ('Name', 'Value', 'Type')) for item in records)
    if not valid:
        diagnostic(home, stage, action, 'invalid_response', 'InvalidResponse')
        return 1
    return 0


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
        if action == 'diagnostic':
            diagnostic(home, *arguments)
        elif action == 'api':
            stage, operation, mode, transport = arguments
            return api_response(home, stage, operation, mode, transport == '0', sys.stdin.read())
        elif action == 'response':
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
    except DiagnosticError:
        print('DNS_DIAGNOSTIC_WRITE_FAILED', file=sys.stderr)
        return 1
    except (CleanupError, OSError, ValueError, IndexError, TypeError):
        # 不输出响应内容、验证值或密钥。
        print('DNS 清理操作未完成，待清理记录已保留；请检查权限、网络及本机日志。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
