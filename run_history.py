"""私有、原子且有界的运行时间线；对外只返回脱敏业务字段。"""
import contextlib
import datetime
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

_spec = importlib.util.spec_from_file_location('history_diagnostics', Path(__file__).with_name('failure_diagnostics.py'))
_diagnostics = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_diagnostics)

KINDS = {'routine', 'forced', 'recovery', 'check'}
STATUSES = {'running', 'succeeded', 'skipped', 'failed', 'interrupted'}
STAGE_STATUSES = STATUSES | {'unknown'}
STAGES = {
    'preflight': '运行前检查', 'backup': '证书与绑定备份', 'certificate_validation': '证书材料校验',
    'recovery': '损坏材料恢复', 'dns_validation': 'DNS 验证', 'issuance': '证书签发流程',
    'deployment': '群晖证书替换', 'tls_verify': '实际 HTTPS 验证',
    'dns_cleanup': '遗留 DNS 记录清理调用', 'dns_cleanup_check': 'DNS 清理结果检查',
    'notification': '成功邮件通知', 'result_recording': '保存执行结果', 'history': '运行记录保存',
}
ID_PATTERN = re.compile(r'run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}')
MAX_FILE_BYTES = 64 * 1024
MAX_RECORDS = 500
MAX_STAGES = 120
RETENTION_SECONDS = 30 * 86400
HISTORY_WARNING = '运行记录未能完整保存，请检查状态目录权限和可用空间；证书任务仍按原安全规则执行。'


class HistoryError(Exception):
    pass


class HistoryNotFound(HistoryError):
    pass


def _timestamp(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat(timespec='milliseconds')


def _epoch(value):
    if not isinstance(value, str) or len(value) > 40:
        raise HistoryError('运行记录时间无效')
    try:
        parsed = datetime.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise HistoryError('运行记录时间无效') from None


def _id_epoch(identifier):
    if not isinstance(identifier, str) or not ID_PATTERN.fullmatch(identifier):
        raise HistoryError('运行记录编号无效')
    try:
        return datetime.datetime.strptime(identifier[4:20], '%Y%m%dT%H%M%SZ').replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except (ValueError, OverflowError):
        raise HistoryError('运行记录编号时间无效') from None


def _safe_text(value, secrets=(), limit=600):
    value = _diagnostics.sanitize(str(value), secrets=secrets, limit=limit)
    value = re.sub(r'https?://[^\s<>"\']+', '[地址已隐藏]', value)
    value = re.sub(r'(?<![A-Za-z0-9])(?:/[^\s<>"\']+|[A-Za-z]:[\\/][^\s<>"\']+)', '[路径已隐藏]', value)
    return value


def _identity(pid, tid=None):
    try:
        path = '/proc/{}/task/{}/stat'.format(pid, tid) if tid is not None else '/proc/{}/stat'.format(pid)
        with open(path, 'rb') as handle:
            raw = handle.read(4096)
        fields = raw.rsplit(b') ', 1)[1].split()
        with open('/proc/sys/kernel/random/boot_id', 'r') as handle:
            boot = handle.read(64).strip()
        if not re.fullmatch(r'[a-f0-9-]{36}', boot) or not fields[19].isdigit():
            return None
        return boot + ':' + fields[19].decode('ascii')
    except (OSError, IndexError, UnicodeError):
        return None


def _alive(owner):
    pid = owner['pid']
    tid = owner['tid']
    if owner['identity'] is not None:
        return _identity(pid, tid) == owner['identity']
    if pid == os.getpid():
        return any(thread.native_id == tid and thread.is_alive() for thread in threading.enumerate())
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class RunHistory:
    def __init__(self, state, uid=0, clock=time.time, monotonic=time.monotonic, alive=None):
        self.state = Path(state)
        self.root = self.state / 'runs'
        self.uid, self.clock, self.monotonic = uid, clock, monotonic
        self.alive = alive or _alive
        if not self.state.is_absolute() or '..' in self.state.parts:
            raise HistoryError('运行记录目录无效')

    def _private(self, path, directory=False):
        info = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if (not kind(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077
                or not directory and info.st_nlink != 1):
            raise HistoryError('运行记录文件类型、属主或权限不安全')
        return info

    def _directory(self, create=False):
        self._private(self.state, directory=True)
        if not os.path.lexists(self.root):
            if not create:
                return False
            try:
                self.root.mkdir(mode=0o700)
            except FileExistsError:
                pass
        self._private(self.root, directory=True)
        return True

    @contextlib.contextmanager
    def _locked(self):
        self._directory(create=True)
        path = self.state / 'run-history.lock'
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self._private(path)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def _paths(self):
        if not self._directory():
            return []
        paths = []
        with os.scandir(str(self.root)) as entries:
            for index, entry in enumerate(entries):
                if index >= 2000:
                    raise HistoryError('运行记录目录条目过多')
                if entry.name.endswith('.json') and ID_PATTERN.fullmatch(entry.name[:-5]):
                    path = self.root / entry.name
                    try:
                        self._private(path)
                    except FileNotFoundError:
                        continue
                    paths.append(path)
        return paths

    def _read(self, path):
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES):
                raise HistoryError('运行记录文件不安全或过大')
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise HistoryError('运行记录文件过大')
        try:
            data = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            self._validate(data, path.stem)
            return data
        except (ValueError, KeyError, TypeError, OverflowError):
            raise HistoryError('运行记录内容无效') from None

    def _validate(self, record, identifier):
        _id_epoch(identifier)
        required = {'version', 'id', 'kind', 'status', 'started_at', 'finished_at', 'duration_seconds',
                    'domains', 'certificate_id', 'summary', 'stages', '_owner', '_monotonic'}
        if (not isinstance(record, dict) or not required <= set(record)
                or record.get('version') != 1 or record.get('id') != identifier
                or record.get('kind') not in KINDS or record.get('status') not in STATUSES
                or not isinstance(record.get('summary'), str) or len(record['summary']) > 1200
                or not isinstance(record.get('stages'), list) or len(record['stages']) > MAX_STAGES):
            raise HistoryError('运行记录内容无效')
        self._context(record['kind'], record['domains'], record['certificate_id'])
        _epoch(record['started_at'])
        if record.get('finished_at') is not None:
            _epoch(record['finished_at'])
        owner = record['_owner']
        if (not isinstance(owner, dict) or not {'pid', 'tid', 'identity'} <= set(owner)
                or type(owner.get('pid')) is not int or not 2 <= owner['pid'] <= 2147483647
                or type(owner.get('tid')) is not int or owner['tid'] < 1
                or owner.get('identity') is not None and not re.fullmatch(r'[a-f0-9-]{36}:[0-9]+', owner['identity'])):
            raise HistoryError('运行记录来源无效')
        for item in [record] + record['stages']:
            if not isinstance(item, dict):
                raise HistoryError('运行阶段无效')
            duration = item.get('duration_seconds')
            if duration is not None and (type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0):
                raise HistoryError('运行耗时无效')
            begin = item.get('_monotonic')
            if begin is not None and (type(begin) not in (int, float) or not math.isfinite(begin) or begin < 0):
                raise HistoryError('运行起点无效')
            if item.get('status') == 'running' and begin is None:
                raise HistoryError('运行阶段缺少起点')
        for stage in record['stages']:
            if (not {'stage', 'status', 'started_at', 'finished_at', 'duration_seconds', 'message', '_monotonic'} <= set(stage)
                    or stage.get('stage') not in STAGES
                    or stage.get('status') not in STAGE_STATUSES or not isinstance(stage.get('message'), str)
                    or len(stage['message']) > 1200):
                raise HistoryError('运行阶段无效')
            for name in ('started_at', 'finished_at'):
                if stage.get(name) is not None:
                    _epoch(stage[name])

    @staticmethod
    def _context(kind, domains, certificate_id):
        if (kind not in KINDS or not isinstance(domains, (list, tuple)) or len(domains) > 100
                or any(not isinstance(name, str) or len(name) > 253
                       or not re.fullmatch(r'(?:\*\.)?[a-z0-9.-]+\.[a-z0-9-]+', name) for name in domains)
                or not isinstance(certificate_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{0,64}', certificate_id)):
            raise HistoryError('运行记录目标无效')

    def _public(self, record, include_stages=True):
        result = {key: record[key] for key in ('id', 'kind', 'status', 'started_at', 'finished_at',
                  'duration_seconds', 'domains', 'certificate_id', 'summary')}
        result['summary'] = _safe_text(result['summary'])
        result['stages'] = []
        running = record['status'] == 'running'
        alive = self.alive(record['_owner']) if running else False
        for original in record['stages'] if include_stages else ():
            stage = {key: original.get(key) for key in ('stage', 'status', 'started_at', 'finished_at',
                                                       'duration_seconds', 'message')}
            stage.update(label=STAGES[stage['stage']], message=_safe_text(stage['message']))
            if running and stage['status'] == 'running':
                if alive:
                    stage['duration_seconds'] = round(max(0, self.monotonic() - original['_monotonic']), 3)
                else:
                    stage.update(status='interrupted', finished_at=None, duration_seconds=None,
                                 message='执行进程已结束，该阶段未记录完成结果。')
            result['stages'].append(stage)
        if running:
            if alive:
                result['duration_seconds'] = round(max(0, self.monotonic() - record['_monotonic']), 3)
            else:
                result.update(status='interrupted', finished_at=None, duration_seconds=None,
                              summary='执行进程已结束，未记录完成结果；中断时间未知。')
        return result

    def list(self, offset=0, limit=20):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
            raise HistoryError('运行记录分页参数无效')
        records = []
        try:
            for path in self._paths():
                try:
                    record = self._read(path)
                    if _epoch(record['started_at']) >= self.clock() - RETENTION_SECONDS:
                        records.append(record)
                except FileNotFoundError:
                    continue
            records.sort(key=lambda value: (value['started_at'], value['id']), reverse=True)
            records = records[:MAX_RECORDS]
            return {'items': [self._public(value, include_stages=False) for value in records[offset:offset + limit]],
                    'total': len(records), 'offset': offset, 'limit': limit, 'warning': self.warning()}
        except OSError:
            raise HistoryError('无法安全读取运行记录') from None

    def get(self, identifier):
        _id_epoch(identifier)
        try:
            if not self._directory():
                raise HistoryNotFound('运行记录不存在或已过保留期限')
            record = self._read(self.root / (identifier + '.json'))
            if _epoch(record['started_at']) < self.clock() - RETENTION_SECONDS:
                raise HistoryNotFound('运行记录不存在或已过保留期限')
            return self._public(record)
        except FileNotFoundError:
            raise HistoryNotFound('运行记录不存在或已过保留期限') from None
        except OSError:
            raise HistoryError('无法安全读取运行记录') from None

    def warning(self):
        self._private(self.state, directory=True)
        path = self.state / 'run-history-error.json'
        if not os.path.lexists(path):
            return None
        self._private(path)
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_size > 1024):
                raise HistoryError('运行记录警告文件不安全或过大')
            raw = handle.read(1025)
        try:
            data = json.loads(raw)
            if len(raw) > 1024 or data.get('version') != 1 or data.get('warning') != HISTORY_WARNING:
                raise ValueError()
            _epoch(data['at'])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HistoryError('运行记录警告内容无效') from None
        return HISTORY_WARNING

    def note_error(self):
        if self.warning() is not None:
            return
        target = self.state / 'run-history-error.json'
        temporary = self.state / ('.run-history-error-' + uuid.uuid4().hex)
        content = json.dumps({'version': 1, 'warning': HISTORY_WARNING, 'at': _timestamp(self.clock())},
                             ensure_ascii=False).encode()
        try:
            descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(temporary), str(target))
        finally:
            if temporary.exists():
                temporary.unlink()

    def _clear_error(self):
        if self.warning() is not None:
            (self.state / 'run-history-error.json').unlink()

    def _save(self, record, prune=False):
        encoded = json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        if len(encoded) > MAX_FILE_BYTES:
            raise HistoryError('运行记录超过大小限制')
        self._validate(record, record['id'])
        with self._locked():
            target = self.root / (record['id'] + '.json')
            if os.path.lexists(target):
                self._private(target)
            temporary = self.root / ('.write-' + uuid.uuid4().hex)
            try:
                descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(str(temporary), str(target))
                descriptor = os.open(str(self.root), os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            finally:
                if temporary.exists():
                    temporary.unlink()
            if prune:
                paths = self._paths()
                paths.sort(key=lambda path: (path == target, path.name), reverse=True)
                cutoff = self.clock() - RETENTION_SECONDS
                for index, path in enumerate(paths):
                    if path == target:
                        continue
                    stamp = _id_epoch(path.stem)
                    if index >= MAX_RECORDS or stamp < cutoff:
                        path.unlink()
            self._clear_error()

    def start(self, kind, domains=(), certificate_id='', summary='', secrets=()):
        self._context(kind, domains, certificate_id)
        timestamp = self.clock()
        stamp = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        record = {'version': 1, 'id': 'run-' + stamp + '-' + uuid.uuid4().hex,
                  'kind': kind, 'status': 'running', 'started_at': _timestamp(timestamp), 'finished_at': None,
                  'duration_seconds': 0, 'domains': list(domains), 'certificate_id': certificate_id,
                  'summary': _safe_text(summary or '正在执行。', secrets), 'stages': [],
                  '_owner': {'pid': os.getpid(), 'tid': threading.get_native_id(),
                             'identity': _identity(os.getpid(), threading.get_native_id())},
                  '_monotonic': self.monotonic()}
        recorder = RunRecorder(self, record, secrets)
        recorder.save(prune=True)
        return recorder


class RunRecorder:
    def __init__(self, history, record, secrets):
        self.history, self.record, self.secrets = history, record, secrets
        self.write_failed = False

    def save(self, prune=False):
        if self.write_failed and not any(stage['stage'] == 'history' for stage in self.record['stages']):
            self._append('history', 'failed', '运行记录曾写入失败；请检查状态目录权限或可用空间。', timed=False)
        if self.record['status'] == 'running':
            self.record['duration_seconds'] = round(max(0, self.history.monotonic() - self.record['_monotonic']), 3)
        try:
            self.history._save(self.record, prune=prune)
        except (HistoryError, OSError, ValueError):
            self.write_failed = True
            try:
                self.history.note_error()
            except (HistoryError, OSError, ValueError):
                pass
            raise

    def context(self, kind, domains, certificate_id, secrets=()):
        self.history._context(kind, domains, certificate_id)
        self.secrets = secrets
        self.record.update(kind=kind, domains=list(domains), certificate_id=certificate_id)
        self.save()

    def _append(self, stage, status, message, timed=True):
        if stage not in STAGES or status not in STAGE_STATUSES or len(self.record['stages']) >= MAX_STAGES:
            raise HistoryError('运行阶段参数无效或过多')
        item = {'stage': stage, 'status': status, 'started_at': None, 'finished_at': None,
                'duration_seconds': None, 'message': _safe_text(message, self.secrets), '_monotonic': None}
        if timed and status == 'running':
            item.update(started_at=_timestamp(self.history.clock()), duration_seconds=0,
                        _monotonic=self.history.monotonic())
        self.record['stages'].append(item)
        return item

    def begin(self, stage, message=''):
        self._append(stage, 'running', message)
        self.save()

    def observe(self, stage, status='unknown', message=''):
        if status == 'running':
            raise HistoryError('无独立计时的阶段不能声明正在执行')
        self._append(stage, status, message, timed=False)
        self.save()

    def finish(self, stage, status='succeeded', message=''):
        if status not in STAGE_STATUSES - {'running'} or stage not in STAGES:
            raise HistoryError('运行阶段结果无效')
        item = next((entry for entry in reversed(self.record['stages'])
                     if entry['stage'] == stage and entry['status'] == 'running'), None)
        if item is None:
            self._append(stage, status, message, timed=False)
        else:
            item.update(status=status, finished_at=_timestamp(self.history.clock()),
                        duration_seconds=round(max(0, self.history.monotonic() - item['_monotonic']), 3),
                        message=_safe_text(message, self.secrets))
        self.save()

    def result(self, status='succeeded', summary=''):
        if status not in STATUSES - {'running'}:
            raise HistoryError('运行结果无效')
        for item in self.record['stages']:
            if item['status'] == 'running':
                item.update(status=status if status in ('failed', 'interrupted') else 'unknown',
                            finished_at=_timestamp(self.history.clock()),
                            duration_seconds=round(max(0, self.history.monotonic() - item['_monotonic']), 3),
                            message='未记录该阶段的完成结果。')
        self.record.update(status=status, summary=_safe_text(summary, self.secrets),
                           finished_at=_timestamp(self.history.clock()),
                           duration_seconds=round(max(0, self.history.monotonic() - self.record['_monotonic']), 3))
        self.save(prune=True)
