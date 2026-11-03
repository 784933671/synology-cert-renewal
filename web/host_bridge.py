#!/usr/bin/env python3
"""群晖本机受限 RPC；所有证书操作仍由原执行器和任务计划负责。"""
import argparse
import base64
import contextlib
import copy
import datetime
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import uuid

_spec = importlib.util.spec_from_file_location('certweb_executor', Path(__file__).resolve().parents[1] / 'certctl.py')
executor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(executor)
_policy_spec = importlib.util.spec_from_file_location('certweb_access_policy', Path(__file__).resolve().parent / 'access_policy.py')
access_policy = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(access_policy)

MAX_REQUEST = 64 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
TASK_ID = 7
RUN_START_WINDOW = 30
FAILURE_ID = re.compile(r'failure-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}')
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,80}')
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')
SNAPSHOT_FILES = ('config.json', 'state/success-notification.json', 'state/web-preferences.json')
PROTECTION_FILES = ('deployment-active.json', 'pending.json', 'run-baseline.json', 'import-bindings.json', 'recovery.json')
REPORT_FIELDS = ('at', 'stage', 'stage_label', 'category', 'code', 'summary', 'hint', 'evidence', 'message', 'archive_error')


class BridgeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def reject(message, code='validation'):
    raise BridgeError(code, message)


def utc(timestamp=None):
    return datetime.datetime.fromtimestamp(time.time() if timestamp is None else timestamp,
                                          datetime.timezone.utc).isoformat(timespec='seconds')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def safe_file(path, limit=1024 * 1024, uid=0):
    """使用 nofollow 与 fstat 读取私有常规文件，拒绝链接和超大文件。"""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or info.st_size > limit:
            reject('本机文件权限或大小不符合要求。', 'unavailable')
        with os.fdopen(fd, 'rb') as handle:
            fd = None
            data = handle.read(limit + 1)
        if len(data) > limit:
            reject('本机文件大小超过限制。', 'unavailable')
        return data
    finally:
        if fd is not None:
            os.close(fd)


def private_directory(path, uid=0):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        reject('本机目录权限不符合要求。', 'unavailable')


def atomic_bytes(path, value):
    fd, name = tempfile.mkstemp(prefix='.web-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, str(path))
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('constant')))


class Scheduler:
    """仅允许读取、修改及触发固定的原 DSM 任务。"""
    def __init__(self, home, capture=executor.capture):
        self.home = Path(home)
        self.capture = capture

    def api(self, api, method, version, params):
        command = shutil.which('synowebapi')
        if not command:
            reject('无法访问群晖任务计划。', 'unavailable')
        arguments = [command, '--exec', 'api=' + api, 'method=' + method, 'version=' + str(version)]
        arguments.extend(key + '=' + json.dumps(value, ensure_ascii=False) for key, value in params.items())
        data = strict_json(self.capture(arguments, timeout=20))
        if not isinstance(data, dict) or data.get('success') is not True or data.get('error'):
            reject('群晖任务计划未返回成功结果。', 'unavailable')
        return data.get('data', {})

    def validate(self, task):
        if (not isinstance(task, dict) or task.get('id') != TASK_ID or task.get('owner') != 'root'
                or type(task.get('enable')) is not bool or not isinstance(task.get('name'), str)
                or not isinstance(task.get('extra'), dict) or not isinstance(task.get('schedule'), dict)):
            reject('原任务结构无法识别，已停止管理操作。', 'unavailable')
        try:
            command = shlex.split(task['extra']['script'])
        except (KeyError, TypeError, ValueError):
            reject('原任务脚本无法核验。', 'unavailable')
        if command != ['/bin/sh', str(self.home / 'run-task.sh')]:
            reject('任务 7 已指向其他脚本，拒绝操作。', 'conflict')
        return task

    def get(self):
        return self.validate(self.api('SYNO.Core.TaskScheduler', 'get', 4, {'id': TASK_ID}))

    def put(self, task):
        self.validate(task)
        params = {key: copy.deepcopy(task[key]) for key in ('id', 'name', 'owner', 'enable', 'schedule', 'extra')}
        params['real_owner'] = task.get('real_owner') or 'tangtao'
        self.api('SYNO.Core.TaskScheduler.Root', 'set', 4, params)
        observed = self.get()
        if any(observed.get(key) != task.get(key) for key in ('id', 'name', 'owner', 'enable', 'schedule', 'extra')):
            reject('群晖任务保存后的回读结果不一致。', 'unavailable')
        return observed

    def run(self):
        self.get()
        command = shutil.which('synoschedtask')
        if not command:
            reject('无法触发群晖原任务。', 'unavailable')
        self.capture([command, '--run', 'id=7', 'check_time=0', 'check_status=0'], timeout=20)

    def history(self):
        return self.api('SYNO.Core.TaskScheduler', 'get_history_status_list', 1, {'id': TASK_ID})


def read_schedule(task):
    raw = task['schedule']
    result = {'enabled': task['enable'], 'mode': 'unsupported', 'interval_hours': 1,
              'hour': 0, 'minute': 0, 'editable': False}
    if (raw.get('date_type') != 0 or raw.get('repeat_date') != 1001
            or raw.get('week_day') != '0,1,2,3,4,5,6' or raw.get('monthly_week') != []
            or raw.get('repeat_min') != 0 or raw.get('version') != 4
            or raw.get('repeat_hour_store_config') is not None
            or raw.get('repeat_min_store_config') is not None
            or type(raw.get('minute')) is not int or not 0 <= raw['minute'] <= 59
            or type(raw.get('hour')) is not int or not 0 <= raw['hour'] <= 23):
        return result
    interval = raw.get('repeat_hour')
    if type(interval) is not int:
        return result
    if interval in (1, 2, 3, 4, 6, 8, 12) and raw['hour'] == 0 and raw.get('last_work_hour') == 23:
        result.update(mode='hourly', interval_hours=interval, editable=True)
    elif interval == 0 and raw.get('last_work_hour') == raw['hour']:
        result.update(mode='daily', hour=raw['hour'], editable=True)
    result['minute'] = raw['minute']
    return result


def write_schedule(task, settings):
    if not isinstance(settings, dict) or set(settings) != {'enabled', 'mode', 'interval_hours', 'hour', 'minute'}:
        reject('检查计划字段不完整或包含未知字段。')
    if (type(settings['enabled']) is not bool or settings['mode'] not in ('hourly', 'daily')
            or type(settings['minute']) is not int or not 0 <= settings['minute'] <= 59
            or type(settings['hour']) is not int or not 0 <= settings['hour'] <= 23
            or type(settings['interval_hours']) is not int or settings['interval_hours'] not in (1, 2, 3, 4, 6, 8, 12)):
        reject('检查计划的时间或频率无效。')
    if not read_schedule(task)['editable']:
        reject('当前 DSM 计划不在支持范围内，请先在群晖调整为每小时或每天执行。', 'conflict')
    result = copy.deepcopy(task)
    result['enable'] = settings['enabled']
    raw = result['schedule']
    raw.update(hour=0 if settings['mode'] == 'hourly' else settings['hour'],
               last_work_hour=23 if settings['mode'] == 'hourly' else settings['hour'],
               repeat_hour=settings['interval_hours'] if settings['mode'] == 'hourly' else 0,
               minute=settings['minute'])
    return result


class Bridge:
    def __init__(self, home=executor.DEFAULT_HOME, controller_factory=None, scheduler=None, uid=0, management_host=None, access_policy_path=None, policy_gid=10100):
        if management_host is not None and (not executor.valid_domain(management_host) or management_host.startswith('*.')):
            reject('管理域名必须是小写的完整域名，不能使用通配符。')
        self.home = Path(home)
        self.uid = uid
        self.management_host = management_host
        self.access_policy_path = Path(access_policy_path) if access_policy_path is not None else None
        self.policy_gid = policy_gid
        self.controller_factory = controller_factory or (lambda: executor.Controller(self.home))
        self.scheduler = scheduler or Scheduler(self.home)
        self.actions = threading.Lock()
        self.check_state = {'running': False, 'last_result': None}
        self.check_lock = threading.Lock()
        self.run_requested_at = -float('inf')
        self.recovery_attempt_at = -float('inf')
        self.transaction = self.home / 'state/web-transaction.json'

    def read(self, path, default=None):
        if not os.path.lexists(path):
            return default
        return strict_json(safe_file(path, uid=self.uid))

    def file_digest(self, path):
        return hashlib.sha256(safe_file(path, uid=self.uid)).hexdigest() if os.path.lexists(path) else None

    def controller(self):
        private_directory(self.home, self.uid)
        private_directory(self.home / 'state', self.uid)
        controller = self.controller_factory()
        controller.load()
        return controller

    def sanitize(self, text, controller, limit=2000):
        return executor.diagnostics.sanitize(text, secrets=controller.diagnostic_secrets(), limit=limit)

    @contextlib.contextmanager
    def action(self):
        if not self.actions.acquire(False):
            reject('已有管理操作正在执行，请稍后重试。', 'busy')
        try:
            if os.path.lexists(self.transaction):
                reject('配置事务尚未恢复，暂时禁止写入和运行。', 'conflict')
            if time.monotonic() - self.run_requested_at < RUN_START_WINDOW:
                reject('原任务正在启动，请稍后刷新状态。', 'busy')
            yield
        finally:
            self.actions.release()

    def protection(self, controller):
        if any(os.path.lexists(controller.state / name) for name in PROTECTION_FILES):
            reject('存在未完成的部署或恢复保护状态，请先完成恢复。', 'conflict')
        if controller.dns_cleanup_count():
            reject('仍有 DNS 验证记录待清理，暂时不能修改配置。', 'conflict')
        notice = self.read(controller.state / 'success-notification.json')
        if notice is not None and (not isinstance(notice, dict) or notice.get('pending') is not None):
            reject('存在待发送通知或通知状态异常，暂时不能修改配置。', 'conflict')
        if notice is not None:
            # 禁用通知时原执行器不验证历史状态，修改前仍核对归属与指纹。
            if (notice.get('version') != 1 or notice.get('certificate_id') != controller.config['certificate_id']
                    or not isinstance(notice.get('last_notified_fingerprint'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', notice['last_notified_fingerprint'])
                    or 'pending' not in notice):
                reject('成功通知基线无效，请先核对当前状态。', 'conflict')

    def choices(self, controller):
        info = executor.read_json(controller.archive / 'INFO')
        if not isinstance(info, dict):
            reject('无法读取群晖证书列表。', 'unavailable')
        choices = []
        for identifier, entry in sorted(info.items()):
            if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier) or not isinstance(entry, dict):
                continue
            description = entry.get('desc')
            try:
                executor.validate_description(description, controller.deployment_method())
                if sum(isinstance(other, dict) and other.get('desc') == description for other in info.values()) != 1:
                    continue
                path = controller.archive / identifier / 'cert.pem'
                if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
                    continue
                domains = executor.certificate_domains(path)
                if not all(executor.valid_domain(domain) for domain in domains):
                    continue
                selectable = self.management_host is None or executor.covers(domains, self.management_host)
                reason = '' if selectable else '此证书不覆盖管理域名 ' + self.management_host
                if selectable and self.management_host is not None and executor.certificate_expiry(path) <= time.time():
                    selectable, reason = False, '此证书已过期，管理页面需要有效且可信的 HTTPS 证书'
                choices.append({'id': identifier, 'description': self.sanitize(description, controller, 1024),
                                'domains': domains, 'selectable': selectable,
                                'reason': reason})
            except (executor.Failure, OSError):
                continue
        return choices

    def revision(self, controller, task):
        payload = {'config': controller.config, 'task': task,
                   'mail_state': self.read(controller.state / 'success-notification.json'),
                   'preferences': self.read(controller.state / 'web-preferences.json')}
        return hashlib.sha256(canonical(payload)).hexdigest()

    def settings_data(self, controller, task):
        config = controller.config
        extra = task['extra']
        preferences = self.read(controller.state / 'web-preferences.json', {})
        return {'revision': self.revision(controller, task), 'certificate_id': config['certificate_id'],
                'description': self.sanitize(config['certificate_description'], controller, 1024),
                'domains': config['domains'], 'certificates': self.choices(controller),
                'email': config['email'], 'renew_before_days': config.get('renew_before_days', 2),
                'secret_id_configured': bool(config.get('secret_id')), 'secret_key_configured': bool(config.get('secret_key')),
                'probes': [{'host': self.sanitize(probe['host'], controller, 253), 'port': probe['port'],
                            'server_name': probe['server_name']} for probe in config['probes']],
                'schedule': read_schedule(task),
                'notifications': {'success_enabled': 'success_notify_email' in config,
                                  'success_email': config.get('success_notify_email', preferences.get('success_email', config['email'])),
                                  'failure_enabled': extra.get('notify_enable') is True,
                                  'failure_email': self.sanitize(extra.get('notify_mail', ''), controller, 254)},
                'deployment_method': controller.deployment_method(), 'timezone': 'Asia/Shanghai'}

    def settings_get(self):
        controller = self.controller()
        with controller.locked():
            controller.load()
            return self.settings_data(controller, self.scheduler.get())

    def safe_result(self, data, controller):
        if not isinstance(data, dict) or type(data.get('success')) is not bool:
            return None
        result = {'at': self.sanitize(data.get('at', ''), controller, 64), 'success': data['success'],
                  'message': self.sanitize(data.get('message') or ('检查完成，证书和 HTTPS 服务正常。' if data['success'] else '执行失败，请查看失败记录。'), controller, 600)}
        if isinstance(data.get('failure'), dict):
            result['failure'] = {key: self.sanitize(data['failure'][key], controller, 1200)
                                 for key in REPORT_FIELDS if isinstance(data['failure'].get(key), str)}
        return result

    def status(self):
        controller = self.controller()
        task = self.scheduler.get()
        running = False
        try:
            with controller.locked():
                pass
        except executor.Busy:
            running = True
            self.run_requested_at = -float('inf')
        cert = controller.current_cert()
        expiry = executor.certificate_expiry(cert)
        days = controller.config.get('renew_before_days', 2)
        schedule = read_schedule(task)
        label = ('每 {} 小时第 {} 分钟'.format(schedule['interval_hours'], schedule['minute']) if schedule['mode'] == 'hourly'
                 else '每天 {:02d}:{:02d}'.format(schedule['hour'], schedule['minute']) if schedule['mode'] == 'daily'
                 else 'DSM 自定义计划（只读）')
        notice = self.read(controller.state / 'success-notification.json', {})
        with self.check_lock:
            check = copy.deepcopy(self.check_state)
        result = self.safe_result(self.read(controller.state / 'last-result.json'), controller)
        return {'certificate': {'id': controller.config['certificate_id'],
                                'description': self.sanitize(controller.config['certificate_description'], controller, 1024),
                                'domains': controller.config['domains'], 'not_after': utc(expiry),
                                'fingerprint': executor.fingerprint(cert), 'remaining_seconds': expiry - int(time.time()),
                                'renew_at': utc(expiry - days * 86400)},
                'renew_before_days': days,
                'task': {'enabled': task['enable'], 'running': running or time.monotonic() - self.run_requested_at < RUN_START_WINDOW,
                         'schedule_text': label, 'last_run': result['at'] if result else None},
                'last_result': result,
                'pending': {'deployment': os.path.lexists(controller.state / 'pending.json'),
                            'dns_cleanup': bool(controller.dns_cleanup_count()),
                            'notification': bool(notice.get('pending')) if isinstance(notice, dict) else True,
                            'interrupted': any(os.path.lexists(controller.state / name) for name in PROTECTION_FILES if name != 'pending.json') or os.path.lexists(self.transaction)},
                'check': check, 'server_time': utc(), 'timezone': 'Asia/Shanghai'}

    def validate_update(self, params, controller, task):
        required = {'revision', 'certificate_id', 'email', 'renew_before_days', 'probes', 'schedule', 'notifications'}
        if not isinstance(params, dict) or not required <= set(params) or set(params) - required - {'secret_id', 'secret_key'}:
            reject('配置字段不完整或包含不允许修改的字段。')
        if not isinstance(params['revision'], str) or not re.fullmatch(r'[0-9a-f]{64}', params['revision']):
            reject('配置版本格式无效。')
        if params['revision'] != self.revision(controller, task):
            reject('配置已被其他操作修改，请刷新后重试。', 'stale_revision')
        identifier = params['certificate_id']
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            reject('证书 ID 格式无效。')
        selected = next((item for item in self.choices(controller) if item['id'] == identifier), None)
        if selected is None:
            reject('请选择具有唯一描述和有效域名的群晖证书。')
        if self.management_host is not None and not executor.covers(selected['domains'], self.management_host):
            reject('所选证书不覆盖管理域名 {}，切换会使管理页面无法访问，请选择覆盖该域名的证书。'.format(self.management_host))
        if self.management_host is not None and executor.certificate_expiry(controller.archive / identifier / 'cert.pem') <= time.time():
            reject('所选证书已过期，管理页面必须使用有效且可信的 HTTPS 证书。')
        config = copy.deepcopy(controller.config)
        domains = selected['domains']
        if identifier == config['certificate_id'] and set(domains) == set(config['domains']):
            domains = config['domains']
        elif 'ttxli.cn' in domains:
            domains = ['ttxli.cn'] + [domain for domain in domains if domain != 'ttxli.cn']
        config.update(certificate_id=identifier, certificate_description=selected['description'], domains=domains,
                      email=params['email'], renew_before_days=params['renew_before_days'], probes=params['probes'])
        secrets = [params.get(key, '') for key in ('secret_id', 'secret_key')]
        if any(not isinstance(value, str) or len(value) > 512 for value in secrets) or bool(secrets[0]) != bool(secrets[1]):
            reject('更换 DNSPod 密钥时必须同时提供 SecretId 和 SecretKey。')
        if secrets[0]:
            config.update(secret_id=secrets[0], secret_key=secrets[1])
        probes = params['probes']
        if not isinstance(probes, list) or not 1 <= len(probes) <= 8:
            reject('请配置 1 到 8 个 HTTPS 验证端点。')
        for probe in probes:
            if not isinstance(probe, dict) or set(probe) != {'host', 'port', 'server_name'}:
                reject('HTTPS 验证端点字段无效。')
            host = probe['host']
            if not isinstance(host, str) or len(host) > 253 or '%' in host:
                reject('验证地址必须是域名或 IP。')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if host != 'localhost' and (not executor.valid_domain(host) or host.startswith('*.')):
                    reject('验证地址必须是域名或 IP。')
        notices = params['notifications']
        if not isinstance(notices, dict) or set(notices) != {'success_enabled', 'success_email', 'failure_enabled', 'failure_email'}:
            reject('通知配置字段无效。')
        for kind in ('success', 'failure'):
            enabled, address = notices[kind + '_enabled'], notices[kind + '_email']
            if (type(enabled) is not bool or not isinstance(address, str) or len(address) > 254
                    or ((enabled or address) and (address.startswith('-') or not EMAIL.fullmatch(address)))):
                reject('通知邮箱或启用状态无效。')
        if notices['success_enabled']:
            config['success_notify_email'] = notices['success_email']
        else:
            config.pop('success_notify_email', None)
        try:
            executor.validate_config(config)
        except executor.Failure:
            reject('证书、邮箱、密钥或验证端点配置无效，请检查填写内容。')
        task = write_schedule(task, params['schedule'])
        task['extra'].update(notify_enable=notices['failure_enabled'], notify_if_error=True,
                             notify_mail=notices['failure_email'])
        return config, task, {'success_email': notices['success_email']}

    def snapshot(self, controller, task):
        root = controller.state / 'web-backups'
        root.mkdir(mode=0o700, exist_ok=True)
        private_directory(root, self.uid)
        name = 'config-' + uuid.uuid4().hex
        directory = root / name
        directory.mkdir(mode=0o700)
        files = {}
        for relative in SNAPSHOT_FILES:
            path = self.home / relative
            files[relative] = base64.b64encode(safe_file(path, uid=self.uid)).decode('ascii') if os.path.lexists(path) else None
        snapshot = {'version': 1, 'task': task, 'files': files, 'at': utc(),
                    'result_digest': self.file_digest(controller.state / 'last-result.json')}
        atomic_bytes(directory / 'snapshot.json', canonical(snapshot))
        atomic_bytes(self.transaction, canonical({'version': 1, 'backup': name, 'phase': 'prepared'}))
        return snapshot

    def commit_decision(self, config, task):
        journal = self.read(self.transaction)
        journal.update(phase='committed', config_digest=hashlib.sha256(canonical(config)).hexdigest(), desired_task=task)
        atomic_bytes(self.transaction, canonical(journal))

    def stage_notification(self, config):
        journal = self.read(self.transaction)
        journal['staged_notice_digest'] = self.file_digest(self.home / 'state/success-notification.json')
        journal['staged_config_digest'] = hashlib.sha256(canonical(config)).hexdigest()
        atomic_bytes(self.transaction, canonical(journal))

    def finish_forward(self, journal):
        expected = journal.get('config_digest')
        current = self.read(self.home / 'config.json')
        if (not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected)
                or hashlib.sha256(canonical(current)).hexdigest() != expected):
            reject('已提交事务的配置已发生变化，请管理员核对后恢复。', 'unavailable')
        executor.validate_config(current)
        task = journal.get('desired_task')
        self.scheduler.put(task)
        self.transaction.unlink()

    def restore(self, snapshot):
        if (not isinstance(snapshot, dict) or snapshot.get('version') != 1
                or not isinstance(snapshot.get('files'), dict) or set(snapshot['files']) != set(SNAPSHOT_FILES)):
            reject('配置备份结构无效，需管理员检查。', 'unavailable')
        task = snapshot['task']
        paused = copy.deepcopy(task)
        paused['enable'] = False
        self.scheduler.put(paused)
        for relative in SNAPSHOT_FILES:
            path = self.home / relative
            contents = snapshot['files'][relative]
            if contents is None:
                if os.path.lexists(path):
                    safe_file(path, uid=self.uid)
                    path.unlink()
            else:
                atomic_bytes(path, base64.b64decode(contents, validate=True))
        self.scheduler.put(task)
        self.transaction.unlink()

    def recover(self):
        if not os.path.lexists(self.transaction):
            return
        controller = self.controller_factory()
        with controller.locked():
            journal = self.read(self.transaction)
            if isinstance(journal, dict) and journal.get('phase') == 'committed':
                self.finish_forward(journal)
                return
            if not isinstance(journal, dict) or journal.get('phase') not in (None, 'prepared'):
                reject('未完成事务阶段无法识别，请管理员核对。', 'unavailable')
            name = journal.get('backup') if isinstance(journal, dict) else None
            if not isinstance(name, str) or not re.fullmatch(r'config-[0-9a-f]{32}', name):
                reject('未完成事务的备份标识无效。', 'unavailable')
            root = controller.state / 'web-backups'
            private_directory(root, self.uid)
            private_directory(root / name, self.uid)
            snapshot = self.read(root / name / 'snapshot.json')
            # 提交前异常退出后，若执行器已推进状态，不能覆盖新的恢复或通知待办。
            self.assert_restore_safe(controller, snapshot, journal)
            self.restore(snapshot)

    def recovery_due(self):
        return os.path.lexists(self.transaction) and time.monotonic() - self.recovery_attempt_at >= 30

    def retry_recovery(self):
        if not self.actions.acquire(False):
            return
        try:
            if not self.recovery_due():
                return
            self.recovery_attempt_at = time.monotonic()
            journal = self.read(self.transaction, {})
            if isinstance(journal, dict) and journal.get('phase') == 'committed':
                self.recover()
        except Exception:
            # 保留提交决策，后续空闲周期继续；不把本机异常输出到日志。
            pass
        finally:
            self.actions.release()

    def assert_restore_safe(self, controller, snapshot, journal=None):
        if any(os.path.lexists(controller.state / name) for name in PROTECTION_FILES):
            reject('事务中断后执行器出现恢复状态，拒绝覆盖；请管理员核对。', 'unavailable')
        notice = self.read(controller.state / 'success-notification.json')
        if isinstance(notice, dict) and notice.get('pending') is not None:
            reject('事务中断后出现待发送通知，拒绝覆盖；请管理员核对。', 'unavailable')
        if journal is not None:
            if ('result_digest' not in snapshot
                    or snapshot['result_digest'] != self.file_digest(controller.state / 'last-result.json')
                    or controller.dns_cleanup_count()):
                reject('事务中断后执行器结果或 DNS 状态已推进，拒绝回退。', 'unavailable')
            previous_config = strict_json(base64.b64decode(snapshot['files']['config.json'], validate=True))
            current_config = self.read(controller.config_file)
            if current_config != previous_config:
                if hashlib.sha256(canonical(current_config)).hexdigest() != journal.get('staged_config_digest'):
                    reject('事务中断后配置已被其他操作修改，拒绝覆盖。', 'unavailable')
                old_notice = snapshot['files']['state/success-notification.json']
                allowed = {hashlib.sha256(base64.b64decode(old_notice, validate=True)).hexdigest() if old_notice is not None else None}
                if 'staged_notice_digest' in journal:
                    allowed.add(journal['staged_notice_digest'])
                if self.file_digest(controller.state / 'success-notification.json') not in allowed:
                    reject('事务中断后通知状态已变化，拒绝覆盖。', 'unavailable')
        previous = snapshot.get('files', {}).get('state/success-notification.json') if isinstance(snapshot, dict) else None
        if previous is not None:
            old_notice = strict_json(base64.b64decode(previous, validate=True))
            if (isinstance(old_notice, dict) and isinstance(notice, dict)
                    and old_notice.get('certificate_id') == notice.get('certificate_id')
                    and old_notice.get('last_notified_fingerprint') != notice.get('last_notified_fingerprint')):
                reject('事务中断后通知状态已推进，拒绝回退通知基线。', 'unavailable')

    def settings_update(self, params):
        with self.action():
            controller = self.controller()
            with controller.locked():
                controller.load()
                self.protection(controller)
                previous_task = self.scheduler.get()
                config, task, preferences = self.validate_update(params, controller, previous_task)
                same_target = (config['certificate_id'] == controller.config['certificate_id']
                               and config['domains'] == controller.config['domains'])
                snapshot = self.snapshot(controller, previous_task)
                committed = False
                try:
                    paused = copy.deepcopy(previous_task)
                    paused['enable'] = False
                    self.scheduler.put(paused)
                    controller.config = config
                    info = controller.preflight()
                    if self.management_host is not None:
                        try:
                            controller.verify_probes(executor.fingerprint(controller.current_cert()), attempts=1, verify_chain=True)
                        except executor.Failure:
                            reject('管理页面必须使用有效且可信的 HTTPS 证书；所选证书的实际服务链验证失败。')
                    bindings = controller.binding_state(info)
                    if not same_target:
                        notice = controller.state / 'success-notification.json'
                        if os.path.lexists(notice):
                            safe_file(notice, uid=self.uid)
                            notice.unlink()
                    controller.initialize_success_notification()
                    if controller.target_bindings(controller.binding_state(controller.metadata())) != controller.target_bindings(bindings):
                        reject('配置过程中证书服务绑定发生变化，已停止保存。', 'conflict')
                    self.protection(controller)
                    self.stage_notification(config)
                    atomic_bytes(controller.config_file, canonical(config))
                    atomic_bytes(controller.state / 'web-preferences.json', canonical(preferences))
                    self.commit_decision(config, task)
                    committed = True
                    self.scheduler.put(task)
                    result = self.settings_data(controller, self.scheduler.get())
                    self.transaction.unlink()
                    return result
                except Exception as error:
                    if not committed:
                        # 原子替换后目录 fsync 也可能失败；以磁盘提交决策为准。
                        try:
                            committed = self.read(self.transaction, {}).get('phase') == 'committed'
                        except Exception:
                            reject('配置事务状态无法确认，已保留备份；请管理员恢复后再操作。', 'unavailable')
                    if committed:
                        reject('新配置已提交，任务启用或结果确认尚未完成；已保留恢复记录，将继续完成且不会回退新待办。', 'unavailable')
                    try:
                        self.assert_restore_safe(controller, snapshot)
                        self.restore(snapshot)
                    except Exception:
                        reject('配置保存失败且回滚未完成，已保留备份；请管理员恢复后再操作。', 'unavailable')
                    if isinstance(error, BridgeError):
                        raise error
                    reject('配置验证或保存失败，已恢复原配置与任务计划。', 'conflict')

    def run(self):
        with self.action():
            controller = self.controller()
            with controller.locked():
                if time.monotonic() - self.run_requested_at < RUN_START_WINDOW:
                    reject('原任务刚刚收到运行请求，请稍后刷新状态。', 'busy')
                self.scheduler.get()
            # 原任务需要获取同一把锁，因此先释放再触发；操作锁防止网页配置插入。
            self.run_requested_at = time.monotonic()
            self.scheduler.run()
            return {'accepted': True, 'message': '已手动触发原 DSM 任务，自动计划启用状态不变；未到续期时间时仅检查。'}

    def check(self):
        if not self.actions.acquire(False):
            reject('已有管理操作正在执行，请稍后重试。', 'busy')
        lock_context = None
        locked = False
        try:
            if os.path.lexists(self.transaction):
                reject('配置事务尚未恢复，暂时无法预检。', 'conflict')
            if time.monotonic() - self.run_requested_at < RUN_START_WINDOW:
                reject('原任务正在启动，请稍后刷新状态。', 'busy')
            controller = self.controller()
            lock_context = controller.locked()
            lock_context.__enter__()
            locked = True
            with self.check_lock:
                self.check_state['running'] = True
            worker = threading.Thread(target=self._check_worker, args=(controller, lock_context), daemon=True)
            worker.start()
            return {'accepted': True, 'message': '已开始预检查，不申请或部署证书。'}
        except Exception:
            if locked:
                lock_context.__exit__(None, None, None)
            with self.check_lock:
                self.check_state['running'] = False
            self.actions.release()
            raise

    def _check_worker(self, controller, lock_context):
        result = {'at': utc(), 'success': False, 'message': '预检查失败，请核对本机环境及 HTTPS 服务。'}
        try:
            controller.preflight()
            result.update(success=True, message='预检查通过：系统、证书、域名、服务绑定与接口正常。')
        except Exception as error:
            if isinstance(error, executor.Failure):
                result['message'] = self.sanitize(str(error), controller, 600)
        finally:
            lock_context.__exit__(None, None, None)
            with self.check_lock:
                self.check_state.update(running=False, last_result=result)
            self.actions.release()

    def archive(self, identifier):
        if not isinstance(identifier, str) or not FAILURE_ID.fullmatch(identifier):
            reject('失败记录标识无效。', 'not_found')
        root = self.home / 'state/failures'
        private_directory(root, self.uid)
        directory = root / identifier
        private_directory(directory, self.uid)
        complete = self.read(directory / 'complete.json')
        if not isinstance(complete, dict) or complete.get('version') != 1:
            reject('失败记录尚未完整保存。', 'not_found')
        return directory

    def failure_get(self, identifier):
        controller = self.controller()
        directory = self.archive(identifier)
        report = self.read(directory / 'report.json')
        if not isinstance(report, dict):
            reject('失败记录格式无效。', 'unavailable')
        safe = {key: self.sanitize(report[key], controller, 2000) for key in REPORT_FIELDS if isinstance(report.get(key), str)}
        logs = []
        for path in sorted(directory.iterdir()):
            if path.name in ('report.json', 'complete.json'):
                continue
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}', path.name) or len(logs) >= 8:
                continue
            data = safe_file(path, limit=executor.diagnostics.MAX_LOG_BYTES, uid=self.uid)
            logs.append({'name': path.name, 'text': self.sanitize(data, controller, 160 * 1024)})
        return {'id': identifier, 'report': safe, 'logs': logs}

    def failure_list(self):
        root = self.home / 'state/failures'
        if not os.path.lexists(root):
            return {'items': []}
        private_directory(root, self.uid)
        items = []
        controller = self.controller()
        for path in sorted(root.iterdir(), reverse=True):
            if not FAILURE_ID.fullmatch(path.name) or len(items) >= 30:
                continue
            try:
                directory = self.archive(path.name)
                report = self.read(directory / 'report.json')
                if not isinstance(report, dict):
                    continue
                item = {'id': path.name}
                item.update({key: self.sanitize(report.get(key, ''), controller, 1000)
                             for key in ('at', 'stage_label', 'summary', 'code')})
                items.append(item)
            except (OSError, ValueError, BridgeError):
                continue
        return {'items': items}

    def security_update(self, params):
        if (not isinstance(params, dict) or set(params) != {'access_mode', 'revision'}
                or params['access_mode'] not in ('lan', 'public')
                or not isinstance(params['revision'], str) or not re.fullmatch(r'[0-9a-f]{32}', params['revision'])):
            reject('访问模式或配置版本无效。')
        if self.access_policy_path is None:
            reject('当前安装尚未启用访问模式配置。', 'unavailable')
        try:
            return access_policy.write_policy(self.access_policy_path, params['access_mode'], params['revision'],
                                              owner_uid=self.uid, gid=self.policy_gid)
        except access_policy.PolicyConflict:
            reject('访问模式已被其他操作修改，请刷新后重试。', 'stale_revision')
        except (OSError, ValueError):
            reject('访问策略无法保存，请检查策略文件和目录权限。', 'unavailable')

    def dispatch(self, request):
        try:
            if not isinstance(request, dict) or set(request) != {'method', 'params'} or not isinstance(request['params'], dict):
                reject('RPC 请求结构无效。', 'invalid_request')
            method, params = request['method'], request['params']
            if not isinstance(method, str):
                reject('RPC 方法无效。', 'invalid_request')
            methods = {'status': self.status, 'settings.get': self.settings_get, 'settings.update': self.settings_update,
                       'run': self.run, 'check': self.check, 'failures.list': self.failure_list,
                       'security.update': self.security_update}
            if method == 'failures.get':
                if set(params) != {'id'}:
                    reject('失败记录请求字段无效。', 'invalid_request')
                data = self.failure_get(params['id'])
            elif method in methods:
                if method not in ('settings.update', 'security.update') and params:
                    reject('该操作不接受额外参数。', 'invalid_request')
                data = methods[method](params) if method in ('settings.update', 'security.update') else methods[method]()
            else:
                reject('不支持该 RPC 操作。', 'invalid_request')
            return {'ok': True, 'data': data}
        except BridgeError as error:
            return {'ok': False, 'error': {'code': error.code, 'message': error.message}}
        except executor.Busy:
            return {'ok': False, 'error': {'code': 'busy', 'message': '证书任务正在运行，请稍后重试。'}}
        except FileNotFoundError:
            return {'ok': False, 'error': {'code': 'not_found', 'message': '所需记录或本机文件不存在。'}}
        except Exception:
            return {'ok': False, 'error': {'code': 'unavailable', 'message': '本机操作未能完成，请检查服务状态或联系管理员。'}}

    def wait_idle(self):
        # 停止监听后等待已接受的配置事务或异步预检释放操作锁。
        with self.actions:
            pass


def peer_uid(connection):
    if hasattr(socket, 'SO_PEERCRED'):
        return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
    if hasattr(connection, 'getpeereid'):
        return connection.getpeereid()[0]
    reject('无法核验本机连接身份。', 'unavailable')


@contextlib.contextmanager
def daemon_lock(path, uid=0):
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            reject('桥接进程锁权限不符合要求。')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            reject('已有桥接服务正在运行。', 'busy')
        yield


class WorkGroup:
    def __init__(self):
        self.lock = threading.Lock()
        self.threads = set()
        self.closed = False

    def start(self, function, *args):
        def run():
            try:
                function(*args)
            finally:
                with self.lock:
                    self.threads.discard(threading.current_thread())
        with self.lock:
            if self.closed:
                return False
            worker = threading.Thread(target=run, daemon=True)
            self.threads.add(worker)
            try:
                worker.start()
            except Exception:
                self.threads.discard(worker)
                raise
        return True

    def close(self):
        with self.lock:
            self.closed = True

    def wait(self):
        with self.lock:
            active = list(self.threads)
        for worker in active:
            worker.join()


def handle_connection(connection, bridge, allowed_uid=10100, timeout=60, identify=peer_uid, operations=None):
    error = {'ok': False, 'error': {'code': 'invalid_request', 'message': '请求格式、长度或超时不符合要求。'}}
    try:
        if identify(connection) not in (0, allowed_uid):
            error['error'] = {'code': 'forbidden', 'message': '此连接身份无权访问证书桥接。'}
            connection.sendall(canonical(error) + b'\n')
            return
        deadline = time.monotonic() + timeout
        buffer = bytearray()
        while b'\n' not in buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('timeout')
            connection.settimeout(remaining)
            chunk = connection.recv(min(8192, MAX_REQUEST + 1 - len(buffer)))
            if not chunk:
                raise ValueError('incomplete')
            buffer.extend(chunk)
            if len(buffer) > MAX_REQUEST:
                raise ValueError('oversize')
        line, trailing = bytes(buffer).split(b'\n', 1)
        if trailing.strip():
            raise ValueError('multiple requests')
        request = strict_json(line.decode('utf-8'))
        completed = threading.Event()
        result = []
        def dispatch():
            try:
                result.append(bridge.dispatch(request))
            finally:
                completed.set()
        if operations is None:
            threading.Thread(target=dispatch, daemon=True).start()
        elif not operations.start(dispatch):
            raise ValueError('service stopping')
        if not completed.wait(max(0, deadline - time.monotonic())):
            response = {'ok': False, 'error': {'code': 'unavailable',
                        'message': '操作尚未返回，请稍后刷新状态；已开始的安全保存或回滚会继续完成。'}}
        else:
            response = result[0] if result else error
        output = canonical(response)
        if len(output) > MAX_RESPONSE:
            raise ValueError('response oversize')
        connection.settimeout(5)
        connection.sendall(output + b'\n')
    except (OSError, ValueError, UnicodeError, RecursionError):
        try:
            connection.settimeout(1)
            connection.sendall(canonical(error) + b'\n')
        except OSError:
            pass
    finally:
        connection.close()


def serve_requests(server, bridge, stop, allowed_uid=10100, parent_pid=None):
    slots = threading.BoundedSemaphore(8)
    connections = set()
    connection_lock = threading.Lock()
    handlers, operations = WorkGroup(), WorkGroup()
    def process(connection):
        try:
            handle_connection(connection, bridge, allowed_uid, operations=operations)
        finally:
            with connection_lock:
                connections.discard(connection)
            slots.release()
    try:
        while not stop.is_set() and (parent_pid is None or os.getppid() == parent_pid):
            if bridge.recovery_due():
                operations.start(bridge.retry_recovery)
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            if not slots.acquire(False):
                connection.close()
                continue
            with connection_lock:
                connections.add(connection)
            handlers.start(process, connection)
    finally:
        server.close()
        operations.close()
        handlers.close()
        with connection_lock:
            active = list(connections)
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        handlers.wait()
        operations.wait()
        bridge.wait_idle()


def serve(bridge, path, allowed_uid=10100, allowed_gid=10100, stop=None, parent_pid=None):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        reject('socket 路径必须是绝对路径。')
    for parent in path.parents:
        if parent.is_symlink():
            reject('socket 目录不能经过符号链接。')
    path.parent.mkdir(mode=0o750, parents=False, exist_ok=True)
    directory = path.parent.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or directory.st_mode & 0o027:
        reject('socket 专用目录权限不符合要求。')
    os.chown(str(path.parent), 0, allowed_gid)
    os.chmod(str(path.parent), 0o750)
    with daemon_lock(path.parent / 'daemon.lock'):
        bridge.recover()
        if os.path.lexists(path):
            old = path.lstat()
            if not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0:
                reject('socket 路径已被其他文件占用。')
            path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        owned = None
        stop = stop or threading.Event()
        try:
            server.bind(str(path))
            owned = path.lstat().st_ino
            os.chown(str(path), 0, allowed_gid)
            os.chmod(str(path), 0o660)
            server.listen(8)
            server.settimeout(1)
            serve_requests(server, bridge, stop, allowed_uid, parent_pid)
        finally:
            server.close()
            if owned is not None and os.path.lexists(path) and path.lstat().st_ino == owned:
                path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=executor.DEFAULT_HOME)
    parser.add_argument('--socket', type=Path)
    parser.add_argument('--task-id', type=int, choices=(TASK_ID,), default=TASK_ID)
    parser.add_argument('--uid', type=int, default=10100)
    parser.add_argument('--gid', type=int, default=10100)
    parser.add_argument('--parent-pid', type=int)
    parser.add_argument('--management-host', required=True)
    parser.add_argument('--access-policy', type=Path)
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0 or (args.parent_pid is not None and args.parent_pid <= 1):
        print('桥接须由 root 运行，并指定独立的非 root 容器身份。', file=sys.stderr)
        return 1
    os.umask(0o077)
    os.environ['PATH'] = executor.SYSTEM_PATH
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        if args.access_policy is not None and (not args.access_policy.is_absolute() or str(args.access_policy) != str(args.access_policy.resolve())):
            raise ValueError('访问策略路径必须是无符号链接的绝对路径')
        serve(Bridge(args.home, management_host=args.management_host, access_policy_path=args.access_policy, policy_gid=args.gid), args.socket or args.home / 'web-run/certweb.sock', args.uid, args.gid, stop, args.parent_pid)
    except Exception:
        print('桥接启动失败，请核查私有目录、进程锁及未完成事务。', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
