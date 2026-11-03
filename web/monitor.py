"""主机独立监测：只读原任务和证书，告警不参与续期执行。"""
import argparse
import contextlib
import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time

DEFAULT_SETTINGS = {'version': 1, 'enabled': True, 'missed_runs': 2,
                    'grace_minutes': 15, 'expiry_hours': 24}
BEIJING = datetime.timezone(datetime.timedelta(hours=8))
CODES = {'task_missed', 'certificate_expiry', 'source_unavailable', 'clock_anomaly'}
LABELS = {'task_missed': '证书检查任务漏跑', 'certificate_expiry': '证书临近到期',
          'source_unavailable': '监测数据暂不可用', 'clock_anomaly': '系统时间需要核对'}
MESSAGES = {'task_missed': '原任务已超过允许的连续未完成次数，请检查群晖任务计划及执行记录。',
            'certificate_expiry': '当前证书已进入到期预警范围，请检查续期及部署结果。',
            'source_unavailable': '无法完整读取原任务或证书状态，已有告警保留，暂不判定恢复。',
            'clock_anomaly': '检测到时间跳变或未来的执行记录，已暂停漏跑判断，请核对 NAS 时间。'}
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')


def utc(value=None):
    return datetime.datetime.fromtimestamp(time.time() if value is None else value,
                                          datetime.timezone.utc).isoformat(timespec='seconds')


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('时间记录无效')
    value = re.sub(r'(T\d{2}:\d{2}:\d{2}\.\d{6})\d+', r'\1', value.replace('Z', '+00:00'))
    result = datetime.datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError('时间记录缺少时区')
    return result.timestamp()


def validate_settings(value):
    if (not isinstance(value, dict) or set(value) != set(DEFAULT_SETTINGS)
            or type(value['version']) is not int or value['version'] != 1
            or type(value['enabled']) is not bool):
        raise ValueError('监测配置字段无效')
    for name, lower, upper in (('missed_runs', 1, 6), ('grace_minutes', 5, 120), ('expiry_hours', 1, 168)):
        if type(value[name]) is not int or not lower <= value[name] <= upper:
            raise ValueError('监测配置范围无效')
    return dict(value)


def directory(path, uid):
    info = Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError('监测目录权限无效')


def read_json(path, default=None, uid=0, limit=256 * 1024):
    path = Path(path)
    directory(path.parent, uid)
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return default
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > limit):
            raise ValueError('监测文件权限或大小无效')
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError('监测文件过大')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('监测文件字段重复')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('无效数字')))


def write_json(path, value, uid=0):
    path = Path(path)
    directory(path.parent, uid)
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('监测输出权限无效')
    data = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(data) > 256 * 1024:
        raise ValueError('监测输出过大')
    descriptor, temporary = tempfile.mkstemp(prefix='.monitor-', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
        descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def locked(path, uid=0):
    path = Path(path)
    directory(path.parent, uid)
    descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, 'a') as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077
                or info.st_nlink != 1):
            raise ValueError('监测锁权限无效')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def lock_busy(path, uid=0):
    try:
        with locked(path, uid):
            return False
    except BlockingIOError:
        return True


def load_settings(native_home, uid=0):
    return validate_settings(read_json(Path(native_home) / 'state/monitor-config.json', DEFAULT_SETTINGS, uid))


def email_valid(value):
    return isinstance(value, str) and len(value) <= 254 and not value.startswith('-') and EMAIL.fullmatch(value) is not None


def masked_email(value):
    if not email_valid(value):
        return None
    local, domain = value.split('@', 1)
    return local[:1] + '***@' + domain


def schedule_window(schedule, after, until):
    """返回宽限后已到期的计划次数和下一计划，固定沿用现有北京时间计划。"""
    if schedule.get('mode') == 'hourly':
        period, offset = schedule['interval_hours'] * 3600, schedule['minute'] * 60
    elif schedule.get('mode') == 'daily':
        period, offset = 86400, schedule['hour'] * 3600 + schedule['minute'] * 60
    else:
        return None, None
    offset -= 8 * 3600
    first = math.floor((after - offset) / period) + 1
    last = math.floor((until - offset) / period)
    return max(0, last - first + 1), (last + 1) * period + offset


class NativeSource:
    def __init__(self, home, task_id, uid=0):
        self.home, self.uid = Path(home), uid
        # 延迟加载避免桥接复用本模块校验器时产生循环导入。
        spec = importlib.util.spec_from_file_location('certweb_monitor_bridge', self.home / 'web/host_bridge.py')
        self.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bridge)
        self.scheduler = self.bridge.Scheduler(self.home, task_id=task_id)

    def controller(self):
        controller = self.bridge.executor.Controller(self.home)
        controller.config = read_json(self.home / 'config.json', uid=self.uid)
        self.bridge.executor.validate_config(controller.config)
        return controller

    def collect(self):
        result = {'task': None, 'schedule': None, 'last_completed': None, 'expires_at': None,
                  'target': None, 'running': None, 'recipient': None, 'delivery_enabled': False,
                  'task_ok': False, 'certificate_ok': False, 'completion_ok': False}
        try:
            task = self.scheduler.get()
            result.update(task=task, schedule=self.bridge.read_schedule(task), task_ok=True)
            extra = task['extra']
            recipient = extra.get('notify_mail')
            result['recipient'] = recipient if email_valid(recipient) else None
            result['delivery_enabled'] = extra.get('notify_enable') is True and email_valid(recipient)
        except Exception:
            pass
        try:
            controller = self.controller()
            result['expires_at'] = self.bridge.executor.certificate_expiry(controller.current_cert())
            result['target'] = controller.config['certificate_id']
            result['certificate_ok'] = True
        except Exception:
            pass
        try:
            previous = read_json(self.home / 'state/last-result.json', uid=self.uid)
            result['last_completed'] = timestamp(previous['at']) if previous is not None else None
            result['running'] = lock_busy(self.home / 'state/run.lock', self.uid)
            result['completion_ok'] = True
        except Exception:
            pass
        return result

    def deliver(self, recipient, event, recovered=False):
        if not email_valid(recipient):
            raise ValueError('通知邮箱无效')
        controller = self.controller()
        settings = controller.call_local_api('SYNO.Core.Notification.Mail.Conf', 'get', timeout=10)
        sender = settings.get('sender_mail')
        if settings.get('enable_mail') is not True or not email_valid(sender):
            raise ValueError('群晖邮件尚未就绪')
        message = EmailMessage(policy=SMTP.clone(linesep='\n', max_line_length=0))
        message['From'], message['To'] = sender, recipient
        message['Subject'] = '证书管家 ' + ('监测恢复通知' if recovered else '监测异常提醒')
        message['Date'] = format_datetime(datetime.datetime.now(datetime.timezone.utc))
        message['Message-ID'] = '<cert-monitor-{}-{}@localhost>'.format(event['id'], 'recovered' if recovered else 'alert')
        message.set_content(('此前告警已恢复。\n' if recovered else '发现需要处理的监测异常。\n')
                            + '\n事件：' + LABELS[event['code']] + '\n首次发现：' + utc(event['since'])
                            + '\n' + ('' if recovered else MESSAGES[event['code']] + '\n')
                            + '\n请登录证书管理页查看当前状态。本邮件不代表已申请或替换证书。\n', cte='8bit')
        process = None
        try:
            process = subprocess.Popen(['/bin/ssmtp', '-f', sender, recipient],
                                       env={'PATH': self.bridge.executor.SYSTEM_PATH, 'HOME': str(self.home), 'LANG': 'C', 'LC_ALL': 'C'},
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
            process.communicate(message.as_bytes(), timeout=25)
            if process.returncode:
                raise ValueError('群晖邮件发送失败')
        finally:
            if process is not None and process.poll() is None:
                controller.stop_process(process)


class Monitor:
    def __init__(self, native_home, web_home, source, uid=0, clock=time.time, monotonic=time.monotonic):
        self.native_home, self.web_home = Path(native_home), Path(web_home)
        self.source, self.uid, self.clock, self.monotonic = source, uid, clock, monotonic
        self.started = monotonic()
        self.previous_clock = None
        self.clock_hold_until = 0
        self.path = self.native_home / 'state/monitor-state.json'
        self.snapshot = self.web_home / 'monitor-status.json'
        self.stopping = False

    def state(self, now):
        default = {'version': 1, 'anchor': now, 'identity': None, 'target': None, 'running_since': None, 'incidents': {}}
        value = read_json(self.path, default, self.uid)
        if (not isinstance(value, dict) or set(value) != set(default) or type(value['version']) is not int or value['version'] != 1
                or not isinstance(value['incidents'], dict) or set(value['incidents']) - CODES
                or (value['target'] is not None and (not isinstance(value['target'], str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value['target'])))
                or (value['identity'] is not None and (not isinstance(value['identity'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', value['identity'])))):
            raise ValueError('监测状态无效')
        for number in (value['anchor'], value['running_since']):
            if number is not None and (type(number) not in (int, float) or not math.isfinite(number) or number < 0):
                raise ValueError('监测时间无效')
        for code, event in value['incidents'].items():
            if (not isinstance(event, dict) or set(event) != {'code', 'id', 'since', 'active', 'notified', 'attempts', 'next_attempt', 'notification_status'}
                    or event['code'] != code or not isinstance(event['id'], str) or not re.fullmatch(r'[0-9a-f]{32}', event['id'])
                    or type(event['active']) is not bool or type(event['notified']) is not bool
                    or type(event['attempts']) is not int or not 0 <= event['attempts'] <= 100
                    or event['notification_status'] not in ('pending', 'sent', 'failed', 'disabled', 'unknown')):
                raise ValueError('监测事件无效')
            for field in ('since', 'next_attempt'):
                if type(event[field]) not in (int, float) or not math.isfinite(event[field]) or event[field] < 0:
                    raise ValueError('监测事件时间无效')
        return value

    def incident(self, state, code, active, now):
        event = state['incidents'].get(code)
        if active is None:
            return
        if active:
            if event is None:
                event = {'code': code, 'id': os.urandom(16).hex(), 'since': now, 'active': True,
                         'notified': False, 'attempts': 0, 'next_attempt': now, 'notification_status': 'pending'}
                state['incidents'][code] = event
            event['active'] = True
        elif event:
            if event['active']:
                event.update(active=False, attempts=0, next_attempt=now, notification_status='pending')
            if not event['notified']:
                del state['incidents'][code]

    def tick(self):
        now, monotonic = self.clock(), self.monotonic()
        settings = load_settings(self.native_home, self.uid)
        state = self.state(now)
        data = self.source.collect()
        grace = settings['grace_minutes'] * 60
        previous = self.previous_clock
        self.previous_clock = (now, monotonic)
        if ((previous and abs((now - previous[0]) - (monotonic - previous[1])) > 300)
                or state['anchor'] > now + 300):
            self.clock_hold_until = monotonic + grace
            state['anchor'] = now
            state['running_since'] = None
        completed = data['last_completed']
        clock_bad = (monotonic < self.clock_hold_until or (completed is not None and completed > now + 300)
                     or state['anchor'] > now + 300)
        complete = data['task_ok'] and data['certificate_ok'] and data['completion_ok']
        schedule = data['schedule'] or {'mode': 'unsupported'}
        supported = schedule['mode'] in ('daily', 'hourly') if data['task_ok'] else None
        enabled = data['task']['enable'] if data['task_ok'] else None
        identity = hashlib.sha256(json.dumps({'settings': settings, 'schedule': schedule,
                                             'enabled': enabled, 'target': data['target']}, sort_keys=True).encode()).hexdigest()
        if complete and state['identity'] != identity:
            # 初次安装允许读取已有完成时间；后续计划/目标/设置变化重新开始观察。
            if state['identity'] is not None:
                state['anchor'] = now
                state['incidents'].pop('task_missed', None)
            state['identity'] = identity
            if state['target'] is not None and state['target'] != data['target']:
                state['incidents'].pop('certificate_expiry', None)
            state['target'] = data['target']
            self.started = monotonic
            state['running_since'] = None
        remaining = int(data['expires_at'] - now) if data['certificate_ok'] else None
        expired = remaining is not None and remaining <= 0
        missed, next_expected = None, None
        missed_decision = None
        if enabled and supported and data['completion_ok'] and not clock_bad:
            anchor = max(state['anchor'], completed if completed is not None else state['anchor'])
            # 首次观测已有历史时不把陈旧记录当作现在刚完成，但启动宽限仍生效。
            if completed is not None and state['identity'] == identity and not os.path.lexists(self.path):
                anchor = completed
                state['anchor'] = completed
            missed, _ = schedule_window(schedule, anchor, now - grace)
            _, next_expected = schedule_window(schedule, now, now)
            if data['running']:
                if state['running_since'] is None:
                    state['running_since'] = now
            else:
                state['running_since'] = None
            running_grace = data['running'] and now - state['running_since'] < grace
            if monotonic - self.started >= grace and not running_grace:
                missed_decision = missed >= settings['missed_runs']
        elif enabled is False:
            # 暂停任务只取消漏跑事件，不发送“已恢复”邮件；证书告警仍独立判断。
            state['incidents'].pop('task_missed', None)
            state['running_since'] = None
        if settings['enabled']:
            self.incident(state, 'source_unavailable', not complete, now)
            self.incident(state, 'clock_anomaly', clock_bad, now)
            self.incident(state, 'task_missed', missed_decision, now)
            self.incident(state, 'certificate_expiry', remaining <= settings['expiry_hours'] * 3600
                          if remaining is not None and not clock_bad else None, now)
        delivery_enabled = settings['enabled'] and data['delivery_enabled']
        last_error = None
        # 先持久化事件；异常/重启不会丢失待发状态，发送结果提交后才清除。
        write_json(self.path, state, self.uid)
        for code, event in list(state['incidents'].items()):
            if code in ('source_unavailable', 'clock_anomaly'):
                event['notification_status'] = 'unknown'
                continue
            if not delivery_enabled or self.stopping:
                event['notification_status'] = 'disabled'
                continue
            if not complete or clock_bad or (code == 'task_missed' and missed_decision is None):
                continue
            if event['active'] and event['notified']:
                event['notification_status'] = 'sent'
                continue
            if event['next_attempt'] > now:
                continue
            try:
                self.source.deliver(data['recipient'], event, recovered=not event['active'])
            except Exception:
                event['attempts'] = min(100, event['attempts'] + 1)
                event['next_attempt'] = now + min(3600, 60 * (2 ** min(event['attempts'] - 1, 6)))
                event['notification_status'] = 'failed'
                last_error = '监测邮件发送失败，已保留并安排重试'
            else:
                if event['active']:
                    event.update(notified=True, attempts=0, notification_status='sent')
                else:
                    del state['incidents'][code]
            write_json(self.path, state, self.uid)
        write_json(self.path, state, self.uid)
        alerts = []
        for code, event in state['incidents'].items():
            if event['active']:
                alerts.append({'code': code, 'label': '证书已经到期' if code == 'certificate_expiry' and expired else LABELS[code],
                               'since': utc(event['since']), 'message': '当前证书已经到期，请立即检查续期及部署结果。'
                               if code == 'certificate_expiry' and expired else MESSAGES[code],
                               'notification_status': event['notification_status']})
        if last_error is None and any(event['notification_status'] == 'failed' for event in state['incidents'].values()):
            last_error = '监测邮件发送失败，已保留并安排重试'
        status = ('disabled' if not settings['enabled'] else 'error' if expired and not clock_bad
                  else 'unknown' if not complete or clock_bad or supported is False else 'warning' if alerts else 'ok')
        snapshot = {'version': 1, 'checked_at': utc(now), 'status': status, 'task_enabled': enabled,
                    'schedule_supported': supported, 'last_completed_at': utc(completed) if completed is not None else None,
                    'next_expected_at': utc(next_expected) if next_expected is not None else None,
                    'missed_runs': missed, 'certificate_remaining_seconds': remaining, 'alerts': alerts,
                    'delivery': {'enabled': bool(delivery_enabled), 'recipient': masked_email(data['recipient']), 'last_error': last_error},
                    'settings': settings}
        write_json(self.snapshot, snapshot, self.uid)
        return snapshot

    def serve(self, parent_pid):
        with locked(self.native_home / 'state/monitor.lock', self.uid):
            def stop(*_):
                self.stopping = True
                # 立即展开正在发送邮件的 finally，回收 ssmtp 进程组。
                raise SystemExit(0)
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, stop)
            while not self.stopping and os.getppid() == parent_pid:
                try:
                    self.tick()
                except Exception:
                    # 私有状态损坏时不重置事件，避免重复通知；保留旧快照让页面显示过期。
                    pass
                for _ in range(60):
                    if self.stopping or os.getppid() != parent_pid:
                        break
                    time.sleep(1)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-home', required=True, type=Path)
    parser.add_argument('--web-home', required=True, type=Path)
    parser.add_argument('--task-id', required=True, type=int)
    parser.add_argument('--parent-pid', required=True, type=int)
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or args.parent_pid <= 1 or not 1 <= args.task_id <= 2147483647:
        return 1
    os.umask(0o077)
    for path in (args.native_home, args.web_home):
        if not path.is_absolute() or str(path) != str(path.resolve()):
            return 1
        directory(path, 0)
    try:
        Monitor(args.native_home, args.web_home, NativeSource(args.native_home, args.task_id)).serve(args.parent_pid)
        return 0
    except (OSError, ValueError):
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
