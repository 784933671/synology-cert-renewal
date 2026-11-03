"""按证书和恢复状态调整唯一 DSM 任务的频率，不执行签发或续期。"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import stat
import time

_spec = importlib.util.spec_from_file_location('certweb_adaptive_monitor', Path(__file__).with_name('monitor.py'))
monitor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(monitor)

RETRY = 75
WINDOW_SECONDS = 48 * 3600
DEFAULT_PLAN = {'version': 1, 'hour': 3, 'minute': 18}
MESSAGES = {
    'disabled': '当前使用固定计划，自适应同步未修改任务。',
    'paused': '原任务已暂停，自适应同步不会启用任务。',
    'daily': '证书正常且待办已完成，当前每天检查一次。',
    'hourly': '已进入到期前 48 小时，或仍有待办/未确认结果，当前每小时检查。',
    'busy': '原任务或配置事务正在处理，稍后再同步检查频率。',
    'conflict': '原任务计划已被另外修改，自适应同步已停止覆盖，请核对检查计划。',
    'error': '检查频率同步未确认，请核对私有状态、权限及原任务。',
}


def validate_plan(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'hour', 'minute'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['hour']) is not int or not 0 <= value['hour'] <= 23
            or type(value['minute']) is not int or not 0 <= value['minute'] <= 59):
        raise ValueError('自适应计划无效')
    return dict(value)


def preference_plan(preferences):
    if not isinstance(preferences, dict):
        raise ValueError('检查计划配置无效')
    return validate_plan(preferences['adaptive_schedule']) if 'adaptive_schedule' in preferences else None


def physical_settings(plan, mode, enabled):
    plan = validate_plan(plan)
    if mode not in ('daily', 'hourly') or type(enabled) is not bool:
        raise ValueError('实际检查计划无效')
    return {'enabled': enabled, 'mode': mode, 'interval_hours': 1,
            'hour': plan['hour'] if mode == 'daily' else 0, 'minute': plan['minute']}


def belongs_to_plan(schedule, plan):
    plan = validate_plan(plan)
    return bool(schedule.get('editable') is True and schedule.get('minute') == plan['minute']
                and ((schedule.get('mode') == 'daily' and schedule.get('hour') == plan['hour'])
                     or (schedule.get('mode') == 'hourly' and schedule.get('interval_hours') == 1)))


def display_schedule(task, preferences, read_schedule):
    raw = read_schedule(task)
    plan = preference_plan(preferences)
    if plan is None:
        return raw
    matches = belongs_to_plan(raw, plan)
    result = {'enabled': task['enable'], 'mode': 'adaptive', 'interval_hours': 1,
            'hour': plan['hour'], 'minute': plan['minute'], 'editable': matches,
            'message': MESSAGES[raw['mode']] if matches else MESSAGES['conflict']}
    if matches:
        result['active_mode'] = raw['mode']
    return result


def desired_mode(controller, executor, uid=0, now=None):
    """只有当前证书的成功结果及全部待办均可核实时才允许降为每日。"""
    now = time.time() if now is None else now
    state = controller.state
    try:
        certificate = controller.current_cert()
        if executor.certificate_expiry(certificate) - now <= WINDOW_SECONDS:
            return 'hourly'
        current = executor.fingerprint(certificate)
        if not isinstance(current, str) or not re.fullmatch(r'[0-9a-f]{64}', current):
            return 'hourly'
        if set(executor.certificate_domains(certificate)) != set(controller.config['domains']):
            return 'hourly'
        if any(os.path.lexists(state / name) for name in executor.RENEWAL_PROTECTION_FILES):
            return 'hourly'
        if controller.dns_cleanup_count():
            return 'hourly'
        request = controller.manual_renewal()
        if request and (request['state'] in ('queued', 'running') or request.get('recovery_only')):
            return 'hourly'
        notice = monitor.read_json(state / 'success-notification.json', uid=uid)
        if notice is None and controller.config.get('success_notify_email'):
            return 'hourly'
        if notice is not None and (not isinstance(notice, dict) or notice.get('version') != 1
                or notice.get('certificate_id') != controller.config['certificate_id']
                or not isinstance(notice.get('last_notified_fingerprint'), str)
                or re.fullmatch(r'[0-9a-f]{64}', notice['last_notified_fingerprint']) is None
                or 'pending' not in notice or notice['pending'] is not None
                or (controller.config.get('success_notify_email') and notice['last_notified_fingerprint'] != current)):
            return 'hourly'
        candidate = controller.candidate()
        if not candidate.is_file() or executor.fingerprint(candidate) != current:
            return 'hourly'
        result = monitor.read_json(state / 'last-result.json', uid=uid)
        if (not isinstance(result, dict) or result.get('success') is not True
                or result.get('fingerprint') != current
                or ('certificate_id' in result and result['certificate_id'] != controller.config['certificate_id'])
                or monitor.timestamp(result.get('at')) > now + 5):
            return 'hourly'
        return 'daily'
    except Exception:
        # 缺失或不明状态保留恢复机会，原执行器仍负责安全校验和失败通知。
        return 'hourly'


class NativeSource:
    def __init__(self, native_home, task_id, uid=0):
        self.home = Path(native_home)
        monitor.directory(self.home / 'web', uid)
        for relative in ('certctl.py', 'failure_diagnostics.py', 'run_history.py', 'web/host_bridge.py',
                         'web/access_policy.py', 'web/login_mail.py', 'web/observability.py',
                         'web/monitor.py', 'web/adaptive_schedule.py'):
            info = (self.home / relative).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError('计划模块权限无效')
        spec = importlib.util.spec_from_file_location('certweb_adaptive_bridge', self.home / 'web/host_bridge.py')
        self.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bridge)
        self.scheduler = self.bridge.Scheduler(self.home, task_id=task_id)
        self.controller = self.bridge.executor.Controller(self.home)
        self.executor = self.bridge.executor
        self.read_schedule = self.bridge.read_schedule
        self.write_schedule = self.bridge.write_schedule


def same_task(first, second):
    return all(first.get(key) == second.get(key) for key in ('id', 'name', 'owner', 'enable', 'schedule', 'extra'))


class AdaptiveSchedule:
    def __init__(self, native_home, web_home, task_id, source=None, uid=0, clock=time.time):
        self.native_home, self.web_home = Path(native_home), Path(web_home)
        self.task_id, self.source, self.uid, self.clock = task_id, source, uid, clock
        self.current_mode = None
        self.plan = None
        self.certificate_id = None
        self.message = MESSAGES['error']

    def record(self, status):
        self.message = MESSAGES[status]
        monitor.write_json(self.web_home / 'adaptive-schedule.json', {
            'version': 1, 'at': monitor.utc(self.clock()), 'status': status,
            'message': self.message, 'current_mode': self.current_mode,
            'plan': self.plan, 'certificate_id': self.certificate_id,
        }, self.uid)

    def attempt(self):
        for path in (self.native_home, self.web_home):
            if not path.is_absolute() or path != path.resolve():
                raise ValueError('计划目录无效')
            monitor.directory(path, self.uid)
            if path.stat().st_mode & 0o077:
                raise ValueError('计划目录必须私有')
        if type(self.task_id) is not int or not 1 <= self.task_id <= 2147483647:
            raise ValueError('任务 ID 无效')
        with monitor.locked(self.web_home / 'adaptive-schedule.lock', self.uid):
            with monitor.locked(self.native_home / 'state/run.lock', self.uid):
                if os.path.lexists(self.native_home / 'state/web-transaction.json'):
                    self.record('busy')
                    return RETRY
                preferences = monitor.read_json(self.native_home / 'state/web-preferences.json', {}, self.uid)
                plan = preference_plan(preferences)
                self.plan = plan
                if plan is None:
                    self.record('disabled')
                    return 0
                source = self.source or NativeSource(self.native_home, self.task_id, self.uid)
                controller, scheduler = source.controller, source.scheduler
                controller.load()
                self.certificate_id = controller.config['certificate_id']
                task = scheduler.get()
                raw = source.read_schedule(task)
                self.current_mode = raw['mode'] if raw['mode'] in ('daily', 'hourly') else None
                if not belongs_to_plan(raw, plan):
                    self.record('conflict')
                    return 1
                if not task['enable']:
                    self.record('paused')
                    return 0
                mode = desired_mode(controller, source.executor, self.uid, self.clock())
                desired = source.write_schedule(task, physical_settings(plan, mode, task['enable']))
                if not same_task(task, desired):
                    # 控制台写入不受本地锁约束，提交前再次核对完整任务。
                    if not same_task(scheduler.get(), task):
                        self.record('conflict')
                        return 1
                    try:
                        observed = scheduler.put(desired)
                    except Exception:
                        observed = scheduler.get()
                        if same_task(observed, task):
                            self.record('error')
                            return RETRY
                        if not same_task(observed, desired):
                            self.record('conflict')
                            return 1
                    if not same_task(observed, desired):
                        self.record('conflict')
                        return 1
                self.current_mode = mode
                self.record(mode)
                return 0

    def once(self):
        try:
            return self.attempt()
        except (KeyboardInterrupt, InterruptedError):
            self.message = MESSAGES['error']
            return RETRY
        except BlockingIOError:
            self.message = MESSAGES['busy']
            return RETRY
        except Exception:
            try:
                self.record('error')
            except Exception:
                pass
            return 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-home', required=True, type=Path)
    parser.add_argument('--web-home', required=True, type=Path)
    parser.add_argument('--task-id', required=True, type=int)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        return 1
    os.umask(0o077)
    def stop(*_):
        # 让 subprocess.run 回收命令后再释放任务锁，避免留下仍在写任务的子进程。
        raise KeyboardInterrupt()
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        operation = AdaptiveSchedule(args.native_home, args.web_home, args.task_id)
        result = operation.once()
        print(operation.message, flush=True)
        return result
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    raise SystemExit(main())
