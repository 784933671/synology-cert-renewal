"""每个项目或容器启动代只投递一次原 DSM 检查任务，不创建额外调度器。"""
import argparse
import contextlib
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import time

_spec = importlib.util.spec_from_file_location('certweb_startup_monitor', Path(__file__).with_name('monitor.py'))
monitor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(monitor)

RETRY = 75
MESSAGES = {
    'dispatching': '启动检查已保留投递记录；若进程中断，不会重复投递，请核对原任务记录。',
    'dispatched': '已向原 DSM 任务投递普通检查，结果以原任务执行记录为准。',
    'unknown': '启动检查投递结果无法确认，本启动代不自动重复投递，请核对原任务记录。',
    'completed': '本次启动后原任务已完成检查，无需重复投递。',
}
STATE_FIELDS = {'version', 'generation', 'generation_id', 'started_at', 'native_home',
                'task_id', 'status', 'at', 'message'}


class RetryLater(Exception):
    pass


def identity(generation_id, started_at):
    if (not isinstance(generation_id, str) or not re.fullmatch(r'[0-9a-f]{64}', generation_id)
            or not isinstance(started_at, str)
            or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', started_at)):
        raise ValueError('启动标识无效')
    started = monitor.timestamp(started_at)
    if not math.isfinite(started) or started <= 0:
        raise ValueError('启动时间无效')
    generation = hashlib.sha256((generation_id + '\n' + started_at).encode('ascii')).hexdigest()
    return generation, started


def safe_home(path, uid):
    path = Path(path)
    if not path.is_absolute() or str(path) != str(path.resolve()):
        raise ValueError('运行目录无效')
    monitor.directory(path, uid)
    if path.lstat().st_mode & 0o077:
        raise ValueError('运行目录不是私有目录')
    return path


def validate_state(value, home, task_id):
    if (not isinstance(value, dict) or set(value) != STATE_FIELDS
            or type(value['version']) is not int or value['version'] != 1
            or type(value['task_id']) is not int or value['task_id'] != task_id
            or value['native_home'] != str(home)
            or not isinstance(value['status'], str) or value['status'] not in MESSAGES
            or value['message'] != MESSAGES[value['status']]):
        raise ValueError('启动检查状态无效')
    generation, started = identity(value['generation_id'], value['started_at'])
    if value['generation'] != generation or monitor.timestamp(value['at']) <= 0:
        raise ValueError('启动检查状态标识无效')
    return started


class NativeTask:
    def __init__(self, home, task_id, uid=0):
        self.home = home
        monitor.directory(home / 'web', uid)
        for relative in ('certctl.py', 'failure_diagnostics.py', 'run_history.py',
                         'web/host_bridge.py', 'web/access_policy.py', 'web/login_mail.py',
                         'web/observability.py', 'web/monitor.py', 'web/adaptive_schedule.py'):
            info = (home / relative).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError('本机执行模块权限无效')
        spec = importlib.util.spec_from_file_location('certweb_startup_bridge', home / 'web/host_bridge.py')
        self.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bridge)

        class EnabledScheduler(self.bridge.Scheduler):
            def get(self):
                try:
                    task = self.api('SYNO.Core.TaskScheduler', 'get', 4, {'id': self.task_id})
                except Exception:
                    raise RetryLater() from None
                # 结构或脚本归属错误不能作为暂时不可用处理。
                task = self.validate(task)
                if not task['enable']:
                    raise RetryLater()
                return task

        self.scheduler = EnabledScheduler(home, task_id=task_id)
        self.controller = self.bridge.executor.Controller(home)

    def prepare(self):
        self.scheduler.get()
        if os.path.lexists(self.home / 'state/web-transaction.json'):
            raise RetryLater()
        if not os.path.lexists(self.home / 'config.json'):
            raise RetryLater()
        self.controller.load()
        self.controller.assert_manual_idle()
        if not shutil.which('synoschedtask'):
            raise RetryLater()

    @contextlib.contextmanager
    def locked(self):
        try:
            with self.controller.locked():
                yield
        except self.bridge.executor.Busy:
            raise RetryLater() from None

    def run(self, before_dispatch):
        # Scheduler.run 再次读取并验证任务，暂停状态不会被 check_status=0 绕过。
        self.scheduler.run(before_dispatch=before_dispatch)


class StartupCheck:
    def __init__(self, native_home, web_home, task_id, generation_id, started_at,
                 source=None, uid=0, clock=time.time):
        self.native_home, self.web_home = Path(native_home), Path(web_home)
        self.task_id, self.generation_id, self.started_at = task_id, generation_id, started_at
        self.source, self.uid, self.clock = source, uid, clock
        self.path = self.web_home / 'startup-check.json'
        self.claimed = False
        self.message = '启动检查未执行。'

    def save(self, status):
        monitor.write_json(self.path, {
            'version': 1, 'generation': self.generation, 'generation_id': self.generation_id,
            'started_at': self.started_at, 'native_home': str(self.native_home),
            'task_id': self.task_id, 'status': status, 'at': monitor.utc(self.clock()),
            'message': MESSAGES[status],
        }, self.uid)
        self.message = MESSAGES[status]

    def completed_since_start(self):
        previous = monitor.read_json(self.native_home / 'state/last-result.json', uid=self.uid)
        if previous is None:
            return False
        if not isinstance(previous, dict) or type(previous.get('success')) is not bool:
            raise ValueError('原任务完成记录无效')
        completed = monitor.timestamp(previous.get('at'))
        if completed > self.clock() + 5:
            return False
        return completed >= self.started

    def claim_dispatch(self):
        # 只在 DSM 查询及命令定位成功后记录意图；此前失败可以安全重试。
        self.save('dispatching')
        self.claimed = True

    def attempt(self):
        self.generation, self.started = identity(self.generation_id, self.started_at)
        if type(self.task_id) is not int or not 1 <= self.task_id <= 2147483647:
            raise ValueError('任务 ID 无效')
        safe_home(self.native_home, self.uid)
        safe_home(self.web_home, self.uid)
        with monitor.locked(self.web_home / 'startup-check.lock', self.uid):
            previous = monitor.read_json(self.path, uid=self.uid)
            if previous is not None:
                validate_state(previous, self.native_home, self.task_id)
                if previous['generation'] == self.generation:
                    self.message = previous['message']
                    return 0
            monitor.directory(self.native_home / 'state', self.uid)
            source = self.source or NativeTask(self.native_home, self.task_id, self.uid)
            with source.locked():
                source.prepare()
                if self.completed_since_start():
                    self.save('completed')
                    return 0
            try:
                # 原任务需要同一把续期锁，必须先释放才能等待 DSM 应答。
                source.run(self.claim_dispatch)
                self.save('dispatched')
            except BaseException:
                if self.claimed:
                    self.message = MESSAGES['unknown']
                    try:
                        self.save('unknown')
                    except Exception:
                        pass
                raise
            return 0

    def once(self):
        try:
            return self.attempt()
        except (KeyboardInterrupt, SystemExit):
            return 0 if self.claimed else RETRY
        except (RetryLater, BlockingIOError, FileNotFoundError):
            if not self.claimed:
                self.message = '启动检查尚未投递，待任务启用、空闲且依赖就绪后重试。'
                return RETRY
        except Exception:
            if not self.claimed:
                self.message = '无法安全执行启动检查，请核对私有状态、权限及原任务配置。'
                return 1
        # claim 后任何错误均不能证明 DSM 没有执行，禁止同代自动重试。
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-home', required=True, type=Path)
    parser.add_argument('--web-home', required=True, type=Path)
    parser.add_argument('--task-id', required=True, type=int)
    parser.add_argument('--generation-id', required=True)
    parser.add_argument('--started-at', required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        return 1
    os.umask(0o077)
    def stop(*_):
        raise KeyboardInterrupt()
    handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        checker = StartupCheck(args.native_home, args.web_home, args.task_id, args.generation_id, args.started_at)
        result = checker.once()
        print(checker.message, flush=True)
        return result
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    raise SystemExit(main())
