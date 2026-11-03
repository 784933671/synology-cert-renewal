"""群晖原生监督进程：先应用访问策略，再启动 Docker 管理服务。"""
import argparse
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

if __package__:
    from .access_policy import read_policy, initialize_policy, write_policy, write_applied
    from .network_guard import NetworkGuard, GuardError, validate_network
    from .tls_sync import sync_tls, TLSBusy
    from . import monitor as health_monitor
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from access_policy import read_policy, initialize_policy, write_policy, write_applied
    from network_guard import NetworkGuard, GuardError, validate_network
    from tls_sync import sync_tls, TLSBusy
    import monitor as health_monitor

CONTAINER = 'synology-cert-web'
MANAGED_LABEL = 'io.github.784933671.certweb.managed'
DEFAULT_CONFIG = Path('/usr/local/share/synology-cert-web/deployment.json')
START_STABLE_SECONDS = 60
STARTUP_CHECK_RETRY_SECONDS = 60
SCHEDULE_SYNC_SECONDS = 60
SCHEDULE_SYNC_TIMEOUT = 120


def private_json(path, value):
    temporary = path.with_name(path.name + '.new')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(value, handle, ensure_ascii=False)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(temporary), str(path))


def load_config(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('缺少部署配置')
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise ValueError('部署配置必须仅 root 可读写')
    config = json.loads(path.read_text())
    expected = {'home', 'native_home', 'bind', 'networks', 'denied', 'port', 'origin'}
    if set(config) - {'task_id'} != expected:
        raise ValueError('部署配置字段不正确')
    validate_network(config['bind'], config['networks'], config['denied'], config['port'])
    for key in ('home', 'native_home'):
        item = Path(config[key])
        if not item.is_absolute() or str(item) != str(item.resolve()) or not item.is_dir():
            raise ValueError('部署目录无效')
        if item.stat().st_uid != 0 or item.stat().st_mode & 0o022:
            raise ValueError('部署目录不可由非 root 用户写入')
    config['task_id'] = validate_task_id(config.get('task_id', 7))
    config['authority'], config['hostname'] = validate_origin(config['origin'], config['port'])
    return config


def validate_task_id(value):
    if type(value) is not int or not 1 <= value <= 2147483647:
        raise ValueError('任务 ID 必须是正整数')
    return value


def validate_origin(value, port):
    origin = urlsplit(value)
    if origin.scheme != 'https' or not origin.hostname or origin.port != port or origin.path or origin.query or origin.fragment or origin.username:
        raise ValueError('必须使用明确的 HTTPS 管理域名')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', origin.hostname):
        raise ValueError('管理域名格式无效')
    try:
        ipaddress.ip_address(origin.hostname)
    except ValueError:
        pass
    else:
        raise ValueError('管理入口使用证书覆盖的域名，不使用 IP')
    return origin.netloc, origin.hostname


class Deployment:
    def __init__(self, config, config_path, clock=None):
        self.config, self.config_path = config, Path(config_path)
        self.home = Path(config['home'])
        self.code = self.home / 'code'
        self.access_path = self.home / 'access/access.json'
        self.guard = NetworkGuard(config['bind'], config['networks'], config['denied'], config['port'])
        self.bridge = None
        self.monitor = None
        self.monitor_started_at = None
        self.startup_check = None
        self.startup_requested_generation = None
        self.startup_container_generation = None
        self.startup_generation = None
        self.startup_attempted_at = None
        self.startup_done = False
        self.startup_terminating_at = None
        self.startup_killed = False
        self.startup_message = None
        self.schedule_sync = None
        self.schedule_attempted_at = None
        self.schedule_terminating_at = None
        self.schedule_killed = False
        self.stopping = False
        self.last_message = None
        self.started = False
        self.last_container = None
        self.clock = clock or time.monotonic
        self.ready_since = None
        self.last_policy = None
        self.phase = 'initializing'
        self.health = {}
        self.observed_container = None
        self.env = dict(os.environ, PATH='/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin')

    def command(self, args, timeout=40):
        result = subprocess.run(args, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('管理服务操作未完成')
        return result.stdout

    def compose(self, *args):
        return self.command(['/usr/local/bin/docker', 'compose', '--project-name', 'synology-cert-web', '--env-file', str(self.home / 'deployment.env'), '-f', str(self.code / 'compose.yaml')] + list(args), timeout=90)

    def container(self):
        result = subprocess.run(['/usr/local/bin/docker', 'inspect', CONTAINER], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=15)
        if result.returncode:
            self.command(['/usr/local/bin/docker', 'info', '--format', '{{.ServerVersion}}'], timeout=15)
            return None
        item = json.loads(result.stdout)[0]
        if item.get('Config', {}).get('Labels', {}).get(MANAGED_LABEL) != 'true':
            raise RuntimeError('同名容器不属于本服务')
        self.last_container = item
        return item

    def stop_container(self):
        try:
            container = self.container()
            if container and container.get('State', {}).get('Running'):
                self.command(['/usr/local/bin/docker', 'stop', '-t', '20', CONTAINER], timeout=30)
                current = self.container()
                if current and current.get('State', {}).get('Running'):
                    raise RuntimeError('管理容器仍在运行')
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            if not self.emergency_stop():
                raise RuntimeError('无法确认管理容器已关闭')
        self.started = False
        self.ready_since = None

    def emergency_stop(self):
        item = self.last_container or {}
        pid, identifier = item.get('State', {}).get('Pid'), item.get('Id', '')
        if type(pid) is not int or pid <= 1 or not re.fullmatch(r'[a-f0-9]{64}', identifier):
            return False
        def matches():
            try:
                return identifier in Path('/proc/{}/cgroup'.format(pid)).read_text()
            except FileNotFoundError:
                return False
        if not matches():
            return not Path('/proc/{}'.format(pid)).exists()
        # 只在 PID 的 cgroup 仍属于已核验的本应用容器时终止其 PID 1。
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not matches():
                return True
            time.sleep(0.1)
        if matches():
            os.kill(pid, signal.SIGKILL)
        for _ in range(20):
            if not matches():
                return True
            time.sleep(0.1)
        return False

    def log(self, status, message):
        if message != self.last_message:
            print(time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + message, flush=True)
            self.last_message = message
        private_json(self.home / 'deployment-state.json', {'status': status, 'stage': self.phase, 'message': message, 'at': time.time(), 'pid': os.getpid()})
        self.record_event(status, message)

    def record_event(self, status, message):
        """仅保存监督程序固定文案；真实升级锁与事务共同证明维护原因。"""
        uid = os.geteuid()
        try:
            with health_monitor.locked(self.home / 'deployment-events.lock', uid):
                path = self.home / 'deployment-events.json'
                previous = health_monitor.read_json(path, {'version': 1, 'items': []}, uid)
                if (not isinstance(previous, dict) or previous.get('version') != 1
                        or not isinstance(previous.get('items'), list) or len(previous['items']) > 100):
                    return
                items = previous['items']
                if any(not isinstance(item, dict) or set(item) != {'at', 'category', 'status', 'stage', 'message'}
                       or any(not isinstance(value, str) or len(value) > 1000 for value in item.values()) for item in items):
                    return
                if items and (items[0].get('status'), items[0].get('stage'), items[0].get('message')) == (status, self.phase, message):
                    return
                category = ('fault' if status == 'blocked' or (self.phase in ('docker', 'bridge', 'policy') and status in ('waiting', 'stopping'))
                            else 'recovery' if status == 'running' and items and any(item.get('category') == 'fault' for item in items[:5])
                            else 'info')
                try:
                    journal = health_monitor.read_json(self.home / 'upgrade-state.json', {}, uid)
                except (OSError, ValueError):
                    journal = {}
                if (self.phase == 'shutdown' and status in ('stopping', 'stopped') and isinstance(journal, dict)
                        and journal.get('version') == 1 and isinstance(journal.get('work'), str)
                        and re.fullmatch(r'upgrade-[0-9a-f]{32}', journal['work'])
                        and journal.get('phase') in ('prepared', 'switching', 'starting')
                        and os.path.lexists(self.home / 'upgrade.lock')
                        and health_monitor.lock_busy(self.home / 'upgrade.lock', uid)):
                    category = 'maintenance'
                event = {'at': health_monitor.utc(), 'category': category, 'status': status,
                         'stage': self.phase, 'message': message}
                health_monitor.write_json(path, {'version': 1, 'items': [event] + items[:99]}, uid)
        except (OSError, ValueError, TypeError, KeyError):
            pass

    def start_monitor(self):
        if self.stopping or (self.monitor is not None and self.monitor.poll() is None):
            return
        script = self.code / 'monitor.py'
        if script.is_symlink() or not script.is_file():
            return
        current = self.clock()
        if self.monitor_started_at is not None and 0 <= current - self.monitor_started_at < 60:
            return
        self.monitor_started_at = current
        try:
            self.monitor = subprocess.Popen([sys.executable, '-I', str(script),
                '--native-home', self.config['native_home'], '--web-home', str(self.home),
                '--task-id', str(self.config.get('task_id', 7)), '--parent-pid', str(os.getpid())],
                env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            self.monitor = None

    def stop_monitor(self):
        if self.monitor is not None and self.monitor.poll() is None:
            self.monitor.terminate()
            try:
                self.monitor.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.monitor.kill()
                self.monitor.wait(timeout=5)

    def startup_notice(self, message):
        if message != self.startup_message:
            try:
                print(time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + message, flush=True)
                self.startup_message = message
            except OSError:
                pass

    def start_startup_check(self):
        """启动补检独立于 HTTPS；首个容器只建基线，后续真正重启才再检查。"""
        if self.stopping or self.startup_requested_generation is None:
            return
        item = self.observed_container
        state = item.get('State', {}) if isinstance(item, dict) else {}
        identifier = item.get('Id') if isinstance(item, dict) else None
        began = state.get('StartedAt') if isinstance(state, dict) else None
        container_generation = ((identifier, began) if isinstance(identifier, str)
                                and re.fullmatch(r'[a-f0-9]{64}', identifier)
                                and isinstance(began, str) and len(began) <= 64
                                and state.get('Running') is True and not state.get('Restarting') else None)
        if container_generation is not None:
            if self.startup_container_generation is not None and container_generation != self.startup_container_generation:
                self.startup_requested_generation = container_generation
            self.startup_container_generation = container_generation
        generation = self.startup_requested_generation
        current = self.clock()
        try:
            if self.startup_check is not None:
                result = self.startup_check.poll()
                if result is None:
                    if generation != self.startup_generation:
                        if self.startup_terminating_at is None:
                            self.startup_check.terminate()
                            self.startup_terminating_at = current
                        elif not self.startup_killed and current - self.startup_terminating_at >= 5:
                            self.startup_check.kill()
                            self.startup_killed = True
                    return
                self.startup_check = None
                if self.startup_terminating_at is None:
                    self.startup_done = result != 75
                    self.startup_notice('本次启动检查已处理，本启动代不再重复触发。' if result == 0 else
                                        '启动检查等待原任务启用或当前执行完成。' if result == 75 else
                                        '启动检查未完成，请检查私有启动检查记录；每日续期任务保持原计划。')
            if generation != self.startup_generation:
                self.startup_generation = generation
                self.startup_attempted_at = None
                self.startup_done = False
                self.startup_terminating_at = None
                self.startup_killed = False
            if self.startup_done:
                return
            if (self.startup_attempted_at is not None
                    and 0 <= current - self.startup_attempted_at < STARTUP_CHECK_RETRY_SECONDS):
                return
            self.startup_attempted_at = current
            script = self.code / 'startup_check.py'
            info = script.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError('启动检查程序权限无效')
            self.startup_check = subprocess.Popen([sys.executable, '-I', str(script),
                '--native-home', self.config['native_home'], '--web-home', str(self.home),
                '--task-id', str(self.config.get('task_id', 7)),
                '--generation-id', generation[0], '--started-at', generation[1]],
                env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            self.startup_notice('启动检查暂未启动，稍后重试；每日续期任务保持原计划。')

    def stop_startup_check(self):
        if self.startup_check is not None and self.startup_check.poll() is None:
            self.startup_check.terminate()
            try:
                self.startup_check.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.startup_check.kill()
                self.startup_check.wait(timeout=5)

    def start_schedule_sync(self):
        """只同步原 DSM 任务的频率，签发仍由原任务独立执行。"""
        if self.stopping or self.startup_requested_generation is None:
            return
        current = self.clock()
        try:
            if self.schedule_sync is not None:
                result = self.schedule_sync.poll()
                if result is None:
                    elapsed = current - self.schedule_attempted_at
                    if elapsed >= SCHEDULE_SYNC_TIMEOUT or elapsed < 0:
                        if self.schedule_terminating_at is None:
                            self.schedule_sync.terminate()
                            self.schedule_terminating_at = current
                        elif not self.schedule_killed and current - self.schedule_terminating_at >= 5:
                            self.schedule_sync.kill()
                            self.schedule_killed = True
                    return
                self.schedule_sync = None
                self.schedule_terminating_at = None
                self.schedule_killed = False
            if (self.schedule_attempted_at is not None
                    and 0 <= current - self.schedule_attempted_at < SCHEDULE_SYNC_SECONDS):
                return
            self.schedule_attempted_at = current
            script = self.code / 'adaptive_schedule.py'
            info = script.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError('计划同步程序权限无效')
            self.schedule_sync = subprocess.Popen([sys.executable, '-I', str(script),
                '--native-home', self.config['native_home'], '--web-home', str(self.home),
                '--task-id', str(self.config.get('task_id', 7))], env=self.env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            self.startup_notice('自适应计划暂未同步，稍后重试；原 DSM 任务继续执行。')

    def stop_schedule_sync(self):
        if self.schedule_sync is not None and self.schedule_sync.poll() is None:
            self.schedule_sync.terminate()
            try:
                self.schedule_sync.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.schedule_sync.kill()
                self.schedule_sync.wait(timeout=5)
    def publish_health(self):
        item = self.observed_container
        state = item.get('State', {}) if isinstance(item, dict) else {}
        running = state.get('Running') if type(state.get('Running')) is bool else None
        raw_health = state.get('Health', {}).get('Status') if isinstance(state.get('Health', {}), dict) else None
        health = raw_health if raw_health in ('healthy', 'unhealthy', 'starting') else 'unknown'
        restart_count = item.get('RestartCount') if isinstance(item, dict) else None
        restart_count = restart_count if type(restart_count) is int and restart_count >= 0 else None
        started_at, uptime = None, None
        try:
            began = health_monitor.timestamp(state.get('StartedAt'))
            if 0 < began <= time.time():
                started_at = health_monitor.utc(began)
                uptime = max(0, int(time.time() - began)) if running else None
        except (ValueError, TypeError, OverflowError):
            pass
        container_status = ('error' if running is False or health == 'unhealthy' else
                            'ok' if running and health == 'healthy' else 'warning' if running else 'unknown')
        components = [{'key': 'container', 'label': '管理容器', 'status': container_status,
                       'message': {'ok': '容器及 HTTPS 健康检查正常', 'error': '容器未运行或健康检查失败',
                                   'warning': '容器运行中，健康检查结果尚未确认', 'unknown': '容器状态暂未确认'}[container_status]}]
        labels = {'bridge': '群晖桥接', 'tls': '管理页 HTTPS 证书', 'access': '访问策略与防火墙'}
        for key, label in labels.items():
            status = self.health.get(key, 'unknown')
            components.append({'key': key, 'label': label, 'status': status,
                               'message': {'ok': '检查正常', 'warning': '正在等待任务或服务就绪',
                                           'error': '检查失败，管理入口已进入保护流程', 'unknown': '本轮尚未确认'}[status]})
        alive = self.monitor is not None and self.monitor.poll() is None
        components.append({'key': 'monitor', 'label': '独立证书监测', 'status': 'ok' if alive else 'warning',
                           'message': '主机监测进程运行中' if alive else '监测进程暂未运行，等待监督程序重建'})
        snapshot = {'version': 1, 'checked_at': health_monitor.utc(), 'components': components,
                    'container': {'running': running, 'health': health, 'restart_count': restart_count,
                                  'oom_killed': state.get('OOMKilled') if type(state.get('OOMKilled')) is bool else None,
                                  'started_at': started_at, 'uptime_seconds': uptime}}
        try:
            health_monitor.write_json(self.home / 'runtime-health.json', snapshot, os.geteuid())
        except (OSError, ValueError):
            pass

    def report(self, status, message):
        try:
            self.log(status, message)
            return True
        except OSError:
            # 磁盘或日志输出故障不能阻止安全停服，也不累积启动就绪时间。
            self.ready_since = None
            return False

    def start_bridge(self):
        if self.bridge is not None and self.bridge.poll() is None:
            return
        self.ready_since = None
        self.phase = 'bridge'
        if self.bridge is not None:
            self.report('stopping', '群晖桥接进程已退出，正在停止管理容器并重建桥接。')
            self.stop_container()
        else:
            self.report('starting', '正在启动群晖桥接，管理容器须等待环境连续稳定。')
        log_path = self.home / 'bridge.log'
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as log:
            self.bridge = subprocess.Popen([sys.executable, '-I', str(Path(self.config['native_home']) / 'web/host_bridge.py'), '--home', self.config['native_home'], '--socket', str(self.home / 'bridge/certweb.sock'), '--task-id', str(self.config.get('task_id', 7)), '--uid', '10100', '--gid', '10100', '--parent-pid', str(os.getpid()), '--management-host', self.config['hostname'], '--access-policy', str(self.access_path)], env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def apply_access_policy(self):
        self.phase = 'policy'
        policy = read_policy(self.access_path)
        identity = (policy['mode'], policy['revision'])
        if self.last_policy is not None and self.last_policy != identity:
            self.ready_since = None
            self.report('reconfiguring', '管理入口访问策略已变化，重新检查启动条件。')
        self.guard.access_mode = policy['mode']
        if not self.guard.valid():
            self.ready_since = None
            self.report('stopping', '检测到管理入口防火墙规则变化，正在停止管理容器后修复规则。')
            self.stop_container()
            self.guard.install()
        write_applied(self.access_path, policy)
        self.last_policy = identity
        return policy

    def bridge_ready(self):
        import socket
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(3)
                connection.connect(str(self.home / 'bridge/certweb.sock'))
            return self.bridge.poll() is None
        except OSError:
            return False

    def reconcile(self):
        """单次检查；仅停止状态的容器需要完整稳定窗口。"""
        if self.stopping:
            return
        self.health = {}
        self.observed_container = None
        try:
            policy = self.apply_access_policy()
            self.health['access'] = 'ok'
            self.phase = 'tls'
            tls_ready = True
            try:
                changed = sync_tls(Path(self.config['native_home']), self.home / 'tls', self.config['hostname'])
                if changed:
                    self.ready_since = None
            except TLSBusy:
                self.ready_since = None
                tls_ready = False
                if not (self.home / 'tls/current.cert').exists():
                    raise RuntimeError('HTTPS 材料尚未就绪')
            self.health['tls'] = 'ok' if tls_ready else 'warning'
            self.phase = 'bridge'
            self.start_bridge()
            bridge_ready = self.bridge_ready()
            self.health['bridge'] = 'ok' if bridge_ready else 'warning'
            credentials_ready = (self.home / 'data/auth.sqlite3').exists()
            self.phase = 'docker'
            item = self.container()
            self.observed_container = item
            running = bool(item and item.get('State', {}).get('Running') and not item['State'].get('Restarting'))
            if running:
                self.started = True
                self.ready_since = None
            elif self.started:
                self.started = False
                self.ready_since = None
                self.report('waiting', '检测到管理容器因内存不足退出，等待环境连续稳定后重新启动。'
                            if item and item.get('State', {}).get('OOMKilled') is True
                            else '检测到管理容器已退出，等待环境连续稳定后重新启动。')
            if not tls_ready:
                self.phase = 'tls'
                self.ready_since = None
                self.report('waiting', '续期任务正在处理 HTTPS 材料，暂停管理容器启动计时。')
                return
            if not bridge_ready:
                self.phase = 'bridge'
                self.ready_since = None
                self.report('waiting', '等待群晖桥接服务就绪，暂停管理容器启动计时。')
                return
            if not credentials_ready:
                self.phase = 'credentials'
                self.ready_since = None
                self.report('setup', '等待管理员账号初始化。')
                return
            if not running:
                self.phase = 'stability'
                current = self.clock()
                if self.ready_since is None or current < self.ready_since:
                    self.ready_since = current
                if current - self.ready_since < START_STABLE_SECONDS:
                    self.report('stabilizing', '启动条件已就绪，等待连续稳定 60 秒后启动管理容器。')
                    return
                # 启动前消耗本次稳定窗口；失败或立即退出均须重新等待。
                self.ready_since = None
                self.phase = 'start'
                if not self.report('starting', '环境已连续稳定 60 秒，正在启动管理容器。'):
                    return
                if self.stopping:
                    return
                self.compose('up', '-d', '--no-build')
                item = self.container()
                self.observed_container = item
                if not item or not item.get('State', {}).get('Running') or item['State'].get('Restarting'):
                    raise RuntimeError('管理容器启动后未保持运行')
                self.started = True
            self.phase = 'running'
            self.report('running', '管理服务运行中，访问模式：{}。'.format('仅内网' if policy['mode'] == 'lan' else '允许外网'))
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, GuardError, subprocess.TimeoutExpired):
            self.ready_since = None
            key = {'policy': 'access', 'tls': 'tls', 'bridge': 'bridge'}.get(self.phase)
            if key:
                self.health[key] = 'error'
            self.observed_container = None
            labels = {'policy': '访问策略或防火墙检查失败', 'tls': 'HTTPS 材料检查失败',
                      'bridge': '群晖桥接检查失败', 'docker': 'Docker 状态检查失败',
                      'start': '管理容器启动失败'}
            reason = labels.get(self.phase, '管理服务启动条件检查失败')
            self.report('stopping', reason + '，正在停止管理容器。')
            stopped = True
            try:
                self.stop_container()
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.TimeoutExpired):
                stopped = False
            self.report('blocked', reason + '，管理服务保持关闭，等待环境恢复稳定。' if stopped
                     else reason + '，且无法确认管理容器已关闭；请通过 NAS 检查。')
        finally:
            self.publish_health()

    def serve(self):
        fd = os.open(str(self.home / 'supervisor.lock'), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 0
            private_json(self.home / 'supervisor.pid', {'pid': os.getpid()})
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: setattr(self, 'stopping', True))
            try:
                self.startup_requested_generation = (secrets.token_hex(32), dt.datetime.now(dt.timezone.utc).isoformat())
                self.start_schedule_sync()
                self.start_startup_check()
                while not self.stopping:
                    self.reconcile()
                    self.start_monitor()
                    self.start_schedule_sync()
                    self.start_startup_check()
                    for _ in range(10):
                        if self.stopping:
                            break
                        time.sleep(1)
            finally:
                self.phase = 'shutdown'
                self.report('stopping', '监督进程正在退出，停止管理容器与群晖桥接。')
                stopped = True
                try:
                    self.stop_container()
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    stopped = False
                try:
                    self.stop_schedule_sync()
                except (OSError, subprocess.TimeoutExpired):
                    pass
                try:
                    self.stop_startup_check()
                except (OSError, subprocess.TimeoutExpired):
                    pass
                try:
                    self.stop_monitor()
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if self.bridge is not None and self.bridge.poll() is None:
                    self.bridge.terminate()
                    try:
                        self.bridge.wait(timeout=300)
                    except subprocess.TimeoutExpired:
                        self.bridge.kill()
                        self.bridge.wait(timeout=5)
                self.report('stopped' if stopped else 'blocked', '管理服务已停止，原证书续期任务不受影响。' if stopped else '监督进程已退出，但无法确认管理容器已关闭；请通过 NAS 检查。')
                (self.home / 'supervisor.pid').unlink(missing_ok=True)
        return 0 if stopped else 1


def process_matches(pid, script, config_path):
    try:
        if type(pid) is not int or pid <= 1:
            return False
        args = Path('/proc/{}/cmdline'.format(pid)).read_bytes().split(b'\0')
        return str(script).encode() in args and str(config_path).encode() in args and b'serve' in args
    except OSError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('command', choices=['start', 'serve', 'stop', 'status', 'set-access-mode'])
    parser.add_argument('--mode', choices=['lan', 'public'])
    args = parser.parse_args(argv)
    if args.command == 'set-access-mode' and args.mode is None:
        parser.error('set-access-mode 需要 --mode lan 或 --mode public')
    if os.geteuid() != 0:
        parser.error('必须在群晖 root 终端运行')
    os.umask(0o077)
    try:
        config = load_config(args.config)
        home = Path(config['home'])
        if args.command == 'set-access-mode':
            policy_path = home / 'access/access.json'
            current = initialize_policy(policy_path)
            updated = write_policy(policy_path, args.mode, current['revision'])
            print(json.dumps({'access_mode': updated['mode'], 'message': '访问模式已保存，运行中的管理服务会自动应用。'}, ensure_ascii=False))
            return 0
        script = Path(__file__).resolve()
        pid_path = home / 'supervisor.pid'
        pid = json.loads(pid_path.read_text()).get('pid') if pid_path.exists() else None
        alive = process_matches(pid, script, args.config)
        if args.command == 'status':
            print(json.dumps({'supervisor_running': alive, 'state': json.loads((home / 'deployment-state.json').read_text()) if (home / 'deployment-state.json').exists() else None}, ensure_ascii=False))
            return 0
        if args.command == 'start':
            if alive:
                return 0
            log = home / 'supervisor.log'
            if log.exists() and log.stat().st_size > 2 * 1024 * 1024:
                os.replace(str(log), str(log) + '.1')
            fd = os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'a') as handle:
                subprocess.Popen([sys.executable, '-I', str(script), '--config', str(args.config), 'serve'], stdin=subprocess.DEVNULL, stdout=handle, stderr=handle, start_new_session=True)
            return 0
        if args.command == 'stop':
            if alive:
                os.kill(pid, signal.SIGTERM)
                for _ in range(350):
                    if not process_matches(pid, script, args.config):
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError('管理服务尚未完成退出')
            service = Deployment(config, args.config)
            service.phase = 'shutdown'
            service.stop_container()
            service.log('stopped', '管理服务已停止，原证书续期任务不受影响。')
            return 0
        return Deployment(config, args.config).serve()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print('管理服务操作失败，请检查私有部署配置或运行状态。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
