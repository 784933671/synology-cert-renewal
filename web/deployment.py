"""群晖原生监督进程：先应用访问策略，再启动 Docker 管理服务。"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
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
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from access_policy import read_policy, initialize_policy, write_policy, write_applied
    from network_guard import NetworkGuard, GuardError, validate_network
    from tls_sync import sync_tls, TLSBusy

CONTAINER = 'synology-cert-web'
MANAGED_LABEL = 'io.github.784933671.certweb.managed'
DEFAULT_CONFIG = Path('/usr/local/share/synology-cert-web/deployment.json')
START_STABLE_SECONDS = 60


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
        self.stopping = False
        self.last_message = None
        self.started = False
        self.last_container = None
        self.clock = clock or time.monotonic
        self.ready_since = None
        self.last_policy = None
        self.phase = 'initializing'
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
        try:
            policy = self.apply_access_policy()
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
            self.phase = 'bridge'
            self.start_bridge()
            bridge_ready = self.bridge_ready()
            credentials_ready = (self.home / 'data/auth.sqlite3').exists()
            self.phase = 'docker'
            item = self.container()
            running = bool(item and item.get('State', {}).get('Running') and not item['State'].get('Restarting'))
            if running:
                self.started = True
                self.ready_since = None
            elif self.started:
                self.started = False
                self.ready_since = None
                self.report('waiting', '检测到管理容器已退出，等待环境连续稳定后重新启动。')
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
                if not item or not item.get('State', {}).get('Running') or item['State'].get('Restarting'):
                    raise RuntimeError('管理容器启动后未保持运行')
                self.started = True
            self.phase = 'running'
            self.report('running', '管理服务运行中，访问模式：{}。'.format('仅内网' if policy['mode'] == 'lan' else '允许外网'))
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, GuardError, subprocess.TimeoutExpired):
            self.ready_since = None
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
                while not self.stopping:
                    self.reconcile()
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
