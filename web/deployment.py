"""群晖原生监督进程：先验证内网边界，再启动 Docker 管理服务。"""
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
    from .network_guard import NetworkGuard, GuardError, validate_network
    from .tls_sync import sync_tls, TLSBusy
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from network_guard import NetworkGuard, GuardError, validate_network
    from tls_sync import sync_tls, TLSBusy

CONTAINER = 'synology-cert-web'
MANAGED_LABEL = 'io.github.784933671.certweb.managed'
DEFAULT_CONFIG = Path('/usr/local/share/synology-cert-web/deployment.json')


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
    if set(config) != expected:
        raise ValueError('部署配置字段不正确')
    validate_network(config['bind'], config['networks'], config['denied'], config['port'])
    for key in ('home', 'native_home'):
        item = Path(config[key])
        if not item.is_absolute() or str(item) != str(item.resolve()) or not item.is_dir():
            raise ValueError('部署目录无效')
        if item.stat().st_uid != 0 or item.stat().st_mode & 0o022:
            raise ValueError('部署目录不可由非 root 用户写入')
    origin = urlsplit(config['origin'])
    if origin.scheme != 'https' or not origin.hostname or origin.port != config['port'] or origin.path or origin.query or origin.fragment or origin.username:
        raise ValueError('必须使用明确的 HTTPS 管理域名')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', origin.hostname):
        raise ValueError('管理域名格式无效')
    try:
        ipaddress.ip_address(origin.hostname)
    except ValueError:
        pass
    else:
        raise ValueError('管理入口使用证书覆盖的域名，不使用 IP')
    config['authority'] = origin.netloc
    config['hostname'] = origin.hostname
    return config


class Deployment:
    def __init__(self, config, config_path):
        self.config, self.config_path = config, Path(config_path)
        self.home = Path(config['home'])
        self.code = self.home / 'code'
        self.guard = NetworkGuard(config['bind'], config['networks'], config['denied'], config['port'])
        self.bridge = None
        self.stopping = False
        self.last_message = None
        self.started = False
        self.last_container = None
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
        private_json(self.home / 'deployment-state.json', {'status': status, 'message': message, 'at': time.time(), 'pid': os.getpid()})

    def start_bridge(self):
        if self.bridge is not None and self.bridge.poll() is None:
            return
        if self.bridge is not None:
            self.stop_container()
        log_path = self.home / 'bridge.log'
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as log:
            self.bridge = subprocess.Popen([sys.executable, '-I', str(Path(self.config['native_home']) / 'web/host_bridge.py'), '--home', self.config['native_home'], '--socket', str(self.home / 'bridge/certweb.sock'), '--task-id', '7', '--uid', '10100', '--gid', '10100', '--parent-pid', str(os.getpid()), '--management-host', self.config['hostname']], env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def bridge_ready(self):
        import socket
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(3)
                connection.connect(str(self.home / 'bridge/certweb.sock'))
            return self.bridge.poll() is None
        except OSError:
            return False

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
                    try:
                        if not self.guard.valid():
                            self.stop_container()
                            self.guard.install()
                        try:
                            sync_tls(Path(self.config['native_home']), self.home / 'tls', self.config['hostname'])
                        except TLSBusy:
                            if not (self.home / 'tls/current.cert').exists():
                                raise RuntimeError('续期任务正在运行，等待 TLS 材料')
                        self.start_bridge()
                        if not self.bridge_ready():
                            self.log('starting', '等待群晖桥接服务就绪。')
                        elif not (self.home / 'data/auth.sqlite3').exists():
                            self.log('setup', '等待管理员账号初始化。')
                        else:
                            item = self.container()
                            if not item or not item.get('State', {}).get('Running'):
                                self.compose('up', '-d', '--no-build')
                            self.started = True
                            self.log('running', '管理服务运行中，内网访问规则已校验。')
                    except (OSError, ValueError, RuntimeError, GuardError, subprocess.TimeoutExpired):
                        stopped = True
                        try:
                            self.stop_container()
                        except (OSError, RuntimeError, subprocess.TimeoutExpired):
                            stopped = False
                        self.log('blocked', '管理服务保持关闭：请检查网络规则、HTTPS 材料或 Docker 状态。' if stopped else '访问保护异常，且无法确认管理容器已关闭；请通过 NAS 检查。')
                    for _ in range(10):
                        if self.stopping:
                            break
                        time.sleep(1)
            finally:
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
                self.log('stopped' if stopped else 'blocked', '管理服务已停止，原证书续期任务不受影响。' if stopped else '监督进程已退出，但无法确认管理容器已关闭；请通过 NAS 检查。')
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
    parser.add_argument('command', choices=['start', 'serve', 'stop', 'status'])
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('必须在群晖 root 终端运行')
    os.umask(0o077)
    try:
        config = load_config(args.config)
        home = Path(config['home'])
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
            service.stop_container()
            service.log('stopped', '管理服务已停止，原证书续期任务不受影响。')
            return 0
        return Deployment(config, args.config).serve()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print('管理服务操作失败，请检查私有部署配置或运行状态。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
