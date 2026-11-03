"""证书管家引导安装入口；只在私有终端接收凭据。"""
import argparse
import contextlib
import fcntl
import getpass
import grp
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shlex
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from web.deployment import load_config, MANAGED_LABEL
from web.login_mail import email_valid
from web.network_guard import validate_network
from web.setup_upgrade import Upgrade, UpgradeError, atomic_bytes, regular, directory, ACME_STAMP, copy_payload, fsync_directory
from web.tls_sync import validate_material

SOURCE = Path(__file__).resolve().parents[1]
HOME = Path('/usr/local/share/synology-cert-web')
NATIVE = Path('/usr/local/share/synology-cert-renewal')
STATE = Path('/usr/local/share/synology-cert-setup')
RC = Path('/usr/local/etc/rc.d/S99synology-cert-web.sh')
DOCKER = '/usr/local/bin/docker'
ENV = dict(os.environ, PATH='/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin')


class SetupError(RuntimeError):
    pass


def run(args, timeout=90, interactive=False, input_text=None):
    try:
        result = subprocess.run(args, timeout=timeout, env=ENV, universal_newlines=True,
                                input=input_text, stdout=None if interactive else subprocess.PIPE,
                                stderr=None if interactive else subprocess.PIPE)
        if result.returncode:
            raise SetupError('步骤执行失败；请根据终端提示检查后重新运行同一安装命令')
        return result.stdout or ''
    except (OSError, subprocess.SubprocessError):
        raise SetupError('步骤未完成；请检查系统依赖、网络或 Docker 后重试') from None


def read_private(path, uid=0):
    regular(path, uid, private=True)
    if path.stat().st_size > 1024 * 1024:
        raise SetupError('安装状态文件过大')
    return json.loads(path.read_text())


def executor(source):
    spec = importlib.util.spec_from_file_location('cert_setup_executor', Path(source) / 'certctl.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def network_defaults(route, addresses):
    route_line = next((line for line in route.splitlines() if line.startswith('default ')), '')
    gateway = re.search(r'\bvia ([0-9.]+)', route_line)
    interface = re.search(r'\bdev (\S+)', route_line)
    if not gateway or not interface:
        return {}
    for line in addresses.splitlines():
        pieces = line.split()
        if len(pieces) < 4 or pieces[1].split('@')[0] != interface.group(1) or pieces[2] != 'inet':
            continue
        try:
            address = ipaddress.IPv4Interface(pieces[3])
            values = {'bind': str(address.ip), 'network': str(address.network), 'gateway': gateway.group(1)}
            validate_network(values['bind'], [values['network']], [values['gateway']], 18443)
            return values
        except ValueError:
            continue
    return {}


def validate_options(value, domains):
    expected = {'bind', 'network', 'gateway', 'port', 'hostname', 'email', 'access_mode'}
    if not isinstance(value, dict) or set(value) != expected:
        raise SetupError('安装参数不完整')
    validate_network(value['bind'], [value['network']], [value['gateway']], value['port'])
    name = value['hostname']
    if (not isinstance(name, str) or name != name.lower() or len(name) > 253
            or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in name.split('.'))
            or '.' not in name):
        raise SetupError('管理域名格式不正确')
    if not any(name == domain or (domain.startswith('*.') and name.endswith(domain[1:])
                                 and name.count('.') == domain.count('.')) for domain in domains):
        raise SetupError('管理域名必须在所选证书覆盖范围内')
    if not email_valid(value['email']) or value['access_mode'] not in ('lan', 'public'):
        raise SetupError('邮箱或访问模式不正确')
    return value


class Wizard:
    def __init__(self, source=SOURCE, home=HOME, native=NATIVE, state=STATE,
                 runner=run, ask=input, hidden=getpass.getpass, uid=0, sleeper=time.sleep):
        self.source, self.home, self.native, self.state = map(Path, (source, home, native, state))
        self.runner, self.ask, self.hidden, self.uid, self.sleep = runner, ask, hidden, uid, sleeper
        self.journal = {}

    def save(self):
        atomic_bytes(self.state / 'install.json', json.dumps(self.journal, ensure_ascii=False).encode())

    def source_digest(self):
        digest = hashlib.sha256()
        with tempfile.TemporaryDirectory(prefix='.source-check-', dir=str(self.state)) as temporary:
            payload = Path(temporary) / 'web'
            copy_payload(self.source, payload)
            for path in sorted(payload.rglob('*')):
                if path.is_file():
                    digest.update(str(path.relative_to(payload)).encode() + b'\0' + path.read_bytes() + b'\0')
        for name in ('setup.sh', 'install.sh', 'certctl.py', 'run_history.py', 'failure_diagnostics.py', 'dns_cleanup.py',
                     'dns_cleanup_retry.sh', 'dns_tencent_tracked.sh'):
            regular(self.source / name)
            digest.update(name.encode() + b'\0' + (self.source / name).read_bytes() + b'\0')
        return digest.hexdigest()

    @contextlib.contextmanager
    def locked(self):
        self.state.mkdir(mode=0o700, exist_ok=True)
        directory(self.state, self.uid, private=True)
        fd = os.open(str(self.state / 'setup.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as handle:
            regular(self.state / 'setup.lock', self.uid, private=True)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError('已有安装或升级正在执行') from None
            yield

    def preflight(self, version_path=Path('/etc.defaults/VERSION')):
        if os.geteuid() != self.uid or self.uid != 0:
            raise SetupError('请在 NAS 私有终端执行 sudo sh setup.sh')
        if not version_path.is_file() or platform.machine() not in ('x86_64', 'amd64'):
            raise SetupError('一键入口当前支持 DSM 7 的 x86_64 群晖，例如 DS218+')
        version = re.search(r'^productversion="(7\.[0-9.]+)"', version_path.read_text(), re.M)
        if not version:
            raise SetupError('一键入口需要 DSM 7；旧版脚本部署仍按原说明操作')
        for name in ('install.sh', 'certctl.py', 'run_history.py', 'failure_diagnostics.py', 'dns_cleanup.py',
                     'dns_cleanup_retry.sh', 'dns_tencent_tracked.sh', 'web/install-web.py'):
            regular(self.source / name)
        for command in ('/usr/syno/bin/synowebapi', '/usr/bin/iptables', '/usr/bin/ip6tables', '/bin/ssmtp', DOCKER):
            if not os.access(command, os.X_OK):
                raise SetupError('缺少系统组件，请先安装并启动 Docker/Container Manager，检查 DSM 邮件和防火墙组件')
        self.runner([DOCKER, 'info', '--format', '{{.ServerVersion}}'])
        self.runner([DOCKER, 'compose', 'version'])
        # ps 使用单个固定名称筛选，既有其他容器不受影响。
        ids = self.runner([DOCKER, 'ps', '-aq', '--filter', 'name=^/synology-cert-web$']).strip()
        if ids:
            items = json.loads(self.runner([DOCKER, 'inspect', 'synology-cert-web']))
            if len(items) != 1 or items[0].get('Config', {}).get('Labels', {}).get(MANAGED_LABEL) != 'true':
                raise SetupError('同名 Docker 容器不属于本项目，已停止以免覆盖')
            if not (self.home / 'deployment.json').exists():
                raise SetupError('发现无对应部署配置的管理容器，请先核对原安装')
        for lookup in (pwd.getpwuid, grp.getgrgid):
            try:
                lookup(10100)
            except KeyError:
                continue
            raise SetupError('容器专用 UID/GID 10100 已被 NAS 账号或群组占用，请先处理权限冲突')
        print('环境检查通过：DSM {}，Docker/Compose 可用。'.format(version.group(1)))

    def detect_network(self):
        try:
            return network_defaults(self.runner(['/sbin/ip', '-4', 'route', 'show', 'default']),
                                    self.runner(['/sbin/ip', '-o', '-4', 'addr', 'show']))
        except (SetupError, ValueError):
            return {}

    def prompt_options(self, config):
        defaults = self.detect_network()
        domains = config['domains']
        default_host = next((x for x in domains if not x.startswith('*.')), 'nas.' + domains[0][2:])
        def field(label, default=''):
            return self.ask(label + (' [{}]'.format(default) if default else '') + ': ').strip() or default
        while True:
            try:
                value = {'bind': field('NAS 内网 IPv4', defaults.get('bind', '')),
                         'network': field('允许访问的内网网段', defaults.get('network', '')),
                         'gateway': field('路由器内网 IP', defaults.get('gateway', '')),
                         'hostname': field('管理页域名（必须由证书覆盖）', default_host),
                         'port': int(field('管理 HTTPS 端口', '18443')),
                         'email': field('管理员登录验证码邮箱', config['email']),
                         'access_mode': field('访问模式：lan 仅内网，public 允许外网', 'lan')}
                return validate_options(value, domains)
            except (ValueError, SetupError):
                print('参数不符合要求，请重新填写准确的内网、域名、端口和邮箱。')

    def native_controller(self):
        module = executor(self.source)
        return module, module.Controller(self.native)

    def mail_ready(self):
        module, controller = self.native_controller()
        try:
            data = controller.call_local_api('SYNO.Core.Notification.Mail.Conf', 'get', timeout=15)
        except module.Failure:
            raise SetupError('无法读取 DSM 通知邮件配置，请先在控制面板设置并测试邮件') from None
        if data.get('enable_mail') is not True or not email_valid(data.get('sender_mail')):
            raise SetupError('请先在 DSM 控制面板配置并测试通知邮件，再运行安装命令')

    def native_ready(self):
        if not self.native.exists():
            print('正在安装证书执行器和固定版本 acme.sh……')
            self.runner(['/bin/sh', str(self.source / 'install.sh')], timeout=300, interactive=True)
        directory(self.native, self.uid, private=True)
        regular(self.native / 'ACME-VERSION', self.uid, private=True)
        if (self.native / 'ACME-VERSION').read_text() != ACME_STAMP:
            raise SetupError('原 acme.sh 版本不兼容；未覆盖原证书和配置')
        if not (self.home / 'deployment.json').exists():
            self.update_native_code()
        if not (self.native / 'config.json').exists():
            print('按提示选择 DSM 中要管理的现有证书，并填写 DNSPod 子账号密钥。')
            self.runner([sys.executable, '-I', str(self.native / 'certctl.py'), '--home', str(self.native), 'configure'],
                        timeout=3600, interactive=True)
        module, controller = self.native_controller()
        try:
            with controller.locked():
                controller.load()
                controller.preflight()
        except (module.Failure, module.Busy):
            raise SetupError('原证书配置或 HTTPS 服务预检失败，请先完成原执行器的检查与恢复') from None
        return controller.config

    def update_native_code(self):
        """脚本用户加装看板时只更新程序，事务备份留在安装目录。"""
        files = {'certctl.py': 'certctl.py', 'run_history.py': 'run_history.py', 'failure_diagnostics.py': 'failure_diagnostics.py',
                 'dns_cleanup.py': 'dns_cleanup.py', 'dns_cleanup_retry.sh': 'dns_cleanup_retry.sh',
                 'acme/dnsapi/dns_tencent.sh': 'dns_tencent_tracked.sh'}
        journal_path = self.state / 'native-update.json'
        def restore_native(snapshot, backup):
            for target, name in snapshot.items():
                destination = self.native / target
                directory(destination.parent, self.uid, private=True)
                if name is None and target == 'run_history.py':
                    if os.path.lexists(destination):
                        regular(destination, self.uid, private=True)
                        destination.unlink()
                        fsync_directory(destination.parent)
                elif name == files[target]:
                    regular(backup / name, self.uid, private=True)
                    if os.path.lexists(destination):
                        regular(destination, self.uid, private=True)
                    atomic_bytes(destination, (backup / name).read_bytes())
                else:
                    raise SetupError('原执行器备份路径无效')
        with contextlib.ExitStack() as stack:
            descriptor = os.open(str(self.native / 'state/run.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            handle = stack.enter_context(os.fdopen(descriptor, 'a'))
            regular(self.native / 'state/run.lock', self.uid, private=True)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError('原续期任务正在运行，请完成后重新运行安装') from None
            if journal_path.exists():
                previous = read_private(journal_path, self.uid)
                backup = self.state / previous.get('backup', '')
                if not re.fullmatch('native-backup-[0-9a-f]{16}', previous.get('backup', '')) or set(previous.get('files', {})) != set(files):
                    raise SetupError('原执行器升级恢复记录无效')
                directory(backup, self.uid, private=True)
                restore_native(previous['files'], backup)
                journal_path.unlink()
            changes = {}
            for target, source in files.items():
                regular(self.source / source)
                exists = os.path.lexists(self.native / target)
                if exists or target != 'run_history.py':
                    regular(self.native / target, self.uid, private=True)
                directory((self.native / target).parent, self.uid, private=True)
                content = (self.source / source).read_bytes()
                if not exists or content != (self.native / target).read_bytes():
                    changes[target] = content
            if not changes:
                return
            backup = self.state / ('native-backup-' + secrets.token_hex(8))
            backup.mkdir(mode=0o700)
            originals = {}
            for target, name in files.items():
                exists = os.path.lexists(self.native / target)
                originals[target] = name if exists else None
                if exists:
                    atomic_bytes(backup / name, (self.native / target).read_bytes())
            atomic_bytes(journal_path, json.dumps({'backup': backup.name, 'files': originals}).encode())
            try:
                for target, content in changes.items():
                    atomic_bytes(self.native / target, content)
            except BaseException:
                restore_native(originals, backup)
                raise
            journal_path.unlink()

    def check_port(self, options):
        if self.ready():
            return
        current = self.managed_container() if (self.home / 'deployment.json').exists() else None
        if current and current.get('State', {}).get('Running') is True:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind((options['bind'], options['port']))
        except OSError:
            raise SetupError('管理 IP 未配置在本机或端口已占用，请先处理地址/端口冲突') from None

    def tls_ready(self, options, config):
        source = Path('/usr/syno/etc/certificate/_archive') / config['certificate_id']
        try:
            validate_material(source, options['hostname'])
        except (ValueError, OSError, subprocess.SubprocessError):
            print('所选证书尚不能用于可信 HTTPS 管理入口，需要先申请并替换证书。')
            if self.ask('现在运行原证书任务申请/恢复并验证？[y/N]: ').strip().lower() != 'y':
                raise SetupError('安装已保留进度；准备好有效证书后重新执行同一命令')
            self.runner([sys.executable, '-I', str(self.native / 'certctl.py'), '--home', str(self.native), 'run'],
                        timeout=1800, interactive=True)
            validate_material(source, options['hostname'])

    def auth_cli(self, args, password=None):
        command = [DOCKER, 'run', '--rm']
        if password is not None:
            command.append('--interactive')
        command += ['--network', 'none', '--user', '10100:10100',
                    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--env', 'CERTWEB_DATA_DIR=/data', '--mount',
                    'type=bind,source=' + str(self.home / 'data') + ',target=/data',
                    '--entrypoint', 'python', 'synology-cert-web:local', '-m', 'web.backend']
        return self.runner(command + args,
                           timeout=90, input_text=password + '\n' if password is not None else None)

    def credentials_ready(self, options):
        db = self.home / 'data/auth.sqlite3'
        exists = False
        if db.exists():
            regular(db, 10100, private=True)
            with sqlite3.connect('file:' + str(db) + '?mode=ro', uri=True) as conn:
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables - {'users', 'sessions', 'attempts', 'audit', 'login_security', 'login_challenges', 'email_sends', 'sqlite_sequence'}:
                    raise SetupError('认证数据库包含未知结构，未覆盖原数据')
                users = conn.execute('SELECT username FROM users').fetchall() if 'users' in tables else []
                if users and users != [('admin',)]:
                    raise SetupError('安装进度中的管理员记录异常，未重置任何密码')
                exists = bool(users)
        if not exists:
            while True:
                password = self.hidden('设置管理账号 admin 密码（12～128 个字符，不回显）: ')
                confirm = self.hidden('再次输入密码: ')
                if not 12 <= len(password) <= 128 or password != confirm or '\x00' in password or '\n' in password or '\r' in password:
                    print('密码长度不符合要求或两次输入不一致，请重试。')
                    continue
                self.auth_cli(['init', '--username', 'admin', '--password-stdin'], password)
                password = confirm = None
                break
            print('管理员凭据已保存。')
        policy_path = self.native / 'web/login-email.json'
        if policy_path.exists():
            policy = read_private(policy_path, self.uid)
            if (set(policy) != {'recipient', 'policy_version'} or policy['recipient'] != options['email']
                    or not re.fullmatch('[0-9a-f]{32}', policy['policy_version'])):
                raise SetupError('已有登录邮箱策略与安装进度不符，未覆盖原绑定')
        else:
            policy = {'recipient': options['email'], 'policy_version': secrets.token_hex(16)}
            atomic_bytes(policy_path, json.dumps(policy).encode())
        with sqlite3.connect('file:' + str(db) + '?mode=ro', uri=True) as conn:
            row = conn.execute('SELECT email,policy_version,enabled FROM login_security WHERE username=?', ('admin',)).fetchone()
            required = conn.execute('SELECT email_login_required FROM users WHERE username=?', ('admin',)).fetchone()
        if row != (policy['recipient'], policy['policy_version'], 1) or not required or required[0] != 1:
            self.auth_cli(['enable-email-login', '--username', 'admin', '--email', policy['recipient'],
                           '--policy-version', policy['policy_version']])

    def managed_container(self):
        try:
            item = json.loads(self.runner([DOCKER, 'inspect', 'synology-cert-web']))[0]
            if (item.get('Config', {}).get('Labels', {}).get(MANAGED_LABEL) == 'true'
                    and any(m.get('Destination') == '/data' and m.get('Source') == str(self.home / 'data')
                            for m in item.get('Mounts', []))):
                return item
        except (SetupError, ValueError, IndexError, KeyError):
            pass
        return None

    def ready(self):
        item = self.managed_container()
        return bool(item and item.get('State', {}).get('Running') is True
                    and item.get('State', {}).get('Health', {}).get('Status') == 'healthy')

    def verify_service(self, options, config):
        origin = 'https://{}:{}'.format(options['hostname'], options['port'])
        health = self.runner(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
                              '--connect-timeout', '5', '--max-time', '15', '--resolve',
                              '{}:{}:{}'.format(options['hostname'], options['port'], options['bind']), origin + '/healthz'])
        if json.loads(health) != {'ok': True}:
            raise SetupError('管理 HTTPS 实际访问验证失败')
        code = ("import asyncio,json;from web.backend.bridge import BridgeClient;"
                "d=asyncio.run(BridgeClient('/bridge/certweb.sock').call('status'));"
                "print(json.dumps({'certificate_id':d.get('certificate',{}).get('id'),"
                "'pending_clear':not any(d.get('pending',{}).values())}))")
        status = json.loads(self.runner([DOCKER, 'exec', 'synology-cert-web', 'python', '-c', code]))
        if status != {'certificate_id': config['certificate_id'], 'pending_clear': True}:
            raise SetupError('实际证书桥接状态未通过验收，新建续期任务尚未启用')

    def install(self):
        from web.setup_tasks import TaskSetup
        journal_path = self.state / 'install.json'
        if journal_path.exists():
            self.journal = read_private(journal_path, self.uid)
            if not isinstance(self.journal, dict) or self.journal.get('version') != 1 or self.journal.get('home') != str(self.home) or self.journal.get('native') != str(self.native):
                raise SetupError('安装进度与目标目录不匹配')
            if self.journal.get('complete'):
                raise SetupError('本安装已完成；请运行 sudo sh setup.sh upgrade 保留配置升级')
            if self.journal.get('source_sha256') != self.source_digest():
                raise SetupError('安装包与未完成进度不同；请先用原安装包完成安装，再使用 upgrade')
        elif self.home.exists():
            raise SetupError('管理目录已存在但不是本次安装进度，请使用 upgrade 或先核对原目录')
        else:
            self.journal = {'version': 1, 'home': str(self.home), 'native': str(self.native), 'complete': False,
                            'source_sha256': self.source_digest()}
            self.save()
        self.mail_ready()
        config = self.native_ready()
        options = self.journal.get('options')
        if options and not (self.home / 'deployment.json').exists():
            if self.ask('沿用上次填写的内网、域名和邮箱参数？[Y/n]: ').strip().lower() == 'n':
                options = None
        if options is None:
            options = self.prompt_options(config)
            self.check_port(options)
            self.journal['options'] = options
            self.save()
        options = validate_options(self.journal['options'], config['domains'])
        self.check_port(options)
        origin = 'https://{}:{}'.format(options['hostname'], options['port'])
        print('管理入口：{}；访问模式：{}；原证书域名：{}'.format(origin, options['access_mode'], ', '.join(config['domains'])))
        self.tls_ready(options, config)
        task_setup = TaskSetup(self.native, state_path=self.state / 'task.json', uid=self.uid)
        task = task_setup.ensure(options['email'])
        install_script = self.source / 'web/install-web.py'
        self.runner([sys.executable, '-I', str(install_script), '--home', str(self.home), 'prepare',
                     '--native-home', str(self.native), '--bind', options['bind'], '--network', options['network'],
                     '--deny', options['gateway'], '--port', str(options['port']), '--origin', origin,
                     '--access-mode', options['access_mode'], '--task-id', str(task['id'])], timeout=90)
        installed = load_config(self.home / 'deployment.json')
        expected = {'bind': options['bind'], 'networks': [options['network']], 'denied': [options['gateway']],
                    'port': options['port'], 'origin': origin, 'task_id': task['id'], 'native_home': str(self.native)}
        if any(installed.get(k) != value for k, value in expected.items()):
            raise SetupError('现有部署参数与安装进度不一致，未覆盖现有设置')
        if not self.journal.get('built'):
            print('正在构建 Docker 镜像，首次下载依赖可能需要数分钟……')
            self.runner([sys.executable, '-I', str(install_script), '--home', str(self.home), 'build'], timeout=1800, interactive=True)
            self.journal['built'] = True
            self.save()
        self.credentials_ready(options)
        if RC.exists():
            regular(RC, self.uid)
            expected_command = shlex.join(['/usr/bin/python3', '-I', str(self.home / 'code/deployment.py'),
                                          '--config', str(self.home / 'deployment.json')])
            if 'exec ' + expected_command + ' "$1"' not in RC.read_text():
                raise SetupError('同名开机脚本不属于本安装，未覆盖')
            if not self.ready():
                self.runner([sys.executable, '-I', str(self.home / 'code/deployment.py'), '--config',
                             str(self.home / 'deployment.json'), 'stop'], timeout=360)
            self.runner([sys.executable, '-I', str(self.home / 'code/deployment.py'), '--config', str(self.home / 'deployment.json'), 'start'])
        else:
            self.runner([sys.executable, '-I', str(install_script), '--home', str(self.home), 'activate'], timeout=120)
        for _ in range(180):
            if self.ready():
                break
            self.sleep(1)
        else:
            raise SetupError('管理服务健康检查未通过；进度已保留，新建续期任务尚未启用')
        self.verify_service(options, config)
        task_setup.activate(task['id'])
        self.journal['complete'] = True
        self.save()
        print('安装完成：{}\n账号：admin；请使用刚设置的密码和邮箱验证码登录。'.format(origin))
        if options['access_mode'] == 'lan':
            print('请在内网 DNS 或 hosts 中将 {} 指向 {}；路由器设置不会被安装器修改。'.format(options['hostname'], options['bind']))
        else:
            print('允许外网模式已选择；路由器端口映射与公网 DNS 需自行配置。')


def main(argv=None):
    parser = argparse.ArgumentParser(description='证书管家：一条命令引导安装、保留配置升级或只读检查')
    parser.add_argument('command', nargs='?', choices=('auto', 'install', 'upgrade', 'recover', 'check'), default='auto')
    args = parser.parse_args(argv)
    os.umask(0o077)
    os.environ['PATH'] = ENV['PATH']
    wizard = Wizard()
    try:
        wizard.preflight()
        if args.command == 'check':
            if (HOME / 'deployment.json').exists():
                config = load_config(HOME / 'deployment.json')
                print('已有管理层；入口 {}；任务编号 {}。检查模式未写入配置。'.format(config['origin'], config.get('task_id', 7)))
            else:
                print('首次安装环境可用；还需在向导中确认邮件、证书和内网参数。检查模式未写入配置。')
            return 0
        if not sys.stdin.isatty():
            raise SetupError('请在 NAS 私有交互终端运行，不要通过 curl 管道执行')
        with wizard.locked():
            command = args.command
            if command == 'auto':
                state = read_private(STATE / 'install.json') if (STATE / 'install.json').exists() else {}
                if not isinstance(state, dict):
                    raise SetupError('安装进度格式不正确，请先检查私有安装记录')
                command = 'install' if state and not state.get('complete') else 'upgrade' if (HOME / 'deployment.json').exists() else 'install'
            if command in ('upgrade', 'recover'):
                updater = Upgrade(SOURCE, HOME)
                print('正在构建并检查升级镜像；切换前会备份现有代码和认证数据。' if command == 'upgrade' else '正在检查未完成的升级事务。')
                result = updater.run() if command == 'upgrade' else updater.recover()
                if command == 'upgrade' and result.get('recovered'):
                    print('上次中断的升级事务已处理，继续执行本次升级……')
                    result = updater.run()
                print('升级完成，原配置、密码、邮箱验证和续期计划已保留。' if result.get('upgraded') else '恢复检查完成，未宣称新版本已上线。')
            else:
                wizard.install()
        return 0
    except (SetupError, UpgradeError) as error:
        print('未完成：' + str(error), file=sys.stderr)
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError):
        print('未完成：系统状态或安装参数不符合要求；请检查权限、依赖和私有安装进度后重试。', file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print('安装已中断；保留已有配置，重新运行同一命令可继续。', file=sys.stderr)
    except Exception:
        print('未完成：群晖接口或安装步骤返回异常，进度与原数据已保留，请检查后重试。', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
