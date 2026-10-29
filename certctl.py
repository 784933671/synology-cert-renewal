#!/usr/bin/env python3
"""群晖证书续期：只更新已选证书，实际 TLS 指纹决定部署是否成功。"""
import argparse
import contextlib
import datetime
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

DEFAULT_HOME = Path('/usr/local/share/synology-cert-renewal')
ARCHIVE = Path('/usr/syno/etc/certificate/_archive')
ACME_VERSION = '3.1.6'
CA = 'https://acme-v02.api.letsencrypt.org/directory'
TEMP_USER = 'sc-acmesh-tmp'
SYSTEM_PATH = '/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
RECOVERY_INTERVAL = 24 * 60 * 60
RECOVERY_LIMIT = 3


class Failure(Exception):
    pass


class Busy(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def private(path, directory=False, uid=0):
    try:
        info = path.lstat()
    except OSError:
        raise Failure('找不到所需文件：{}'.format(path))
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise Failure('{} 必须由 root 持有，目录权限 700、文件权限 600。'.format(path))


def save_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    try:
        with path.open(encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        raise Failure('无法读取有效 JSON：{}'.format(path))


def capture(args, timeout=20, data=None):
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure('命令无法执行或超时：{}'.format(Path(args[0]).name))
    if result.returncode:
        raise Failure('命令失败：{}，请检查系统环境。'.format(Path(args[0]).name))
    return result.stdout


def certificate_domains(path):
    content = capture(['openssl', 'x509', '-in', str(path), '-noout', '-text']).decode()
    domains = sorted(set(re.findall(r'DNS:([^,\s]+)', content)))
    if not domains:
        raise Failure('现有证书没有 DNS SAN，无法自动推导应保留的域名。')
    return domains


def fingerprint(path):
    return hashlib.sha256(capture(['openssl', 'x509', '-in', str(path), '-outform', 'DER'])).hexdigest()


def pem_chain(path):
    try:
        content = path.read_text()
        blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', content, re.S)
        if not blocks:
            raise ValueError()
        return [ssl.PEM_cert_to_DER_cert(block) for block in blocks]
    except (OSError, ValueError, ssl.SSLError):
        raise Failure('证书链中缺少有效 PEM 证书。')


def valid_domain(value):
    if not isinstance(value, str) or len(value) > 253:
        return False
    name = value[2:] if value.startswith('*.') else value
    labels = name.split('.')
    return len(labels) > 1 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                   for label in labels) and not all(x.isdigit() for x in labels)


def covers(domains, name):
    return name in domains or any(d.startswith('*.') and name.count('.') == d.count('.')
                                  and name.endswith(d[1:]) for d in domains)


def validate_config(config):
    if not isinstance(config, dict) or config.get('version') != 1:
        raise Failure('配置版本无效，请重新 configure。')
    for key in ('certificate_id', 'certificate_description', 'email', 'secret_id', 'secret_key'):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise Failure('配置缺少字段：{}'.format(key))
    if not re.fullmatch(r'[A-Za-z0-9_-]+', config['certificate_id']):
        raise Failure('证书 ID 格式无效。')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', config['certificate_description']):
        raise Failure('请先在 DSM 中将证书描述改为唯一英文标识，例如 ttxli-cn-auto。')
    domains = config.get('domains')
    if not isinstance(domains, list) or not domains or not all(valid_domain(x) for x in domains):
        raise Failure('域名配置无效；请使用小写 ASCII 域名或其通配符。')
    if len(set(domains)) != len(domains):
        raise Failure('域名配置不能重复。')
    if not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', config['email']):
        raise Failure('邮箱格式无效；请使用常规 ASCII 邮箱地址。')
    if any(not re.fullmatch(r'[A-Za-z0-9+/=_-]+', config[key]) for key in ('secret_id', 'secret_key')):
        raise Failure('腾讯云密钥格式无效，请直接复制控制台生成的密钥，不要添加引号。')
    if type(config.get('dsm_http_port')) is not int or not 1 <= config['dsm_http_port'] <= 65535:
        raise Failure('DSM HTTP 端口无效。')
    probes = config.get('probes')
    if not isinstance(probes, list) or not probes:
        raise Failure('至少配置一个实际 HTTPS 服务验证端点。')
    for probe in probes:
        if not isinstance(probe, dict) or not isinstance(probe.get('host'), str) or not probe['host']:
            raise Failure('HTTPS 验证地址无效。')
        if any(c.isspace() for c in probe['host']) or '/' in probe['host']:
            raise Failure('验证地址只能填写主机名或 IP。')
        if type(probe.get('port')) is not int or not 1 <= probe['port'] <= 65535:
            raise Failure('HTTPS 验证端口无效。')
        name = probe.get('server_name', '')
        if not valid_domain(name) or name.startswith('*.') or not covers(domains, name):
            raise Failure('验证端点的 SNI 必须是证书覆盖的具体域名，不能使用通配符。')


def port_prompt(label, default):
    value = input('{} [{}]: '.format(label, default)).strip() or str(default)
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise Failure('端口必须是 1 到 65535 的整数。')
    return int(value)


class Controller:
    def __init__(self, home, archive=ARCHIVE):
        self.home = home
        self.archive = archive
        self.acme = home / 'acme'
        self.state = home / 'state'
        self.config_file = home / 'config.json'
        self.marker = self.state / 'deployment-active.json'
        self.config = None

    @contextlib.contextmanager
    def locked(self):
        private(self.home, directory=True)
        self.state.mkdir(mode=0o700, exist_ok=True)
        private(self.state, directory=True)
        lock = self.state / 'run.lock'
        fd = os.open(str(lock), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as handle:
            private(lock)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy('已有任务运行，本次跳过。')
            yield

    def log(self, message):
        line = '{} {}'.format(now(), message)
        print(line, flush=True)
        path = self.state / 'events.log'
        if path.exists():
            private(path)
            if path.stat().st_size > 1024 * 1024:
                os.replace(str(path), str(path) + '.1')
        with path.open('a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def load(self):
        private(self.config_file)
        self.config = read_json(self.config_file)
        validate_config(self.config)

    def system_check(self):
        version_path = Path('/etc.defaults/VERSION')
        if not version_path.is_file():
            raise Failure('此工具必须在群晖 DSM 本机运行。')
        version = re.search(r'^productversion="([0-9.]+)"', version_path.read_text(), re.M)
        try:
            number = tuple(int(x) for x in version.group(1).split('.')) if version else ()
        except ValueError:
            raise Failure('无法识别 DSM 版本。')
        if not number or number[0] not in (6, 7) or number < (6, 2, 4):
            raise Failure('需要 DSM 6.2.4 或更新版本。')
        for command in ('curl', 'openssl', 'synouser', 'synogroup', 'synosetkeyvalue', 'synogetkeyvalue'):
            if not shutil.which(command):
                raise Failure('缺少系统命令：{}'.format(command))
        policy = capture(['synogetkeyvalue', '/etc/synoinfo.conf', 'otp_enforce_option']).decode().strip()
        if policy not in ('', 'none'):
            raise Failure('DSM 已开启强制双重验证；当前临时管理员方案已停止，不会修改该策略。')
        if self.temp_user_exists():
            raise Failure('已存在 {}，请先核实其来源并清理残留，工具不会删除已有账号。'.format(TEMP_USER))
        private(self.acme, directory=True)
        private(self.acme / 'acme.sh')
        output = capture(['/bin/sh', str(self.acme / 'acme.sh'), '--version']).decode()
        if not re.search(r'(?m)^v' + re.escape(ACME_VERSION) + r'\s*$', output):
            raise Failure('acme.sh 版本与安装包固定版本不符，请检查安装文件。')

    def temp_user_exists(self):
        try:
            result = subprocess.run(['synouser', '--get', TEMP_USER], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure('无法检查临时管理员状态。')
        return result.returncode == 0

    def metadata(self):
        info = read_json(self.archive / 'INFO')
        if not isinstance(info, dict):
            raise Failure('群晖证书元数据格式不受支持。')
        matches = [(key, value) for key, value in info.items() if isinstance(value, dict)
                   and value.get('desc') == self.config['certificate_description']]
        if len(matches) != 1 or matches[0][0] != self.config['certificate_id']:
            raise Failure('证书描述不唯一、已改变或证书 ID 已改变，请核对 DSM 后重新配置。')
        return info

    def current_cert(self):
        path = self.archive / self.config['certificate_id'] / 'cert.pem'
        if not path.is_file() or self.archive.resolve() not in path.resolve().parents:
            raise Failure('无法定位选定的群晖证书。')
        return path

    def binding_state(self, info):
        default = self.archive / 'DEFAULT'
        return {'services': {key: sorted(value.get('services', []), key=lambda x: json.dumps(x, sort_keys=True)) for key, value in info.items()
                             if isinstance(value, dict)},
                'default': default.read_text().strip() if default.exists() else None}

    def preflight(self, check_endpoints=True):
        self.system_check()
        if self.marker.exists():
            raise Failure('发现上次中断标记，请先检查临时账号及证书状态；确认恢复后移除 state/deployment-active.json。')
        info = self.metadata()
        if set(certificate_domains(self.current_cert())) != set(self.config['domains']):
            raise Failure('当前群晖证书域名已改变，停止自动替换；请重新 configure。')
        if check_endpoints:
            self.verify_probes(fingerprint(self.current_cert()), attempts=1)
        port = self.config['dsm_http_port']
        body = capture(['curl', '--noproxy', '*', '--fail', '--silent', '--show-error',
                        '--connect-timeout', '5', '--max-time', '15',
                        'http://127.0.0.1:{}/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth'.format(port)])
        try:
            response = json.loads(body)
            if response.get('success') is not True or 'SYNO.API.Auth' not in response.get('data', {}):
                raise ValueError()
        except (ValueError, AttributeError):
            raise Failure('无法通过本机 HTTP 端口访问 DSM API，请检查端口和 HTTP 自动跳转设置。')
        return info

    def configure(self):
        if not sys.stdin.isatty():
            raise Failure('configure 必须在交互终端运行，密钥只在 NAS 本机输入。')
        self.system_check()
        info = read_json(self.archive / 'INFO')
        if not isinstance(info, dict):
            raise Failure('群晖证书元数据格式不受支持。')
        choices = [(key, value) for key, value in sorted(info.items()) if isinstance(value, dict)
                   and re.fullmatch(r'[A-Za-z0-9_-]+', key)]
        if not choices:
            raise Failure('未找到可替换的现有证书，请先在 DSM 导入或创建证书。')
        for index, (key, value) in enumerate(choices, 1):
            cert = self.archive / key / 'cert.pem'
            try:
                if not cert.is_file():
                    raise Failure('缺少证书文件')
                names = ', '.join(certificate_domains(cert))
            except (Failure, OSError) as error:
                names = '不可用：{}'.format(error)
            print('{}: {}  描述={!r}  域名={}'.format(index, key, value.get('desc', ''), names))
        selection = input('选择当前用于 ttxli.cn 的证书编号: ').strip()
        if not selection.isdigit() or not 1 <= int(selection) <= len(choices):
            raise Failure('证书编号无效。')
        key, entry = choices[int(selection) - 1]
        domains = certificate_domains(self.archive / key / 'cert.pem')
        if 'ttxli.cn' in domains:
            domains.remove('ttxli.cn')
            domains.insert(0, 'ttxli.cn')
        name = next((x for x in domains if not x.startswith('*.')), 'nas.' + domains[0][2:])
        description = entry.get('desc', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', description):
            raise Failure('请先在 DSM 将此证书的描述改为唯一英文标识（如 ttxli-cn-auto），再运行 configure。')
        if sum(value.get('desc') == description for _, value in choices) != 1:
            raise Failure('证书描述重复，请先在 DSM 修改为唯一描述。')
        email = input('证书注册邮箱: ').strip()
        http_port = port_prompt('DSM HTTP 端口', 5000)
        probes = []
        while True:
            host = input('HTTPS 验证主机/IP [127.0.0.1]: ').strip() or '127.0.0.1'
            port = port_prompt('HTTPS 服务端口（DSM 通常为 5001，反向代理通常为 443）', 5001)
            sni = input('该服务访问域名/SNI [{}]: '.format(name)).strip() or name
            probes.append({'host': host, 'port': port, 'server_name': sni})
            if input('还要验证其他 HTTPS 服务吗？[y/N]: ').strip().lower() != 'y':
                break
        secret_id = getpass.getpass('腾讯云子账号 SecretId（不回显）: ').strip()
        secret_key = getpass.getpass('腾讯云子账号 SecretKey（不回显）: ').strip()
        self.config = {'version': 1, 'certificate_id': key, 'certificate_description': description,
                       'domains': domains, 'email': email, 'secret_id': secret_id,
                       'secret_key': secret_key, 'dsm_http_port': http_port, 'probes': probes}
        validate_config(self.config)
        self.preflight()
        if self.config_file.exists():
            private(self.config_file)
            save_json(self.state / 'previous-config.json', read_json(self.config_file))
        save_json(self.config_file, self.config)
        (self.state / 'run-baseline.json').unlink(missing_ok=True)
        (self.state / 'pending.json').unlink(missing_ok=True)
        self.log('配置已保存；当前服务与所选证书一致。尚未申请新证书。')

    def candidate_dir(self):
        return self.acme / self.config['domains'][0]

    def candidate(self):
        return self.candidate_dir() / (self.config['domains'][0] + '.cer')

    def candidate_valid(self):
        cert = self.candidate()
        key = self.candidate_dir() / (self.config['domains'][0] + '.key')
        if set(certificate_domains(cert)) != set(self.config['domains']):
            raise Failure('新证书域名与已配置域名不一致，拒绝部署。')
        capture(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '1209600'])
        public_cert = capture(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
        public_key = capture(['openssl', 'pkey', '-in', str(key), '-pubout'])
        if public_cert.strip() != public_key.strip():
            raise Failure('新证书与私钥不匹配，拒绝部署。')
        chain = self.candidate_dir() / 'fullchain.cer'
        ca = self.candidate_dir() / 'ca.cer'
        if pem_chain(chain) != pem_chain(cert) + pem_chain(ca):
            raise Failure('新证书链不完整，拒绝部署。')
        capture(['openssl', 'verify', '-partial_chain', '-trusted', str(ca), str(cert)])

    def backup(self, info):
        signature = fingerprint(self.current_cert()) + hashlib.sha256(
            json.dumps(self.binding_state(info), sort_keys=True).encode()).hexdigest()[:12]
        root = self.state / 'backups'
        root.mkdir(mode=0o700, exist_ok=True)
        private(root, directory=True)
        target = root / signature
        if target.exists():
            private(target, directory=True)
            if (target / 'complete.json').exists():
                return
            shutil.rmtree(target)
        target.mkdir(mode=0o700)
        source = self.current_cert().parent
        for filename in ('cert.pem', 'privkey.pem', 'chain.pem', 'fullchain.pem'):
            path = source / filename
            if path.is_file():
                destination = target / filename
                shutil.copyfile(path, destination)
                destination.chmod(0o600)
        save_json(target / 'INFO.json', info)
        save_json(target / 'bindings.json', self.binding_state(info))
        save_json(target / 'complete.json', {'at': now(), 'certificate_id': self.config['certificate_id']})
        backups = sorted((p for p in root.iterdir() if p.is_dir() and not p.is_symlink()),
                         key=lambda p: p.stat().st_mtime, reverse=True)
        for path in backups[5:]:
            shutil.rmtree(path)

    def prepare_acme_config(self):
        path = self.candidate_dir() / (self.config['domains'][0] + '.conf')
        if not path.exists():
            return
        private(path)
        values = {}
        lines = path.read_text().splitlines()
        for line in lines:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            assignment = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)='([^']*)'", line)
            if assignment is None:
                raise Failure('ACME 域名配置包含不支持的赋值或命令内容。')
            key, value = assignment.groups()
            if key in values:
                raise Failure('ACME 域名配置包含重复字段。')
            values[key] = value
        actual = {values.get('Le_Domain', '')}
        alternate = values.get('Le_Alt', 'no')
        if alternate not in ('', 'no'):
            actual.update(alternate.split(','))
        if actual != set(self.config['domains']):
            raise Failure('历史 ACME 域名范围与当前配置不一致，请核对后迁移配置。')
        forbidden = ('Le_PreHook', 'Le_PostHook', 'Le_RenewHook', 'Le_ReloadCmd',
                     'Le_RealCertPath', 'Le_RealKeyPath', 'Le_RealCACertPath', 'Le_RealFullChainPath',
                     'SYNO_CREATE', 'SAVED_SYNO_CREATE')
        if any(values.get(key) for key in forbidden):
            raise Failure('历史 ACME 配置包含额外命令、安装路径或自动创建证书开关，停止运行。')
        if values.get('Le_DeployHook', '') not in ('', 'synology_dsm'):
            raise Failure('历史 ACME 配置包含其他部署钩子，停止运行。')
        if values.get('Le_Webroot') != 'dns_tencent' or values.get('Le_API') != CA:
            raise Failure('历史 ACME 配置的 DNS 验证方式或签发机构不匹配。')
        # 阻止 renew 内置部署，让新证书先校验，再由包装器显式导入 DSM。
        if 'Le_DeployHook' in values:
            fd, temporary = tempfile.mkstemp(prefix='.domain-conf-', dir=str(path.parent))
            try:
                with os.fdopen(fd, 'w') as handle:
                    handle.write('\n'.join(line for line in lines if not line.startswith('Le_DeployHook=')) + '\n')
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def recover_candidate(self):
        # 隔离整个损坏工作目录，避免未来续期时间、坏私钥或旧 CSR 阻止重新签发。
        self.prepare_acme_config()
        path = self.state / 'recovery.json'
        attempts, last_attempt = 0, 0
        if path.exists():
            private(path)
            previous = read_json(path)
            if (not isinstance(previous, dict) or previous.get('domains') != self.config['domains']
                    or type(previous.get('attempts')) is not int
                    or not 1 <= previous['attempts'] <= RECOVERY_LIMIT
                    or type(previous.get('last_attempt')) is not int):
                raise Failure('证书恢复状态无效或域名已改变，请核查 state/recovery.json。')
            attempts, last_attempt = previous['attempts'], previous['last_attempt']
        timestamp = int(time.time())
        if attempts >= RECOVERY_LIMIT:
            raise Failure('证书自动恢复已连续尝试 3 次，请检查日志并修复原因后再清除 state/recovery.json。')
        if attempts and timestamp - last_attempt < RECOVERY_INTERVAL:
            raise Failure('证书恢复距离上次尝试不足 24 小时，本次不重复申请，保留现有服务证书。')
        source = self.candidate_dir()
        if source.exists():
            private(source, directory=True)
        backups = self.state / 'recovery-backups'
        backups.mkdir(mode=0o700, exist_ok=True)
        private(backups, directory=True)
        save_json(path, {'domains': self.config['domains'], 'attempts': attempts + 1,
                         'last_attempt': timestamp})
        if source.exists():
            snapshot = Path(tempfile.mkdtemp(prefix='attempt-', dir=str(backups)))
            os.replace(source, snapshot / source.name)
        snapshots = sorted((item for item in backups.iterdir() if item.is_dir() and not item.is_symlink()),
                           key=lambda item: item.stat().st_mtime, reverse=True)
        for item in snapshots[RECOVERY_LIMIT:]:
            shutil.rmtree(item)
        self.log('已隔离无效 ACME 工作目录，准备第 {} 次恢复申请。'.format(attempts + 1))

    def invoke_acme(self, arguments):
        # 不继承代理、调试、部署相关环境，避免凭据经代理外发或误用历史配置。
        env = {'PATH': SYSTEM_PATH, 'HOME': str(self.home), 'LANG': 'C', 'LC_ALL': 'C',
               'NO_PROXY': '127.0.0.1,localhost', 'no_proxy': '127.0.0.1,localhost',
               'Tencent_SecretId': self.config['secret_id'], 'Tencent_SecretKey': self.config['secret_key'],
               'SYNO_USE_TEMP_ADMIN': '1', 'SYNO_HOSTNAME': '127.0.0.1', 'SYNO_SCHEME': 'http',
               'SYNO_PORT': str(self.config['dsm_http_port']),
               'SYNO_CERTIFICATE': self.config['certificate_description'], 'SYNO_CREATE': ''}
        self.system_check()
        self.prepare_acme_config()
        output = self.state / 'acme-last.log'
        if output.exists():
            private(output)
        save_json(self.marker, {'at': now(), 'pid': os.getpid(), 'temporary_user': TEMP_USER})
        proc = None
        try:
            with output.open('wb') as log:
                proc = subprocess.Popen(['/bin/sh', str(self.acme / 'acme.sh'), '--home', str(self.acme),
                                         '--config-home', str(self.acme), '--server', CA] + arguments,
                                        env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                        start_new_session=True)
                try:
                    result = proc.wait(timeout=1200)
                except (subprocess.TimeoutExpired, KeyboardInterrupt, InterruptedError):
                    self.stop_process(proc)
                    raise Failure('ACME 操作超时或被中断，请检查本机日志；下次任务会重试。')
            return result
        finally:
            if proc is not None and proc.poll() is None:
                self.stop_process(proc)
            if self.temp_user_exists():
                capture(['synouser', '--del', TEMP_USER])
                if self.temp_user_exists():
                    raise Failure('临时管理员清理失败，请立即在 DSM 核查。')
            self.marker.unlink(missing_ok=True)

    @staticmethod
    def stop_process(proc):
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()

    def probe_fingerprint(self, probe):
        # 对已知目标使用预期证书指纹校验，兼容首次替换过期证书。
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((probe['host'], probe['port']), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=probe['server_name']) as secure:
                    der = secure.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            raise Failure('无法连接 HTTPS 验证端点 {}:{}。'.format(probe['host'], probe['port']))
        return hashlib.sha256(der).hexdigest()

    def verify_probes(self, expected, attempts=1):
        for attempt in range(attempts):
            errors = []
            for probe in self.config['probes']:
                try:
                    if self.probe_fingerprint(probe) != expected:
                        errors.append('{}:{} ({}) 仍呈现其他证书'.format(probe['host'], probe['port'], probe['server_name']))
                except Failure as error:
                    errors.append(str(error))
            if not errors:
                return
            if attempt + 1 < attempts:
                time.sleep(5)
        raise Failure('；'.join(errors) + '。请检查服务证书绑定、端口和域名。')

    def deploy_and_verify(self, before):
        self.candidate_valid()
        expected = fingerprint(self.candidate())
        save_json(self.state / 'pending.json', {'fingerprint': expected, 'at': now()})
        result = self.invoke_acme(['--deploy', '-d', self.config['domains'][0], '--deploy-hook', 'synology_dsm'])
        if result:
            raise Failure('证书已取得，但 DSM 部署失败；保留待部署标记，下次重试。详见 state/acme-last.log。')
        after = self.metadata()
        if self.binding_state(after) != before:
            raise Failure('证书部署后服务绑定发生变化，请根据备份在 DSM 中核对恢复。')
        if fingerprint(self.current_cert()) != expected:
            raise Failure('部署接口返回成功，但 DSM 中证书指纹未更新；下次任务将重试。')
        self.verify_probes(expected, attempts=6)
        (self.state / 'pending.json').unlink(missing_ok=True)
        self.log('新证书已部署；所有配置的 HTTPS 端点指纹一致。')

    def run(self):
        self.load()
        info = self.preflight(check_endpoints=False)
        before = self.binding_state(info)
        baseline = self.state / 'run-baseline.json'
        if baseline.exists():
            previous = read_json(baseline)
            if previous.get('certificate_id') != self.config['certificate_id'] or previous.get('bindings') != before:
                raise Failure('前次操作后服务绑定发生变化，请先按备份核查恢复，或确认当前绑定后重新 configure。')
        self.backup(info)
        save_json(baseline, {'certificate_id': self.config['certificate_id'], 'bindings': before})
        pending = self.state / 'pending.json'
        primary = self.config['domains'][0]
        conf = self.candidate_dir() / (primary + '.conf')
        if self.candidate().exists() and not conf.is_file():
            raise Failure('已有 ACME 证书但配置缺失，停止以避免错误跳过续期。')
        if pending.exists():
            self.log('发现待完成部署，先检查已签发证书。')
        if pending.exists() or self.candidate().exists():
            try:
                self.candidate_valid()
            except Failure:
                save_json(pending, {'at': now(), 'needs_recovery': True})
                self.recover_candidate()
            else:
                (self.state / 'recovery.json').unlink(missing_ok=True)
                if pending.exists():
                    self.deploy_and_verify(before)
        else:
            self.verify_probes(fingerprint(self.current_cert()))
        if self.candidate().exists():
            args = ['--renew', '-d', primary]
        else:
            args = ['--issue', '--dns', 'dns_tencent', '--keylength', '2048', '--accountemail', self.config['email']]
            for domain in self.config['domains']:
                args.extend(['-d', domain])
        result = self.invoke_acme(args)
        if self.candidate().exists() and fingerprint(self.candidate()) != fingerprint(self.current_cert()):
            save_json(pending, {'fingerprint': fingerprint(self.candidate()), 'at': now()})
        if result not in (0, 2):
            raise Failure('签发或续期失败；部署前备份已保留。详见 state/acme-last.log。')
        if not self.candidate().is_file():
            save_json(pending, {'at': now(), 'needs_recovery': True})
            raise Failure('ACME 未生成预期证书，不能将跳过状态当作签发成功。')
        self.candidate_valid()
        (self.state / 'recovery.json').unlink(missing_ok=True)
        if self.binding_state(self.metadata()) != before:
            raise Failure('续期后服务绑定发生变化，请核对备份，停止后续自动操作。')
        expected = fingerprint(self.candidate())
        if expected != fingerprint(self.current_cert()) or pending.exists():
            self.deploy_and_verify(before)
        else:
            try:
                self.verify_probes(expected, attempts=3)
            except Failure:
                save_json(pending, {'fingerprint': expected, 'at': now()})
                raise
        save_json(self.state / 'last-result.json', {'at': now(), 'success': True, 'fingerprint': expected})
        baseline.unlink(missing_ok=True)
        self.log('本次检查完成，证书及 HTTPS 服务均正常。')

    def status(self):
        self.load()
        self.metadata()
        print('域名：' + ', '.join(self.config['domains']))
        print('证书描述：' + self.config['certificate_description'])
        print(capture(['openssl', 'x509', '-in', str(self.current_cert()), '-noout', '-dates']).decode().strip())
        print('待部署：' + ('是' if (self.state / 'pending.json').exists() else '否'))
        result = self.state / 'last-result.json'
        if result.exists():
            print('上次结果：' + json.dumps(read_json(result), ensure_ascii=False))


def interrupted(_signal, _frame):
    raise InterruptedError('操作被中断。')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=DEFAULT_HOME)
    parser.add_argument('command', choices=('configure', 'check', 'run', 'status'))
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print('请在 NAS 上使用 sudo 以 root 运行。', file=sys.stderr)
        return 1
    os.umask(0o077)
    os.environ['PATH'] = SYSTEM_PATH
    signal.signal(signal.SIGTERM, interrupted)
    controller = Controller(args.home)
    try:
        with controller.locked():
            if args.command == 'configure':
                controller.configure()
            elif args.command == 'run':
                controller.run()
            elif args.command == 'check':
                controller.load()
                controller.preflight()
                controller.log('预检查通过：系统、唯一证书、域名、服务绑定与接口正常。')
            else:
                controller.status()
        return 0
    except Busy as error:
        print(str(error))
        return 0
    except (Failure, OSError, KeyboardInterrupt, InterruptedError) as error:
        message = str(error) if isinstance(error, Failure) else '系统操作失败或被中断，请检查文件权限、网络及本机日志。'
        print('失败：' + message, file=sys.stderr)
        if args.command == 'run' and controller.state.is_dir():
            try:
                private(controller.state, directory=True)
                save_json(controller.state / 'last-result.json', {'at': now(), 'success': False, 'message': message})
            except (OSError, Failure):
                pass
        return 1


if __name__ == '__main__':
    sys.exit(main())
