#!/usr/bin/env python3
"""群晖证书续期：只更新已选证书，实际 TLS 指纹决定部署是否成功。"""
import argparse
import contextlib
import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import fcntl
import getpass
import hashlib
import importlib.util
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
import uuid

DEFAULT_HOME = Path('/usr/local/share/synology-cert-renewal')
ARCHIVE = Path('/usr/syno/etc/certificate/_archive')
ACME_VERSION = '3.1.6'
CA = 'https://acme-v02.api.letsencrypt.org/directory'
TEMP_USER = 'sc-acmesh-tmp'
SYSTEM_PATH = '/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
RECOVERY_INTERVAL = 24 * 60 * 60
SHORT_RECOVERY_INTERVAL = 6 * 60 * 60
RECOVERY_LIMIT = 3
MANUAL_RENEWAL_TTL = 10 * 60
MANUAL_RENEWAL_COOLDOWN = 60 * 60
MANUAL_RENEWAL_STATES = ('queued', 'running', 'succeeded', 'failed', 'expired')
RENEWAL_PROTECTION_FILES = ('deployment-active.json', 'pending.json', 'run-baseline.json',
                            'import-bindings.json', 'recovery.json', 'web-transaction.json')

# -I 模式不搜索脚本目录，按固定文件位置加载随安装包交付的诊断模块。
_diagnostic_spec = importlib.util.spec_from_file_location(
    'certificate_failure_diagnostics', Path(__file__).with_name('failure_diagnostics.py'))
diagnostics = importlib.util.module_from_spec(_diagnostic_spec)
_diagnostic_spec.loader.exec_module(diagnostics)


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


def certificate_expiry(path):
    value = capture(['openssl', 'x509', '-in', str(path), '-noout', '-enddate']).decode().strip()
    try:
        if not value.startswith('notAfter='):
            raise ValueError()
        return int(ssl.cert_time_to_seconds(value[len('notAfter='):]))
    except (ValueError, OverflowError):
        raise Failure('无法读取证书到期时间。')


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


def validate_description(description, method):
    if method == 'local_api':
        if (not isinstance(description, str) or not description.strip() or len(description) > 256
                or re.search(r'[\x00-\x1f\x7f-\x9f]', description)):
            raise Failure('证书描述须为 1 到 256 个字符，且不能包含控制字符。')
    elif not isinstance(description, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', description):
        raise Failure('请先在 DSM 中将证书描述改为唯一英文标识，例如 nas-cert-auto。')


def validate_config(config):
    if not isinstance(config, dict) or config.get('version') != 1:
        raise Failure('配置版本无效，请重新 configure。')
    method = config.get('deployment_method', 'synology_dsm')
    if method not in ('local_api', 'synology_dsm'):
        raise Failure('证书部署方式无效，请重新 configure。')
    if 'renew_before_days' in config and (type(config['renew_before_days']) is not int
                                         or not 1 <= config['renew_before_days'] <= 30):
        raise Failure('提前续期天数必须是 1 到 30 的整数。')
    for key in ('certificate_id', 'certificate_description', 'email', 'secret_id', 'secret_key'):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise Failure('配置缺少字段：{}'.format(key))
    if not re.fullmatch(r'[A-Za-z0-9_-]+', config['certificate_id']):
        raise Failure('证书 ID 格式无效。')
    validate_description(config['certificate_description'], method)
    domains = config.get('domains')
    if not isinstance(domains, list) or not domains or not all(valid_domain(x) for x in domains):
        raise Failure('域名配置无效；请使用小写 ASCII 域名或其通配符。')
    if len(set(domains)) != len(domains):
        raise Failure('域名配置不能重复。')
    if not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', config['email']):
        raise Failure('邮箱格式无效；请使用常规 ASCII 邮箱地址。')
    if 'success_notify_email' in config and (not isinstance(config['success_notify_email'], str)
            or config['success_notify_email'].startswith('-')
            or not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', config['success_notify_email'])):
        raise Failure('成功通知邮箱格式无效；禁用时请移除 success_notify_email。')
    if any(not re.fullmatch(r'[A-Za-z0-9+/=_-]+', config[key]) for key in ('secret_id', 'secret_key')):
        raise Failure('腾讯云密钥格式无效，请直接复制控制台生成的密钥，不要添加引号。')
    if method == 'synology_dsm' and (type(config.get('dsm_http_port')) is not int
                                    or not 1 <= config['dsm_http_port'] <= 65535):
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
        self.failure_stage = 'preflight'
        self.diagnostic_logs = {}
        self.acme_evidence = ''
        self.acme_events = []
        self.cleanup_events = []
        self.diagnostic_directory = None
        self.operation_number = 0

    def diagnostic_operation(self, kind):
        private(self.state, directory=True)
        if self.diagnostic_directory is None:
            self.diagnostic_directory = Path(tempfile.mkdtemp(prefix='.diagnostics-', dir=str(self.state)))
        private(self.diagnostic_directory, directory=True)
        self.operation_number += 1
        prefix = '{}-{}'.format(kind, self.operation_number)
        return self.diagnostic_directory / (prefix + '.jsonl'), prefix

    def capture_diagnostic_operation(self, output, event_file, prefix):
        # 捕获本次调用，后续 ACME/清理调用覆盖 last.log 时不会丢失本轮证据。
        events, text = [], ''
        try:
            if output is not None and output.exists():
                private(output)
                if output.stat().st_size <= 1024 * 1024:
                    text = output.read_text(encoding='utf-8', errors='replace')
                else:
                    text = '[日志超过 1 MiB，未复制原始内容；请在 NAS 检查对应 last.log。]'
            if event_file.exists():
                private(event_file)
                if event_file.stat().st_size > 64 * 1024:
                    raise ValueError()
                for line in event_file.read_text().splitlines():
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError()
                    events.append(event)
        except (Failure, OSError, ValueError):
            events.append({'stage': 'dns_cleanup' if prefix.startswith('cleanup') else 'dns_query',
                           'action': 'Journal', 'code': 'DiagnosticWriteFailed', 'category': 'local_state'})
        self.diagnostic_logs[prefix + '.log'] = text
        self.diagnostic_logs[prefix + '-events.jsonl'] = '\n'.join(json.dumps(e, ensure_ascii=False) for e in events)
        return text, events

    def diagnostic_secrets(self):
        config = self.config if isinstance(self.config, dict) else {}
        values = [config.get(key, '') for key in ('secret_id', 'secret_key')]
        try:
            path = self.state / 'dns-cleanup.json'
            if path.exists():
                private(path)
                if path.stat().st_size <= 256 * 1024:
                    data = read_json(path)
                    if isinstance(data, dict) and isinstance(data.get('entries'), list):
                        values.extend(item.get('value', '') for item in data['entries'] if isinstance(item, dict))
        except (Failure, OSError):
            pass
        return tuple(value for value in values if isinstance(value, str) and value)

    def report_failure(self, error):
        secrets = self.diagnostic_secrets()
        message = str(error) if isinstance(error, Failure) else '系统操作失败或被中断，请检查权限、网络及本机日志。'
        message = diagnostics.sanitize(message, secrets=secrets, limit=600)
        stage = self.failure_stage
        events = self.acme_events if stage == 'acme' else self.cleanup_events if stage == 'dns_cleanup' else []
        evidence = self.acme_evidence if stage == 'acme' else ''
        try:
            report = diagnostics.classify(stage, message=message, acme_log=evidence, dns_events=events)
        except (ValueError, TypeError, KeyError):
            report = {'stage': 'unknown', 'stage_label': '未能确定失败阶段', 'category': 'unknown',
                      'code': '', 'summary': '本轮执行失败，现有证据不足以确定具体原因。',
                      'hint': '查看本次失败记录并检查运行目录权限及网络。', 'evidence': 'unknown'}
        report.update({'at': now(), 'message': message})
        try:
            private(self.state, directory=True)
            archive = diagnostics.archive_failure(self.state, report, self.diagnostic_logs, secrets=secrets)
        except (Failure, OSError, ValueError):
            archive = {'archive_path': None, 'archive_error': '无法保存失败日志，请检查运行目录权限和可用空间。'}
        report.update(archive)
        try:
            private(self.state, directory=True)
            save_json(self.state / 'last-result.json', {'at': report['at'], 'success': False,
                                                       'message': message, 'failure': report})
        except (Failure, OSError):
            report['archive_error'] = '无法更新运行结果，请检查运行目录权限和可用空间。'
        lines = ['失败阶段：' + report['stage_label'], '错误摘要：' + report['summary']]
        if report.get('code'):
            lines.append('错误码：' + report['code'])
        lines.extend(['详细说明：' + message, '处理建议：' + report['hint']])
        if report.get('archive_path'):
            lines.append('失败记录：' + str(report['archive_path']))
        if report.get('archive_error'):
            lines.append('日志留存：' + report['archive_error'])
        public_paths = [report['archive_path']] if report.get('archive_path') else []
        print(diagnostics.sanitize('\n'.join(lines), secrets=secrets, public_paths=public_paths),
              file=sys.stderr, flush=True)
        return 1

    def cleanup_diagnostics(self):
        if self.diagnostic_directory is not None:
            try:
                private(self.diagnostic_directory, directory=True)
                shutil.rmtree(self.diagnostic_directory)
            except (Failure, OSError):
                pass
            self.diagnostic_directory = None

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

    def deployment_method(self):
        return (self.config or {}).get('deployment_method', 'synology_dsm')

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
        method = self.deployment_method()
        dependencies = ('curl', 'openssl')
        if method == 'local_api':
            dependencies += ('synowebapi',)
        else:
            dependencies += ('synouser', 'synogroup', 'synosetkeyvalue', 'synogetkeyvalue')
        for command in dependencies:
            if not shutil.which(command):
                raise Failure('缺少系统命令：{}'.format(command))
        if method == 'synology_dsm':
            policy = capture(['synogetkeyvalue', '/etc/synoinfo.conf', 'otp_enforce_option']).decode().strip()
            if policy not in ('', 'none'):
                raise Failure('DSM 已开启强制双重验证；当前临时管理员方案已停止，不会修改该策略。')
            if self.temp_user_exists():
                raise Failure('已存在 {}，请先核实其来源并清理残留，工具不会删除已有账号。'.format(TEMP_USER))
        private(self.acme, directory=True)
        private(self.acme / 'acme.sh')
        for path in (self.home / 'dns_cleanup.py', self.home / 'dns_cleanup_retry.sh',
                     self.acme / 'dnsapi' / 'dns_tencent.sh',
                     self.acme / 'dnsapi' / 'dns_tencent_upstream.sh'):
            private(path)
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

    def target_bindings(self, bindings):
        identifier = self.config['certificate_id']
        if not isinstance(bindings, dict) or identifier not in bindings.get('services', {}):
            raise Failure('运行基线缺少目标证书绑定，请核查备份。')
        return {'services': bindings['services'][identifier],
                'is_default': bindings.get('default') == identifier}

    def call_local_api(self, api, method, params=None, timeout=30):
        command = shutil.which('synowebapi')
        if not command:
            raise Failure('缺少系统命令：synowebapi')
        arguments = [command, '--exec', 'api=' + api, 'method=' + method, 'version=1']
        arguments.extend(key + '=' + json.dumps(value, ensure_ascii=False)
                         for key, value in (params or {}).items())
        body = capture(arguments, timeout=timeout)
        try:
            response = json.loads(body)
            if (not isinstance(response, dict) or response.get('success') is not True
                    or response.get('error') is not None):
                raise ValueError()
            data = response.get('data', {})
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            raise Failure('DSM 本机证书 API 未返回有效成功结果，保留待部署证书。')
        return data

    def local_api_list(self):
        data = self.call_local_api('SYNO.Core.Certificate.CRT', 'list')
        certificates = data.get('certificates')
        if not isinstance(certificates, list) or not all(isinstance(item, dict) for item in certificates):
            raise Failure('DSM 本机证书列表格式不受支持。')
        return certificates

    def local_api_target(self, before):
        certificates = self.local_api_list()
        matches = [item for item in certificates if item.get('desc') == self.config['certificate_description']]
        identifier = self.config['certificate_id']
        if (len(matches) != 1 or matches[0].get('id') != identifier
                or sum(item.get('id') == identifier for item in certificates) != 1):
            raise Failure('DSM 本机 API 中目标证书 ID 或唯一描述不匹配，拒绝导入。')
        target = matches[0]
        if (type(target.get('is_default')) is not bool
                or target['is_default'] != (before['default'] == identifier)):
            raise Failure('DSM 本机 API 与证书默认绑定状态不一致，拒绝导入。')
        return target

    def preflight(self, check_endpoints=True):
        self.system_check()
        if self.marker.exists():
            raise Failure('发现上次中断标记，请先检查部署及证书状态；确认恢复后移除 state/deployment-active.json。')
        info = self.metadata()
        if set(certificate_domains(self.current_cert())) != set(self.config['domains']):
            raise Failure('当前群晖证书域名已改变，停止自动替换；请重新 configure。')
        if check_endpoints:
            # 首次配置只核对旧证书归属，允许随后替换过期或自签名证书。
            self.verify_probes(fingerprint(self.current_cert()), attempts=1, verify_chain=False)
        if self.deployment_method() == 'local_api':
            self.local_api_target(self.binding_state(info))
            return info
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
        method = 'local_api' if shutil.which('synowebapi') else 'synology_dsm'
        self.config = {'deployment_method': method}
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
        selection = input('选择需要自动续期的证书编号: ').strip()
        if not selection.isdigit() or not 1 <= int(selection) <= len(choices):
            raise Failure('证书编号无效。')
        key, entry = choices[int(selection) - 1]
        domains = sorted(certificate_domains(self.archive / key / 'cert.pem'), key=lambda value: value.startswith('*.'))
        name = next((x for x in domains if not x.startswith('*.')), 'nas.' + domains[0][2:])
        description = entry.get('desc', '')
        validate_description(description, method)
        if sum(value.get('desc') == description for _, value in choices) != 1:
            raise Failure('证书描述重复，请先在 DSM 修改为唯一描述。')
        email = input('证书注册邮箱: ').strip()
        renew_days = input('提前续期天数 [2]: ').strip() or '2'
        if not renew_days.isdigit() or not 1 <= int(renew_days) <= 30:
            raise Failure('提前续期天数必须是 1 到 30 的整数。')
        http_port = port_prompt('DSM HTTP 端口', 5000) if method == 'synology_dsm' else 5000
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
        previous = None
        if self.config_file.exists():
            private(self.config_file)
            previous = read_json(self.config_file)
        self.config = {'version': 1, 'deployment_method': method,
                       'renew_before_days': int(renew_days),
                       'certificate_id': key, 'certificate_description': description,
                       'domains': domains, 'email': email, 'secret_id': secret_id,
                       'secret_key': secret_key, 'dsm_http_port': http_port, 'probes': probes}
        if isinstance(previous, dict) and 'success_notify_email' in previous:
            self.config['success_notify_email'] = previous['success_notify_email']
        validate_config(self.config)
        self.preflight()
        notification = self.state / 'success-notification.json'
        if os.path.lexists(notification):
            private(notification)
        same_target = (isinstance(previous, dict)
                       and previous.get('certificate_id') == self.config['certificate_id']
                       and previous.get('domains') == self.config['domains'])
        if same_target:
            self.initialize_success_notification()
        if previous is not None:
            save_json(self.state / 'previous-config.json', previous)
        save_json(self.config_file, self.config)
        if not same_target:
            notification.unlink(missing_ok=True)
            self.initialize_success_notification()
        (self.state / 'run-baseline.json').unlink(missing_ok=True)
        (self.state / 'import-bindings.json').unlink(missing_ok=True)
        (self.state / 'pending.json').unlink(missing_ok=True)
        self.log('配置已保存；当前服务与所选证书一致。尚未申请新证书。')

    def candidate_dir(self):
        return self.acme / self.config['domains'][0]

    def save_manual_renewal(self, request):
        save_json(self.state / 'manual-renewal.json', request)
        # 消耗意图必须连同目录项持久化，断电后也不能再次强制签发。
        descriptor = os.open(str(self.state), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def manual_renewal(self, reconcile=False):
        path = self.state / 'manual-renewal.json'
        if not os.path.lexists(path):
            return None
        private(path)
        request = read_json(path)
        if (not isinstance(request, dict) or request.get('version') != 1
                or not isinstance(request.get('request_id'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', request['request_id'])
                or request.get('state') not in MANUAL_RENEWAL_STATES
                or not isinstance(request.get('certificate_id'), str)
                or not isinstance(request.get('domains'), list) or not request['domains']
                or not all(valid_domain(domain) for domain in request['domains'])
                or not isinstance(request.get('baseline_fingerprint'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', request['baseline_fingerprint'])
                or not isinstance(request.get('baseline_bindings'), dict)
                or any(type(request.get(key)) is not int for key in
                       ('requested_at', 'expires_at', 'cooldown_until'))
                or request['expires_at'] != request['requested_at'] + MANUAL_RENEWAL_TTL
                or type(request.get('force_consumed')) is not bool
                or type(request.get('recovery_only')) is not bool
                or (request['recovery_only'] and (not request['force_consumed']
                    or type(request.get('resume_normal_at')) is not int))
                or (request['state'] == 'queued' and request['force_consumed'])
                or not isinstance(request.get('message'), str)):
            raise Failure('手动申请状态无效，请核查 state/manual-renewal.json。')
        # 仅在持有 run.lock 时协调状态；空闲锁证明 running 的原进程已退出。
        if reconcile and request['state'] == 'queued' and time.time() >= request['expires_at']:
            request.update(state='expired', completed_at=int(time.time()), message='申请请求已过期，未执行强制签发。')
            self.save_manual_renewal(request)
        elif reconcile and request['state'] == 'running':
            request.update(state='failed', completed_at=int(time.time()),
                           message='申请任务已中断；已消耗的签发请求不会再次执行，待办仅恢复部署与清理。')
            self.save_manual_renewal(request)
        return request

    def assert_manual_idle(self):
        request = self.manual_renewal(reconcile=True)
        if request and request['state'] in ('queued', 'running'):
            raise Busy('手动申请正在排队，请等待原任务完成。')
        return request

    def release_manual_protection(self):
        request = self.assert_manual_idle()
        if not request or not request['recovery_only']:
            return
        owned = [self.state / name for name in ('run-baseline.json', 'pending.json')]
        if request.get('protection_released') and not any(os.path.lexists(path) for path in owned):
            return
        if (request['certificate_id'] != self.config['certificate_id']
                or request['domains'] != self.config['domains']
                or fingerprint(self.current_cert()) != request['baseline_fingerprint']
                or self.binding_state(self.metadata()) != request['baseline_bindings']
                or (self.candidate().exists() and fingerprint(self.candidate()) != request['baseline_fingerprint'])
                or any(os.path.lexists(self.state / name) for name in RENEWAL_PROTECTION_FILES
                       if name not in ('run-baseline.json', 'pending.json'))
                or self.dns_cleanup_count()):
            raise Failure('手动申请仍有证书、绑定或清理待办，不能解除保护。')
        notice_path = self.state / 'success-notification.json'
        if os.path.lexists(notice_path):
            private(notice_path)
            notice = read_json(notice_path)
            if not isinstance(notice, dict) or notice.get('pending') is not None:
                raise Failure('手动申请仍有通知待办，不能解除保护。')
        for path in owned:
            if os.path.lexists(path):
                private(path)
                marker = read_json(path)
                if (not isinstance(marker, dict) or marker.get('manual_request_id') != request['request_id']
                        or (path.name == 'pending.json' and marker.get('needs_recovery') is not True)
                        or (path.name == 'run-baseline.json' and
                            (marker.get('certificate_id') != request['certificate_id']
                             or marker.get('bindings') != request['baseline_bindings']))):
                    raise Failure('现有保护不属于本次未取得证书的手动申请，不能解除。')
        # 仅释放可证明没有签发材料的本请求保护，防重放门控独立保留。
        for path in owned:
            path.unlink(missing_ok=True)
        request['protection_released'] = True
        self.save_manual_renewal(request)

    def retire_manual_target(self):
        request = self.manual_renewal()
        if (request and request['recovery_only'] and request.get('protection_released')
                and (request['certificate_id'] != self.config['certificate_id']
                     or request['domains'] != self.config['domains'])):
            request.update(recovery_only=False, message='原申请已结束，配置已切换至其他证书目标。')
            self.save_manual_renewal(request)

    def assert_manual_prerequisites(self):
        if any(os.path.lexists(self.state / name) for name in RENEWAL_PROTECTION_FILES):
            raise Failure('存在未完成的部署或恢复状态，不能立即申请新证书。')
        if self.dns_cleanup_count():
            raise Failure('仍有 DNS 验证记录待清理，不能立即申请新证书。')
        notice_path = self.state / 'success-notification.json'
        if os.path.lexists(notice_path):
            private(notice_path)
            notice = read_json(notice_path)
            if not isinstance(notice, dict) or notice.get('pending') is not None:
                raise Failure('存在待发送通知或通知状态异常，不能立即申请新证书。')
        if self.candidate().exists() and fingerprint(self.candidate()) != fingerprint(self.current_cert()):
            raise Failure('已有未部署的候选证书，不能立即申请新证书。')

    def request_manual_renewal(self):
        previous = self.assert_manual_idle()
        timestamp = int(time.time())
        if previous and timestamp < previous['cooldown_until']:
            raise Busy('上次立即申请仍在一小时冷却期内，请稍后再试。')
        self.release_manual_protection()
        self.assert_manual_prerequisites()
        request = {'version': 1, 'request_id': uuid.uuid4().hex, 'state': 'queued',
                   'certificate_id': self.config['certificate_id'], 'domains': list(self.config['domains']),
                   'baseline_fingerprint': fingerprint(self.current_cert()), 'requested_at': timestamp,
                   'baseline_bindings': self.binding_state(self.metadata()),
                   'expires_at': timestamp + MANUAL_RENEWAL_TTL,
                   'cooldown_until': timestamp + MANUAL_RENEWAL_COOLDOWN,
                   'force_consumed': False, 'recovery_only': False,
                   'message': '已提交一次性申请，等待原 DSM 任务开始执行。'}
        self.save_manual_renewal(request)
        return request

    def consume_manual_renewal(self, request):
        if request['force_consumed']:
            return
        if time.time() >= request['expires_at']:
            raise Failure('申请请求已过期，尚未调用签发服务。')
        request.update(force_consumed=True, recovery_only=True,
                       resume_normal_at=max(request['cooldown_until'],
                           certificate_expiry(self.current_cert()) - self.config['renew_before_days'] * 86400
                           if 'renew_before_days' in self.config else request['cooldown_until']),
                       message='正在申请新证书，本次签发意图已消耗。')
        self.save_manual_renewal(request)

    def candidate(self):
        return self.candidate_dir() / (self.config['domains'][0] + '.cer')

    def renewal_time(self):
        days = self.config.get('renew_before_days')
        return certificate_expiry(self.candidate()) - days * 86400 if days is not None else None

    def renewal_due(self):
        renewal = self.renewal_time()
        return renewal is not None and time.time() >= renewal

    def candidate_valid(self):
        cert = self.candidate()
        key = self.candidate_dir() / (self.config['domains'][0] + '.key')
        if set(certificate_domains(cert)) != set(self.config['domains']):
            raise Failure('新证书域名与已配置域名不一致，拒绝部署。')
        # 已部署证书正常变老时走续期；新导入的证书仍须至少剩余 14 天。
        minimum = 0 if ('renew_before_days' in self.config
                        and fingerprint(cert) == fingerprint(self.current_cert())) else 1209600
        capture(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', str(minimum)])
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

    def prepare_acme_config(self, sync_schedule=True):
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
        # 迁移已有续期时间；仅传 --days 不会重算旧证书的 NextRenewTime。
        updates = {}
        if sync_schedule and 'renew_before_days' in self.config and self.candidate().is_file():
            renewal = self.renewal_time()
            updates = {'Le_RenewalDays': str(-self.config['renew_before_days']),
                       'Le_NextRenewTime': str(renewal),
                       'Le_NextRenewTimeStr': datetime.datetime.fromtimestamp(
                           renewal, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                       'NO_ARI': '1'}
        # 阻止 renew 内置部署，让新证书先校验，再由包装器显式导入 DSM。
        if 'Le_DeployHook' in values or any(values.get(key) != value for key, value in updates.items()):
            fd, temporary = tempfile.mkstemp(prefix='.domain-conf-', dir=str(path.parent))
            try:
                with os.fdopen(fd, 'w') as handle:
                    removed = ('Le_DeployHook=',) + tuple(key + '=' for key in updates)
                    retained = [line for line in lines if not line.startswith(removed)]
                    retained.extend("{}='{}'".format(key, value) for key, value in updates.items())
                    handle.write('\n'.join(retained) + '\n')
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def recover_candidate(self):
        # 隔离整个损坏工作目录，避免未来续期时间、坏私钥或旧 CSR 阻止重新签发。
        self.prepare_acme_config(sync_schedule=False)
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
        interval = SHORT_RECOVERY_INTERVAL if self.config.get('renew_before_days', 30) <= 2 else RECOVERY_INTERVAL
        if attempts and timestamp - last_attempt < interval:
            raise Failure('证书恢复距离上次尝试不足 {} 小时，本次不重复申请，保留现有服务证书。'.format(interval // 3600))
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

    def operation_environment(self):
        # 不继承代理、调试、部署相关环境，避免凭据经代理外发。
        return {'PATH': SYSTEM_PATH, 'HOME': str(self.home), 'LANG': 'C', 'LC_ALL': 'C',
                'NO_PROXY': '127.0.0.1,localhost', 'no_proxy': '127.0.0.1,localhost',
                'CERTCTL_HOME': str(self.home), 'CERTCTL_PYTHON': sys.executable,
                'Tencent_SecretId': self.config['secret_id'], 'Tencent_SecretKey': self.config['secret_key']}

    def dns_cleanup_count(self):
        journal = self.state / 'dns-cleanup.json'
        if not os.path.lexists(journal):
            return 0
        private(journal)
        helper = self.home / 'dns_cleanup.py'
        private(helper)
        count = capture([sys.executable, '-I', str(helper), str(self.home), 'count']).decode().strip()
        if not count.isdigit():
            raise Failure('DNS 清理状态无效，请检查 state/dns-cleanup.json。')
        return int(count)

    def retry_dns_cleanup(self):
        self.failure_stage = 'dns_cleanup'
        if not self.dns_cleanup_count():
            return True
        helper = self.home / 'dns_cleanup_retry.sh'
        private(helper)
        output = self.state / 'dns-cleanup-last.log'
        if output.exists():
            private(output)
        event_file, prefix = self.diagnostic_operation('cleanup')
        env = self.operation_environment()
        env['CERTCTL_DIAGNOSTIC_FILE'] = str(event_file)
        proc = None
        output_ready = False
        try:
            with output.open('wb') as log:
                output_ready = True
                proc = subprocess.Popen(['/bin/sh', str(helper)], env=env,
                                        stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
                try:
                    result = proc.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    self.stop_process(proc)
                    result = 1
            if result:
                self.log('DNS 验证记录尚未清理完成，本轮继续检查证书，结束时报告失败。')
            return result == 0
        finally:
            if proc is not None and proc.poll() is None:
                self.stop_process(proc)
            _, events = self.capture_diagnostic_operation(output if output_ready else None, event_file, prefix)
            self.cleanup_events.extend(events)

    def invoke_acme(self, arguments):
        native = self.deployment_method() == 'local_api'
        if native and (not arguments or arguments[0] not in ('--issue', '--renew')):
            raise Failure('本机 API 模式仅允许 acme.sh 签发或续期，部署由本机 API 完成。')
        env = self.operation_environment()
        arguments = list(arguments)
        if 'renew_before_days' in self.config and arguments and arguments[0] in ('--issue', '--renew'):
            env['NO_ARI'] = '1'
            arguments.extend(['--days', str(-self.config['renew_before_days'])])
        if not native:
            env.update({'SYNO_USE_TEMP_ADMIN': '1', 'SYNO_HOSTNAME': '127.0.0.1', 'SYNO_SCHEME': 'http',
                        'SYNO_PORT': str(self.config['dsm_http_port']),
                        'SYNO_CERTIFICATE': self.config['certificate_description'], 'SYNO_CREATE': ''})
        self.failure_stage = 'preflight'
        self.system_check()
        self.prepare_acme_config()
        operation_stage = 'dsm_deploy' if arguments[0] == '--deploy' else 'acme'
        event_file, prefix = self.diagnostic_operation('deploy' if arguments[0] == '--deploy' else 'acme')
        env['CERTCTL_DIAGNOSTIC_FILE'] = str(event_file)
        output = self.state / 'acme-last.log'
        if output.exists():
            private(output)
        marker = {'at': now(), 'pid': os.getpid(), 'deployment_method': self.deployment_method(),
                  'operation': 'acme'}
        if not native:
            marker['temporary_user'] = TEMP_USER
        save_json(self.marker, marker)
        proc = None
        output_ready = False
        try:
            with output.open('wb') as log:
                output_ready = True
                proc = subprocess.Popen(['/bin/sh', str(self.acme / 'acme.sh'), '--home', str(self.acme),
                                         '--config-home', str(self.acme), '--server', CA] + arguments,
                                        env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                        start_new_session=True)
                self.failure_stage = operation_stage
                try:
                    result = proc.wait(timeout=1200)
                except (subprocess.TimeoutExpired, KeyboardInterrupt, InterruptedError):
                    self.stop_process(proc)
                    raise Failure('ACME 操作超时或被中断，请检查本机日志；下次任务会重试。')
            return result
        finally:
            if proc is not None and proc.poll() is None:
                self.stop_process(proc)
            evidence, events = self.capture_diagnostic_operation(output if output_ready else None, event_file, prefix)
            if arguments[0] != '--deploy':
                self.acme_evidence, self.acme_events = evidence, events
                self.cleanup_events.extend(event for event in events if event.get('stage') == 'dns_cleanup')
            if not native and self.temp_user_exists():
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

    def probe_fingerprint(self, probe, verify_chain=True):
        try:
            if verify_chain:
                # 使用系统根证书验证服务实际提供的链，不加载候选证书的中间链。
                context = ssl.create_default_context()
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((probe['host'], probe['port']), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=probe['server_name']) as secure:
                    der = secure.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError:
            raise Failure('HTTPS 验证端点 {}:{} ({}) 的证书链、域名或有效期校验失败。'.format(
                probe['host'], probe['port'], probe['server_name']))
        except (OSError, ssl.SSLError):
            raise Failure('无法连接 HTTPS 验证端点 {}:{}。'.format(probe['host'], probe['port']))
        return hashlib.sha256(der).hexdigest()

    def verify_probes(self, expected, attempts=1, verify_chain=True):
        for attempt in range(attempts):
            errors = []
            for probe in self.config['probes']:
                try:
                    if self.probe_fingerprint(probe, verify_chain=verify_chain) != expected:
                        errors.append('{}:{} ({}) 仍呈现其他证书'.format(probe['host'], probe['port'], probe['server_name']))
                except Failure as error:
                    errors.append(str(error))
            if not errors:
                return
            if attempt + 1 < attempts:
                time.sleep(5)
        raise Failure('；'.join(errors) + '。请检查服务证书绑定、端口和域名。')

    def deploy_local_api(self, before):
        self.system_check()
        if self.marker.exists():
            raise Failure('存在未核实的部署中断标记，停止导入证书。')
        if self.binding_state(self.metadata()) != before:
            raise Failure('导入前证书绑定已改变，停止导入证书。')
        target = self.local_api_target(before)
        # 使用副本供 DSM 导入，避免内置 API 移走上传文件后破坏 ACME 续期材料。
        with tempfile.TemporaryDirectory(prefix='dsm-import-', dir=str(self.state)) as directory:
            staging = Path(directory)
            staging.chmod(0o700)
            files = {'key_tmp': self.candidate_dir() / (self.config['domains'][0] + '.key'),
                     'cert_tmp': self.candidate(), 'inter_cert_tmp': self.candidate_dir() / 'ca.cer'}
            params = {'id': self.config['certificate_id'],
                      'desc': self.config['certificate_description'],
                      'as_default': 'true' if target['is_default'] else 'false'}
            for name, source in files.items():
                destination = staging / (name + '.pem')
                shutil.copyfile(source, destination)
                destination.chmod(0o600)
                params[name] = str(destination)
            save_json(self.marker, {'at': now(), 'pid': os.getpid(),
                                    'deployment_method': 'local_api', 'operation': 'import'})
            try:
                data = self.call_local_api('SYNO.Core.Certificate', 'import', params, timeout=120)
                if 'id' in data and data['id'] != self.config['certificate_id']:
                    raise Failure('DSM 导入返回了不同的证书 ID，请核对备份及服务绑定。')
            finally:
                self.marker.unlink(missing_ok=True)

    def initialize_success_notification(self):
        if 'success_notify_email' not in self.config:
            return None
        path = self.state / 'success-notification.json'
        if not os.path.lexists(path):
            # 首次启用只建立当前证书基线，不补发历史成功通知。
            state = {'version': 1, 'certificate_id': self.config['certificate_id'],
                     'last_notified_fingerprint': fingerprint(self.current_cert()), 'pending': None}
            save_json(path, state)
            return state
        private(path)
        state = read_json(path)
        valid_fingerprint = lambda value: isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
        if (not isinstance(state, dict) or state.get('version') != 1
                or state.get('certificate_id') != self.config['certificate_id']
                or not valid_fingerprint(state.get('last_notified_fingerprint')) or 'pending' not in state):
            raise Failure('成功通知状态与当前证书不匹配，请核查 state/success-notification.json。')
        event = state['pending']
        if event is not None:
            try:
                if (not isinstance(event, dict) or not valid_fingerprint(event.get('fingerprint'))
                        or event.get('domains') != self.config['domains']
                        or type(event.get('expires_at')) is not int or event['expires_at'] <= 0
                        or not isinstance(event.get('completed_at'), str)):
                    raise ValueError()
                completed = datetime.datetime.fromisoformat(event['completed_at'])
                datetime.datetime.fromtimestamp(event['expires_at'], datetime.timezone.utc)
                if completed.tzinfo is None:
                    raise ValueError()
            except (ValueError, OverflowError, OSError):
                raise Failure('待发送成功通知格式无效，请核查 state/success-notification.json。')
        return state

    def queue_success_notification(self, expected):
        state = self.initialize_success_notification()
        if state is None or state['last_notified_fingerprint'] == expected:
            return
        if state['pending'] is None or state['pending']['fingerprint'] != expected:
            state['pending'] = {'fingerprint': expected, 'completed_at': now(),
                                'expires_at': certificate_expiry(self.current_cert()),
                                'domains': list(self.config['domains'])}
            save_json(self.state / 'success-notification.json', state)

    def deliver_success_notification(self, event):
        try:
            settings = self.call_local_api('SYNO.Core.Notification.Mail.Conf', 'get')
        except Failure:
            raise Failure('无法读取群晖邮件配置；证书已生效，待发送成功通知已保留。')
        sender = settings.get('sender_mail')
        if (settings.get('enable_mail') is not True or not isinstance(sender, str)
                or sender.startswith('-')
                or not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', sender)):
            raise Failure('群晖邮件服务未启用或发件邮箱无效；证书已生效，待发送成功通知已保留。')
        beijing = datetime.timezone(datetime.timedelta(hours=8))
        completed = datetime.datetime.fromisoformat(event['completed_at']).astimezone(beijing)
        expires = datetime.datetime.fromtimestamp(event['expires_at'], beijing)
        # DSM ssmtp 从标准输入读取 LF 文本，再自行转换 SMTP 行结束符。
        message = EmailMessage(policy=SMTP.clone(linesep='\n', max_line_length=0))
        message['From'] = sender
        message['To'] = self.config['success_notify_email']
        message['Subject'] = self.config['domains'][0] + ' 证书续期并替换成功'
        message['Date'] = format_datetime(datetime.datetime.now(datetime.timezone.utc))
        domain = self.config['domains'][0]
        domain = domain[2:] if domain.startswith('*.') else domain
        message['Message-ID'] = '<synology-cert-{}-{}@{}>'.format(
            self.config['certificate_id'], event['fingerprint'], domain)
        message.set_content('群晖证书已更新，实际 HTTPS 服务验证通过。\n\n'
                            '域名：{}\n完成时间：{}（北京时间）\n新到期时间：{}（北京时间）\n'
                            'SHA-256 指纹：{}\n'.format(', '.join(event['domains']),
                                completed.strftime('%Y-%m-%d %H:%M:%S'),
                                expires.strftime('%Y-%m-%d %H:%M:%S'), event['fingerprint']), cte='8bit')
        env = {'PATH': SYSTEM_PATH, 'HOME': str(self.home), 'LANG': 'C', 'LC_ALL': 'C'}
        proc = None
        try:
            proc = subprocess.Popen(['/bin/ssmtp', '-f', sender, self.config['success_notify_email']], env=env,
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                proc.communicate(message.as_bytes(), timeout=60)
            except (subprocess.TimeoutExpired, KeyboardInterrupt, InterruptedError):
                self.stop_process(proc)
                raise Failure('证书已生效，但成功通知发送超时或被中断；下次任务将重试通知。')
            if proc.returncode:
                raise Failure('证书已生效，但成功通知发送失败；请检查 DSM 邮件配置，下次任务将重试通知。')
        except OSError:
            raise Failure('无法调用群晖邮件程序；证书已生效，待发送成功通知已保留。')
        finally:
            if proc is not None and proc.poll() is None:
                self.stop_process(proc)

    def send_success_notification(self, expected):
        state = self.initialize_success_notification()
        if state is None or state['pending'] is None:
            return
        event = state['pending']
        if event['fingerprint'] != expected or fingerprint(self.current_cert()) != expected:
            raise Failure('待发送成功通知与当前服务证书不一致，停止发送并保留记录。')
        if state['last_notified_fingerprint'] != expected:
            self.deliver_success_notification(event)
        state['last_notified_fingerprint'] = expected
        state['pending'] = None
        save_json(self.state / 'success-notification.json', state)
        self.log('证书更新成功通知已提交群晖邮件服务。')

    def deploy_and_verify(self, before):
        self.failure_stage = 'certificate_validation'
        self.candidate_valid()
        self.failure_stage = 'success_notification'
        self.initialize_success_notification()
        self.failure_stage = 'dsm_deploy'
        # 跨续期只保护目标绑定；导入前后仍核对全部绑定，捕获接口副作用。
        current = self.binding_state(self.metadata())
        if self.target_bindings(current) != self.target_bindings(before):
            raise Failure('导入前目标证书绑定已改变，停止导入证书。')
        before = current
        expected = fingerprint(self.candidate())
        save_json(self.state / 'pending.json', {'fingerprint': expected, 'at': now()})
        import_bindings = self.state / 'import-bindings.json'
        save_json(import_bindings, before)
        if self.deployment_method() == 'local_api':
            self.deploy_local_api(before)
        else:
            result = self.invoke_acme(['--deploy', '-d', self.config['domains'][0], '--deploy-hook', 'synology_dsm'])
            if result:
                raise Failure('证书已取得，但 DSM 部署失败；保留待部署标记，下次重试。详见 state/acme-last.log。')
        after = self.metadata()
        if self.binding_state(after) != before:
            raise Failure('证书部署后服务绑定发生变化，请根据备份在 DSM 中核对恢复。')
        import_bindings.unlink(missing_ok=True)
        if fingerprint(self.current_cert()) != expected:
            raise Failure('部署接口返回成功，但 DSM 中证书指纹未更新；下次任务将重试。')
        self.failure_stage = 'tls_verify'
        self.verify_probes(expected, attempts=6)
        self.failure_stage = 'success_notification'
        self.queue_success_notification(expected)
        (self.state / 'pending.json').unlink(missing_ok=True)
        self.log('新证书已部署；所有配置的 HTTPS 端点证书链、域名及指纹校验通过。')

    def run(self):
        self.load()
        self.retire_manual_target()
        request = self.manual_renewal(reconcile=True)
        force = request if request and request['state'] == 'queued' else None
        recovery = request if request and request['recovery_only'] else None
        if recovery and time.time() >= request.get('resume_normal_at', float('inf')):
            # 手动失败不能永久关闭正常到期续期；未来窗口恢复原策略，绝不重放 force。
            request['recovery_only'] = False
            self.save_manual_renewal(request)
            recovery = None
        try:
            if force:
                force.update(state='running', message='正在检查申请条件并申请新证书。')
                self.save_manual_renewal(force)
                self.assert_manual_prerequisites()
            if force or recovery:
                if (request['certificate_id'] != self.config['certificate_id']
                        or request['domains'] != self.config['domains']):
                    raise Failure('手动申请的目标或域名已改变，停止执行。')
            if force and request['baseline_fingerprint'] != fingerprint(self.current_cert()):
                raise Failure('提交请求后当前证书已改变，本次不再申请新证书。')
            self._run(force=force, recovery=recovery)
        except (Exception, KeyboardInterrupt):
            if force or recovery:
                expired = force and not force['force_consumed'] and time.time() >= force['expires_at']
                request.update(state='expired' if expired else 'failed', completed_at=int(time.time()),
                               message='申请请求已过期，未执行强制签发。' if expired else
                               '立即申请或后续验证未完成，请查看失败记录；不会重复执行本次签发请求。')
                self.save_manual_renewal(request)
            raise
        if force or recovery:
            succeeded = (request.get('issuance_result') != 2
                         and fingerprint(self.current_cert()) != request['baseline_fingerprint'])
            request.update(state='succeeded' if succeeded else 'failed', completed_at=int(time.time()),
                           recovery_only=False, message='新证书已替换，HTTPS 验证、DNS 清理及通知均已完成。' if succeeded
                           else '本次签发未确认成功，已完成现有证书验证与清理，未再次申请。')
            self.save_manual_renewal(request)

    def _run(self, force=None, recovery=None):
        self.cleanup_diagnostics()
        self.failure_stage = 'preflight'
        self.diagnostic_logs = {}
        self.acme_evidence, self.acme_events, self.cleanup_events = '', [], []
        cleanup_ok = self.retry_dns_cleanup()
        self.failure_stage = 'preflight'
        info = self.preflight(check_endpoints=False)
        self.failure_stage = 'success_notification'
        self.initialize_success_notification()
        self.failure_stage = 'preflight'
        before = self.binding_state(info)
        import_bindings = self.state / 'import-bindings.json'
        if import_bindings.exists():
            if read_json(import_bindings) != before:
                raise Failure('前次导入后服务绑定发生变化，请先按备份核查恢复。')
            import_bindings.unlink()
        baseline = self.state / 'run-baseline.json'
        if baseline.exists():
            previous = read_json(baseline)
            if (previous.get('certificate_id') != self.config['certificate_id']
                    or self.target_bindings(previous.get('bindings')) != self.target_bindings(before)):
                raise Failure('前次操作后服务绑定发生变化，请先按备份核查恢复，或确认当前绑定后重新 configure。')
        self.failure_stage = 'backup'
        self.backup(info)
        baseline_data = {'certificate_id': self.config['certificate_id'], 'bindings': before}
        if force or recovery:
            baseline_data['manual_request_id'] = (force or recovery)['request_id']
        save_json(baseline, baseline_data)
        self.failure_stage = 'preflight'
        pending = self.state / 'pending.json'
        primary = self.config['domains'][0]
        conf = self.candidate_dir() / (primary + '.conf')
        if self.candidate().exists() and not conf.is_file():
            raise Failure('已有 ACME 证书但配置缺失，停止以避免错误跳过续期。')
        if pending.exists():
            self.log('发现待完成部署，先检查已签发证书。')
        if pending.exists() or self.candidate().exists():
            self.failure_stage = 'certificate_validation'
            try:
                self.candidate_valid()
            except Failure:
                recovery_state = {'at': now(), 'needs_recovery': True}
                if force or recovery:
                    recovery_state['manual_request_id'] = (force or recovery)['request_id']
                save_json(pending, recovery_state)
                if recovery:
                    raise Failure('手动申请的候选证书无效，已停止；不会通过恢复流程再次签发。')
                if force:
                    self.consume_manual_renewal(force)
                self.failure_stage = 'recovery'
                self.recover_candidate()
            else:
                (self.state / 'recovery.json').unlink(missing_ok=True)
                if pending.exists() and (recovery or not self.renewal_due()):
                    self.deploy_and_verify(before)
        else:
            self.failure_stage = 'tls_verify'
            self.verify_probes(fingerprint(self.current_cert()), verify_chain=False)
        if self.candidate().exists():
            args = ['--renew', '-d', primary]
            if force:
                args.append('--force')
        else:
            args = ['--issue', '--dns', 'dns_tencent', '--keylength', '2048', '--accountemail', self.config['email']]
            for domain in self.config['domains']:
                args.extend(['-d', domain])
        if 'renew_before_days' in self.config and self.candidate().exists():
            self.failure_stage = 'preflight'
            self.prepare_acme_config()
        if recovery:
            result = 2
            self.log('恢复已消耗的手动申请，仅完成现有证书部署与清理，不再次签发。')
        elif not force and 'renew_before_days' in self.config and self.candidate().exists() and not self.renewal_due():
            # 门控在包装器中执行，历史 ACME 日期或 CA 窗口不能提前触发签发。
            result = 2
            self.log('尚未进入到期前 {} 天的续期窗口，本次不申请证书。'.format(self.config['renew_before_days']))
        else:
            self.failure_stage = 'acme'
            if force:
                self.consume_manual_renewal(force)
            result = self.invoke_acme(args)
            if force:
                force['issuance_result'] = result
                self.save_manual_renewal(force)
        if self.candidate().exists() and fingerprint(self.candidate()) != fingerprint(self.current_cert()):
            save_json(pending, {'fingerprint': fingerprint(self.candidate()), 'at': now()})
        if result not in (0, 2):
            self.failure_stage = 'acme'
            raise Failure('签发或续期失败；部署前备份已保留。详见 state/acme-last.log。')
        if force and (result == 2 or not self.candidate().is_file()
                      or fingerprint(self.candidate()) == force['baseline_fingerprint']):
            raise Failure('立即申请未生成不同指纹的新证书，不能将跳过或旧证书当作成功。')
        self.failure_stage = 'certificate_validation'
        if not self.candidate().is_file():
            recovery_state = {'at': now(), 'needs_recovery': True}
            if force or recovery:
                recovery_state['manual_request_id'] = (force or recovery)['request_id']
            save_json(pending, recovery_state)
            raise Failure('ACME 未生成预期证书，不能将跳过状态当作签发成功。')
        self.candidate_valid()
        if not recovery and self.renewal_due():
            raise Failure('已进入续期窗口，但尚未获得有效的新证书；下次任务重试。')
        (self.state / 'recovery.json').unlink(missing_ok=True)
        self.failure_stage = 'dsm_deploy'
        if self.target_bindings(self.binding_state(self.metadata())) != self.target_bindings(before):
            raise Failure('续期后服务绑定发生变化，请核对备份，停止后续自动操作。')
        expected = fingerprint(self.candidate())
        if expected != fingerprint(self.current_cert()) or pending.exists():
            self.deploy_and_verify(before)
        else:
            self.failure_stage = 'tls_verify'
            try:
                self.verify_probes(expected, attempts=3)
            except Failure:
                save_json(pending, {'fingerprint': expected, 'at': now()})
                raise
        baseline.unlink(missing_ok=True)
        self.failure_stage = 'dns_cleanup'
        if not cleanup_ok or self.dns_cleanup_count():
            raise Failure('证书及 HTTPS 已验证，但 DNS 验证记录清理失败；下次任务独立重试清理，详见 state/dns-cleanup.json 和清理日志。')
        self.failure_stage = 'success_notification'
        self.send_success_notification(expected)
        self.failure_stage = 'result_recording'
        save_json(self.state / 'last-result.json', {'at': now(), 'success': True, 'fingerprint': expected})
        self.log('本次检查完成，证书及 HTTPS 服务均正常。')

    def status(self):
        self.load()
        self.metadata()
        print('域名：' + ', '.join(self.config['domains']))
        print('部署方式：' + self.deployment_method())
        if 'renew_before_days' in self.config:
            print('续期策略：到期前 {} 天开始续期。'.format(self.config['renew_before_days']))
            if self.candidate().is_file():
                print('最早续期时间（UTC）：' + datetime.datetime.fromtimestamp(
                    self.renewal_time(), datetime.timezone.utc).isoformat())
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
                controller.assert_manual_idle()
                if controller.config_file.exists():
                    controller.load()
                    controller.release_manual_protection()
                controller.configure()
                controller.retire_manual_target()
            elif args.command == 'run':
                try:
                    controller.run()
                except (Failure, OSError, KeyboardInterrupt, InterruptedError) as error:
                    # 在互斥锁内归档，避免下一轮覆盖本次日志或运行结果。
                    return controller.report_failure(error)
                finally:
                    controller.cleanup_diagnostics()
            elif args.command == 'check':
                controller.assert_manual_idle()
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
        if args.command == 'run':
            return controller.report_failure(error)
        message = str(error) if isinstance(error, Failure) else '系统操作失败或被中断，请检查文件权限、网络及本机日志。'
        print('失败：' + diagnostics.sanitize(message, secrets=controller.diagnostic_secrets()), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
