"""固定登录邮箱的验证码与安全提醒；复用 DSM 邮件配置。"""
import contextlib
import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, make_msgid
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')
POLICY_VERSION = re.compile(r'[0-9a-f]{32}')
OPERATIONS = {
    'settings.update': '修改证书、续期计划或通知配置',
    'security.update': '修改管理页面访问范围',
    'monitor.update': '修改运行监测与预警配置',
    'renew': '立即申请并替换证书',
    'password.change': '修改管理员登录密码',
    'sessions.revoke': '撤销指定登录会话',
    'sessions.revoke_others': '退出其他登录设备',
}
SECURITY_EVENTS = {
    'new_login': '新的登录来源',
    'login_failures': '连续登录验证失败',
    'security_change': '重要安全配置已变更',
}
DEVICES = {'desktop': '电脑', 'mobile': '手机', 'tablet': '平板',
           'other': '其他设备', 'unknown': '未知设备'}
SECURITY_RETENTION = 30 * 86400


def valid_time(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


class MailError(Exception):
    pass


def email_valid(value):
    return (isinstance(value, str) and len(value) <= 254 and not value.startswith('-')
            and EMAIL.fullmatch(value) is not None)


class LoginMailer:
    def __init__(self, home, read, write, private_directory, controller_factory,
                 uid=0, hostname='证书管家', clock=time.time):
        self.home = Path(home)
        self.read, self.write = read, write
        self.private_directory = private_directory
        self.controller_factory = controller_factory
        self.uid, self.hostname, self.clock = uid, hostname, clock

    @contextlib.contextmanager
    def locked(self, purpose):
        root = self.home / 'web'
        state = self.home / 'state'
        self.private_directory(root)
        self.private_directory(state)
        descriptor = os.open(str(state / (purpose + '-mail.lock')), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise MailError('安全邮件锁权限异常')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MailError('安全邮件正在发送，请稍后重试') from None
            yield

    def recipient(self, policy_version):
        policy = self.read(self.home / 'web/login-email.json')
        if (not isinstance(policy, dict) or set(policy) != {'recipient', 'policy_version'}
                or not email_valid(policy['recipient'])
                or not isinstance(policy['policy_version'], str)
                or not POLICY_VERSION.fullmatch(policy['policy_version'])
                or policy['policy_version'] != policy_version):
            raise MailError('登录邮箱配置不一致，请从私有终端检查')
        return policy['recipient']

    def reserve(self, policy_version, purpose='login'):
        if purpose not in ('login', 'stepup'):
            raise MailError('验证码用途无效')
        with self.locked(purpose):
            recipient = self.recipient(policy_version)
            path = self.home / 'state' / (purpose + '-mail-rate.json')
            previous = self.read(path) if os.path.lexists(path) else {'attempts': []}
            if (not isinstance(previous, dict) or set(previous) != {'attempts'}
                    or not isinstance(previous['attempts'], list) or len(previous['attempts']) > 20
                    or any(not valid_time(value) for value in previous['attempts'])):
                raise MailError('登录邮件限流记录异常')
            now = self.clock()
            recent = [value for value in previous['attempts'] if value > now - 900]
            if len(recent) >= 5 or any(now - value < 60 for value in recent):
                raise MailError('验证码邮件发送过于频繁，请稍后重试')
            # 发信失败也保留额度；这里绝不写入验证码、挑战令牌或邮箱。
            self.write(path, {'attempts': recent + [now]})
            return recipient

    def send(self, params):
        if (not isinstance(params, dict) or set(params) != {'code', 'policy_version'}
                or not isinstance(params['code'], str) or not re.fullmatch(r'[0-9]{6}', params['code'])
                or not isinstance(params['policy_version'], str)
                or not POLICY_VERSION.fullmatch(params['policy_version'])):
            raise MailError('验证码邮件请求无效')
        try:
            recipient = self.reserve(params['policy_version'])
            return self.deliver(recipient, '管理页登录验证码',
                                '您的登录验证码：{}\n\n验证码有效期为 5 分钟，仅可使用一次。\n'
                                '请仅在证书管家登录页面输入，不要转发给他人。\n'
                                '若不是您本人发起，请检查管理账号密码及最近登录记录。\n'.format(params['code']))
        except MailError:
            raise
        except Exception:
            raise MailError('登录验证码邮件暂时无法发送，请稍后重试') from None

    def send_stepup(self, params):
        if (not isinstance(params, dict) or set(params) != {'code', 'policy_version', 'operation'}
                or not isinstance(params['code'], str) or not re.fullmatch(r'[0-9]{6}', params['code'])
                or not isinstance(params['policy_version'], str) or not POLICY_VERSION.fullmatch(params['policy_version'])
                or not isinstance(params['operation'], str) or params['operation'] not in OPERATIONS):
            raise MailError('操作验证码请求无效')
        try:
            recipient = self.reserve(params['policy_version'], 'stepup')
            return self.deliver(recipient, '敏感操作二次验证',
                                '您正在执行：{}\n\n操作验证码：{}\n\n'
                                '验证码有效期为 5 分钟，仅授权当前操作，请勿转发。\n'
                                '若不是您本人发起，请在管理页撤销其他会话并修改密码。\n'.format(
                                    OPERATIONS[params['operation']], params['code']))
        except MailError:
            raise
        except Exception:
            raise MailError('操作验证码邮件暂时无法发送，请稍后重试') from None

    def security_event(self, params):
        fields = {'event_id', 'event_type', 'policy_version', 'at', 'source_ip', 'device'}
        if (not isinstance(params, dict) or set(params) != fields
                or not isinstance(params['event_id'], str) or not POLICY_VERSION.fullmatch(params['event_id'])
                or not isinstance(params['policy_version'], str) or not POLICY_VERSION.fullmatch(params['policy_version'])
                or not isinstance(params['event_type'], str) or params['event_type'] not in SECURITY_EVENTS
                or not isinstance(params['device'], str) or params['device'] not in DEVICES
                or not isinstance(params['source_ip'], str) or len(params['source_ip']) > 45
                or not re.fullmatch(r'[0-9A-Fa-f:.]+', params['source_ip'])
                or not isinstance(params['at'], str)
                or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', params['at'])):
            raise MailError('安全提醒请求无效')
        try:
            address = str(ipaddress.ip_address(params['source_ip']))
            when = datetime.datetime.fromisoformat(params['at'].replace('Z', '+00:00'))
            stamp = when.timestamp()
            if not valid_time(stamp) or not self.clock() - SECURITY_RETENTION <= stamp <= self.clock() + 60:
                raise ValueError('event age')
        except (ValueError, OverflowError):
            raise MailError('安全提醒来源或时间无效') from None
        normalized = dict(params, source_ip=address, at=when.isoformat())
        fingerprint = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
        return normalized, fingerprint

    def security_state(self, path):
        value = self.read(path) if os.path.lexists(path) else {'version': 1, 'attempts': [], 'sent': []}
        if (not isinstance(value, dict) or set(value) != {'version', 'attempts', 'sent'}
                or type(value['version']) is not int or value['version'] != 1
                or not isinstance(value['attempts'], list) or len(value['attempts']) > 40
                or any(not valid_time(at) for at in value['attempts'])
                or not isinstance(value['sent'], list) or len(value['sent']) > 2048):
            raise MailError('安全提醒记录无效')
        ids = set()
        for item in value['sent']:
            if (not isinstance(item, dict) or set(item) != {'id', 'fingerprint', 'at'}
                    or not isinstance(item['id'], str) or not POLICY_VERSION.fullmatch(item['id'])
                    or not isinstance(item['fingerprint'], str) or not re.fullmatch(r'[0-9a-f]{64}', item['fingerprint'])
                    or not valid_time(item['at']) or item['id'] in ids):
                raise MailError('安全提醒记录无效')
            ids.add(item['id'])
        return value

    def send_security(self, params):
        event, fingerprint = self.security_event(params)
        try:
            # 持有独立邮件锁直至成功落盘，阻止并发 RPC 重复发送同一事件。
            with self.locked('security'):
                recipient = self.recipient(event['policy_version'])
                path = self.home / 'state/security-mail-state.json'
                value = self.security_state(path)
                now = self.clock()
                sent = [item for item in value['sent'] if item['at'] > now - SECURITY_RETENTION]
                previous = next((item for item in sent if item['id'] == event['event_id']), None)
                if previous is not None:
                    if previous['fingerprint'] != fingerprint:
                        raise MailError('安全提醒事件标识冲突')
                    return {'accepted': True}
                recent = [at for at in value['attempts'] if at > now - 86400]
                if len(recent) >= 40 or sum(at > now - 3600 for at in recent) >= 10 or any(now - at < 15 for at in recent):
                    raise MailError('安全提醒发送过于频繁，请稍后重试')
                value = {'version': 1, 'attempts': recent + [now], 'sent': sent}
                self.write(path, value)
                stamp = datetime.datetime.fromisoformat(event['at']).astimezone(datetime.timezone(datetime.timedelta(hours=8)))
                body = ('安全事件：{}\n发生时间：{}（北京时间）\n来源地址：{}\n设备类型：{}\n事件编号：{}\n\n'
                        '若不是您本人的操作，请核对操作审计、撤销可疑会话并修改密码。\n'
                        '此邮件为管理页安全提醒，不代表证书自动续期发生故障。\n').format(
                            SECURITY_EVENTS[event['event_type']], stamp.strftime('%Y-%m-%d %H:%M:%S'),
                            event['source_ip'], DEVICES[event['device']], event['event_id'])
                self.deliver(recipient, '管理页安全提醒：' + SECURITY_EVENTS[event['event_type']], body)
                value['sent'] = (sent + [{'id': event['event_id'], 'fingerprint': fingerprint, 'at': now}])[-2048:]
                self.write(path, value)
                return {'accepted': True}
        except MailError:
            raise
        except Exception:
            raise MailError('安全提醒邮件暂时无法发送，请稍后重试') from None

    def deliver(self, recipient, subject, body):
        proc = None
        controller = None
        try:
            controller = self.controller_factory()
            settings = controller.call_local_api('SYNO.Core.Notification.Mail.Conf', 'get', timeout=10)
            sender = settings.get('sender_mail')
            if settings.get('enable_mail') is not True or not email_valid(sender):
                raise MailError('群晖邮件服务未启用或发件邮箱无效')
            # 与现有续期通知相同，DSM ssmtp 需要 LF + 8bit 正文。
            message = EmailMessage(policy=SMTP.clone(linesep='\n', max_line_length=0))
            message['From'], message['To'] = sender, recipient
            message['Subject'] = self.hostname + ' ' + subject
            message['Date'] = format_datetime(datetime.datetime.now(datetime.timezone.utc))
            message['Message-ID'] = make_msgid()
            message.set_content(body, cte='8bit')
            proc = subprocess.Popen(['/bin/ssmtp', '-f', sender, recipient],
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/usr/syno/bin:/usr/syno/sbin',
                                         'HOME': str(self.home), 'LANG': 'C', 'LC_ALL': 'C'},
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            proc.communicate(message.as_bytes(), timeout=25)
            if proc.returncode:
                raise MailError('安全邮件发送失败，请检查群晖邮件配置')
            return {'accepted': True}
        except (subprocess.TimeoutExpired, KeyboardInterrupt, InterruptedError):
            raise MailError('安全邮件发送超时或被中断，请稍后重试') from None
        except MailError:
            raise
        except Exception:
            raise MailError('安全邮件暂时无法发送，请稍后重试') from None
        finally:
            if proc is not None and proc.poll() is None:
                controller.stop_process(proc)
