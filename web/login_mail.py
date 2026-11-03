"""固定收件人的登录验证码邮件；复用 DSM 邮件配置，不保存验证码。"""
import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, make_msgid
import fcntl
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')
POLICY_VERSION = re.compile(r'[0-9a-f]{32}')


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

    def reserve(self, policy_version):
        root = self.home / 'web'
        state = self.home / 'state'
        self.private_directory(root)
        self.private_directory(state)
        descriptor = os.open(str(state / 'login-mail.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise MailError('登录邮件锁权限异常')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MailError('登录邮件正在发送，请稍后重试') from None
            policy = self.read(root / 'login-email.json')
            if (not isinstance(policy, dict) or set(policy) != {'recipient', 'policy_version'}
                    or not email_valid(policy['recipient'])
                    or not isinstance(policy['policy_version'], str)
                    or not POLICY_VERSION.fullmatch(policy['policy_version'])
                    or policy['policy_version'] != policy_version):
                raise MailError('登录邮箱配置不一致，请从私有终端检查')
            path = state / 'login-mail-rate.json'
            previous = self.read(path) if os.path.lexists(path) else {'attempts': []}
            if (not isinstance(previous, dict) or set(previous) != {'attempts'}
                    or not isinstance(previous['attempts'], list) or len(previous['attempts']) > 20
                    or any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                           for value in previous['attempts'])):
                raise MailError('登录邮件限流记录异常')
            now = self.clock()
            recent = [value for value in previous['attempts'] if value > now - 900]
            if len(recent) >= 5 or any(now - value < 60 for value in recent):
                raise MailError('验证码邮件发送过于频繁，请稍后重试')
            # 发信失败也保留额度；这里绝不写入验证码、挑战令牌或邮箱。
            self.write(path, {'attempts': recent + [now]})
            return policy['recipient']

    def send(self, params):
        if (not isinstance(params, dict) or set(params) != {'code', 'policy_version'}
                or not isinstance(params['code'], str) or not re.fullmatch(r'[0-9]{6}', params['code'])
                or not isinstance(params['policy_version'], str)
                or not POLICY_VERSION.fullmatch(params['policy_version'])):
            raise MailError('验证码邮件请求无效')
        proc = None
        controller = None
        try:
            recipient = self.reserve(params['policy_version'])
            controller = self.controller_factory()
            settings = controller.call_local_api('SYNO.Core.Notification.Mail.Conf', 'get', timeout=10)
            sender = settings.get('sender_mail')
            if settings.get('enable_mail') is not True or not email_valid(sender):
                raise MailError('群晖邮件服务未启用或发件邮箱无效')
            # 与现有续期通知相同，DSM ssmtp 需要 LF + 8bit 正文。
            message = EmailMessage(policy=SMTP.clone(linesep='\n', max_line_length=0))
            message['From'], message['To'] = sender, recipient
            message['Subject'] = self.hostname + ' 管理页登录验证码'
            message['Date'] = format_datetime(datetime.datetime.now(datetime.timezone.utc))
            message['Message-ID'] = make_msgid()
            message.set_content('您的登录验证码：{}\n\n验证码有效期为 5 分钟，仅可使用一次。\n'
                                '请仅在证书管家登录页面输入，不要转发给他人。\n'
                                '若不是您本人发起，请检查管理账号密码及最近登录记录。\n'.format(params['code']), cte='8bit')
            proc = subprocess.Popen(['/bin/ssmtp', '-f', sender, recipient],
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/usr/syno/bin:/usr/syno/sbin',
                                         'HOME': str(self.home), 'LANG': 'C', 'LC_ALL': 'C'},
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            proc.communicate(message.as_bytes(), timeout=25)
            if proc.returncode:
                raise MailError('登录验证码邮件发送失败，请检查群晖邮件配置')
            return {'accepted': True}
        except (subprocess.TimeoutExpired, KeyboardInterrupt, InterruptedError):
            raise MailError('登录验证码邮件发送超时或被中断，请稍后重试') from None
        except MailError:
            raise
        except Exception:
            raise MailError('登录验证码邮件暂时无法发送，请稍后重试') from None
        finally:
            if proc is not None and proc.poll() is None:
                controller.stop_process(proc)
