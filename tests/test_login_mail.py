import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from unittest.mock import Mock, patch

from web.login_mail import LoginMailer, MailError


class LoginMailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        for name in ('state', 'web'):
            (self.home / name).mkdir(mode=0o700)
        self.now = [1700000000]
        self.version = 'a' * 32
        self.policy_path = self.home / 'web/login-email.json'
        self.write(self.policy_path, {'recipient': 'login@example.com', 'policy_version': self.version})
        self.controller = Mock()
        self.controller.call_local_api.return_value = {'enable_mail': True, 'sender_mail': 'sender@example.net'}
        self.proc = Mock(returncode=0)
        self.proc.poll.return_value = 0
        self.sender = self.new_sender()

    def write(self, path, data):
        path.write_text(json.dumps(data))
        path.chmod(0o600)

    def read(self, path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('unsafe fixture file')
        return json.loads(path.read_text())

    def directory(self, path):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('unsafe fixture directory')

    def new_sender(self):
        return LoginMailer(self.home, self.read, self.write, self.directory, lambda: self.controller,
                           uid=os.getuid(), hostname='example.com', clock=lambda: self.now[0])

    def send(self, **override):
        with patch('web.login_mail.subprocess.Popen', return_value=self.proc) as launch:
            result = self.sender.send(dict({'code': '024681', 'policy_version': self.version}, **override))
        return result, launch

    def test_fixed_recipient_lf_chinese_body_and_no_code_in_state_or_response(self):
        result, launch = self.send()
        self.assertEqual(result, {'accepted': True})
        self.assertEqual(launch.call_args.args[0], ['/bin/ssmtp', '-f', 'sender@example.net', 'login@example.com'])
        self.assertEqual(launch.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(launch.call_args.kwargs['stdout'], subprocess.DEVNULL)
        raw = self.proc.communicate.call_args.args[0]
        self.assertNotIn(b'\r\n', raw)
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(message['To'], 'login@example.com')
        self.assertIn('登录验证码', str(message['Subject']))
        self.assertIn('024681', message.get_content())
        self.assertEqual(message['Content-Transfer-Encoding'], '8bit')
        self.assertLessEqual(self.proc.communicate.call_args.kwargs['timeout'], 30)
        for path in (self.home / 'state').iterdir():
            self.assertNotIn('024681', path.read_text())
            self.assertNotIn('login@example.com', path.read_text())

    def test_extra_fields_or_non_ascii_code_are_rejected_without_email(self):
        for params in ({'email': 'other@example.com'}, {'subject': 'other'}, {'body': 'other'},
                       {'code': '１２３４５６'}, {'code': '12345\n'}, {'code': '1234567'},
                       {'code': 123456}, {'code': '123456\r\nBcc:x@example.com'}):
            with self.subTest(params=list(params)):
                with patch('web.login_mail.subprocess.Popen') as launch, self.assertRaises(MailError):
                    self.sender.send(dict({'code': '024681', 'policy_version': self.version}, **params))
                launch.assert_not_called()

    def test_wrong_policy_version_cannot_send_to_stale_or_unexpected_recipient(self):
        with patch('web.login_mail.subprocess.Popen') as launch, self.assertRaises(MailError):
            self.sender.send({'code': '024681', 'policy_version': 'b' * 32})
        launch.assert_not_called()
        self.assertFalse((self.home / 'state/login-mail-rate.json').exists())

    def test_policy_rejects_mail_header_and_command_injection(self):
        for recipient in ('-option@example.com', 'a@example.com\nBcc:other@example.com', 'a@example.com,b@example.com', 'a@example.com\r'):
            with self.subTest(recipient=repr(recipient)):
                self.write(self.policy_path, {'recipient': recipient, 'policy_version': self.version})
                with patch('web.login_mail.subprocess.Popen') as launch, self.assertRaises(MailError):
                    self.sender.send({'code': '024681', 'policy_version': self.version})
                launch.assert_not_called()

    def test_send_cooldown_and_account_limit_persist_across_sender_restart(self):
        for index in range(5):
            self.send()
            self.sender = self.new_sender()
            with self.assertRaises(MailError):
                self.send()
            self.now[0] += 60
        with self.assertRaises(MailError):
            self.send()
        self.now[0] += 901
        self.send()

    def test_delivery_error_keeps_rate_limit_without_exposing_code(self):
        self.proc.returncode = 1
        with self.assertRaises(MailError) as raised:
            self.send()
        self.assertNotIn('024681', str(raised.exception))
        self.proc.returncode = 0
        self.sender = self.new_sender()
        with self.assertRaises(MailError):
            self.send()

    def test_timeout_stops_process_and_discards_sensitive_exception_text(self):
        self.proc.communicate.side_effect = subprocess.TimeoutExpired(['private', '024681'], 25)
        self.proc.poll.return_value = None
        with self.assertRaises(MailError) as raised:
            self.send()
        self.assertNotIn('024681', str(raised.exception))
        self.controller.stop_process.assert_called_once_with(self.proc)

    def test_invalid_private_state_permissions_and_symlink_fail_closed(self):
        path = self.home / 'state/login-mail-rate.json'
        self.write(path, {'attempts': ['invalid']})
        with self.assertRaises(MailError):
            self.send()
        self.write(path, {'attempts': []})
        path.chmod(0o644)
        with self.assertRaises(MailError):
            self.send()
        path.unlink()
        path.symlink_to(self.policy_path)
        with self.assertRaises(MailError):
            self.send()

    def test_disabled_sender_never_starts_smtp_or_reads_credentials_elsewhere(self):
        self.controller.call_local_api.return_value = {'enable_mail': False, 'sender_mail': 'sender@example.net'}
        with patch('web.login_mail.subprocess.Popen') as launch, self.assertRaises(MailError):
            self.sender.send({'code': '024681', 'policy_version': self.version})
        launch.assert_not_called()
        self.controller.call_local_api.assert_called_once_with('SYNO.Core.Notification.Mail.Conf', 'get', timeout=10)


if __name__ == '__main__':
    unittest.main()
