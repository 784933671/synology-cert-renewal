import datetime
import fcntl
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

from web import host_bridge, login_mail


class SecurityMailTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        for name in ('web', 'state'):
            (self.home / name).mkdir(mode=0o700)
        self.now = 1793754000
        self.version = 'a' * 32
        self.write(self.home / 'web/login-email.json', {'recipient': 'admin@example.com', 'policy_version': self.version})
        self.controller = Mock()
        self.controller.call_local_api.return_value = {'enable_mail': True, 'sender_mail': 'sender@example.com'}
        self.controller.locked.side_effect = AssertionError('mail must not acquire certificate lock')
        self.proc = Mock(returncode=0)
        self.proc.poll.return_value = 0
        self.sender = self.new_sender()
        patcher = patch('web.login_mail.subprocess.Popen', return_value=self.proc)
        self.launch = patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def read(self, path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('private-file failure')
        return json.loads(path.read_text())

    def directory(self, path):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('private-directory failure')

    def new_sender(self):
        return login_mail.LoginMailer(self.home, self.read, self.write, self.directory, lambda: self.controller,
                                      uid=os.getuid(), hostname='example.com', clock=lambda: self.now)

    def stepup(self, **overrides):
        return dict({'code': '024681', 'policy_version': self.version, 'operation': 'settings.update'}, **overrides)

    def event(self, **overrides):
        return dict({'event_id': 'b' * 32, 'event_type': 'new_login', 'policy_version': self.version,
                     'at': datetime.datetime.fromtimestamp(self.now, datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
                     'source_ip': '203.0.113.7', 'device': 'desktop'}, **overrides)

    def message(self):
        raw = self.proc.communicate.call_args.args[0]
        self.assertNotIn(b'\r\n', raw)
        return BytesParser(policy=policy.default).parsebytes(raw)

    def test_stepup_uses_fixed_recipient_specific_operation_and_8bit_body(self):
        self.assertEqual(self.sender.send_stepup(self.stepup()), {'accepted': True})
        message = self.message()
        self.assertEqual(message['To'], 'admin@example.com')
        self.assertIn('敏感操作二次验证', str(message['Subject']))
        self.assertIn('修改证书、续期计划或通知配置', message.get_content())
        self.assertIn('024681', message.get_content())
        self.assertEqual(message['Content-Transfer-Encoding'], '8bit')
        self.assertEqual(self.launch.call_args.args[0][-1], 'admin@example.com')
        for path in (self.home / 'state').iterdir():
            self.assertNotIn('024681', path.read_text())
            self.assertNotIn('admin@example.com', path.read_text())

    def test_all_supported_operations_have_fixed_human_readable_names(self):
        self.assertEqual(login_mail.OPERATIONS['password.change'], '修改管理员登录密码')
        self.assertEqual(login_mail.OPERATIONS['abuse.update'], '修改接口防护额度与临时封禁设置')
        self.assertEqual(login_mail.OPERATIONS['abuse.unblock'], '解除来源 IP 的临时封禁')
        for operation, label in login_mail.OPERATIONS.items():
            with self.subTest(operation=operation):
                self.now += 901
                self.sender.send_stepup(self.stepup(operation=operation))
                self.assertIn(label, self.message().get_content())

    def test_stepup_rejects_arbitrary_template_fields_and_code_injection(self):
        for change in ({'email': 'other@example.com'}, {'subject': 'subject'}, {'body': 'body'},
                       {'operation': 'exec'}, {'operation': ['renew']}, {'code': '１２３４５６'},
                       {'code': '123456\n'}, {'policy_version': 'a' * 32 + '\n'}):
            with self.subTest(change=change), self.assertRaises(login_mail.MailError):
                self.sender.send_stepup(self.stepup(**change))
        self.launch.assert_not_called()

    def test_login_stepup_and_security_quotas_are_independent(self):
        self.sender.send({'code': '123456', 'policy_version': self.version})
        self.sender.send_stepup(self.stepup())
        self.sender.send_security(self.event())
        self.assertEqual(self.launch.call_count, 3)
        with self.assertRaises(login_mail.MailError):
            self.sender.send_stepup(self.stepup())
        with self.assertRaises(login_mail.MailError):
            self.sender.send({'code': '123456', 'policy_version': self.version})

    def test_stepup_quota_survives_restart_and_failed_delivery(self):
        self.proc.returncode = 1
        with self.assertRaises(login_mail.MailError):
            self.sender.send_stepup(self.stepup())
        self.proc.returncode = 0
        self.sender = self.new_sender()
        with self.assertRaises(login_mail.MailError):
            self.sender.send_stepup(self.stepup())
        self.now += 60
        self.sender.send_stepup(self.stepup())
        self.assertEqual(self.launch.call_count, 2)

    def test_stepup_interval_and_window_limit_are_persistent(self):
        for _ in range(5):
            self.sender.send_stepup(self.stepup())
            self.now += 60
            self.sender = self.new_sender()
        with self.assertRaises(login_mail.MailError):
            self.sender.send_stepup(self.stepup())
        self.now += 901
        self.sender.send_stepup(self.stepup())

    def test_security_message_has_only_fixed_fields_and_no_user_supplied_html(self):
        self.sender.send_security(self.event())
        message = self.message()
        self.assertEqual(message['To'], 'admin@example.com')
        self.assertIn('新的登录来源', str(message['Subject']))
        self.assertIn('北京时间', message.get_content())
        self.assertIn('203.0.113.7', message.get_content())
        self.assertIn('电脑', message.get_content())
        self.assertIn('b' * 32, message.get_content())
        self.assertEqual(message['Content-Transfer-Encoding'], '8bit')
        state = (self.home / 'state/security-mail-state.json').read_text()
        self.assertNotIn('203.0.113.7', state)
        self.assertNotIn('admin@example.com', state)

    def test_security_success_deduplicates_across_restart_even_during_cooldown(self):
        event = self.event()
        self.sender.send_security(event)
        self.sender = self.new_sender()
        self.assertEqual(self.sender.send_security(event), {'accepted': True})
        self.assertEqual(self.launch.call_count, 1)
        self.assertEqual(len(self.read(self.home / 'state/security-mail-state.json')['attempts']), 1)

    def test_security_same_id_with_changed_payload_is_rejected(self):
        self.sender.send_security(self.event())
        for change in ({'source_ip': '203.0.113.8'}, {'device': 'mobile'}, {'event_type': 'login_failures'}):
            with self.subTest(change=change), self.assertRaises(login_mail.MailError):
                self.sender.send_security(self.event(**change))
        self.assertEqual(self.launch.call_count, 1)

    def test_security_rejects_old_policy_even_for_previously_sent_event(self):
        event = self.event()
        self.sender.send_security(event)
        self.write(self.home / 'web/login-email.json', {'recipient': 'new@example.com', 'policy_version': 'c' * 32})
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(event)
        self.assertEqual(self.launch.call_count, 1)

    def test_security_failure_consumes_quota_but_can_retry_same_id_after_cooldown(self):
        event = self.event()
        self.proc.returncode = 1
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(event)
        self.assertEqual(self.read(self.home / 'state/security-mail-state.json')['sent'], [])
        self.proc.returncode = 0
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(event)
        self.now += 15
        self.assertEqual(self.sender.send_security(event), {'accepted': True})
        self.assertEqual(self.launch.call_count, 2)

    def test_security_hourly_quota_does_not_consume_otp_quota(self):
        for index in range(10):
            self.sender.send_security(self.event(event_id='%032x' % index))
            self.now += 15
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(self.event(event_id='f' * 32))
        self.sender.send_stepup(self.stepup())
        self.sender.send({'code': '123456', 'policy_version': self.version})
        self.now += 3601
        self.sender.send_security(self.event(event_id='f' * 32))

    def test_security_daily_quota_survives_sender_restart(self):
        for hour in range(4):
            for index in range(10):
                self.sender.send_security(self.event(event_id='%032x' % (hour * 10 + index)))
                self.now += 15
            self.now += 3601
            self.sender = self.new_sender()
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(self.event(event_id='f' * 32))
        self.now += 86401
        self.sender.send_security(self.event(event_id='f' * 32))

    def test_security_invalid_template_fields_time_ip_and_device_never_send(self):
        changes = ({'email': 'other@example.com'}, {'body': 'html'}, {'event_id': '../state'},
                   {'event_type': 'exec'}, {'device': '<script>'}, {'device': ['desktop']},
                   {'source_ip': '-option'}, {'source_ip': 'fe80::1%\nBcc:other@example.com'},
                   {'source_ip': 'fe80::1%eth0'}, {'source_ip': '203.0.113.7\r\n'},
                   {'at': '2026-11-04T09:00:00+08:00'}, {'at': '2026-99-04T01:00:00Z'},
                   {'at': '2020-01-01T01:00:00Z'}, {'at': True}, {'at': '2099-01-01T00:00:00Z'})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(login_mail.MailError):
                self.sender.send_security(self.event(**change))
        self.launch.assert_not_called()

    def test_equivalent_ipv6_and_utc_timestamp_normalize_for_deduplication(self):
        event = self.event(source_ip='2001:db8::1')
        self.sender.send_security(event)
        event.update(source_ip='2001:0DB8:0:0:0:0:0:1', at=event['at'].replace('Z', '+00:00'))
        self.sender.send_security(event)
        self.assertEqual(self.launch.call_count, 1)

    def test_security_lock_prevents_concurrent_send_and_does_not_take_certificate_lock(self):
        with (self.home / 'state/run.lock').open('w') as run_lock:
            fcntl.flock(run_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.sender.locked('security'):
                with self.assertRaises(login_mail.MailError):
                    self.new_sender().send_security(self.event())
            self.sender.send_security(self.event())
        self.controller.locked.assert_not_called()
        self.assertEqual(self.launch.call_count, 1)

    def test_unsafe_security_state_and_locks_fail_closed(self):
        path = self.home / 'state/security-mail-state.json'
        invalid = ({'version': True, 'attempts': [], 'sent': []},
                   {'version': 1, 'attempts': [float('nan')], 'sent': []},
                   {'version': 1, 'attempts': [], 'sent': [{'id': 'x'}]},
                   {'version': 1, 'attempts': [self.now] * 41, 'sent': []})
        for value in invalid:
            self.write(path, value)
            with self.assertRaises(login_mail.MailError):
                self.sender.send_security(self.event())
        path.unlink()
        path.symlink_to(self.home / 'web/login-email.json')
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(self.event())
        path.unlink()
        lock = self.home / 'state/security-mail.lock'
        lock.chmod(0o644)
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(self.event())
        self.launch.assert_not_called()

    def test_quota_persistence_failure_prevents_smtp(self):
        self.sender.write = Mock(side_effect=OSError('private-data'))
        for method, params in ((self.sender.send_stepup, self.stepup()), (self.sender.send_security, self.event())):
            with self.assertRaises(login_mail.MailError) as caught:
                method(params)
            self.assertNotIn('private-data', str(caught.exception))
        self.launch.assert_not_called()

    def test_security_completion_write_failure_does_not_claim_success(self):
        original = self.sender.write
        calls = []
        def write(path, value):
            calls.append(path)
            if len(calls) == 2:
                raise OSError('private-data')
            original(path, value)
        self.sender.write = write
        with self.assertRaises(login_mail.MailError):
            self.sender.send_security(self.event())
        self.assertEqual(self.launch.call_count, 1)
        self.assertEqual(self.read(self.home / 'state/security-mail-state.json')['sent'], [])

    def test_timeout_is_sanitized_and_process_terminated(self):
        self.proc.communicate.side_effect = subprocess.TimeoutExpired(['024681'], 25)
        self.proc.poll.return_value = None
        for method, params in ((self.sender.send_stepup, self.stepup()), (self.sender.send_security, self.event())):
            with self.assertRaises(login_mail.MailError) as caught:
                method(params)
            self.assertNotIn('024681', str(caught.exception))
        self.assertEqual(self.controller.stop_process.call_count, 2)

    def test_all_security_templates_and_supported_device_labels(self):
        index = 0
        for event_type in login_mail.SECURITY_EVENTS:
            for device, label in login_mail.DEVICES.items():
                self.now += 3601
                self.sender.send_security(self.event(event_id='%032x' % index, event_type=event_type, device=device))
                self.assertIn(label, self.message().get_content())
                index += 1

    def test_mail_rpcs_do_not_dispatch_certificate_task_and_sanitize_errors(self):
        scheduler = Mock()
        bridge = host_bridge.Bridge(self.home, lambda: self.controller, scheduler, uid=os.getuid())
        for rpc, method, params in (('auth.stepup.send', 'send_stepup', self.stepup()),
                                    ('auth.security.send', 'send_security', self.event())):
            with self.subTest(rpc=rpc):
                with patch.object(bridge.login_mail, method, return_value={'accepted': True}) as send:
                    self.assertEqual(bridge.dispatch({'method': rpc, 'params': params}),
                                     {'ok': True, 'data': {'accepted': True}})
                    send.assert_called_once_with(params)
                with patch.object(bridge.login_mail, method, side_effect=host_bridge.login_mail.MailError('secret-data')):
                    result = bridge.dispatch({'method': rpc, 'params': params})
                self.assertEqual(result['error']['code'], 'unavailable')
                self.assertNotIn('secret-data', json.dumps(result))
        scheduler.run.assert_not_called()
        scheduler.put.assert_not_called()
        self.controller.locked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
