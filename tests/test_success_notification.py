import contextlib
import copy
import datetime
from email import policy
from email.parser import BytesParser
import importlib.util
import io
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'success_notification_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl
RECIPIENT = 'operator+renewal@example.com'
SENDER = 'synology-sender@example.net'


class SuccessNotificationConfigurationTests(unittest.TestCase):
    def test_success_recipient_is_optional_and_rejects_header_or_command_injection(self):
        certctl.validate_config(FIXTURES.configuration())
        certctl.validate_config(dict(FIXTURES.configuration(), success_notify_email=RECIPIENT))
        for address in ('', None, True, 'not-an-email', 'a@example.com\nBcc: victim@example.com',
                        '-option@example.com', "$(uname)@example.com", 'a@example.com,b@example.com'):
            with self.subTest(address=address):
                with self.assertRaises(certctl.Failure):
                    certctl.validate_config(dict(FIXTURES.configuration(), success_notify_email=address))


class SuccessNotificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURES.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURES.CertificateTests.tearDownClass)

    def setUp(self):
        self.fixture = FIXTURES.CertificateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.configure_runtime_mocks()
        self.controller = self.fixture.controller
        self.controller.config.update(deployment_method='local_api', renew_before_days=2,
                                      success_notify_email=RECIPIENT)
        self.controller.deliver_success_notification = mock.Mock()
        self.notice_path = self.controller.state / 'success-notification.json'

    def state(self):
        return certctl.read_json(self.notice_path)

    def run_main(self):
        output = io.StringIO()
        with mock.patch.object(certctl, 'Controller', return_value=self.controller), \
             mock.patch.object(certctl.os, 'geteuid', return_value=0), \
             mock.patch.object(certctl.signal, 'signal'), \
             mock.patch.object(certctl, 'SYSTEM_PATH', os.environ['PATH']), \
             mock.patch.dict(os.environ), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = certctl.main(['--home', str(self.controller.home), 'run'])
        for key in ('secret_id', 'secret_key'):
            self.assertNotIn(self.controller.config[key], output.getvalue())
        return result

    def existing(self, name='old'):
        self.fixture.install_current(name)
        self.fixture.prepare_candidate(name)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('无需再次申请证书'))
        self.controller.deploy_local_api = mock.Mock(side_effect=AssertionError('无需再次导入证书'))

    def renewal(self):
        self.existing('short')
        def issue(arguments):
            self.assertEqual(arguments[0], '--renew')
            self.fixture.prepare_candidate('new')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=issue)
        self.controller.deploy_local_api = mock.Mock(
            side_effect=lambda before: self.fixture.install_current('new'))

    def assert_mail_pending(self):
        self.assertEqual(self.state()['pending']['fingerprint'], self.fixture.new_fingerprint)
        self.assertFalse((self.controller.state / 'pending.json').exists())

    def new_event(self):
        return {'fingerprint': self.fixture.new_fingerprint,
                'completed_at': '2026-10-30T01:04:56+00:00',
                'expires_at': int(datetime.datetime(2027, 1, 28, 1, 4, 56,
                    tzinfo=datetime.timezone.utc).timestamp()),
                'domains': self.controller.config['domains']}

    def test_disabled_notification_keeps_existing_behavior_without_state_or_mail(self):
        self.controller.config.pop('success_notify_email')
        self.renewal()
        self.controller.run()
        self.controller.deliver_success_notification.assert_not_called()
        self.assertFalse(self.notice_path.exists())

    def test_first_enable_baselines_current_certificate_and_normal_checks_remain_silent(self):
        self.existing()
        self.controller.run()
        baseline = self.state()
        self.assertEqual(baseline['last_notified_fingerprint'], self.fixture.old_fingerprint)
        self.assertIsNone(baseline['pending'])
        self.assertEqual(stat.S_IMODE(self.notice_path.stat().st_mode), 0o600)
        self.controller.run()
        self.assertEqual(self.state(), baseline)
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.controller.deliver_success_notification.assert_not_called()

    def test_due_renewal_sends_once_after_verified_replacement_and_later_checks_are_silent(self):
        self.renewal()
        def sent(event):
            self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)
            self.assertFalse((self.controller.state / 'pending.json').exists())
            self.assertEqual(event['fingerprint'], self.fixture.new_fingerprint)
            self.assertEqual(event['domains'], self.controller.config['domains'])
            self.assertEqual(event['expires_at'], certctl.certificate_expiry(self.controller.current_cert()))
            self.assertTrue(self.controller.probe_fingerprint.called)
        self.controller.deliver_success_notification.side_effect = sent
        self.controller.run()
        self.controller.deliver_success_notification.assert_called_once()
        self.assertEqual(self.state()['last_notified_fingerprint'], self.fixture.new_fingerprint)
        self.assertIsNone(self.state()['pending'])
        self.existing('new')
        self.controller.run()
        self.controller.deliver_success_notification.assert_called_once()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()

    def test_reimporting_identical_certificate_does_not_send_success_notice(self):
        self.existing()
        self.controller.initialize_success_notification()
        certctl.save_json(self.controller.state / 'pending.json', {
            'fingerprint': self.fixture.old_fingerprint, 'at': certctl.now()})
        self.controller.deploy_local_api = mock.Mock(side_effect=lambda before: self.fixture.install_current('old'))
        self.controller.run()
        self.controller.deploy_local_api.assert_called_once()
        self.controller.deliver_success_notification.assert_not_called()
        self.assertIsNone(self.state()['pending'])

    def test_failed_import_does_not_notify_until_existing_candidate_is_retried_successfully(self):
        self.renewal()
        self.controller.deploy_local_api.side_effect = certctl.Failure('模拟导入失败')
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.deliver_success_notification.assert_not_called()
        self.assertIsNone(self.state()['pending'])
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('已有新证书不可重复申请'))
        self.controller.deploy_local_api.side_effect = lambda before: self.fixture.install_current('new')
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deliver_success_notification.assert_called_once()

    def test_failed_live_tls_verification_does_not_notify_until_service_recovers(self):
        self.renewal()
        self.controller.probe_fingerprint.side_effect = lambda probe, **kwargs: self.fixture.old_fingerprint
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.deliver_success_notification.assert_not_called()
        self.assertIsNone(self.state()['pending'])
        self.assertTrue((self.controller.state / 'pending.json').exists())
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不能重复申请'))
        self.controller.probe_fingerprint.side_effect = lambda probe, **kwargs: certctl.fingerprint(
            self.controller.current_cert())
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deliver_success_notification.assert_called_once()

    def test_dns_cleanup_failure_defers_success_notice_until_later_clean_check(self):
        self.renewal()
        self.controller.retry_dns_cleanup = mock.Mock(return_value=False)
        self.controller.dns_cleanup_count = mock.Mock(return_value=1)
        self.assertEqual(self.run_main(), 1)
        self.controller.deliver_success_notification.assert_not_called()
        self.assert_mail_pending()
        self.existing('new')
        self.controller.retry_dns_cleanup.return_value = True
        self.controller.dns_cleanup_count.return_value = 0
        self.assertEqual(self.run_main(), 0)
        self.controller.deliver_success_notification.assert_called_once()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertIsNone(self.state()['pending'])

    def test_mail_failure_is_reported_and_next_run_only_retries_notification(self):
        self.renewal()
        self.controller.deliver_success_notification.side_effect = certctl.Failure('模拟邮件发送失败')
        self.assertEqual(self.run_main(), 1)
        self.assertFalse(certctl.read_json(self.controller.state / 'last-result.json')['success'])
        self.assert_mail_pending()
        event = copy.deepcopy(self.state()['pending'])
        self.existing('new')
        self.controller.deliver_success_notification.side_effect = None
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.controller.deliver_success_notification.call_count, 2)
        self.assertEqual(self.controller.deliver_success_notification.call_args.args[0], event)
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertTrue(certctl.read_json(self.controller.state / 'last-result.json')['success'])
        self.assertIsNone(self.state()['pending'])

    def test_pending_notice_survives_controller_restart_without_reissuing_certificate(self):
        self.renewal()
        self.controller.deliver_success_notification.side_effect = certctl.Failure('模拟暂时不可用')
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        previous = self.controller
        controller = certctl.Controller(previous.home, previous.archive)
        controller.config = copy.deepcopy(previous.config)
        controller.load = mock.Mock()
        controller.preflight = mock.Mock(side_effect=lambda **kwargs: controller.metadata())
        controller.probe_fingerprint = mock.Mock(side_effect=lambda probe, **kwargs:
            certctl.fingerprint(controller.current_cert()))
        controller.log = mock.Mock()
        controller.invoke_acme = mock.Mock(side_effect=AssertionError('重启后不能重新申请'))
        controller.deploy_local_api = mock.Mock(side_effect=AssertionError('重启后无需重复导入'))
        controller.deliver_success_notification = mock.Mock()
        controller.run()
        controller.deliver_success_notification.assert_called_once()
        controller.invoke_acme.assert_not_called()
        controller.deploy_local_api.assert_not_called()
        self.assertIsNone(self.state()['pending'])

    def test_invalid_state_identity_content_and_permissions_are_not_silently_reset(self):
        self.controller.initialize_success_notification()
        original = self.state()
        changes = ({'version': 999}, {'certificate_id': 'OTHER'}, {'last_notified_fingerprint': 'bad'},
                   {'pending': {'fingerprint': self.fixture.new_fingerprint}},
                   {'pending': dict(self.new_event(), domains=['other.example.com'])})
        for change in changes:
            with self.subTest(change=change):
                invalid = dict(original, **change)
                certctl.save_json(self.notice_path, invalid)
                with self.assertRaises(certctl.Failure):
                    self.controller.initialize_success_notification()
                self.assertEqual(self.state(), invalid)
        certctl.save_json(self.notice_path, original)
        self.notice_path.chmod(0o644)
        with self.assertRaises(certctl.Failure):
            self.controller.initialize_success_notification()

    def test_pending_notice_for_different_live_certificate_cannot_be_sent(self):
        self.controller.initialize_success_notification()
        state = self.state()
        state['pending'] = self.new_event()
        certctl.save_json(self.notice_path, state)
        with self.assertRaises(certctl.Failure):
            self.controller.send_success_notification(self.fixture.old_fingerprint)
        self.controller.deliver_success_notification.assert_not_called()
        self.assertEqual(self.state()['pending'], state['pending'])

    def reconfigure(self, selection='1'):
        answers = [selection, 'operator@example.com', '', '', '', '', 'n']
        with mock.patch.object(certctl.shutil, 'which', return_value='/usr/syno/bin/synowebapi'), \
             mock.patch.object(certctl.sys.stdin, 'isatty', return_value=True), \
             mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'preflight'), \
             mock.patch('builtins.input', side_effect=answers), \
             mock.patch.object(certctl.getpass, 'getpass', side_effect=['TEST_ID', 'TEST_KEY']), \
             contextlib.redirect_stdout(io.StringIO()):
            self.controller.configure()

    def pending_after_smtp_failure(self):
        self.renewal()
        self.controller.deliver_success_notification.side_effect = certctl.Failure('模拟邮件暂时不可用')
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        certctl.save_json(self.controller.config_file, self.controller.config)
        self.assert_mail_pending()
        self.controller.deliver_success_notification.reset_mock()
        self.controller.deliver_success_notification.side_effect = None
        return copy.deepcopy(self.state())

    def test_reconfigure_same_target_preserves_success_mail_setting_and_pending_notice(self):
        before = self.pending_after_smtp_failure()
        self.reconfigure()
        saved = certctl.read_json(self.controller.config_file)
        self.assertEqual(saved['success_notify_email'], RECIPIENT)
        self.assertEqual(self.state(), before)
        self.controller.deliver_success_notification.assert_not_called()
        self.existing('new')
        self.controller.run()
        self.controller.deliver_success_notification.assert_called_once_with(before['pending'])
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertIsNone(self.state()['pending'])

    def test_reconfigure_different_target_creates_baseline_without_sending_old_notice(self):
        self.pending_after_smtp_failure()
        other = self.fixture.archive / 'XYZ789'
        other.mkdir(mode=0o700)
        shutil.copyfile(self.fixture.fixtures / 'old.pem', other / 'cert.pem')
        changed = copy.deepcopy(self.fixture.info)
        changed['XYZ789'] = {'desc': 'other-certificate', 'services': []}
        certctl.save_json(self.fixture.archive / 'INFO', changed)
        self.reconfigure('2')
        self.assertEqual(self.controller.config['certificate_id'], 'XYZ789')
        self.assertEqual(self.controller.config['success_notify_email'], RECIPIENT)
        self.assertEqual(self.state()['certificate_id'], 'XYZ789')
        self.assertEqual(self.state()['last_notified_fingerprint'], self.fixture.old_fingerprint)
        self.assertIsNone(self.state()['pending'])
        self.fixture.prepare_candidate('old')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('未到续期时间'))
        self.controller.deploy_local_api = mock.Mock(side_effect=AssertionError('证书不需替换'))
        self.controller.run()
        self.controller.deliver_success_notification.assert_not_called()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()

    def deliver(self, event, process):
        settings = {'enable_mail': True, 'sender_mail': SENDER}
        with mock.patch.object(certctl.subprocess, 'Popen', return_value=process) as popen, \
             mock.patch.object(self.controller, 'call_local_api', return_value=settings) as api:
            certctl.Controller.deliver_success_notification(self.controller, event)
        api.assert_called_once_with('SYNO.Core.Notification.Mail.Conf', 'get')
        return popen

    def test_smtp_message_is_utf8_addressed_has_beijing_times_and_omits_all_credentials(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (None, None)
        process.poll.return_value = 0
        inherited = {'HTTP_PROXY': 'http://proxy.invalid', 'https_proxy': 'http://proxy.invalid',
                     'Tencent_SecretId': 'ENV_ID_MUST_NOT_LEAK', 'Tencent_SecretKey': 'ENV_KEY_MUST_NOT_LEAK'}
        with mock.patch.dict(os.environ, inherited):
            popen = self.deliver(self.new_event(), process)
        args, options = popen.call_args.args[0], popen.call_args.kwargs
        self.assertEqual(args, ['/bin/ssmtp', '-f', SENDER, RECIPIENT])
        self.assertTrue(options['start_new_session'])
        self.assertEqual(options['stdin'], subprocess.PIPE)
        self.assertEqual(process.communicate.call_args.kwargs['timeout'], 60)
        raw = process.communicate.call_args.args[0]
        self.assertNotIn(b'\r', raw)
        headers, literal_body = raw.split(b'\n\n', 1)
        self.assertFalse(any(line.startswith((b' ', b'\t')) for line in headers.splitlines()))
        self.assertIn('群晖证书已更新'.encode('utf-8'), literal_body)
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(str(parsed['From']), SENDER)
        self.assertEqual(str(parsed['To']), RECIPIENT)
        self.assertIn('ttxli.cn', str(parsed['Subject']))
        self.assertIn('成功', str(parsed['Subject']))
        self.assertEqual(parsed['Content-Transfer-Encoding'], '8bit')
        body = parsed.get_content()
        self.assertIn('2026-10-30 09:04:56', body)
        self.assertIn('2027-01-28 09:04:56', body)
        self.assertIn('北京时间', body)
        self.assertIn(self.fixture.new_fingerprint[:16], body)
        for value in [self.controller.config['secret_id'], self.controller.config['secret_key'],
                      inherited['Tencent_SecretId'], inherited['Tencent_SecretKey']]:
            self.assertNotIn(value, repr(args) + repr(options['env']) + raw.decode('utf-8'))
        for name in inherited:
            self.assertNotIn(name, options['env'])

    def test_disabled_mail_or_invalid_sender_never_launches_smtp(self):
        invalid = [{'enable_mail': False, 'sender_mail': SENDER},
                   {'enable_mail': 1, 'sender_mail': SENDER},
                   {'sender_mail': SENDER}]
        invalid.extend({'enable_mail': True, 'sender_mail': sender} for sender in (
            None, '', True, 'not-an-address', '-option@example.com',
            'a@example.com\nBcc: victim@example.com', 'a@example.com,b@example.com'))
        for settings in invalid:
            with self.subTest(settings=settings), \
                 mock.patch.object(self.controller, 'call_local_api', return_value=settings), \
                 mock.patch.object(certctl.subprocess, 'Popen') as popen:
                with self.assertRaises(certctl.Failure):
                    certctl.Controller.deliver_success_notification(self.controller, self.new_event())
                popen.assert_not_called()

    def test_mail_configuration_read_failure_is_safe_and_does_not_launch_smtp(self):
        with mock.patch.object(self.controller, 'call_local_api',
                               side_effect=certctl.Failure('SENSITIVE_API_ERROR')), \
             mock.patch.object(certctl.subprocess, 'Popen') as popen:
            with self.assertRaises(certctl.Failure) as error:
                certctl.Controller.deliver_success_notification(self.controller, self.new_event())
        self.assertNotIn('SENSITIVE_API_ERROR', str(error.exception))
        popen.assert_not_called()

    def test_smtp_failure_is_sanitized(self):
        process = mock.Mock(returncode=78)
        process.communicate.return_value = (b'', b'secret-error-detail')
        process.poll.return_value = 78
        with self.assertRaises(certctl.Failure) as error:
            self.deliver(self.new_event(), process)
        self.assertNotIn('secret-error-detail', str(error.exception))

    def test_smtp_timeout_terminates_process_group_and_raises_failure(self):
        process = mock.Mock(pid=123456, returncode=None)
        process.communicate.side_effect = subprocess.TimeoutExpired('ssmtp', 60)
        process.wait.return_value = 0
        process.poll.return_value = 0
        with mock.patch.object(certctl.os, 'killpg') as killpg, self.assertRaises(certctl.Failure):
            self.deliver(self.new_event(), process)
        killpg.assert_called_once_with(process.pid, signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=10)


if __name__ == '__main__':
    unittest.main()
