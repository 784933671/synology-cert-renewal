import importlib.util
from pathlib import Path
import shutil
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('forced_renewal_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


class ForcedRenewalTests(unittest.TestCase):
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
        self.controller.config['renew_before_days'] = 2
        self.fixture.prepare_candidate('old')

    def request(self):
        with self.controller.locked():
            return self.controller.request_manual_renewal()

    def state(self):
        return self.controller.manual_renewal()

    def issue_and_deploy(self, arguments):
        if arguments[0] in ('--renew', '--issue'):
            self.assertTrue(self.state()['force_consumed'])
            self.fixture.prepare_candidate('new')
        else:
            self.assertEqual(arguments[0], '--deploy')
            self.fixture.install_current('new')
        return 0

    def test_force_outside_window_changes_certificate_and_ordinary_run_only_checks(self):
        self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        request = self.request()
        self.controller.run()
        calls = self.controller.invoke_acme.call_args_list
        self.assertEqual(calls[0].args[0], ['--renew', '-d', 'ttxli.cn', '--force'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.state()['request_id'], request['request_id'])
        self.assertEqual(self.state()['state'], 'succeeded')
        self.assertFalse(self.state()['recovery_only'])
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)
        self.assertEqual(len(list((self.controller.state / 'backups').glob('*/complete.json'))), 1)
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)

    def test_skip_or_unchanged_fingerprint_never_reports_success(self):
        for result in (0, 2):
            with self.subTest(result=result):
                self.request()
                self.controller.invoke_acme = mock.Mock(return_value=result)
                with self.assertRaisesRegex(certctl.Failure, '不同指纹'):
                    self.controller.run()
                self.assertEqual(self.state()['state'], 'failed')
                self.assertTrue(self.state()['force_consumed'])
                self.controller.run()
                self.controller.invoke_acme.assert_called_once()
                self.assertEqual(self.state()['state'], 'failed')
                self.assertFalse(self.state()['recovery_only'])
                (self.controller.state / 'manual-renewal.json').unlink()

    def test_pending_recovery_cleanup_or_mail_prevents_request(self):
        for filename in certctl.RENEWAL_PROTECTION_FILES:
            with self.subTest(filename=filename):
                path = self.controller.state / filename
                certctl.save_json(path, {'protected': True})
                before = path.read_bytes()
                with self.assertRaises(certctl.Failure):
                    self.request()
                self.assertEqual(path.read_bytes(), before)
                self.assertIsNone(self.state())
                path.unlink()
        with mock.patch.object(self.controller, 'dns_cleanup_count', return_value=1):
            with self.assertRaises(certctl.Failure):
                self.request()
        certctl.save_json(self.controller.state / 'success-notification.json', {'pending': {'fingerprint': 'b' * 64}})
        with self.assertRaises(certctl.Failure):
            self.request()

    def test_executor_rechecks_pending_created_after_request(self):
        self.request()
        pending = self.controller.state / 'pending.json'
        certctl.save_json(pending, {'protected': True})
        self.controller.invoke_acme = mock.Mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(certctl.read_json(pending), {'protected': True})
        self.assertEqual(self.state()['state'], 'failed')
        self.assertFalse(self.state()['force_consumed'])

    def test_target_change_and_orphan_candidate_prevent_forcing(self):
        self.request()
        self.fixture.install_current('new')
        self.controller.invoke_acme = mock.Mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        (self.controller.state / 'manual-renewal.json').unlink()
        with self.assertRaises(certctl.Failure):
            self.request()

    def test_expired_request_does_not_force_and_preserves_cooldown(self):
        request = self.request()
        self.controller.invoke_acme = mock.Mock()
        with mock.patch.object(certctl.time, 'time', return_value=request['expires_at']):
            self.controller.run()
            self.controller.invoke_acme.assert_not_called()
            self.assertEqual(self.state()['state'], 'expired')
            with self.assertRaises(certctl.Busy):
                self.request()
        with mock.patch.object(certctl.time, 'time', return_value=request['cooldown_until']):
            renewed = self.request()
        self.assertNotEqual(request['request_id'], renewed['request_id'])

    def test_interrupt_and_restart_cannot_replay_consumed_force(self):
        self.request()
        self.controller.invoke_acme = mock.Mock(side_effect=SystemExit('process stopped'))
        with self.assertRaises(SystemExit):
            self.controller.run()
        self.assertEqual(self.state()['state'], 'running')
        self.assertTrue(self.state()['force_consumed'])
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不得重放签发'))
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(self.state()['state'], 'failed')
        self.assertFalse(self.state()['recovery_only'])

    def test_timeout_then_recovery_deploys_existing_new_candidate_without_second_issue(self):
        self.request()
        def timeout(arguments):
            self.fixture.prepare_candidate('new')
            raise certctl.Failure('ACME 超时')
        self.controller.invoke_acme = mock.Mock(side_effect=timeout)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        def deploy(arguments):
            self.assertEqual(arguments[0], '--deploy')
            self.fixture.install_current('new')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=deploy)
        self.controller.run()
        self.controller.invoke_acme.assert_called_once()
        self.assertEqual(self.state()['state'], 'succeeded')

    def test_damaged_manual_candidate_is_not_reissued_until_future_normal_window(self):
        self.request()
        def corrupt(arguments):
            (self.controller.candidate_dir() / 'fullchain.cer').write_text('broken')
            return 1
        self.controller.invoke_acme = mock.Mock(side_effect=corrupt)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        with self.assertRaisesRegex(certctl.Failure, '不会通过恢复流程再次签发'):
            self.controller.run()
        self.controller.invoke_acme.assert_called_once()
        resume = self.state()['resume_normal_at']
        original_expiry = certctl.certificate_expiry
        def expiry(path):
            return resume + 90 * 86400 if certctl.fingerprint(path) == self.fixture.new_fingerprint else original_expiry(path)
        def normal(arguments):
            self.assertNotIn('--force', arguments)
            if arguments[0] == '--issue':
                self.fixture.prepare_candidate('new')
            elif arguments[0] == '--deploy':
                self.fixture.install_current('new')
            else:
                self.fail('损坏候选应走既有恢复签发')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=normal)
        with mock.patch.object(certctl.time, 'time', return_value=resume), \
                mock.patch.object(certctl, 'certificate_expiry', side_effect=expiry):
            self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertFalse(self.state()['recovery_only'])
        self.assertEqual(self.state()['state'], 'failed')

    def test_missing_material_after_manual_issue_failure_cannot_bootstrap_again(self):
        shutil.rmtree(self.controller.candidate_dir())
        self.request()
        self.controller.invoke_acme = mock.Mock(return_value=1)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_args.args[0][0], '--issue')
        for attempt in range(2):
            with self.subTest(attempt=attempt), self.assertRaises(certctl.Failure):
                self.controller.run()
        self.controller.invoke_acme.assert_called_once()
        self.assertTrue(self.state()['recovery_only'])
        self.assertGreater(self.state()['resume_normal_at'], time.time() + 86400)

    def test_failed_issue_allows_credential_repair_and_new_explicit_request_after_cooldown(self):
        shutil.rmtree(self.controller.candidate_dir())
        first = self.request()
        self.controller.invoke_acme = mock.Mock(return_value=1)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.release_manual_protection()
        self.assertFalse((self.controller.state / 'run-baseline.json').exists())
        self.assertTrue(self.state()['recovery_only'])
        self.controller.config.update(secret_id='REPAIRED_ID', secret_key='REPAIRED_KEY')
        with self.assertRaises(certctl.Busy):
            self.request()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_called_once()
        with mock.patch.object(certctl.time, 'time', return_value=first['cooldown_until']):
            second = self.request()
            self.assertNotEqual(second['request_id'], first['request_id'])
            self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
            self.controller.run()
        self.assertEqual(self.state()['state'], 'succeeded')

    def test_new_material_or_changed_bindings_cannot_release_failed_request_protection(self):
        self.request()
        def issue(arguments):
            self.fixture.prepare_candidate('new')
            return 1
        self.controller.invoke_acme = mock.Mock(side_effect=issue)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        before = (self.controller.state / 'run-baseline.json').read_bytes()
        with self.assertRaises(certctl.Failure):
            self.controller.release_manual_protection()
        self.assertEqual((self.controller.state / 'run-baseline.json').read_bytes(), before)
        self.fixture.prepare_candidate('old')
        (self.controller.state / 'pending.json').unlink()
        info = self.controller.metadata()
        info['ABC123']['services'].append({'service': 'changed'})
        certctl.save_json(self.controller.archive / 'INFO', info)
        with self.assertRaises(certctl.Failure):
            self.controller.release_manual_protection()

    def test_explicit_new_request_can_recover_old_damaged_material_once(self):
        first = self.request()
        def corrupt(arguments):
            (self.controller.candidate_dir() / 'fullchain.cer').write_text('broken')
            return 1
        self.controller.invoke_acme = mock.Mock(side_effect=corrupt)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        with mock.patch.object(certctl.time, 'time', return_value=first['cooldown_until']):
            second = self.request()
            self.assertNotEqual(second['request_id'], first['request_id'])
            self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
            self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertEqual(self.controller.invoke_acme.call_args_list[0].args[0][0], '--issue')
        self.assertEqual(self.state()['state'], 'succeeded')

    def test_successful_target_change_retires_only_released_failed_intent(self):
        shutil.rmtree(self.controller.candidate_dir())
        self.request()
        self.controller.invoke_acme = mock.Mock(return_value=1)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.release_manual_protection()
        self.controller.config['domains'] = ['other.example.com']
        self.controller.retire_manual_target()
        self.assertEqual(self.state()['state'], 'failed')
        self.assertFalse(self.state()['recovery_only'])

    def test_legacy_policy_resumes_ordinary_acme_rules_after_cooldown(self):
        self.controller.config.pop('renew_before_days')
        self.request()
        self.controller.invoke_acme = mock.Mock(return_value=1)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual(self.state()['resume_normal_at'], self.state()['cooldown_until'])

    def test_interruption_during_quarantine_cannot_restart_as_unforced_bootstrap(self):
        (self.controller.candidate_dir() / 'fullchain.cer').write_text('broken')
        self.request()
        recover = self.controller.recover_candidate
        def crash():
            self.assertTrue(self.state()['force_consumed'])
            recover()
            raise SystemExit('crash after quarantine')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不得重新bootstrap'))
        with mock.patch.object(self.controller, 'recover_candidate', side_effect=crash):
            with self.assertRaises(SystemExit):
                self.controller.run()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()

    def test_pre_issue_expiry_consumes_no_force(self):
        request = self.request()
        def delayed(**kwargs):
            clock.return_value = request['expires_at']
            return self.controller.metadata()
        self.controller.preflight = mock.Mock(side_effect=delayed)
        self.controller.invoke_acme = mock.Mock()
        with mock.patch.object(certctl.time, 'time', return_value=request['requested_at']) as clock:
            with self.assertRaisesRegex(certctl.Failure, '过期'):
                self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(self.state()['state'], 'expired')
        self.assertFalse(self.state()['force_consumed'])

    def test_notification_failure_retries_mail_without_second_issuance(self):
        self.request()
        self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
        self.controller.send_success_notification = mock.Mock(side_effect=certctl.Failure('邮件发送失败'))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual(self.state()['state'], 'failed')
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)
        self.controller.send_success_notification.side_effect = None
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertEqual(self.controller.send_success_notification.call_count, 2)
        self.assertEqual(self.state()['state'], 'succeeded')

    def test_dns_cleanup_failure_preserves_failure_then_recovers_without_issue(self):
        self.request()
        def issue(arguments):
            result = self.issue_and_deploy(arguments)
            self.controller.dns_cleanup_count.return_value = 1
            return result
        self.controller.dns_cleanup_count = mock.Mock(return_value=0)
        self.controller.invoke_acme = mock.Mock(side_effect=issue)
        with self.assertRaisesRegex(certctl.Failure, '清理失败'):
            self.controller.run()
        self.assertEqual(self.state()['state'], 'failed')
        def cleanup():
            self.controller.dns_cleanup_count.return_value = 0
            return True
        self.controller.retry_dns_cleanup = mock.Mock(side_effect=cleanup)
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertEqual(self.state()['state'], 'succeeded')


if __name__ == '__main__':
    unittest.main()
