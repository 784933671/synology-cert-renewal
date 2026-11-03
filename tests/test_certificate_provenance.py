import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('provenance_fixture', Path(__file__).with_name('test_certctl.py'))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
certctl = FIXTURE.certctl


class CertificateProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURE.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURE.CertificateTests.tearDownClass)

    def setUp(self):
        self.fixture = FIXTURE.CertificateTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.configure_runtime_mocks()
        self.controller = self.fixture.controller
        self.controller.config.update(deployment_method='local_api', renew_before_days=2)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('unexpected CA request'))
        self.controller.deploy_local_api = mock.Mock(side_effect=lambda before:self.fixture.install_current('new'))

    def baseline(self):
        return certctl.read_json(self.controller.state / 'run-baseline.json')

    def test_regular_check_refuses_orphan_old_candidate_after_external_replacement(self):
        self.fixture.prepare_candidate('old')
        self.fixture.install_current('new')
        certctl.save_json(self.controller.state / 'last-result.json', {
            'success': True, 'fingerprint': self.fixture.old_fingerprint})
        with self.assertRaisesRegex(certctl.Failure, '拒绝用旧候选覆盖'):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)
        self.assertFalse((self.controller.state / 'pending.json').exists())

    def test_valid_pending_cannot_override_external_shorter_lived_certificate(self):
        self.fixture.prepare_candidate('new')
        self.fixture.record_owned_candidate()
        self.controller.save_pending(self.fixture.new_fingerprint, self.controller.binding_state(self.fixture.info))
        self.fixture.install_current('short')
        external = certctl.fingerprint(self.controller.current_cert())
        with self.assertRaisesRegex(certctl.Failure, '被外部替换'):
            self.controller.run()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), external)

    def test_external_replacement_during_issuance_is_not_overwritten(self):
        self.fixture.install_current('short')
        self.fixture.prepare_candidate('short')
        def issue(arguments):
            self.assertTrue(self.baseline()['issuance_started'])
            self.fixture.prepare_candidate('new')
            self.fixture.install_current('old')
            return 0
        self.controller.invoke_acme.side_effect = issue
        with self.assertRaisesRegex(certctl.Failure, '被外部替换'):
            self.controller.run()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.old_fingerprint)

    def test_interruption_after_issuance_recovers_without_pending_or_second_ca_request(self):
        def issue(arguments):
            self.assertEqual(arguments[0], '--issue')
            self.assertTrue(self.baseline()['issuance_started'])
            self.assertIsNone(self.baseline()['candidate_before'])
            self.fixture.prepare_candidate('new')
            raise SystemExit('interrupted after material was written')
        self.controller.invoke_acme.side_effect = issue
        with self.assertRaises(SystemExit):
            self.controller.run()
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertIsNone(self.baseline()['issued_fingerprint'])
        self.controller.invoke_acme.side_effect = AssertionError('must recover existing material')
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 1)
        self.controller.deploy_local_api.assert_called_once()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)

    def test_interruption_after_import_recovers_same_candidate(self):
        self.fixture.prepare_candidate('new')
        self.fixture.record_owned_candidate()
        def imported(before):
            self.fixture.install_current('new')
            raise SystemExit('interrupted after DSM import')
        self.controller.deploy_local_api.side_effect = imported
        with self.assertRaises(SystemExit):
            self.controller.run()
        self.assertTrue((self.controller.state / 'pending.json').exists())
        self.controller.deploy_local_api.side_effect = lambda before:None
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertFalse((self.controller.state / 'pending.json').exists())

    def test_imported_owned_certificate_remains_recognized_after_corrupt_key_is_quarantined(self):
        for recorded in (True, False):
            with self.subTest(recorded_result=recorded):
                self.fixture.install_current('old')
                self.fixture.prepare_candidate('new')
                self.fixture.record_owned_candidate()
                if not recorded:
                    baseline = self.baseline()
                    baseline['issued_fingerprint'] = None
                    self.controller.save_run_baseline(baseline)
                self.fixture.install_current('new')
                (self.controller.candidate_dir() / 'ttxli.cn.key').write_text('broken-key')
                def issue(arguments):
                    self.assertEqual(arguments[0], '--issue')
                    self.assertEqual(self.baseline()['certificate_fingerprint'], self.fixture.new_fingerprint)
                    self.fixture.prepare_candidate('new')
                    return 0
                self.controller.invoke_acme = mock.Mock(side_effect=issue)
                self.controller.run()
                self.controller.invoke_acme.assert_called_once()
                self.assertFalse((self.controller.state / 'pending.json').exists())
                self.assertTrue(certctl.read_json(self.controller.state / 'last-result.json')['success'])

    def test_legacy_pending_migrates_only_with_matching_success_baseline(self):
        self.fixture.prepare_candidate('new')
        certctl.save_json(self.controller.state / 'pending.json', {'fingerprint': self.fixture.new_fingerprint})
        certctl.save_json(self.controller.state / 'last-result.json', {
            'success': True, 'fingerprint': self.fixture.old_fingerprint})
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_called_once()

    def test_legacy_pending_without_known_baseline_is_preserved_for_review(self):
        self.fixture.prepare_candidate('new')
        path = self.controller.state / 'pending.json'
        certctl.save_json(path, {'fingerprint': self.fixture.new_fingerprint})
        original = path.read_bytes()
        with self.assertRaisesRegex(certctl.Failure, '缺少可核实的签发来源'):
            self.controller.run()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(path.read_bytes(), original)

    def test_recorded_candidate_substitution_is_rejected_even_with_same_sans(self):
        self.fixture.prepare_candidate('new')
        self.fixture.record_owned_candidate()
        self.fixture.prepare_candidate('short')
        with self.assertRaisesRegex(certctl.Failure, '不是本次已记录签发'):
            self.controller.run()
        self.controller.deploy_local_api.assert_not_called()

    def test_existing_matching_candidate_needs_no_issuance_after_upgrade(self):
        self.fixture.prepare_candidate('old')
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertTrue(certctl.read_json(self.controller.state / 'last-result.json')['success'])

    def test_issuance_intent_is_fsynced_before_calling_ca(self):
        calls = []
        fsync = certctl.os.fsync
        def synced(descriptor):
            calls.append('fsync')
            return fsync(descriptor)
        def issue(arguments):
            self.assertTrue(self.baseline()['issuance_started'])
            self.assertEqual(calls[-1], 'fsync')
            calls.append('ca')
            self.fixture.prepare_candidate('new')
            return 0
        self.controller.invoke_acme.side_effect = issue
        with mock.patch.object(certctl.os, 'fsync', side_effect=synced):
            self.controller.run()
        self.assertEqual(calls.count('ca'), 1)


if __name__ == '__main__':
    unittest.main()
