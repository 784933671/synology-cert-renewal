import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'binding_recovery_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


class BindingRecoveryTests(unittest.TestCase):
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

    def write_info(self, info):
        certctl.save_json(self.fixture.archive / 'INFO', info)

    def add_unrelated(self, info, identifier='OTHER1'):
        info[identifier] = {'desc': identifier, 'services': []}
        return info

    def install_candidate(self, name='old'):
        self.fixture.install_current(name)
        self.fixture.prepare_candidate(name)

    def save_legacy_baseline(self, info):
        certctl.save_json(self.controller.state / 'run-baseline.json', {
            'certificate_id': 'ABC123', 'bindings': self.controller.binding_state(info)})

    def assert_success(self):
        result = certctl.read_json(self.controller.state / 'last-result.json')
        self.assertTrue(result['success'])
        self.assertEqual(result['fingerprint'], certctl.fingerprint(self.controller.current_cert()))
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertFalse((self.controller.state / 'run-baseline.json').exists())

    def renewal_and_deployment(self, on_renew=None, on_deploy=None):
        def acme(arguments):
            if arguments[0] == '--renew':
                self.fixture.prepare_candidate('new')
                if on_renew:
                    on_renew()
                return 0
            if arguments[0] == '--deploy':
                self.fixture.install_current('new')
                if on_deploy:
                    on_deploy()
                return 0
            self.fail('现有完整证书应续期，不应重新签发')
        self.controller.invoke_acme = mock.Mock(side_effect=acme)

    def test_unrelated_certificate_created_during_renewal_still_deploys(self):
        self.install_candidate('short')
        changed = self.add_unrelated(copy.deepcopy(self.fixture.info), 'QUICKCONNECT')
        self.renewal_and_deployment(on_renew=lambda: self.write_info(changed))
        self.controller.run()
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list],
                         ['--renew', '--deploy'])
        self.assertEqual(certctl.read_json(self.fixture.archive / 'INFO'), changed)
        self.assert_success()

    def test_legacy_baseline_allows_unrelated_certificate_added_between_runs(self):
        self.install_candidate()
        self.save_legacy_baseline(self.fixture.info)
        self.write_info(self.add_unrelated(copy.deepcopy(self.fixture.info)))
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不能签发'))
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assert_success()

    def test_legacy_baseline_allows_unrelated_certificate_removed_between_runs(self):
        self.install_candidate()
        previous = self.add_unrelated(copy.deepcopy(self.fixture.info))
        self.save_legacy_baseline(previous)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不能签发'))
        self.controller.run()
        self.assert_success()

    def test_legacy_baseline_allows_unrelated_service_changes_between_runs(self):
        self.install_candidate()
        previous = self.add_unrelated(copy.deepcopy(self.fixture.info))
        self.save_legacy_baseline(previous)
        changed = copy.deepcopy(previous)
        changed['OTHER1']['services'] = [{'service': 'ftp', 'subscriber': 'system', 'isPkg': False}]
        self.write_info(changed)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不能签发'))
        self.controller.run()
        self.assert_success()

    def test_legacy_baseline_allows_default_switch_between_other_certificates(self):
        self.install_candidate()
        info = self.add_unrelated(self.add_unrelated(copy.deepcopy(self.fixture.info)), 'OTHER2')
        self.write_info(info)
        default = self.fixture.archive / 'DEFAULT'
        default.write_text('OTHER1')
        self.save_legacy_baseline(info)
        default.write_text('OTHER2')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不能签发'))
        self.controller.run()
        self.assertEqual(default.read_text(), 'OTHER2')
        self.assert_success()

    def test_legacy_baseline_still_blocks_target_service_change(self):
        self.install_candidate()
        self.save_legacy_baseline(self.fixture.info)
        changed = copy.deepcopy(self.fixture.info)
        changed['ABC123']['services'] = []
        self.write_info(changed)
        self.controller.invoke_acme = mock.Mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertTrue((self.controller.state / 'run-baseline.json').exists())

    def test_legacy_baseline_still_blocks_target_default_change(self):
        self.install_candidate()
        info = self.add_unrelated(copy.deepcopy(self.fixture.info))
        self.write_info(info)
        self.save_legacy_baseline(info)
        (self.fixture.archive / 'DEFAULT').write_text('OTHER1')
        self.controller.invoke_acme = mock.Mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()

    def test_failed_run_new_baseline_allows_unrelated_addition_on_retry(self):
        self.install_candidate('short')
        self.controller.invoke_acme = mock.Mock(return_value=1)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertTrue((self.controller.state / 'run-baseline.json').exists())
        self.write_info(self.add_unrelated(copy.deepcopy(self.fixture.info)))
        self.renewal_and_deployment()
        self.controller.run()
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list],
                         ['--renew', '--deploy'])
        self.assert_success()

    def test_target_services_changed_during_renewal_blocks_deployment_and_retry(self):
        self.install_candidate('short')
        changed = copy.deepcopy(self.fixture.info)
        changed['ABC123']['services'] = []
        self.renewal_and_deployment(on_renew=lambda: self.write_info(changed))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list],
                         ['--renew'])
        self.controller.invoke_acme.reset_mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()),
                         certctl.fingerprint(self.fixture.fixtures / 'short.pem'))

    def test_target_default_changed_during_renewal_blocks_deployment(self):
        self.install_candidate('short')
        self.write_info(self.add_unrelated(copy.deepcopy(self.fixture.info)))
        self.renewal_and_deployment(
            on_renew=lambda: (self.fixture.archive / 'DEFAULT').write_text('OTHER1'))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list],
                         ['--renew'])

    def test_unrelated_service_mutation_during_import_stays_blocked_on_retry(self):
        self.install_candidate('short')
        info = self.add_unrelated(copy.deepcopy(self.fixture.info))
        info['OTHER1']['services'] = [{'service': 'ftp', 'subscriber': 'system', 'isPkg': False}]
        self.write_info(info)
        changed = copy.deepcopy(info)
        changed['OTHER1']['services'] = []
        self.renewal_and_deployment(on_deploy=lambda: self.write_info(changed))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertTrue((self.controller.state / 'pending.json').exists())
        self.controller.invoke_acme.reset_mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertFalse((self.controller.state / 'last-result.json').exists())
        self.write_info(info)
        self.renewal_and_deployment()
        self.controller.run()
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list],
                         ['--deploy'])
        self.assert_success()


if __name__ == '__main__':
    unittest.main()
