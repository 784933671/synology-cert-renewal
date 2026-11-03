import importlib.util
from pathlib import Path
import re
import shutil
import ssl
import stat
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'renewal_policy_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


def expiry(path):
    text = certctl.capture(['openssl', 'x509', '-in', str(path), '-noout', '-enddate']).decode().strip()
    return int(ssl.cert_time_to_seconds(text.split('=', 1)[1]))


def domain_config(path):
    return dict(re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)='([^']*)'$", path.read_text()))


class RenewalPolicyConfigurationTests(unittest.TestCase):
    def test_fixed_renewal_days_are_optional_and_strictly_bounded(self):
        certctl.validate_config(FIXTURES.configuration())
        for days in (1, 2, 30):
            with self.subTest(days=days):
                certctl.validate_config(dict(FIXTURES.configuration(), renew_before_days=days))
        for days in (True, False, '2', None, 0, -2, 31, 1.5):
            with self.subTest(days=days):
                with self.assertRaises(certctl.Failure):
                    certctl.validate_config(dict(FIXTURES.configuration(), renew_before_days=days))


class RenewalPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURES.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURES.CertificateTests.tearDownClass)
        fixtures = FIXTURES.CertificateTests.fixtures
        FIXTURES.openssl('x509', '-req', '-in', str(fixtures / 'old.csr'), '-days', '10',
                         '-CA', str(fixtures / 'ca.pem'), '-CAkey', str(fixtures / 'ca.key'),
                         '-CAcreateserial', '-extfile', str(fixtures / 'old.cnf'),
                         '-extensions', 'ext', '-out', str(fixtures / 'ten.pem'))
        shutil.copyfile(fixtures / 'old.key', fixtures / 'ten.key')

    def setUp(self):
        self.fixture = FIXTURES.CertificateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.configure_runtime_mocks()
        self.controller = self.fixture.controller
        self.controller.config['renew_before_days'] = 2

    def installed_candidate(self, name):
        self.fixture.install_current(name)
        self.fixture.prepare_candidate(name)
        return certctl.fingerprint(self.controller.current_cert())

    def assert_success(self):
        result = certctl.read_json(self.controller.state / 'last-result.json')
        self.assertTrue(result['success'])
        self.assertEqual(result['fingerprint'], certctl.fingerprint(self.controller.current_cert()))
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertFalse((self.controller.state / 'run-baseline.json').exists())

    def test_deployed_ten_day_certificate_waits_without_recovery_or_acme_calls(self):
        served = self.installed_candidate('ten')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('48 小时窗口外不得申请'))
        with mock.patch.object(self.controller, 'recover_candidate',
                               side_effect=AssertionError('已部署且有效的证书不能因不足 14 天被恢复')):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertGreater(self.controller.probe_fingerprint.call_count, 0)
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), served)
        self.assert_success()

    def test_fixed_policy_wait_still_detects_wrong_live_tls(self):
        self.installed_candidate('ten')
        self.controller.probe_fingerprint.return_value = None
        self.controller.probe_fingerprint.side_effect = lambda probe, **kwargs: '0' * 64
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不得申请'))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertTrue((self.controller.state / 'pending.json').exists())

    def test_deployed_one_day_certificate_renews_then_deploys_fresh_material(self):
        self.installed_candidate('short')
        calls = []
        def acme(arguments):
            calls.append(arguments)
            if arguments[0] == '--renew':
                self.fixture.prepare_candidate('new')
                return 0
            if arguments[0] == '--deploy':
                self.fixture.install_current('new')
                return 0
            self.fail('完整有效的已部署证书应续期，不能隔离后重新签发')
        self.controller.invoke_acme = mock.Mock(side_effect=acme)
        with mock.patch.object(self.controller, 'recover_candidate',
                               side_effect=AssertionError('不能进入损坏恢复')):
            self.controller.run()
        self.assertEqual([args[0] for args in calls], ['--renew', '--deploy'])
        self.assertFalse(any('--force' in args for args in calls))
        self.assert_success()

    def test_exact_48_hour_boundary_controls_renewal_and_rejects_false_skip(self):
        self.installed_candidate('old')
        due = expiry(self.controller.candidate()) - 2 * 86400
        self.controller.invoke_acme = mock.Mock(return_value=2)
        with mock.patch.object(certctl.time, 'time', return_value=due - 1):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assert_success()
        for moment in (due, due + 1):
            with self.subTest(moment=moment), \
                 mock.patch.object(certctl.time, 'time', return_value=moment), \
                 mock.patch.object(self.controller, 'recover_candidate',
                                   side_effect=AssertionError('未损坏的旧证书不能恢复')):
                self.controller.invoke_acme.reset_mock()
                with self.assertRaises(certctl.Failure):
                    self.controller.run()
                self.controller.invoke_acme.assert_called_once()
                self.assertEqual(self.controller.invoke_acme.call_args.args[0][0], '--renew')
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.old_fingerprint)

    def test_pending_current_certificate_in_window_renews_before_any_redeploy(self):
        self.installed_candidate('short')
        certctl.save_json(self.controller.state / 'pending.json', {'at': certctl.now()})
        calls = []
        def acme(arguments):
            calls.append(arguments[0])
            if arguments[0] == '--renew':
                self.fixture.prepare_candidate('new')
                return 0
            if arguments[0] == '--deploy':
                self.fixture.install_current('new')
                return 0
            self.fail('不应重新签发已有完整证书')
        self.controller.invoke_acme = mock.Mock(side_effect=acme)
        self.controller.run()
        self.assertEqual(calls, ['--renew', '--deploy'])
        self.assert_success()

    def test_pending_fresh_certificate_is_deployed_even_outside_renewal_window(self):
        self.fixture.prepare_candidate('new')
        self.fixture.record_owned_candidate()
        certctl.save_json(self.controller.state / 'pending.json', {'at': certctl.now()})
        def acme(arguments):
            self.assertEqual(arguments[0], '--deploy')
            self.fixture.install_current('new')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=acme)
        self.controller.run()
        self.controller.invoke_acme.assert_called_once()
        self.assert_success()

    def test_new_short_or_wrong_domain_certificate_is_still_rejected(self):
        for fixture in ('short', 'wrong'):
            with self.subTest(fixture=fixture):
                self.fixture.prepare_candidate(fixture)
                with self.assertRaises(certctl.Failure):
                    self.controller.candidate_valid()
                self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.old_fingerprint)

    def test_old_configuration_keeps_existing_acme_renewal_behavior(self):
        self.controller.config.pop('renew_before_days')
        self.installed_candidate('old')
        self.controller.invoke_acme = mock.Mock(return_value=2)
        self.controller.run()
        self.controller.invoke_acme.assert_called_once_with(['--renew', '-d', 'ttxli.cn'])
        self.assert_success()

    def test_existing_acme_schedule_is_migrated_from_real_certificate_expiry(self):
        served = self.installed_candidate('old')
        conf = self.controller.candidate_dir() / 'ttxli.cn.conf'
        conf.write_text(conf.read_text() + "Le_RenewalDays='60'\nLe_NextRenewTime='1234567890'\n"
                        "Le_NextRenewTimeStr='old schedule'\nLe_DeployHook='synology_dsm'\n"
                        "Le_Keylength='2048'\n")
        key = self.controller.candidate_dir() / 'ttxli.cn.key'
        original_key = key.read_bytes()
        self.controller.prepare_acme_config()
        values = domain_config(conf)
        self.assertEqual(values['Le_RenewalDays'], '-2')
        self.assertEqual(values['NO_ARI'], '1')
        self.assertEqual(int(values['Le_NextRenewTime']), expiry(self.controller.candidate()) - 172800)
        self.assertNotEqual(values['Le_NextRenewTimeStr'], 'old schedule')
        self.assertEqual(values['Le_Keylength'], '2048')
        self.assertNotIn('Le_DeployHook', values)
        self.assertEqual(stat.S_IMODE(conf.stat().st_mode), 0o600)
        self.assertEqual(key.read_bytes(), original_key)
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), served)

    def test_schedule_migration_refuses_foreign_domain_before_writing(self):
        self.installed_candidate('old')
        conf = self.controller.candidate_dir() / 'ttxli.cn.conf'
        original = conf.read_text().replace("Le_Domain='ttxli.cn'", "Le_Domain='unrelated.example.com'")
        conf.write_text(original)
        with self.assertRaises(certctl.Failure):
            self.controller.prepare_acme_config()
        self.assertEqual(conf.read_text(), original)

    def test_no_policy_keeps_existing_schedule_metadata(self):
        self.controller.config.pop('renew_before_days')
        self.installed_candidate('old')
        conf = self.controller.candidate_dir() / 'ttxli.cn.conf'
        original = conf.read_text() + "Le_RenewalDays='60'\nLe_NextRenewTime='1234567890'\n"
        conf.write_text(original)
        self.controller.prepare_acme_config()
        self.assertEqual(conf.read_text(), original)

    def test_damaged_or_missing_leaf_is_quarantined_and_reissued_with_fixed_policy(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.installed_candidate('old')
                leaf = self.controller.candidate()
                if missing:
                    leaf.unlink()
                else:
                    leaf.write_text('MALFORMED LEAF CERTIFICATE\n')
                certctl.save_json(self.controller.state / 'pending.json', {'at': certctl.now()})
                calls = []
                def acme(arguments):
                    calls.append(arguments[0])
                    if arguments[0] == '--issue':
                        self.assertFalse(self.controller.candidate_dir().exists())
                        self.assertEqual(certctl.fingerprint(self.controller.current_cert()),
                                         self.fixture.old_fingerprint)
                        preserved = list((self.controller.state / 'recovery-backups').glob('*/ttxli.cn'))
                        self.assertTrue(preserved)
                        if not missing:
                            self.assertTrue(any((p / 'ttxli.cn.cer').read_text() == 'MALFORMED LEAF CERTIFICATE\n'
                                                for p in preserved if (p / 'ttxli.cn.cer').exists()))
                        self.fixture.prepare_candidate('new')
                        return 0
                    if arguments[0] == '--deploy':
                        self.fixture.install_current('new')
                        return 0
                    self.fail('坏证书应隔离后签发，不能被旧续期时间跳过')
                self.controller.invoke_acme = mock.Mock(side_effect=acme)
                self.controller.run()
                self.assertEqual(calls, ['--issue', '--deploy'])
                self.assertFalse((self.controller.state / 'recovery.json').exists())
                self.assert_success()

    def test_two_day_policy_recovery_retries_after_six_hours_not_earlier(self):
        original = self.installed_candidate('old')
        timestamp = int(time.time())
        with mock.patch.object(certctl.time, 'time', return_value=timestamp):
            self.controller.recover_candidate()
        self.fixture.prepare_candidate('old')
        with mock.patch.object(certctl.time, 'time', return_value=timestamp + 6 * 3600 - 1):
            with self.assertRaises(certctl.Failure):
                self.controller.recover_candidate()
        saved = certctl.read_json(self.controller.state / 'recovery.json')
        self.assertEqual(saved['attempts'], 1)
        self.assertTrue(self.controller.candidate().exists())
        with mock.patch.object(certctl.time, 'time', return_value=timestamp + 6 * 3600):
            self.controller.recover_candidate()
        saved = certctl.read_json(self.controller.state / 'recovery.json')
        self.assertEqual(saved['attempts'], 2)
        self.assertEqual(saved['last_attempt'], timestamp + 6 * 3600)
        self.assertFalse(self.controller.candidate_dir().exists())
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), original)

    def test_legacy_and_longer_policies_keep_24_hour_recovery_cooldown(self):
        for days in (None, 3):
            with self.subTest(days=days):
                if days is None:
                    self.controller.config.pop('renew_before_days', None)
                else:
                    self.controller.config['renew_before_days'] = days
                (self.controller.state / 'recovery.json').unlink(missing_ok=True)
                self.installed_candidate('old')
                timestamp = int(time.time())
                with mock.patch.object(certctl.time, 'time', return_value=timestamp):
                    self.controller.recover_candidate()
                self.fixture.prepare_candidate('old')
                with mock.patch.object(certctl.time, 'time', return_value=timestamp + 6 * 3600):
                    with self.assertRaises(certctl.Failure):
                        self.controller.recover_candidate()
                self.assertEqual(certctl.read_json(self.controller.state / 'recovery.json')['attempts'], 1)
                with mock.patch.object(certctl.time, 'time', return_value=timestamp + 24 * 3600):
                    self.controller.recover_candidate()
                self.assertEqual(certctl.read_json(self.controller.state / 'recovery.json')['attempts'], 2)

    def test_acme_issue_and_renew_receive_negative_days_and_disable_ari(self):
        self.installed_candidate('old')
        self.controller.config['deployment_method'] = 'local_api'
        process = mock.Mock(wait=mock.Mock(return_value=2), poll=mock.Mock(return_value=2))
        real_popen = certctl.subprocess.Popen
        acme_calls = []
        def launch(command, *args, **kwargs):
            if command[:2] == ['/bin/sh', str(self.controller.acme / 'acme.sh')]:
                acme_calls.append((command, kwargs))
                return process
            return real_popen(command, *args, **kwargs)
        for operation in ('--issue', '--renew'):
            with self.subTest(operation=operation), \
                 mock.patch.object(self.controller, 'system_check'), \
                 mock.patch.object(certctl.subprocess, 'Popen', side_effect=launch):
                self.assertEqual(self.controller.invoke_acme([operation, '-d', 'ttxli.cn']), 2)
                args, kwargs = acme_calls[-1]
                self.assertEqual(args[args.index('--days') + 1], '-2')
                self.assertEqual(kwargs['env']['NO_ARI'], '1')
                self.assertNotIn('--force', args)
                self.assertFalse(self.controller.marker.exists())
        self.assertEqual(len(acme_calls), 2)


if __name__ == '__main__':
    unittest.main()
