import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / 'certctl.py'
SPEC = importlib.util.spec_from_file_location('certctl', MODULE)
certctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(certctl)


def configuration():
    return {
        'version': 1,
        'certificate_id': 'ABC123',
        'certificate_description': 'ttxli-cn-auto',
        'domains': ['ttxli.cn', '*.ttxli.cn'],
        'email': 'operator@example.com',
        'secret_id': 'SECRET-ID-MUST-NOT-LEAK',
        'secret_key': 'SECRET-KEY-MUST-NOT-LEAK',
        'dsm_http_port': 5000,
        'probes': [{'host': '127.0.0.1', 'port': 5001, 'server_name': 'ttxli.cn'}],
    }


def openssl(*arguments):
    subprocess.run(['openssl'] + list(arguments), stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, check=True)


class ConfigurationTests(unittest.TestCase):
    def test_valid_domain_and_wildcard_boundaries(self):
        for domain in ('ttxli.cn', 'nas.ttxli.cn', '*.ttxli.cn', 'xn--fiqs8s.cn'):
            with self.subTest(domain=domain):
                self.assertTrue(certctl.valid_domain(domain))
        for domain in ('localhost', '*.cn', 'a..cn', '-bad.cn', 'bad-.cn', '192.168.1.1',
                       'TTXLI.cn', 'a/b.cn', '*.*.cn', 'a' * 64 + '.cn', '', None):
            with self.subTest(domain=domain):
                self.assertFalse(certctl.valid_domain(domain))
        self.assertTrue(certctl.covers(['*.ttxli.cn'], 'nas.ttxli.cn'))
        self.assertFalse(certctl.covers(['*.ttxli.cn'], 'ttxli.cn'))
        self.assertFalse(certctl.covers(['*.ttxli.cn'], 'deep.nas.ttxli.cn'))
        self.assertFalse(certctl.covers(['*.ttxli.cn'], 'nas.fake-ttxli.cn'))

    def test_normal_configuration_is_accepted(self):
        certctl.validate_config(configuration())

    def test_rejects_duplicate_domains_bad_ports_and_uncovered_sni(self):
        changes = [
            {'domains': ['ttxli.cn', 'ttxli.cn']},
            {'dsm_http_port': True},
            {'dsm_http_port': 0},
            {'certificate_id': '../ABC123'},
            {'certificate_description': 'bad\\description'},
            {'email': 'no-at-sign'},
            {'secret_key': ''},
            {'probes': []},
            {'probes': [{'host': '127.0.0.1', 'port': 5001, 'server_name': '*.ttxli.cn'}]},
            {'probes': [{'host': '127.0.0.1', 'port': 5001, 'server_name': 'deep.nas.ttxli.cn'}]},
            {'probes': [{'host': 'http://localhost', 'port': 5001, 'server_name': 'ttxli.cn'}]},
        ]
        for change in changes:
            with self.subTest(change=change):
                value = configuration()
                value.update(change)
                with self.assertRaises(certctl.Failure):
                    certctl.validate_config(value)

    def test_credentials_and_email_reject_shell_metacharacters(self):
        for key, value in (('secret_id', "AKID'quoted"), ('secret_key', '$(uname)'),
                           ('secret_key', 'line1\nline2'), ('secret_key', '`uname`'),
                           ('email', "user'quoted@example.com"), ('email', '$(uname)@example.com')):
            with self.subTest(field=key, value=value):
                config = configuration()
                config[key] = value
                with self.assertRaises(certctl.Failure):
                    certctl.validate_config(config)

    def test_regular_email_and_console_token_characters_are_accepted(self):
        config = configuration()
        config['email'] = 'operator.name+nas@example.com'
        config['secret_id'] = 'AKID_0123456789-abcd'
        config['secret_key'] = 'aZ09+/=_-'
        certctl.validate_config(config)

    def test_private_files_reject_permissions_symlinks_and_wrong_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'secret'
            path.write_text('secret')
            path.chmod(0o600)
            certctl.private(path, uid=os.getuid())
            path.chmod(0o644)
            with self.assertRaises(certctl.Failure):
                certctl.private(path, uid=os.getuid())
            path.chmod(0o600)
            with self.assertRaises(certctl.Failure):
                certctl.private(path, uid=os.getuid() + 1)
            link = Path(folder) / 'link'
            link.symlink_to(path)
            with self.assertRaises(certctl.Failure):
                certctl.private(link, uid=os.getuid())

    def test_atomic_json_has_private_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            certctl.save_json(path, {'value': "literal'\n$()"})
            self.assertEqual(certctl.read_json(path), {'value': "literal'\n$()"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_temp = tempfile.TemporaryDirectory()
        cls.fixtures = Path(cls.fixture_temp.name)
        ca_config = cls.fixtures / 'ca.cnf'
        ca_config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n'
                             '[dn]\nCN=Local Test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\n'
                             'keyUsage=critical,keyCertSign,cRLSign\n')
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
                '-config', str(ca_config), '-keyout', str(cls.fixtures / 'ca.key'),
                '-out', str(cls.fixtures / 'ca.pem'))
        for name, domains, days in (
            ('old', ['ttxli.cn', '*.ttxli.cn'], 90),
            ('new', ['ttxli.cn', '*.ttxli.cn'], 90),
            ('wrong', ['wrong.example.com'], 90),
            ('short', ['ttxli.cn', '*.ttxli.cn'], 1),
        ):
            conf = cls.fixtures / (name + '.cnf')
            conf.write_text('[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n'
                            '[dn]\nCN=' + domains[0] + '\n[ext]\nsubjectAltName=' +
                            ','.join('DNS:' + domain for domain in domains) + '\n'
                            'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n')
            key = cls.fixtures / (name + '.key')
            request = cls.fixtures / (name + '.csr')
            cert = cls.fixtures / (name + '.pem')
            openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', str(conf),
                    '-keyout', str(key), '-out', str(request))
            openssl('x509', '-req', '-in', str(request), '-days', str(days),
                    '-CA', str(cls.fixtures / 'ca.pem'), '-CAkey', str(cls.fixtures / 'ca.key'),
                    '-CAcreateserial', '-extfile', str(conf), '-extensions', 'ext', '-out', str(cert))
        cls.old_fingerprint = certctl.fingerprint(cls.fixtures / 'old.pem')
        cls.new_fingerprint = certctl.fingerprint(cls.fixtures / 'new.pem')

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.archive = self.root / 'archive'
        self.home.mkdir(mode=0o700)
        self.archive.mkdir(mode=0o700)
        (self.home / 'state').mkdir(mode=0o700)
        (self.home / 'acme').mkdir(mode=0o700)
        (self.archive / 'ABC123').mkdir(mode=0o700)
        self.info = {'ABC123': {'desc': 'ttxli-cn-auto', 'services': [
            {'service': 'default', 'subscriber': 'system', 'isPkg': False}]}}
        certctl.save_json(self.archive / 'INFO', self.info)
        (self.archive / 'DEFAULT').write_text('ABC123')
        self.install_current('old')
        self.controller = certctl.Controller(self.home, self.archive)
        self.controller.config = configuration()
        self.original_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.original_umask)
        original_private = certctl.private
        self.private_patch = mock.patch.object(certctl, 'private',
            side_effect=lambda path, directory=False, uid=0: original_private(path, directory, os.getuid()))
        self.private_patch.start()
        self.addCleanup(self.private_patch.stop)
        self.sleep_patch = mock.patch.object(certctl.time, 'sleep')
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)
        trust = mock.patch.dict(os.environ, {'SSL_CERT_FILE': str(self.fixtures / 'ca.pem')})
        trust.start()
        self.addCleanup(trust.stop)

    def install_current(self, fixture):
        target = self.archive / 'ABC123'
        shutil.copyfile(self.fixtures / (fixture + '.pem'), target / 'cert.pem')
        shutil.copyfile(self.fixtures / (fixture + '.key'), target / 'privkey.pem')
        shutil.copyfile(self.fixtures / 'ca.pem', target / 'chain.pem')
        (target / 'fullchain.pem').write_bytes((self.fixtures / (fixture + '.pem')).read_bytes()
                                             + (self.fixtures / 'ca.pem').read_bytes())

    def prepare_candidate(self, fixture='new'):
        target = self.controller.candidate_dir()
        target.mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(self.fixtures / (fixture + '.pem'), self.controller.candidate())
        shutil.copyfile(self.fixtures / (fixture + '.key'), target / 'ttxli.cn.key')
        shutil.copyfile(self.fixtures / 'ca.pem', target / 'ca.cer')
        (target / 'fullchain.cer').write_bytes(self.controller.candidate().read_bytes()
                                              + (target / 'ca.cer').read_bytes())
        (target / 'ttxli.cn.conf').write_text(
            "Le_Domain='ttxli.cn'\nLe_Alt='*.ttxli.cn'\nLe_Webroot='dns_tencent'\n"
            + "Le_API='" + certctl.CA + "'\n")

    def record_owned_candidate(self):
        current = certctl.fingerprint(self.controller.current_cert())
        self.controller.save_run_baseline({
            'certificate_id': self.controller.config['certificate_id'],
            'bindings': self.controller.binding_state(self.controller.metadata()),
            'provenance_version': 1, 'certificate_fingerprint': current,
            'candidate_before': None, 'issuance_started': True,
            'issued_fingerprint': self.controller.candidate_identity()
                if self.controller.candidate_identity() not in (None, 'unreadable') else None})

    def configure_runtime_mocks(self):
        self.controller.load = mock.Mock()
        self.controller.preflight = mock.Mock(side_effect=lambda **kwargs: self.controller.metadata())
        self.controller.probe_fingerprint = mock.Mock(side_effect=lambda probe, **kwargs:
            certctl.fingerprint(self.controller.current_cert()))
        self.controller.log = mock.Mock()

    def test_bootstrap_tls_probe_reads_untrusted_leaf_fingerprint_and_sends_sni(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.fixtures / 'new.pem'), str(self.fixtures / 'new.key'))
        received_names = []
        context.set_servername_callback(lambda connection, name, ctx: received_names.append(name))
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        errors = []
        def serve():
            try:
                raw, _ = listener.accept()
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as connection:
                    connection.recv(1)
            except Exception as error:
                errors.append(error)
            finally:
                listener.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            actual = self.controller.probe_fingerprint({
                'host': '127.0.0.1', 'port': port, 'server_name': 'ttxli.cn'}, verify_chain=False)
            self.assertEqual(actual, self.new_fingerprint)
        finally:
            thread.join(timeout=6)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received_names, ['ttxli.cn'])

    def test_real_certificate_domains_and_fingerprints(self):
        self.assertEqual(set(certctl.certificate_domains(self.controller.current_cert())),
                         {'ttxli.cn', '*.ttxli.cn'})
        self.assertNotEqual(self.old_fingerprint, self.new_fingerprint)

    def test_metadata_rejects_duplicate_description(self):
        info = copy.deepcopy(self.info)
        info['XYZ789'] = copy.deepcopy(info['ABC123'])
        certctl.save_json(self.archive / 'INFO', info)
        with self.assertRaises(certctl.Failure):
            self.controller.metadata()

    def test_metadata_rejects_changed_certificate_id(self):
        certctl.save_json(self.archive / 'INFO', {'XYZ789': self.info['ABC123']})
        with self.assertRaises(certctl.Failure):
            self.controller.metadata()

    def test_current_certificate_rejects_symlink_escape(self):
        target = self.archive / 'ABC123' / 'cert.pem'
        target.unlink()
        target.symlink_to(self.fixtures / 'old.pem')
        with self.assertRaises(certctl.Failure):
            self.controller.current_cert()

    def test_candidate_accepts_matching_key_and_sans(self):
        self.prepare_candidate()
        self.controller.candidate_valid()

    def test_candidate_rejects_wrong_key(self):
        self.prepare_candidate()
        shutil.copyfile(self.fixtures / 'old.key', self.controller.candidate_dir() / 'ttxli.cn.key')
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()

    def test_candidate_rejects_changed_sans(self):
        self.prepare_candidate('wrong')
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()

    def test_candidate_rejects_near_expiration(self):
        self.prepare_candidate('short')
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()

    def test_candidate_rejects_missing_chain(self):
        self.prepare_candidate()
        (self.controller.candidate_dir() / 'ca.cer').unlink()
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()

    def test_candidate_rejects_empty_ca(self):
        self.prepare_candidate()
        (self.controller.candidate_dir() / 'ca.cer').write_text('')
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()

    def test_candidate_rejects_leaf_only_fullchain(self):
        self.prepare_candidate()
        shutil.copyfile(self.controller.candidate(), self.controller.candidate_dir() / 'fullchain.cer')
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()

    def test_deploy_false_success_retains_pending(self):
        self.prepare_candidate()
        self.record_owned_candidate()
        before = self.controller.binding_state(self.info)
        self.controller.invoke_acme = mock.Mock(return_value=0)
        with self.assertRaises(certctl.Failure):
            self.controller.deploy_and_verify(before)
        self.assertTrue((self.controller.state / 'pending.json').exists())
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.old_fingerprint)

    def test_deploy_rejects_stale_live_tls(self):
        self.prepare_candidate()
        self.record_owned_candidate()
        before = self.controller.binding_state(self.info)
        self.controller.invoke_acme = mock.Mock(side_effect=lambda args: (self.install_current('new'), 0)[1])
        self.controller.probe_fingerprint = mock.Mock(return_value=self.old_fingerprint)
        with self.assertRaises(certctl.Failure):
            self.controller.deploy_and_verify(before)
        self.assertTrue((self.controller.state / 'pending.json').exists())

    def test_deploy_rejects_changed_service_bindings(self):
        self.prepare_candidate()
        self.record_owned_candidate()
        before = self.controller.binding_state(self.info)
        def deployment(args):
            self.install_current('new')
            changed = copy.deepcopy(self.info)
            changed['ABC123']['services'] = []
            certctl.save_json(self.archive / 'INFO', changed)
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=deployment)
        with self.assertRaises(certctl.Failure):
            self.controller.deploy_and_verify(before)
        self.assertTrue((self.controller.state / 'pending.json').exists())

    def test_first_failed_deployment_retried_on_next_run(self):
        self.configure_runtime_mocks()
        calls = []
        def first_run(args):
            calls.append(args)
            if '--issue' in args:
                self.prepare_candidate()
                return 0
            if '--deploy' in args:
                return 1
            self.fail('unexpected ACME command')
        self.controller.invoke_acme = mock.Mock(side_effect=first_run)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertTrue((self.controller.state / 'pending.json').exists())
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.old_fingerprint)
        calls.clear()
        def second_run(args):
            calls.append(args)
            if '--deploy' in args:
                self.install_current('new')
                return 0
            if '--renew' in args:
                return 2
            self.fail('should not force a second certificate issuance')
        self.controller.invoke_acme = mock.Mock(side_effect=second_run)
        self.controller.run()
        self.assertTrue(any('--deploy' in args for args in calls))
        self.assertFalse(any('--issue' in args or '--force' in args for args in calls))
        self.assertFalse((self.controller.state / 'pending.json').exists())
        result = certctl.read_json(self.controller.state / 'last-result.json')
        self.assertTrue(result['success'])
        state_text = '\n'.join(path.read_text() for path in self.controller.state.glob('*.json'))
        self.assertNotIn(self.controller.config['secret_id'], state_text)
        self.assertNotIn(self.controller.config['secret_key'], state_text)

    def test_near_expiry_pending_certificate_is_reissued_before_deployment(self):
        self.configure_runtime_mocks()
        self.prepare_candidate('short')
        self.record_owned_candidate()
        certctl.save_json(self.controller.state / 'pending.json', {
            'fingerprint': certctl.fingerprint(self.controller.candidate()), 'at': certctl.now()})
        calls = []
        def renewal(args):
            calls.append(args)
            if '--issue' in args:
                self.assertFalse(self.controller.candidate_dir().exists())
                self.prepare_candidate('new')
                return 0
            if '--deploy' in args:
                self.install_current('new')
                return 0
            self.fail('unusable candidate should be reissued from a clean domain directory')
        self.controller.invoke_acme = mock.Mock(side_effect=renewal)
        self.controller.run()
        self.assertIn('--issue', calls[0])
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.new_fingerprint)
        self.assertFalse((self.controller.state / 'pending.json').exists())

    def test_corrupt_pending_material_is_reissued_without_reusing_old_key_or_schedule(self):
        self.configure_runtime_mocks()
        for filename in ('fullchain.cer', 'ca.cer', 'ttxli.cn.key', 'ttxli.cn.cer', 'missing-leaf'):
            with self.subTest(filename=filename):
                self.install_current('old')
                self.prepare_candidate()
                self.record_owned_candidate()
                directory = self.controller.candidate_dir()
                conf = directory / 'ttxli.cn.conf'
                with conf.open('a') as handle:
                    handle.write("Le_NextRenewTime='4102444800'\n")
                (directory / 'ttxli.cn.csr').write_text('unusable old CSR')
                certctl.save_json(self.controller.state / 'pending.json', {'at': certctl.now()})
                if filename == 'missing-leaf':
                    self.controller.candidate().unlink()
                else:
                    (directory / filename).write_text('TRUNCATED')

                def acme(args):
                    if '--issue' in args:
                        self.assertFalse(directory.exists())
                        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.old_fingerprint)
                        self.assertEqual(args, ['--issue', '--dns', 'dns_tencent', '--keylength', '2048',
                            '--accountemail', 'operator@example.com', '-d', 'ttxli.cn', '-d', '*.ttxli.cn'])
                        self.prepare_candidate()
                        return 0
                    if '--deploy' in args:
                        self.install_current('new')
                        return 0
                    self.fail('damaged candidate must not use scheduled renewal')

                self.controller.invoke_acme = mock.Mock(side_effect=acme)
                self.controller.run()
                self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.new_fingerprint)
                self.assertFalse((self.controller.state / 'pending.json').exists())
                self.assertFalse((self.controller.state / 'recovery.json').exists())
                snapshots = list((self.controller.state / 'recovery-backups').iterdir())
                self.assertLessEqual(len(snapshots), certctl.RECOVERY_LIMIT)
                self.assertTrue(any((path / 'ttxli.cn' / 'ttxli.cn.csr').read_text() == 'unusable old CSR'
                                    for path in snapshots))

    def test_failed_recovery_is_rate_limited_and_stops_after_three_attempts(self):
        self.configure_runtime_mocks()
        self.prepare_candidate()
        self.record_owned_candidate()
        (self.controller.candidate_dir() / 'fullchain.cer').write_text('TRUNCATED')
        pending = self.controller.state / 'pending.json'
        certctl.save_json(pending, {'at': certctl.now()})

        def failed_issue(args):
            self.assertIn('--issue', args)
            self.prepare_candidate()
            (self.controller.candidate_dir() / 'fullchain.cer').write_text('TRUNCATED')
            return 1

        self.controller.invoke_acme = mock.Mock(side_effect=failed_issue)
        start = 2000000000
        for attempt in range(certctl.RECOVERY_LIMIT):
            with mock.patch.object(certctl.time, 'time', return_value=start + attempt * certctl.RECOVERY_INTERVAL):
                with self.assertRaisesRegex(certctl.Failure, '签发或续期失败'):
                    self.controller.run()
            self.assertEqual(self.controller.invoke_acme.call_count, attempt + 1)
            self.assertTrue(pending.exists())
            self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.old_fingerprint)
            if attempt == 0:
                with mock.patch.object(certctl.time, 'time', return_value=start + 60):
                    with self.assertRaisesRegex(certctl.Failure, '不足 24 小时'):
                        self.controller.run()
                self.assertEqual(self.controller.invoke_acme.call_count, 1)
        with mock.patch.object(certctl.time, 'time', return_value=start + 4 * certctl.RECOVERY_INTERVAL):
            with self.assertRaisesRegex(certctl.Failure, '连续尝试 3 次'):
                self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 3)
        self.assertEqual(certctl.read_json(self.controller.state / 'recovery.json')['attempts'], 3)

    def test_corruption_after_success_is_recovered_without_existing_pending_marker(self):
        self.configure_runtime_mocks()
        for filename in ('ttxli.cn.cer', 'fullchain.cer'):
            with self.subTest(filename=filename):
                self.install_current('old')
                self.prepare_candidate('old')
                (self.controller.candidate_dir() / filename).write_text('TRUNCATED')
                self.assertFalse((self.controller.state / 'pending.json').exists())

                def acme(args):
                    if '--issue' in args:
                        self.assertFalse(self.controller.candidate_dir().exists())
                        self.assertTrue((self.controller.state / 'pending.json').exists())
                        self.prepare_candidate()
                        return 0
                    self.assertIn('--deploy', args)
                    self.install_current('new')
                    return 0

                self.controller.invoke_acme = mock.Mock(side_effect=acme)
                self.controller.run()
                self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.new_fingerprint)
                self.assertFalse((self.controller.state / 'pending.json').exists())

    def test_valid_candidate_clears_interrupted_recovery_before_retrying_deployment(self):
        self.configure_runtime_mocks()
        self.prepare_candidate()
        self.record_owned_candidate()
        certctl.save_json(self.controller.state / 'pending.json', {'at': certctl.now()})
        recovery = self.controller.state / 'recovery.json'
        certctl.save_json(recovery, {'domains': self.controller.config['domains'],
            'attempts': certctl.RECOVERY_LIMIT, 'last_attempt': 2000000000})
        self.controller.invoke_acme = mock.Mock(return_value=1)
        with self.assertRaisesRegex(certctl.Failure, 'DSM 部署失败'):
            self.controller.run()
        self.controller.invoke_acme.assert_called_once_with(
            ['--deploy', '-d', 'ttxli.cn', '--deploy-hook', 'synology_dsm'])
        self.assertFalse(recovery.exists())
        self.assertTrue((self.controller.state / 'pending.json').exists())

    def test_recovery_validates_saved_config_before_quarantine_or_issuance(self):
        self.configure_runtime_mocks()
        self.prepare_candidate()
        self.record_owned_candidate()
        directory = self.controller.candidate_dir()
        (directory / 'fullchain.cer').write_text('TRUNCATED')
        with (directory / 'ttxli.cn.conf').open('a') as handle:
            handle.write("Le_PreHook='unexpected-command'\n")
        certctl.save_json(self.controller.state / 'pending.json', {'at': certctl.now()})
        self.controller.invoke_acme = mock.Mock()
        with self.assertRaisesRegex(certctl.Failure, '额外命令'):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertTrue(directory.exists())
        self.assertFalse((self.controller.state / 'recovery.json').exists())

    def test_recovered_valid_candidate_retries_deployment_without_another_issuance(self):
        self.configure_runtime_mocks()
        self.prepare_candidate()
        self.record_owned_candidate()
        (self.controller.candidate_dir() / 'fullchain.cer').write_text('TRUNCATED')
        pending = self.controller.state / 'pending.json'
        certctl.save_json(pending, {'at': certctl.now()})

        def first_attempt(args):
            if '--issue' in args:
                self.prepare_candidate()
                return 0
            self.assertIn('--deploy', args)
            return 1

        self.controller.invoke_acme = mock.Mock(side_effect=first_attempt)
        with self.assertRaisesRegex(certctl.Failure, 'DSM 部署失败'):
            self.controller.run()
        self.assertTrue(pending.exists())
        self.assertFalse((self.controller.state / 'recovery.json').exists())

        def second_attempt(args):
            if '--deploy' in args:
                self.install_current('new')
                return 0
            self.assertIn('--renew', args)
            return 2

        self.controller.invoke_acme = mock.Mock(side_effect=second_attempt)
        self.controller.run()
        self.assertFalse(pending.exists())
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.new_fingerprint)

    def test_deployed_certificate_with_stale_tls_is_retried_next_run(self):
        self.configure_runtime_mocks()
        self.prepare_candidate('old')
        def first_attempt(args):
            if '--renew' in args:
                self.prepare_candidate('new')
                return 0
            if '--deploy' in args:
                self.install_current('new')
                return 0
            self.fail('unexpected ACME command')
        self.controller.invoke_acme = mock.Mock(side_effect=first_attempt)
        self.controller.probe_fingerprint = mock.Mock(return_value=self.old_fingerprint)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.new_fingerprint)
        self.assertTrue((self.controller.state / 'pending.json').exists())
        calls = []
        def second_attempt(args):
            calls.append(args)
            if '--deploy' in args:
                self.controller.probe_fingerprint.return_value = self.new_fingerprint
                return 0
            if '--renew' in args:
                return 2
            self.fail('should retry deployment without issuing another certificate')
        self.controller.invoke_acme = mock.Mock(side_effect=second_attempt)
        self.controller.run()
        self.assertTrue(any('--deploy' in args for args in calls))
        self.assertFalse((self.controller.state / 'pending.json').exists())

    def test_changed_bindings_remain_blocked_on_next_run(self):
        self.configure_runtime_mocks()
        def first_attempt(args):
            if '--issue' in args:
                self.prepare_candidate('new')
                return 0
            if '--deploy' in args:
                self.install_current('new')
                changed = copy.deepcopy(self.info)
                changed['ABC123']['services'] = []
                certctl.save_json(self.archive / 'INFO', changed)
                return 0
            self.fail('unexpected ACME command')
        self.controller.invoke_acme = mock.Mock(side_effect=first_attempt)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme = mock.Mock(return_value=0)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()

    def test_return_two_is_success_when_existing_certificate_is_valid(self):
        self.configure_runtime_mocks()
        self.prepare_candidate('old')
        self.controller.invoke_acme = mock.Mock(return_value=2)
        self.controller.run()
        self.assertTrue(certctl.read_json(self.controller.state / 'last-result.json')['success'])
        self.assertFalse((self.controller.state / 'pending.json').exists())

    def test_return_two_without_expected_certificate_is_failure(self):
        self.configure_runtime_mocks()
        self.controller.invoke_acme = mock.Mock(return_value=2)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertFalse((self.controller.state / 'last-result.json').exists())

    def test_candidate_without_renewal_config_fails_before_acme(self):
        self.configure_runtime_mocks()
        self.prepare_candidate('old')
        (self.controller.candidate_dir() / 'ttxli.cn.conf').unlink()
        self.controller.invoke_acme = mock.Mock()
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.controller.invoke_acme.assert_not_called()

    def test_backup_preserves_key_and_binding_metadata(self):
        self.controller.backup(self.info)
        folders = list((self.controller.state / 'backups').iterdir())
        self.assertEqual(len(folders), 1)
        self.assertEqual((folders[0] / 'privkey.pem').read_bytes(), (self.fixtures / 'old.key').read_bytes())
        self.assertEqual(stat.S_IMODE((folders[0] / 'privkey.pem').stat().st_mode), 0o600)
        self.assertEqual(certctl.read_json(folders[0] / 'bindings.json'), self.controller.binding_state(self.info))
        self.controller.backup(self.info)
        self.assertEqual(len(list((self.controller.state / 'backups').iterdir())), 1)

    @contextlib.contextmanager
    def mocked_dsm(self, policy='none', existing_user=False):
        original_is_file = Path.is_file
        original_read_text = Path.read_text
        def is_file(path):
            return True if str(path) == '/etc.defaults/VERSION' else original_is_file(path)
        def read_text(path, *args, **kwargs):
            if str(path) == '/etc.defaults/VERSION':
                return 'productversion="7.2.1"\nmajorversion="7"\nminorversion="2"\nmicroversion="1"\n'
            return original_read_text(path, *args, **kwargs)
        def fake_capture(args, **kwargs):
            if args[0] == 'synogetkeyvalue':
                return policy.encode()
            if '--version' in args:
                return ('v' + certctl.ACME_VERSION + '\n').encode()
            raise AssertionError('unexpected command: ' + repr(args))
        with mock.patch.object(Path, 'is_file', is_file), mock.patch.object(Path, 'read_text', read_text), \
             mock.patch.object(certctl.shutil, 'which', return_value='/usr/bin/mock'), \
             mock.patch.object(certctl, 'capture', side_effect=fake_capture) as commands, \
             mock.patch.object(self.controller, 'temp_user_exists', return_value=existing_user), \
             mock.patch.object(certctl, 'private'):
            yield commands

    def test_forced_two_factor_refuses_without_mutating_policy(self):
        with self.mocked_dsm(policy='all') as commands:
            with self.assertRaises(certctl.Failure):
                self.controller.system_check()
        self.assertEqual(commands.call_args_list, [mock.call(
            ['synogetkeyvalue', '/etc/synoinfo.conf', 'otp_enforce_option'])])

    def test_preexisting_temporary_account_refuses_without_deleting(self):
        with self.mocked_dsm(existing_user=True) as commands:
            with self.assertRaises(certctl.Failure):
                self.controller.system_check()
        self.assertFalse(any('synouser' in call.args[0] or 'synosetkeyvalue' in call.args[0]
                             for call in commands.call_args_list))

    def test_nonempty_syno_create_zero_is_rejected(self):
        self.prepare_candidate()
        path = self.controller.candidate_dir() / 'ttxli.cn.conf'
        path.write_text(path.read_text() + "SAVED_SYNO_CREATE='0'\n")
        with mock.patch.object(self.controller, 'system_check'), mock.patch.object(certctl.subprocess, 'Popen') as popen:
            with self.assertRaises(certctl.Failure):
                self.controller.invoke_acme(['--deploy'])
        popen.assert_not_called()

    def test_prepare_acme_config_removes_automatic_deploy_hook_only(self):
        self.prepare_candidate()
        path = self.controller.candidate_dir() / 'ttxli.cn.conf'
        original = path.read_text()
        path.write_text(original + "Le_DeployHook='synology_dsm'\nLe_NextRenewTime='1234567890'\n")
        self.controller.prepare_acme_config()
        contents = path.read_text()
        self.assertNotIn('Le_DeployHook=', contents)
        self.assertIn("Le_NextRenewTime='1234567890'", contents)
        self.assertTrue(contents.startswith(original))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_prepare_acme_config_rejects_other_hooks_or_deploy_paths(self):
        for extra in ("Le_PreHook='echo unsafe'", "Le_PostHook='echo unsafe'",
                      "Le_RenewHook='echo unsafe'", "Le_ReloadCmd='echo unsafe'",
                      "Le_DeployHook='ssh'", "Le_RealCertPath='/etc/certificate.pem'",
                      "Le_RealKeyPath='/etc/key.pem'", "Le_RealCACertPath='/etc/ca.pem'",
                      "Le_RealFullChainPath='/etc/fullchain.pem'", "SAVED_SYNO_CREATE='0'"):
            with self.subTest(extra=extra):
                self.prepare_candidate()
                path = self.controller.candidate_dir() / 'ttxli.cn.conf'
                content = path.read_text() + extra + '\n'
                path.write_text(content)
                with self.assertRaises(certctl.Failure):
                    self.controller.prepare_acme_config()
                self.assertEqual(path.read_text(), content)

    def test_prepare_acme_config_rejects_scope_provider_or_ca_changes(self):
        for old, new in (("Le_Alt='*.ttxli.cn'", "Le_Alt='different.example.com'"),
                         ("Le_Domain='ttxli.cn'", "Le_Domain='different.example.com'"),
                         ("Le_Webroot='dns_tencent'", "Le_Webroot='dns_manual'"),
                         (certctl.CA, 'https://another-ca.example/directory')):
            with self.subTest(new=new):
                self.prepare_candidate()
                path = self.controller.candidate_dir() / 'ttxli.cn.conf'
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaises(certctl.Failure):
                    self.controller.prepare_acme_config()

    def test_prepare_acme_config_rejects_duplicate_fields_and_executable_lines(self):
        for extra in ("Le_Domain='ttxli.cn'", 'echo unsafe', "Le_Broken='unclosed"):
            with self.subTest(extra=extra):
                self.prepare_candidate()
                path = self.controller.candidate_dir() / 'ttxli.cn.conf'
                path.write_text(path.read_text() + extra + '\n')
                with self.assertRaises(certctl.Failure):
                    self.controller.prepare_acme_config()

    def test_prepare_acme_config_rejects_unquoted_and_command_suffix_assignments(self):
        for extra in ("Le_New=plain", 'Le_New="double-quoted"', "Le_New='safe'; echo unsafe",
                      "Le_New=$(uname)", "Le_New='safe'\necho unsafe"):
            with self.subTest(extra=extra):
                self.prepare_candidate()
                path = self.controller.candidate_dir() / 'ttxli.cn.conf'
                original = path.read_text() + extra + '\n'
                path.write_text(original)
                with self.assertRaises(certctl.Failure):
                    self.controller.prepare_acme_config()
                self.assertEqual(path.read_text(), original)

    def test_owned_temporary_user_is_cleaned_after_acme(self):
        process = mock.Mock()
        process.wait.return_value = 1
        process.poll.return_value = 1
        with mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'temp_user_exists', side_effect=[True, False]), \
             mock.patch.object(certctl.subprocess, 'Popen', return_value=process), \
             mock.patch.object(certctl, 'capture', return_value=b'') as commands:
            self.assertEqual(self.controller.invoke_acme(['--deploy']), 1)
        commands.assert_called_once_with(['synouser', '--del', certctl.TEMP_USER])
        self.assertFalse(self.controller.marker.exists())

    def test_failed_temporary_user_cleanup_keeps_interruption_marker(self):
        process = mock.Mock()
        process.wait.return_value = 0
        process.poll.return_value = 0
        with mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'temp_user_exists', return_value=True), \
             mock.patch.object(certctl.subprocess, 'Popen', return_value=process), \
             mock.patch.object(certctl, 'capture', return_value=b''):
            with self.assertRaises(certctl.Failure):
                self.controller.invoke_acme(['--deploy'])
        self.assertTrue(self.controller.marker.exists())

    def test_acme_process_does_not_inherit_proxy_or_expose_secret_in_argv(self):
        process = mock.Mock()
        process.wait.return_value = 0
        process.poll.return_value = 0
        with mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'temp_user_exists', return_value=False), \
             mock.patch.object(certctl.subprocess, 'Popen', return_value=process) as popen, \
             mock.patch.dict(os.environ, {'HTTP_PROXY': 'http://untrusted.example', 'DEBUG': '3'}):
            self.assertEqual(self.controller.invoke_acme(['--renew', '-d', 'ttxli.cn']), 0)
        arguments = popen.call_args.args[0]
        environment = popen.call_args.kwargs['env']
        self.assertNotIn(self.controller.config['secret_key'], ' '.join(arguments))
        self.assertNotIn('HTTP_PROXY', environment)
        self.assertNotIn('DEBUG', environment)
        self.assertEqual(environment['SYNO_HOSTNAME'], '127.0.0.1')
        self.assertEqual(environment['SYNO_CREATE'], '')
        self.assertFalse(self.controller.marker.exists())


if __name__ == '__main__':
    unittest.main()
