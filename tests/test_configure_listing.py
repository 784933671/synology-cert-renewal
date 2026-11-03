import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'certctl_listing', Path(__file__).resolve().parents[1] / 'certctl.py')
certctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(certctl)


class ConfigureListingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixtures.cleanup)
        root = Path(cls.fixtures.name)
        config = root / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
        key = root / 'key.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(key), '2048'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for name, san in (('no-san', None), ('ip-only', 'IP:127.0.0.1'),
                          ('valid', 'DNS:ttxli.cn,DNS:*.ttxli.cn')):
            command = ['openssl', 'req', '-new', '-x509', '-key', str(key),
                       '-config', str(config), '-subj', '/CN=ttxli.cn', '-days', '60',
                       '-out', str(root / (name + '.pem'))]
            if san is not None:
                command.extend(['-addext', 'subjectAltName=' + san])
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / 'archive'
        archive.mkdir()
        entries = {'A_NoSan': 'no-san', 'B_IpOnly': 'ip-only',
                   'C_Corrupt': 'corrupt', 'D_Missing': 'missing', 'E_Target': 'valid'}
        for identifier, fixture in entries.items():
            directory = archive / identifier
            directory.mkdir()
            if fixture == 'corrupt':
                (directory / 'cert.pem').write_text('not a certificate\n')
            elif fixture != 'missing':
                shutil.copyfile(Path(self.fixtures.name) / (fixture + '.pem'), directory / 'cert.pem')
        (archive / 'INFO').write_text(json.dumps({
            identifier: {'desc': identifier, 'services': []} for identifier in entries}))
        self.controller = certctl.Controller(root / 'home', archive)
        self.controller.home.mkdir()
        self.controller.state.mkdir()

    @contextlib.contextmanager
    def interaction(self, answers):
        output = io.StringIO()
        with mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'preflight') as preflight, \
             mock.patch.object(self.controller, 'log'), \
             mock.patch.object(certctl.sys.stdin, 'isatty', return_value=True), \
             mock.patch('builtins.input', side_effect=answers) as prompt, \
             mock.patch.object(certctl.getpass, 'getpass', side_effect=['TEST_ID', 'TEST_KEY']) as secret, \
             contextlib.redirect_stdout(output):
            yield output, prompt, secret, preflight

    def test_valid_target_can_be_configured_with_unusable_unrelated_certificates(self):
        with self.interaction(['5', 'operator@example.com', '', '', '', '', '', 'n']) as state:
            output, prompt, secret, preflight = state
            self.controller.configure()
        listing = output.getvalue().splitlines()
        self.assertEqual(len(listing), 5)
        for identifier, line in zip(('A_NoSan', 'B_IpOnly', 'C_Corrupt', 'D_Missing'), listing):
            self.assertIn(identifier, line)
            self.assertIn('不可用：', line)
        self.assertIn('缺少证书文件', listing[3])
        self.assertIn('ttxli.cn', listing[4])
        self.assertNotIn('不可用', listing[4])
        saved = certctl.read_json(self.controller.config_file)
        self.assertEqual(saved['certificate_id'], 'E_Target')
        self.assertEqual(saved['domains'], ['ttxli.cn', '*.ttxli.cn'])
        self.assertEqual(prompt.call_count, 8)
        self.assertEqual(saved['renew_before_days'], 2)
        self.assertEqual(secret.call_count, 2)
        preflight.assert_called_once_with()

    def test_configure_preserves_another_domain_order_without_site_specific_prompt(self):
        domains = ['service.example.com', 'example.com']
        with self.interaction(['5', 'operator@example.com', '', '', '', '', '', 'n']) as state, \
             mock.patch.object(certctl, 'certificate_domains', return_value=list(domains)):
            self.controller.configure()
        saved = certctl.read_json(self.controller.config_file)
        self.assertEqual(saved['domains'], domains)
        self.assertNotIn('ttxli.cn', state[1].call_args_list[0].args[0])

    def assert_selected_unusable_certificate_is_rejected(self, selection):
        with self.interaction([selection]) as state:
            output, prompt, secret, preflight = state
            with self.assertRaises(certctl.Failure):
                self.controller.configure()
        self.assertEqual(len(output.getvalue().splitlines()), 5)
        self.assertEqual(prompt.call_count, 1)
        secret.assert_not_called()
        preflight.assert_not_called()
        self.assertFalse(self.controller.config_file.exists())

    def test_selected_certificate_without_san_is_rejected(self):
        self.assert_selected_unusable_certificate_is_rejected('1')

    def test_selected_certificate_with_only_ip_san_is_rejected(self):
        self.assert_selected_unusable_certificate_is_rejected('2')

    def test_selected_corrupt_certificate_is_rejected(self):
        self.assert_selected_unusable_certificate_is_rejected('3')

    def test_selected_missing_certificate_is_rejected(self):
        self.assert_selected_unusable_certificate_is_rejected('4')


if __name__ == '__main__':
    unittest.main()
