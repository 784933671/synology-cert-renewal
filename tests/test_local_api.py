import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'native_certificate_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


class LocalApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURES.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURES.CertificateTests.tearDownClass)

    def setUp(self):
        self.fixture = FIXTURES.CertificateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.controller = self.fixture.controller
        self.controller.config.update(deployment_method='local_api', certificate_description='家庭 NAS 证书')
        self.fixture.info['ABC123']['desc'] = self.controller.config['certificate_description']
        certctl.save_json(self.fixture.archive / 'INFO', self.fixture.info)
        self.controller.log = mock.Mock()
        self.controller.probe_fingerprint = mock.Mock(
            side_effect=lambda probe, **kwargs: certctl.fingerprint(self.controller.current_cert()))

    def target(self, is_default=True):
        return {'id': 'ABC123', 'desc': self.controller.config['certificate_description'],
                'is_default': is_default}

    def before(self):
        return self.controller.binding_state(self.fixture.info)

    @contextlib.contextmanager
    def api(self, on_import):
        def call(api, method, params=None, timeout=30):
            if (api, method) == ('SYNO.Core.Certificate.CRT', 'list'):
                return {'certificates': [self.target(self.before()['default'] == 'ABC123')]}
            self.assertEqual((api, method), ('SYNO.Core.Certificate', 'import'))
            self.assertEqual(timeout, 120)
            return on_import(params)

        with mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'call_local_api', side_effect=call) as calls, \
             mock.patch.object(self.controller, 'invoke_acme', side_effect=AssertionError('不能调用部署钩子')), \
             mock.patch.object(self.controller, 'temp_user_exists', side_effect=AssertionError('不能读取临时账号')):
            yield calls

    def test_native_description_supports_chinese_spaces_but_rejects_controls(self):
        self.controller.config.pop('dsm_http_port')
        certctl.validate_config(self.controller.config)
        for description in ('', '  ', 'a\nb', 'a\x00b', 'a\x7fb', 'a\x85b', 'a' * 257):
            with self.subTest(description=repr(description)):
                config = dict(self.controller.config, certificate_description=description)
                with self.assertRaises(certctl.Failure):
                    certctl.validate_config(config)
        legacy = FIXTURES.configuration()
        self.controller.config = legacy
        self.assertEqual(self.controller.deployment_method(), 'synology_dsm')
        legacy['certificate_description'] = '家庭 NAS 证书'
        with self.assertRaises(certctl.Failure):
            certctl.validate_config(legacy)

    def test_configure_selects_native_without_prompting_http_port(self):
        answers = ['1', 'operator@example.com', '', '', '', '', 'n']
        with mock.patch.object(certctl.shutil, 'which', return_value='/usr/syno/bin/synowebapi'), \
             mock.patch.object(certctl.sys.stdin, 'isatty', return_value=True), \
             mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'preflight') as preflight, \
             mock.patch('builtins.input', side_effect=answers) as prompts, \
             mock.patch.object(certctl.getpass, 'getpass', side_effect=['TEST_ID', 'TEST_KEY']), \
             contextlib.redirect_stdout(io.StringIO()):
            self.controller.configure()
        saved = certctl.read_json(self.controller.config_file)
        self.assertEqual(saved['deployment_method'], 'local_api')
        self.assertEqual(saved['renew_before_days'], 2)
        self.assertEqual(saved['certificate_description'], '家庭 NAS 证书')
        self.assertEqual(saved['certificate_id'], 'ABC123')
        self.assertFalse(any('HTTP 端口' in call.args[0] for call in prompts.call_args_list))
        preflight.assert_called_once_with()

    def test_native_system_check_never_reads_two_factor_or_accounts(self):
        with self.fixture.mocked_dsm(policy='admin', existing_user=True) as commands:
            self.controller.system_check()
            self.controller.temp_user_exists.assert_not_called()
        self.assertEqual(commands.call_args_list, [mock.call(
            ['/bin/sh', str(self.controller.acme / 'acme.sh'), '--version'])])

    def test_legacy_system_check_still_rejects_enforced_two_factor(self):
        self.controller.config.pop('deployment_method')
        with self.fixture.mocked_dsm(policy='admin') as commands:
            with self.assertRaises(certctl.Failure):
                self.controller.system_check()
        self.assertEqual(commands.call_args_list, [mock.call(
            ['synogetkeyvalue', '/etc/synoinfo.conf', 'otp_enforce_option'])])

    def test_native_requires_synowebapi(self):
        with self.fixture.mocked_dsm(policy='admin') as commands, \
             mock.patch.object(certctl.shutil, 'which', side_effect=lambda name:
                               None if name == 'synowebapi' else '/usr/bin/' + name):
            with self.assertRaises(certctl.Failure):
                self.controller.system_check()
        commands.assert_not_called()

    def test_api_passes_json_arguments_without_shell_interpretation(self):
        params = {'desc': '家庭 "NAS" $(uname)', 'as_default': 'false'}
        response = subprocess.CompletedProcess([], 0, b'{"success":true,"data":{"id":"ABC123"}}', b'')
        with mock.patch.object(certctl.shutil, 'which', return_value='/usr/syno/bin/synowebapi'), \
             mock.patch.object(certctl.subprocess, 'run', return_value=response) as run:
            result = self.controller.call_local_api('SYNO.Core.Certificate', 'import', params, timeout=120)
        self.assertEqual(result, {'id': 'ABC123'})
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ['/usr/syno/bin/synowebapi', '--exec',
                                     'api=SYNO.Core.Certificate', 'method=import', 'version=1'])
        self.assertEqual(dict(value.split('=', 1) for value in command[5:]),
                         {key: json.dumps(value, ensure_ascii=False) for key, value in params.items()})
        self.assertFalse(run.call_args.kwargs.get('shell', False))
        self.assertEqual(run.call_args.kwargs['timeout'], 120)

    def test_api_rejects_failed_malformed_or_nonzero_results(self):
        bodies = [b'', b'not-json', b'[]', b'{"success":false}', b'{"success":1}',
                  b'{"success":true,"error":{"code":105}}', b'{"success":true,"data":[]}',
                  b'{"success":true,"data":null}', b'\xff']
        for body in bodies:
            with self.subTest(body=body), \
                 mock.patch.object(certctl.shutil, 'which', return_value='/usr/syno/bin/synowebapi'), \
                 mock.patch.object(certctl.subprocess, 'run',
                                   return_value=subprocess.CompletedProcess([], 0, body, b'')):
                with self.assertRaises(certctl.Failure):
                    self.controller.call_local_api('SYNO.Core.Certificate.CRT', 'list')
        with mock.patch.object(certctl.shutil, 'which', return_value='/usr/syno/bin/synowebapi'), \
             mock.patch.object(certctl.subprocess, 'run',
                               return_value=subprocess.CompletedProcess([], 1, b'{"success":true}', b'')):
            with self.assertRaises(certctl.Failure):
                self.controller.call_local_api('SYNO.Core.Certificate.CRT', 'list')
        with mock.patch.object(certctl.shutil, 'which', return_value='/usr/syno/bin/synowebapi'), \
             mock.patch.object(certctl.subprocess, 'run', side_effect=subprocess.TimeoutExpired('synowebapi', 30)):
            with self.assertRaises(certctl.Failure):
                self.controller.call_local_api('SYNO.Core.Certificate.CRT', 'list')

    def test_list_rejects_unusable_certificate_collections(self):
        for data in ({}, {'certificates': {}}, {'certificates': None}, {'certificates': ['ABC123']}):
            with self.subTest(data=data), mock.patch.object(self.controller, 'call_local_api', return_value=data):
                with self.assertRaises(certctl.Failure):
                    self.controller.local_api_list()

    def test_target_rejects_wrong_or_ambiguous_identity_and_default(self):
        target = self.target()
        lists = [[], [dict(target, id='OTHER')], [dict(target, desc='other')],
                 [target, dict(target, id='OTHER')], [target, dict(target, desc='other')],
                 [dict(target, is_default=False)], [dict(target, is_default=1)],
                 [{'id': 'ABC123', 'desc': target['desc']}]]
        for certificates in lists:
            with self.subTest(certificates=certificates), \
                 mock.patch.object(self.controller, 'local_api_list', return_value=certificates):
                with self.assertRaises(certctl.Failure):
                    self.controller.local_api_target(self.before())

    def test_native_preflight_uses_local_api_and_keeps_tls_verification(self):
        with mock.patch.object(self.controller, 'system_check'), \
             mock.patch.object(self.controller, 'local_api_list', return_value=[self.target()]) as listing, \
             mock.patch.object(certctl, 'capture', wraps=certctl.capture) as commands:
            self.controller.preflight()
        listing.assert_called_once_with()
        self.controller.probe_fingerprint.assert_called_once()
        self.assertTrue(all(call.args[0][0] == 'openssl' for call in commands.call_args_list))

    def test_import_preserves_identity_default_and_sources_when_api_consumes_uploads(self):
        self.fixture.prepare_candidate()
        sources = {'key_tmp': self.controller.candidate_dir() / 'ttxli.cn.key',
                   'cert_tmp': self.controller.candidate(),
                   'inter_cert_tmp': self.controller.candidate_dir() / 'ca.cer'}
        original = {key: path.read_bytes() for key, path in sources.items()}
        for is_default in (True, False):
            with self.subTest(is_default=is_default):
                self.fixture.install_current('old')
                (self.fixture.archive / 'DEFAULT').write_text('ABC123' if is_default else 'OTHER')
                before = self.before()
                directories = []

                def consume(params):
                    self.assertEqual(params['id'], 'ABC123')
                    self.assertEqual(params['desc'], '家庭 NAS 证书')
                    self.assertEqual(params['as_default'], 'true' if is_default else 'false')
                    for key, source in sources.items():
                        temporary = Path(params[key])
                        self.assertNotEqual(temporary, source)
                        self.assertEqual(stat.S_IMODE(temporary.stat().st_mode), 0o600)
                        self.assertEqual(stat.S_IMODE(temporary.parent.stat().st_mode), 0o700)
                        self.assertEqual(temporary.read_bytes(), original[key])
                        directories.append(temporary.parent)
                        temporary.unlink()
                    self.fixture.install_current('new')
                    return {'id': 'ABC123'}

                with self.api(consume):
                    self.controller.deploy_and_verify(before)
                self.assertEqual(self.before(), before)
                self.assertTrue(all(not directory.exists() for directory in directories))
                self.assertEqual({key: path.read_bytes() for key, path in sources.items()}, original)
                self.assertFalse((self.controller.state / 'pending.json').exists())
                self.assertFalse(self.controller.marker.exists())

    def test_failed_or_wrong_id_import_cleans_temporary_files_and_retains_pending(self):
        self.fixture.prepare_candidate()
        for failure in ('api-error', 'wrong-id'):
            with self.subTest(failure=failure):
                directories = []

                def fail(params):
                    directories.append(Path(params['key_tmp']).parent)
                    if failure == 'api-error':
                        raise certctl.Failure('模拟 DSM 导入失败')
                    return {'id': 'OTHER'}

                with self.api(fail), self.assertRaises(certctl.Failure):
                    self.controller.deploy_and_verify(self.before())
                self.assertTrue(directories)
                self.assertTrue(all(not directory.exists() for directory in directories))
                self.assertTrue((self.controller.state / 'pending.json').exists())
                self.assertFalse(self.controller.marker.exists())
                self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.old_fingerprint)
                self.controller.candidate_valid()

    def test_native_deploy_keeps_archive_binding_default_and_live_tls_checks(self):
        self.fixture.prepare_candidate()
        original = copy.deepcopy(self.fixture.info)
        for failure in ('archive', 'binding', 'default', 'tls'):
            with self.subTest(failure=failure):
                self.fixture.install_current('old')
                certctl.save_json(self.fixture.archive / 'INFO', original)
                (self.fixture.archive / 'DEFAULT').write_text('ABC123')
                before = self.before()
                self.controller.probe_fingerprint = mock.Mock(side_effect=lambda probe, **kwargs:
                    self.fixture.old_fingerprint if failure == 'tls'
                    else certctl.fingerprint(self.controller.current_cert()))

                def change(params):
                    if failure != 'archive':
                        self.fixture.install_current('new')
                    if failure == 'binding':
                        changed = copy.deepcopy(original)
                        changed['ABC123']['services'] = []
                        certctl.save_json(self.fixture.archive / 'INFO', changed)
                    if failure == 'default':
                        (self.fixture.archive / 'DEFAULT').write_text('OTHER')
                    return {'id': 'ABC123'}

                with self.api(change), self.assertRaises(certctl.Failure):
                    self.controller.deploy_and_verify(before)
                self.assertTrue((self.controller.state / 'pending.json').exists())
                if failure == 'tls':
                    self.assertGreater(self.controller.probe_fingerprint.call_count, 0)

    def test_changed_bindings_prevent_native_import(self):
        self.fixture.prepare_candidate()
        before = self.before()
        changed = copy.deepcopy(self.fixture.info)
        changed['ABC123']['services'] = []
        certctl.save_json(self.fixture.archive / 'INFO', changed)
        with self.api(lambda params: self.fail('绑定变化后不应导入')) as calls, \
             self.assertRaises(certctl.Failure):
            self.controller.deploy_and_verify(before)
        calls.assert_not_called()

    def test_native_acme_has_no_admin_environment_or_account_cleanup(self):
        self.fixture.prepare_candidate()
        self.controller.config.pop('dsm_http_port')
        conf = self.controller.candidate_dir() / 'ttxli.cn.conf'
        conf.write_text(conf.read_text() + "Le_DeployHook='synology_dsm'\n")
        for returncode in (0, 1):
            process = mock.Mock(wait=mock.Mock(return_value=returncode), poll=mock.Mock(return_value=returncode))
            with self.subTest(returncode=returncode), \
                 mock.patch.object(self.controller, 'system_check'), \
                 mock.patch.object(self.controller, 'temp_user_exists', side_effect=AssertionError('不能读取临时账号')), \
                 mock.patch.object(certctl, 'capture', side_effect=AssertionError('不能调用账号命令')), \
                 mock.patch.object(certctl.subprocess, 'Popen', return_value=process) as popen, \
                 mock.patch.dict(certctl.os.environ, {'SYNO_USERNAME': 'personal-admin', 'SYNO_PASSWORD': 'secret'}):
                self.assertEqual(self.controller.invoke_acme(['--renew', '-d', 'ttxli.cn']), returncode)
            environment = popen.call_args.kwargs['env']
            self.assertFalse(any(key.startswith('SYNO_') for key in environment))
            self.assertEqual(environment['Tencent_SecretId'], self.controller.config['secret_id'])
            self.assertNotIn('Le_DeployHook=', conf.read_text())
            self.assertFalse(self.controller.marker.exists())

    def test_native_acme_refuses_direct_deployment_hook(self):
        with mock.patch.object(certctl.subprocess, 'Popen') as process, self.assertRaises(certctl.Failure):
            self.controller.invoke_acme(['--deploy', '-d', 'ttxli.cn', '--deploy-hook', 'synology_dsm'])
        process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
