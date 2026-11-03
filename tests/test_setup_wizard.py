import contextlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import shlex
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from web import setup


OPTIONS = {'bind': '10.10.10.37', 'network': '10.10.10.0/24', 'gateway': '10.10.10.1',
           'port': 18443, 'hostname': 'nas.example.com', 'email': 'admin@example.com', 'access_mode': 'lan'}


class WizardTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        previous_umask = os.umask(0o077)
        os.umask(previous_umask)
        self.addCleanup(os.umask, previous_umask)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state, self.home, self.native, self.source = [self.root / x for x in ('setup', 'web', 'native', 'source')]
        for p in (self.state, self.native, self.source):
            p.mkdir(mode=0o700)
        self.calls = []
        self.wizard = setup.Wizard(self.source, self.home, self.native, self.state,
                                  runner=self.runner, ask=lambda _: '', uid=os.getuid(), sleeper=lambda _: None)
        self.wizard.source_digest = Mock(return_value='a' * 64)
        self.config = {'domains': ['nas.example.com'], 'email': 'admin@example.com', 'certificate_id': 'target'}

    def runner(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return ''

    def journal(self, **extra):
        value = {'version': 1, 'home': str(self.home), 'native': str(self.native), 'complete': False,
                 'source_sha256': 'a' * 64, 'options': copy.deepcopy(OPTIONS)}
        value.update(extra)
        setup.atomic_bytes(self.state / 'install.json', json.dumps(value).encode())
        return value

    def test_network_defaults_use_only_default_route_interface(self):
        values = setup.network_defaults('default via 10.10.10.1 dev bond0\n',
                                       '2: docker0 inet 172.17.0.1/16 scope global\n3: bond0 inet 10.10.10.37/24 scope global\n')
        self.assertEqual(values, {'bind': '10.10.10.37', 'network': '10.10.10.0/24', 'gateway': '10.10.10.1'})
        self.assertEqual(setup.network_defaults('default dev ppp0', ''), {})

    def test_options_reject_wrong_san_public_ranges_and_header_injection(self):
        setup.validate_options(OPTIONS, self.config['domains'])
        for key, value in [('hostname', 'other.example.com'), ('hostname', 'nas.example.com;id'),
                           ('network', '0.0.0.0/0'), ('gateway', OPTIONS['bind']),
                           ('email', 'admin@example.com\nBcc: attacker@example.com'), ('port', True)]:
            with self.subTest(key=key), self.assertRaises((setup.SetupError, ValueError)):
                setup.validate_options(dict(OPTIONS, **{key: value}), self.config['domains'])
        with self.assertRaises(setup.SetupError):
            setup.validate_options(dict(OPTIONS, hostname='a.b.example.com'), ['*.example.com'])

    def test_completed_install_does_not_reconfigure_or_reenable_mfa(self):
        self.journal(complete=True)
        self.wizard.mail_ready = Mock()
        with self.assertRaisesRegex(setup.SetupError, 'upgrade'):
            self.wizard.install()
        self.wizard.mail_ready.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_resume_requires_same_package_before_any_mutation(self):
        self.journal(source_sha256='b' * 64)
        self.wizard.mail_ready = Mock()
        with self.assertRaisesRegex(setup.SetupError, '安装包'):
            self.wizard.install()
        self.wizard.mail_ready.assert_not_called()

    def test_foreign_management_directory_is_not_adopted(self):
        self.home.mkdir()
        with self.assertRaisesRegex(setup.SetupError, '已存在'):
            self.wizard.install()
        self.assertFalse((self.state / 'install.json').exists())

    def test_stopped_healthy_container_is_not_ready(self):
        item = {'Config': {'Labels': {setup.MANAGED_LABEL: 'true'}},
                'State': {'Running': False, 'Health': {'Status': 'healthy'}},
                'Mounts': [{'Destination': '/data', 'Source': str(self.home / 'data')}]}
        self.wizard.runner = Mock(return_value=json.dumps([item]))
        self.assertFalse(self.wizard.ready())
        item['State']['Running'] = True
        self.wizard.runner.return_value = json.dumps([item])
        self.assertTrue(self.wizard.ready())
        item['Mounts'][0]['Source'] = '/somebody/else'
        self.wizard.runner.return_value = json.dumps([item])
        self.assertFalse(self.wizard.ready())

    def test_occupied_port_is_reported_without_changing_configuration(self):
        self.wizard.ready = Mock(return_value=False)
        with patch('web.setup.socket.socket') as constructor:
            constructor.return_value.__enter__.return_value.bind.side_effect = OSError('private OS detail')
            with self.assertRaisesRegex(setup.SetupError, '端口'):
                self.wizard.check_port(OPTIONS)
        self.assertEqual(self.calls, [])

    def test_unhealthy_owned_container_can_release_its_port_during_resume(self):
        self.home.mkdir()
        (self.home / 'deployment.json').write_text('{}')
        self.wizard.ready = Mock(return_value=False)
        self.wizard.managed_container = Mock(return_value={'State': {'Running': True}})
        with patch('web.setup.socket.socket') as constructor:
            self.wizard.check_port(OPTIONS)
            constructor.assert_not_called()

    def prepare_install(self):
        self.journal(built=True)
        self.home.mkdir()
        (self.home / 'deployment.json').write_text('{}')
        self.wizard.mail_ready = Mock()
        self.wizard.native_ready = Mock(return_value=self.config)
        self.wizard.tls_ready = Mock()
        self.wizard.check_port = Mock()
        self.wizard.credentials_ready = Mock()
        self.wizard.ready = Mock(return_value=True)
        self.wizard.verify_service = Mock()
        self.task = Mock()
        self.task.ensure.return_value = {'id': 42}
        configuration = {'bind': OPTIONS['bind'], 'networks': [OPTIONS['network']], 'denied': [OPTIONS['gateway']],
                         'port': OPTIONS['port'], 'origin': 'https://nas.example.com:18443', 'task_id': 42,
                         'native_home': str(self.native)}
        for patcher in (patch('web.setup_tasks.TaskSetup', return_value=self.task),
                        patch('web.setup.load_config', return_value=configuration), patch('web.setup.RC', self.root / 'rc')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_resume_always_repairs_prepare_and_activates_task_after_real_checks(self):
        self.prepare_install()
        def activate(identifier):
            self.assertEqual(identifier, 42)
            self.wizard.credentials_ready.assert_called_once()
            self.wizard.verify_service.assert_called_once()
        self.task.activate.side_effect = activate
        self.wizard.install()
        prepare = [args for args, _ in self.calls if 'prepare' in args]
        self.assertEqual(len(prepare), 1)
        self.assertEqual(prepare[0][-2:], ['--task-id', '42'])
        self.assertTrue(setup.read_private(self.state / 'install.json', os.getuid())['complete'])

    def test_unhealthy_service_never_enables_new_task(self):
        self.prepare_install()
        self.wizard.ready.return_value = False
        with self.assertRaisesRegex(setup.SetupError, '健康'):
            self.wizard.install()
        self.task.activate.assert_not_called()
        self.wizard.verify_service.assert_not_called()
        self.assertFalse(setup.read_private(self.state / 'install.json', os.getuid())['complete'])

    def test_https_or_bridge_failure_never_enables_new_task(self):
        self.prepare_install()
        self.wizard.verify_service.side_effect = setup.SetupError('桥接异常')
        with self.assertRaises(setup.SetupError):
            self.wizard.install()
        self.task.activate.assert_not_called()

    def test_unhealthy_resumed_service_is_restarted_before_enabling_task(self):
        self.prepare_install()
        command = shlex.join(['/usr/bin/python3', '-I', str(self.home / 'code/deployment.py'),
                              '--config', str(self.home / 'deployment.json')])
        (self.root / 'rc').write_text('exec ' + command + ' "$1"')
        self.wizard.ready = Mock(side_effect=[False, True])
        self.wizard.install()
        lifecycle = [args[-1] for args, _ in self.calls if str(self.home / 'code/deployment.py') in args]
        self.assertEqual(lifecycle, ['stop', 'start'])
        self.task.activate.assert_called_once_with(42)

    def test_bad_saved_options_can_be_reentered_before_prepare(self):
        self.prepare_install()
        (self.home / 'deployment.json').unlink()
        self.wizard.ask = lambda _: 'n'
        self.wizard.prompt_options = Mock(return_value=copy.deepcopy(OPTIONS))
        self.wizard.install()
        self.wizard.prompt_options.assert_called_once()

    def test_tls_rejection_does_not_implicitly_request_certificate(self):
        with patch('web.setup.validate_material', side_effect=ValueError):
            with self.assertRaisesRegex(setup.SetupError, '保留进度'):
                self.wizard.tls_ready(OPTIONS, self.config)
        self.assertFalse(any('run' in args for args, _ in self.calls))

    def credentials_fixture(self, empty=False):
        self.home.mkdir()
        (self.home / 'data').mkdir(mode=0o700)
        (self.native / 'web').mkdir(mode=0o700)
        self.db = self.home / 'data/auth.sqlite3'
        if empty:
            self.db.touch(mode=0o600)
        self.wizard.hidden = Mock(side_effect=['unique-test-password', 'unique-test-password'])
        def command(args, **kwargs):
            self.calls.append((args, kwargs))
            with sqlite3.connect(self.db) as conn:
                if 'init' in args:
                    self.assertIn('--interactive', args[:args.index('synology-cert-web:local')])
                    self.assertTrue(kwargs.get('input_text'))
                    conn.executescript('CREATE TABLE IF NOT EXISTS users(username TEXT, email_login_required INTEGER);'
                                       'CREATE TABLE IF NOT EXISTS login_security(username TEXT,email TEXT,policy_version TEXT,enabled INTEGER);')
                    conn.execute('INSERT INTO users VALUES(?,0)', ('admin',))
                elif 'enable-email-login' in args:
                    conn.execute('INSERT INTO login_security VALUES(?,?,?,1)',
                                 ('admin', args[args.index('--email') + 1], args[args.index('--policy-version') + 1]))
                    conn.execute('UPDATE users SET email_login_required=1')
            self.db.chmod(0o600)
            return ''
        self.wizard.runner = command
        original = setup.regular
        patcher = patch('web.setup.regular', side_effect=lambda path, uid=None, private=False: original(path, os.getuid() if uid == 10100 else uid, private))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_empty_database_after_interrupted_init_is_completed_without_deleting(self):
        self.credentials_fixture(empty=True)
        self.wizard.credentials_ready(OPTIONS)
        self.assertEqual(len([x for x, _ in self.calls if 'init' in x]), 1)
        self.assertTrue(self.db.exists())

    def test_password_is_stdin_only_and_resume_preserves_user_and_mfa(self):
        self.credentials_fixture()
        self.wizard.credentials_ready(OPTIONS)
        self.wizard.credentials_ready(OPTIONS)
        self.assertEqual(len([x for x, _ in self.calls if 'init' in x]), 1)
        self.assertEqual(len([x for x, _ in self.calls if 'enable-email-login' in x]), 1)
        self.assertEqual(self.wizard.hidden.call_count, 2)
        for args, _ in self.calls:
            self.assertNotIn('unique-test-password', ' '.join(args))
        self.assertEqual(self.calls[0][1]['input_text'], 'unique-test-password\n')
        self.assertNotIn('unique-test-password', (self.native / 'web/login-email.json').read_text())

    def test_password_cli_attaches_container_stdin_without_exposing_password(self):
        password = 'isolated-cli-test-password'
        self.wizard.auth_cli(['init', '--username', 'admin', '--password-stdin'], password)
        args, options = self.calls[0]
        self.assertIn('--interactive', args[:args.index('synology-cert-web:local')])
        self.assertEqual(options['input_text'], password + '\n')
        self.assertFalse(any(password in argument for argument in args))
        self.assertNotIn('--tty', args)

    def test_mail_configuration_does_not_open_unused_container_stdin(self):
        self.wizard.auth_cli(['enable-email-login', '--username', 'admin', '--email', OPTIONS['email'],
                              '--policy-version', 'a' * 32])
        args, options = self.calls[0]
        self.assertNotIn('--interactive', args)
        self.assertIsNone(options['input_text'])

    def test_existing_different_mail_policy_is_not_overwritten(self):
        self.credentials_fixture()
        self.wizard.credentials_ready(OPTIONS)
        original = (self.native / 'web/login-email.json').read_bytes()
        with self.assertRaisesRegex(setup.SetupError, '绑定'):
            self.wizard.credentials_ready(dict(OPTIONS, email='other@example.com'))
        self.assertEqual(original, (self.native / 'web/login-email.json').read_bytes())

    def test_unknown_database_is_not_reset(self):
        self.credentials_fixture(empty=True)
        with sqlite3.connect(self.db) as conn:
            conn.execute('CREATE TABLE unrelated(value TEXT)')
        with self.assertRaisesRegex(setup.SetupError, '未知'):
            self.wizard.credentials_ready(OPTIONS)
        self.wizard.hidden.assert_not_called()

    def native_fixture(self):
        (self.native / 'state').mkdir(mode=0o700)
        (self.native / 'acme/dnsapi').mkdir(mode=0o700, parents=True)
        (self.native / 'acme').chmod(0o700)
        for target, source in {'certctl.py': 'certctl.py', 'run_history.py': 'run_history.py', 'failure_diagnostics.py': 'failure_diagnostics.py',
                               'dns_cleanup.py': 'dns_cleanup.py', 'dns_cleanup_retry.sh': 'dns_cleanup_retry.sh',
                               'acme/dnsapi/dns_tencent.sh': 'dns_tencent_tracked.sh'}.items():
            (self.source / source).write_bytes(b'new code')
            (self.native / target).write_bytes(b'old code')
            (self.native / target).chmod(0o600)
        (self.native / 'config.json').write_bytes(b'unchanged credentials')

    def test_native_update_preserves_configuration_and_rolls_back_partial_copy(self):
        self.native_fixture()
        real_write = setup.atomic_bytes
        failed = [False]
        def write(path, content, *args, **kwargs):
            if Path(path) == self.native / 'failure_diagnostics.py' and content == b'new code' and not failed[0]:
                failed[0] = True
                raise OSError('interrupted')
            return real_write(path, content, *args, **kwargs)
        with patch('web.setup.atomic_bytes', side_effect=write), self.assertRaises(OSError):
            self.wizard.update_native_code()
        self.assertEqual((self.native / 'certctl.py').read_bytes(), b'old code')
        self.wizard.update_native_code()
        self.assertEqual((self.native / 'certctl.py').read_bytes(), b'new code')
        self.assertEqual((self.native / 'config.json').read_bytes(), b'unchanged credentials')
        self.assertFalse((self.state / 'native-update.json').exists())

    def test_native_busy_does_not_replace_code(self):
        self.native_fixture()
        with (self.native / 'state/run.lock').open('w') as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(setup.SetupError, '正在运行'):
                self.wizard.update_native_code()
        self.assertEqual((self.native / 'certctl.py').read_bytes(), b'old code')

    def test_existing_script_install_adds_history_module_and_preserves_missing_file_on_rollback(self):
        self.native_fixture()
        history = self.native / 'run_history.py'
        history.unlink()
        real_write = setup.atomic_bytes
        failed = [False]
        def fail_after_new_module(path, content, *args, **kwargs):
            if Path(path) == self.native / 'dns_cleanup.py' and not failed[0]:
                failed[0] = True
                self.assertTrue(history.exists())
                raise OSError('fixture interrupted installation')
            return real_write(path, content, *args, **kwargs)
        with patch.object(setup, 'atomic_bytes', side_effect=fail_after_new_module):
            with self.assertRaises(OSError):
                self.wizard.update_native_code()
        self.assertFalse(history.exists())
        self.assertEqual((self.native / 'certctl.py').read_bytes(), b'old code')
        self.assertTrue((self.state / 'native-update.json').exists())
        self.wizard.update_native_code()
        self.assertEqual(history.read_bytes(), b'new code')
        self.assertEqual((self.native / 'config.json').read_bytes(), b'unchanged credentials')
        self.assertFalse((self.state / 'native-update.json').exists())

    def test_check_mode_never_creates_state_or_invokes_install(self):
        with patch('web.setup.Wizard') as cls, patch('web.setup.HOME', self.home):
            self.assertEqual(setup.main(['check']), 0)
            cls.return_value.locked.assert_not_called()
            cls.return_value.install.assert_not_called()
        self.assertFalse((self.state / 'install.json').exists())

    def test_preflight_rejects_host_uid_or_gid_collision_without_mutation(self):
        version = self.root / 'VERSION'
        version.write_text('productversion="7.4.1"\n')
        self.wizard.uid = 0
        for collision in ('user', 'group'):
            with self.subTest(collision=collision), patch('web.setup.os.geteuid', return_value=0), \
                    patch('web.setup.platform.machine', return_value='x86_64'), patch('web.setup.regular'), \
                    patch('web.setup.os.access', return_value=True), \
                    patch('web.setup.pwd.getpwuid', side_effect=None if collision == 'user' else KeyError), \
                    patch('web.setup.grp.getgrgid', side_effect=None if collision == 'group' else KeyError):
                with self.assertRaisesRegex(setup.SetupError, 'UID/GID'):
                    self.wizard.preflight(version)
        self.assertFalse((self.state / 'install.json').exists())

    def test_unexpected_api_failure_does_not_print_exception_or_credentials(self):
        stderr = io.StringIO()
        with patch('web.setup.Wizard') as cls, contextlib.redirect_stderr(stderr):
            cls.return_value.preflight.side_effect = RuntimeError('SecretKey=do-not-print')
            self.assertEqual(setup.main(['check']), 1)
        self.assertNotIn('do-not-print', stderr.getvalue())
        self.assertNotIn('Traceback', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
