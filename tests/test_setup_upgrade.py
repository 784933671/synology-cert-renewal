import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from web.setup_upgrade import Upgrade, UpgradeError, ACME_STAMP, NATIVE_FILES, copy_payload

ROOT = Path(__file__).resolve().parents[1]
OLD = 'sha256:' + '1' * 64
NEW = 'sha256:' + '2' * 64


class PowerLoss(BaseException):
    pass


class DockerFixture:
    def __init__(self, home):
        self.home = home
        self.calls = []
        self.running = True
        self.alias = self.image = OLD
        self.failed_build = self.failed_health = self.failed_stop = False
        self.other_writer = False
        self.migrate = False
        self.before_stop = None

    def __call__(self, args, timeout=60):
        self.calls.append(args)
        if args[0].endswith('docker'):
            command = args[1:]
            if command[0] == 'build':
                if not self.running:
                    raise AssertionError('build must precede downtime')
                if self.failed_build:
                    raise RuntimeError('secret-error-must-not-escape')
                if self.before_stop:
                    self.before_stop()
                return ''
            if command[:2] == ['image', 'inspect']:
                return self.alias if command[2].endswith(':local') else NEW
            if command[0] == 'tag':
                self.alias = OLD if command[1] == OLD else NEW
                return ''
            if command[:2] == ['ps', '-a']:
                return 'synology-cert-web\n'
            if command == ['ps', '-q']:
                return 'writer\n' if self.other_writer else ('container\n' if self.running else '')
            if command[:2] == ['inspect', '--format']:
                return json.dumps([{'RW': True, 'Source': str(self.home / 'data')}])
            if command == ['inspect', 'synology-cert-web']:
                return json.dumps([{'Image': self.image, 'Config': {'Labels': {'io.github.784933671.certweb.managed': 'true'}},
                                    'State': {'Running': self.running, 'Restarting': False,
                                              'Health': {'Status': 'unhealthy' if self.failed_health and self.image == NEW else 'healthy'}}}])
            raise AssertionError(args)
        action = args[-1]
        if action == 'stop':
            if self.failed_stop:
                raise RuntimeError('secret-stop-error')
            self.running = False
        elif action == 'start':
            self.running = True
            self.image = self.alias
            if self.migrate and self.image == NEW:
                with sqlite3.connect(str(self.home / 'data/auth.sqlite3')) as c:
                    c.execute('CREATE TABLE upgraded_table (value TEXT)')
        else:
            raise AssertionError(args)
        return ''


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o700)
        copy_payload(ROOT, self.source / 'web')
        for path in set(NATIVE_FILES.values()):
            destination = self.source / path
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes((ROOT / path).read_bytes())
            destination.chmod(0o600)
        self.home = self.root / 'manager'
        self.native = self.root / 'native'
        for root in (self.home, self.native):
            root.mkdir(mode=0o700)
        for name in ('code', 'data', 'access'):
            (self.home / name).mkdir(mode=0o700)
        for name in ('state', 'web', 'acme', 'acme/dnsapi'):
            (self.native / name).mkdir(mode=0o700)
        self.write(self.native / 'ACME-VERSION', ACME_STAMP)
        self.write(self.native / 'config.json', '{"secret_key":"test-private-key"}')
        self.write(self.native / 'state/pending.json', '{"preserve":true}')
        self.write(self.native / 'web/login-email.json', '{"preserve":true}')
        self.write(self.home / 'access/access.json', '{"mode":"lan"}')
        self.write(self.home / 'deployment.json', json.dumps({'home': str(self.home), 'native_home': str(self.native)}))
        self.write(self.home / 'deployment.env', 'private deployment\n')
        self.write(self.home / 'code/deployment.py', '# original deployment\n')
        for path in NATIVE_FILES:
            self.write(self.native / path, 'old:' + path)
        with sqlite3.connect(str(self.home / 'data/auth.sqlite3')) as c:
            c.execute('CREATE TABLE users(username TEXT, password_hash TEXT, email_login_required INTEGER)')
            c.execute('INSERT INTO users VALUES(?,?,?)', ('admin', 'test-private-hash', 1))
        (self.home / 'data/auth.sqlite3').chmod(0o600)
        self.original_db = (self.home / 'data/auth.sqlite3').read_bytes()
        self.runner = DockerFixture(self.home)
        self.upgrade = Upgrade(self.source, self.home, runner=self.runner, uid=os.getuid(), sleeper=lambda _: None)

    @staticmethod
    def write(path, text):
        path.write_text(text)
        path.chmod(0o600)

    def assert_preserved(self):
        self.assertEqual((self.native / 'config.json').read_text(), '{"secret_key":"test-private-key"}')
        self.assertEqual((self.native / 'state/pending.json').read_text(), '{"preserve":true}')
        self.assertEqual((self.native / 'web/login-email.json').read_text(), '{"preserve":true}')
        self.assertEqual((self.home / 'access/access.json').read_text(), '{"mode":"lan"}')
        with sqlite3.connect(str(self.home / 'data/auth.sqlite3')) as c:
            self.assertEqual(c.execute('SELECT * FROM users').fetchall(), [('admin', 'test-private-hash', 1)])
            self.assertEqual(c.execute("SELECT count(*) FROM sqlite_master WHERE name='upgraded_table'").fetchone()[0], 0)

    def test_success_builds_before_stop_preserves_credentials_and_runtime(self):
        result = self.upgrade.run()
        self.assertTrue(result['upgraded'])
        self.assert_preserved()
        self.assertEqual(self.runner.image, NEW)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'complete')
        self.assertTrue((Path(result['backup']) / 'auth.sqlite3').exists())
        for target, source in NATIVE_FILES.items():
            self.assertEqual((self.native / target).read_bytes(), (self.source / source).read_bytes())
        self.assertEqual((self.native / 'ACME-VERSION').read_text(), ACME_STAMP)
        self.assertFalse(any('synowebapi' in x for args in self.runner.calls for x in args))

    def test_upgrade_accepts_health_after_startup_stabilization_and_probe_delay(self):
        actual = self.upgrade.healthy
        checks = []
        def delayed(image):
            checks.append(image)
            return len(checks) > 120 and actual(image)
        self.upgrade.healthy = delayed
        self.assertTrue(self.upgrade.run()['upgraded'])
        self.assertEqual(self.runner.image, NEW)
        self.assert_preserved()

    def test_rollback_allows_same_startup_stabilization_budget(self):
        self.runner.failed_health = True
        actual = self.upgrade.healthy
        old_checks = []
        def delayed(image):
            if image == OLD:
                old_checks.append(image)
                return len(old_checks) > 120 and actual(image)
            return actual(image)
        self.upgrade.healthy = delayed
        with self.assertRaisesRegex(UpgradeError, '已恢复原版本'):
            self.upgrade.run()
        self.assertEqual(self.runner.image, OLD)
        self.assertTrue(self.runner.running)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'rolled_back')
        self.assert_preserved()

    def test_build_failure_never_stops_or_mutates_live_service(self):
        self.runner.failed_build = True
        with self.assertRaises(UpgradeError) as error:
            self.upgrade.run()
        self.assertNotIn('secret-error', str(error.exception))
        self.assertTrue(self.runner.running)
        self.assertFalse(self.upgrade.journal.exists())
        self.assertFalse(any(args[-1] == 'stop' for args in self.runner.calls))
        self.assert_preserved()

    def test_acme_engine_mismatch_rejected_before_docker(self):
        self.write(self.native / 'ACME-VERSION', 'different-version')
        with self.assertRaises(UpgradeError):
            self.upgrade.run()
        self.assertFalse(self.runner.calls)
        self.assert_preserved()

    def test_unhealthy_upgrade_restores_old_image_code_and_migrated_database(self):
        self.runner.failed_health = self.runner.migrate = True
        with self.assertRaisesRegex(UpgradeError, '已恢复原版本'):
            self.upgrade.run()
        self.assertEqual(self.runner.image, OLD)
        self.assertTrue(self.runner.running)
        self.assertEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'rolled_back')
        for name in NATIVE_FILES:
            self.assertEqual((self.native / name).read_text(), 'old:' + name)
        self.assert_preserved()

    def test_power_loss_between_code_renames_can_recover_with_missing_code_directory(self):
        original = os.rename
        def rename(source, target):
            if Path(source).name == 'new-code':
                raise PowerLoss()
            return original(source, target)
        with patch('web.setup_upgrade.os.rename', side_effect=rename), self.assertRaises(PowerLoss):
            self.upgrade.run()
        self.assertFalse((self.home / 'code').exists())
        result = self.upgrade.recover()
        self.assertTrue(result['recovered'])
        self.assertEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')
        self.assert_preserved()
        self.assertTrue(self.runner.running)

    def test_database_not_restored_while_another_container_can_write_it(self):
        self.runner.failed_health = self.runner.migrate = True
        original = self.upgrade.wait_healthy
        def wait(image):
            if image == NEW:
                self.runner.other_writer = True
            original(image)
        self.upgrade.wait_healthy = wait
        with self.assertRaisesRegex(UpgradeError, '自动恢复未完成'):
            self.upgrade.run()
        with sqlite3.connect(str(self.home / 'data/auth.sqlite3')) as c:
            self.assertEqual(c.execute("SELECT count(*) FROM sqlite_master WHERE name='upgraded_table'").fetchone()[0], 1)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'rollback_failed')
        self.runner.other_writer = False
        self.upgrade.wait_healthy = original
        self.assertTrue(self.upgrade.recover()['recovered'])
        self.assert_preserved()

    def test_live_container_stop_failure_does_not_overwrite_authentication(self):
        self.runner.failed_stop = True
        with self.assertRaisesRegex(UpgradeError, '自动恢复未完成'):
            self.upgrade.run()
        self.assertTrue(self.runner.running)
        self.assertEqual((self.home / 'data/auth.sqlite3').read_bytes(), self.original_db)
        self.assertEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')
        self.runner.failed_stop = False
        self.assertTrue(self.upgrade.recover()['recovered'])
        self.assert_preserved()

    def test_native_busy_does_not_stop_management_service(self):
        path = self.native / 'state/run.lock'
        self.write(path, '')
        with path.open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(UpgradeError, '原任务正在运行'):
                self.upgrade.run()
        self.assertFalse(any(args[-1] == 'stop' for args in self.runner.calls))
        self.assertTrue(self.runner.running)
        self.assert_preserved()

    def test_upgrade_lock_rejects_concurrent_invocation_before_build(self):
        path = self.home / 'upgrade.lock'
        self.write(path, '')
        with path.open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(UpgradeError):
                self.upgrade.run()
        self.assertFalse(self.runner.calls)

    def test_source_filter_excludes_live_data_env_private_keys_and_caches(self):
        for name in ('login-email.json', 'deployment.json', 'deployment.env', 'key.pem', '.env'):
            self.write(self.source / 'web' / name, 'must-not-copy')
        data = self.source / 'web/data'
        data.mkdir(mode=0o700)
        self.write(data / 'auth.sqlite3', 'must-not-copy')
        target = self.root / 'payload'
        copy_payload(self.source, target)
        self.assertFalse(any('must-not-copy' in p.read_text() for p in target.rglob('*') if p.is_file()))
        self.assertFalse((target / 'data').exists())

    def test_selected_source_symlink_is_rejected(self):
        target = self.source / 'web/frontend/src/extra.ts'
        target.symlink_to(self.native / 'config.json')
        with self.assertRaises(UpgradeError):
            self.upgrade.run()
        self.assertTrue(self.runner.running)
        self.assert_preserved()

    def test_native_symlink_is_rejected_before_build(self):
        target = self.native / 'certctl.py'
        target.unlink()
        target.symlink_to(self.native / 'config.json')
        with self.assertRaises(UpgradeError):
            self.upgrade.run()
        self.assertFalse(self.runner.calls)
        self.assert_preserved()

    def test_invalid_private_config_error_does_not_expose_contents(self):
        self.write(self.home / 'deployment.json', '{"private": "test-secret", broken-json')
        with self.assertRaises(UpgradeError) as caught:
            self.upgrade.run()
        self.assertNotIn('test-secret', str(caught.exception))
        self.assertFalse(self.runner.calls)

    def test_completed_upgrade_recovery_does_not_restart_running_service(self):
        self.upgrade.run()
        count = len(self.runner.calls)
        self.assertEqual(self.upgrade.recover(), {'recovered': False})
        self.assertEqual(len(self.runner.calls), count)


if __name__ == '__main__':
    unittest.main()
