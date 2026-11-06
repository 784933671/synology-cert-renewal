import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from web.setup_upgrade import (Upgrade, UpgradeError, UpgradePending, ACME_STAMP, NATIVE_FILES,
                               HEALTH_WAIT_SECONDS, RENEWAL_WAIT_SECONDS, copy_payload)
from web.deployment import Deployment

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
        self.failed_project_start = False
        self.stopped_for_maintenance = False
        self.other_writer = False
        self.migrate = False
        self.before_stop = None
        self.after_start = None
        self.project_name = None
        self.project_render = None

    def __call__(self, args, timeout=60):
        self.calls.append(args)
        if args[0].endswith('docker'):
            command = args[1:]
            if command[0] == 'compose':
                if command[-3:] == ['config', '--format', 'json']:
                    return json.dumps(self.project_render)
                if command[-3:] == ['up', '-d', '--no-build']:
                    if self.failed_project_start and self.alias == NEW:
                        raise RuntimeError('secret-project-start-error')
                    self.start_container()
                    return ''
            if command[0] == 'build':
                if self.stopped_for_maintenance:
                    raise AssertionError('build must precede downtime')
                if self.failed_build:
                    raise RuntimeError('secret-error-must-not-escape')
                if self.before_stop:
                    self.before_stop()
                return ''
            if command[:2] == ['image', 'inspect']:
                if command[2].endswith(':local') and self.alias is None:
                    raise RuntimeError('local image tag is missing')
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
                labels = {'io.github.784933671.certweb.managed': 'true'}
                if self.project_name:
                    labels.update({'com.docker.compose.project': self.project_name, 'com.docker.compose.service': 'certweb'})
                return json.dumps([{'Image': self.image, 'Config': {'Labels': labels},
                                    'State': {'Running': self.running, 'Restarting': False,
                                              'Health': {'Status': 'unhealthy' if self.failed_health and self.image == NEW else 'healthy'}}}])
            raise AssertionError(args)
        action = args[-1]
        if action == 'stop':
            self.stopped_for_maintenance = True
            if self.failed_stop:
                raise RuntimeError('secret-stop-error')
            self.running = False
        elif action == 'start':
            self.stopped_for_maintenance = False
            if not (self.home / 'container-project.json').exists():
                self.start_container()
        else:
            raise AssertionError(args)
        return ''

    def start_container(self):
        self.running = True
        self.image = self.alias
        if self.migrate and self.image == NEW:
            with sqlite3.connect(str(self.home / 'data/auth.sqlite3')) as c:
                c.execute('CREATE TABLE upgraded_table (value TEXT)')
        if self.after_start:
            self.after_start()


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
        self.elapsed = 0
        self.upgrade = Upgrade(self.source, self.home, runner=self.runner, uid=os.getuid(),
                               clock=lambda: self.elapsed, sleeper=self.advance)

    def advance(self, seconds):
        self.elapsed += seconds

    def hold_renewal(self):
        path = self.native / 'state/run.lock'
        if not path.exists():
            self.write(path, '')
        handle = path.open('a')
        self.addCleanup(handle.close)
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return handle

    def start_busy_upgrade(self):
        handles = []
        def start():
            if self.runner.image == NEW:
                if not handles:
                    handles.append(self.hold_renewal())
                self.runner.running = False
        self.runner.after_start = start
        with self.assertRaises(UpgradePending):
            self.upgrade.run()
        return handles[0]

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

    def test_long_startup_renewal_has_full_health_budget_after_real_lock_releases(self):
        handles = []
        def start():
            if self.runner.image == NEW:
                handles.append(self.hold_renewal())
                self.runner.running = False
                service = Deployment({'home': str(self.home), 'native_home': str(self.native),
                    'bind': '10.10.10.37', 'networks': ['10.10.10.0/24'], 'denied': ['10.10.10.1'],
                    'port': 18443, 'hostname': 'ttxli.cn'}, self.home / 'deployment.json')
                (self.home / 'tls').mkdir()
                (self.home / 'tls/current.cert').write_text('existing certificate')
                service.apply_access_policy = Mock(return_value={'mode': 'lan'})
                service.start_bridge = Mock()
                service.bridge_ready = Mock(return_value=True)
                service.container = Mock(return_value={'State': {'Running': False, 'Restarting': False}})
                service.compose = Mock()
                service.reconcile()
                state = json.loads((self.home / 'deployment-state.json').read_text())
                self.assertEqual((state['stage'], state['status']), ('tls', 'waiting'))
                service.compose.assert_not_called()
        self.runner.after_start = start
        def advance(seconds):
            self.advance(seconds)
            if self.elapsed >= 240 and not handles[0].closed:
                handles[0].close()
            if self.elapsed >= 240 + HEALTH_WAIT_SECONDS - 1:
                self.runner.running = True
        self.upgrade.sleep = advance
        with patch('web.setup_upgrade.time', Mock(time=Mock(side_effect=AssertionError('wall clock used')))):
            result = self.upgrade.run()
        self.assertTrue(result['upgraded'])
        self.assertEqual(self.elapsed, 240 + HEALTH_WAIT_SECONDS - 1)
        self.assertEqual(sum(args[-1] == 'stop' for args in self.runner.calls), 1)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'complete')
        self.assert_preserved()

    def test_long_busy_timeout_keeps_supervisor_and_starting_transaction_for_recovery(self):
        handle = self.start_busy_upgrade()
        self.assertEqual(self.elapsed, RENEWAL_WAIT_SECONDS + HEALTH_WAIT_SECONDS)
        self.assertEqual(sum(args[-1] == 'stop' for args in self.runner.calls), 1)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'starting')
        self.assertNotEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')
        self.assert_preserved()
        handle.close()
        self.runner.running = True
        calls = len(self.runner.calls)
        self.assertTrue(self.upgrade.recover()['recovered'])
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'complete')
        self.assertFalse(any(args[-1] in ('stop', 'start') for args in self.runner.calls[calls:]))
        self.assertEqual(self.runner.image, NEW)

    def test_upgrade_retry_confirms_pending_start_before_new_package_can_be_applied(self):
        handle = self.start_busy_upgrade()
        handle.close()
        self.runner.running = True
        calls = len(self.runner.calls)
        self.assertTrue(self.upgrade.run()['recovered'])
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'complete')
        self.assertFalse(any(args[-1] in ('stop', 'start') for args in self.runner.calls[calls:]))

    def test_recovery_while_renewal_still_busy_does_not_stop_supervisor(self):
        self.start_busy_upgrade()
        stops = sum(args[-1] == 'stop' for args in self.runner.calls)
        with self.assertRaises(UpgradePending):
            self.upgrade.recover()
        self.assertEqual(sum(args[-1] == 'stop' for args in self.runner.calls), stops)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'starting')
        self.assert_preserved()

    def test_failed_health_cannot_stop_service_if_renewal_wins_rollback_race(self):
        self.runner.failed_health = True
        actual_wait = self.upgrade.wait_healthy
        handles = []
        def wait(image):
            try:
                actual_wait(image)
            except UpgradeError:
                handles.append(self.hold_renewal())
                raise
        self.upgrade.wait_healthy = wait
        with self.assertRaises(UpgradePending):
            self.upgrade.run()
        self.assertEqual(sum(args[-1] == 'stop' for args in self.runner.calls), 1)
        self.assertTrue(self.runner.running)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'starting')
        handles[0].close()
        self.upgrade.wait_healthy = actual_wait
        self.assertTrue(self.upgrade.recover()['recovered'])
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'rolled_back')
        self.assertEqual(self.runner.image, OLD)
        self.assert_preserved()

    def test_restore_holds_run_lock_before_stopping_and_releases_before_restart(self):
        self.runner.failed_health = True
        runner = self.runner
        stops = []
        starts = []
        def command(args, timeout=60):
            if not args[0].endswith('docker'):
                path = self.native / 'state/run.lock'
                with path.open('a') as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        busy = False
                    except BlockingIOError:
                        busy = True
                (stops if args[-1] == 'stop' else starts).append(busy)
            return runner(args, timeout)
        self.upgrade.runner = command
        with self.assertRaisesRegex(UpgradeError, '已恢复原版本'):
            self.upgrade.run()
        self.assertEqual(stops, [True, True])
        self.assertEqual(starts, [False, False])
        self.assert_preserved()

    def test_interruption_during_busy_health_wait_keeps_supervisor_for_completion(self):
        def start():
            self.hold_renewal()
            self.runner.running = False
        self.runner.after_start = start
        def interrupt(_seconds):
            raise KeyboardInterrupt()
        self.upgrade.sleep = interrupt
        with self.assertRaises(UpgradePending):
            self.upgrade.run()
        self.assertEqual(sum(args[-1] == 'stop' for args in self.runner.calls), 1)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'starting')

    def test_invalid_monotonic_clock_does_not_trigger_destructive_rollback(self):
        self.runner.failed_health = True
        self.elapsed = 10
        self.upgrade.sleep = lambda _seconds: setattr(self, 'elapsed', 0)
        with self.assertRaises(UpgradePending):
            self.upgrade.run()
        self.assertEqual(sum(args[-1] == 'stop' for args in self.runner.calls), 1)
        self.assertTrue(self.runner.running)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'starting')

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

    def enable_project(self):
        from web.container_project import export_project
        self.runner.project_name = 'cert-project'
        self.runner.project_render = {'services': {'certweb': {
            'image': 'synology-cert-web:local', 'container_name': 'synology-cert-web',
            'network_mode': 'host', 'user': '10100:10100', 'read_only': True, 'init': True,
            'restart': 'no', 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
            'labels': {'io.github.784933671.certweb.managed': 'true'},
            'environment': {'OLD_CONFIG': 'kept'},
            'volumes': [{'type': 'bind', 'source': str(self.home / name), 'target': '/' + name,
                         'read_only': name != 'data'} for name in ('data', 'bridge', 'tls', 'access')]}}}
        self.project = export_project(self.home, self.root / 'project', 'cert-project', self.runner, uid=os.getuid())
        self.project_file = self.root / 'project/docker-compose.yml'
        self.old_project = self.project_file.read_bytes()
        self.runner.calls.clear()

    def test_project_upgrade_refreshes_saved_file_and_starts_same_project(self):
        self.enable_project()
        self.runner.project_render['services']['certweb']['environment']['NEW_CONFIG'] = 'updated'
        self.upgrade.run()
        manifest = json.loads(self.project_file.read_text())
        self.assertEqual(manifest['services']['certweb']['environment']['NEW_CONFIG'], 'updated')
        starts = [args for args in self.runner.calls if args[-3:] == ['up', '-d', '--no-build']]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0][starts[0].index('--project-name') + 1], 'cert-project')
        self.assertEqual(starts[0][starts[0].index('-f') + 1], str(self.project_file))
        self.assertTrue(self.runner.running)
        self.assertEqual(self.runner.image, NEW)
        self.assert_preserved()

    def test_explicit_upgrade_starts_previously_stopped_project_after_build(self):
        self.enable_project()
        self.runner.running = False
        self.assertTrue(self.upgrade.run()['upgraded'])
        build = next(index for index, args in enumerate(self.runner.calls) if args[1:2] == ['build'])
        stop = next(index for index, args in enumerate(self.runner.calls) if args[-1] == 'stop')
        self.assertLess(build, stop)
        self.assertTrue(self.runner.running)
        self.assertEqual(self.runner.image, NEW)
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'complete')
        self.assert_preserved()

    def test_project_upgrade_recreates_missing_local_tag_before_refresh(self):
        self.enable_project()
        self.runner.alias = None
        self.runner.project_render['services']['certweb']['environment']['NEW_CONFIG'] = 'updated'
        self.assertTrue(self.upgrade.run()['upgraded'])
        self.assertEqual((self.runner.alias, self.runner.image), (NEW, NEW))
        self.assertTrue(self.runner.running)
        state = json.loads(self.upgrade.journal.read_text())
        self.assertEqual(state['old_image'], OLD)
        self.assertEqual(state['phase'], 'complete')
        manifest = json.loads(self.project_file.read_text())
        self.assertEqual(manifest['services']['certweb']['environment']['NEW_CONFIG'], 'updated')
        self.assert_preserved()

    def test_project_refresh_failure_restores_missing_local_tag_to_old_image(self):
        self.enable_project()
        self.runner.alias = None
        self.runner.project_render = {'invalid': 'DO_NOT_PRINT'}
        with self.assertRaisesRegex(UpgradeError, '已恢复原版本') as caught:
            self.upgrade.run()
        self.assertNotIn('DO_NOT_PRINT', str(caught.exception))
        self.assertEqual((self.runner.alias, self.runner.image), (OLD, OLD))
        self.assertTrue(self.runner.running)
        self.assertEqual(self.project_file.read_bytes(), self.old_project)
        self.assertEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')
        self.assertEqual(json.loads(self.upgrade.journal.read_text())['phase'], 'rolled_back')
        self.assert_preserved()

    def test_failed_project_compose_start_restores_original_deployment(self):
        self.enable_project()
        self.runner.project_render['services']['certweb']['environment']['NEW_CONFIG'] = 'updated'
        self.runner.failed_project_start = True
        with self.assertRaisesRegex(UpgradeError, '已恢复原版本') as caught:
            self.upgrade.run()
        self.assertNotIn('secret-project-start-error', str(caught.exception))
        state = json.loads(self.upgrade.journal.read_text())
        self.assertEqual(self.project_file.read_bytes(), self.old_project)
        self.assertEqual((self.home / 'data/auth.sqlite3').read_bytes(),
                         (self.home / 'upgrades' / state['work'] / 'auth.sqlite3').read_bytes())
        self.assertEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')
        self.assertEqual((self.runner.alias, self.runner.image), (OLD, OLD))
        self.assertTrue(self.runner.running)
        self.assertEqual(state['phase'], 'rolled_back')
        starts = [args for args in self.runner.calls if args[-3:] == ['up', '-d', '--no-build']]
        self.assertEqual(len(starts), 2)
        for arguments in starts:
            self.assertEqual(arguments[arguments.index('--project-name') + 1], 'cert-project')
            self.assertEqual(arguments[arguments.index('-f') + 1], str(self.project_file))
        for name in NATIVE_FILES:
            self.assertEqual((self.native / name).read_text(), 'old:' + name)
        self.assert_preserved()

    def test_failed_project_upgrade_restores_manifest_and_old_image(self):
        self.enable_project()
        self.runner.project_render['services']['certweb']['environment']['NEW_CONFIG'] = 'updated'
        self.runner.failed_health = True
        with self.assertRaises(UpgradeError):
            self.upgrade.run()
        self.assertEqual(self.project_file.read_bytes(), self.old_project)
        self.assertEqual(self.runner.image, OLD)
        self.assert_preserved()

    def test_project_identity_conflict_is_rejected_before_build_or_stop(self):
        self.enable_project()
        self.runner.project_name = 'other-project'
        with self.assertRaises(UpgradeError):
            self.upgrade.run()
        self.assertFalse(any(args[-1] == 'stop' or args[1:2] == ['build'] for args in self.runner.calls))
        self.assertEqual(self.project_file.read_bytes(), self.old_project)

    def test_project_refresh_failure_restores_manifest_before_restart(self):
        self.enable_project()
        self.runner.project_render = {'invalid': 'DO_NOT_PRINT'}
        with self.assertRaises(UpgradeError):
            self.upgrade.run()
        self.assertEqual(self.project_file.read_bytes(), self.old_project)
        self.assertEqual(self.runner.image, OLD)

    def test_first_custom_project_upgrade_failure_retains_name_in_legacy_supervisor(self):
        self.runner.project_name = 'existing-project'
        original = "args = ['docker', 'compose', '--project-name', 'synology-cert-web', '--env-file', 'private.env']\n"
        self.write(self.home / 'code/deployment.py', original)
        self.runner.failed_health = True
        with self.assertRaisesRegex(UpgradeError, '已恢复原版本'):
            self.upgrade.run()
        state = json.loads(self.upgrade.journal.read_text())
        self.assertEqual(state['legacy_project'], 'existing-project')
        self.assertIn("'--project-name', 'existing-project'", (self.home / 'code/deployment.py').read_text())
        self.assertEqual((self.home / 'upgrades' / state['work'] / 'legacy-deployment.py').read_text(), original)
        self.assertEqual(self.runner.image, OLD)
        self.assertFalse(any(args[-3:] == ['up', '-d', '--no-build'] for args in self.runner.calls))

    def test_unrecognized_legacy_supervisor_is_not_rewritten(self):
        with self.assertRaisesRegex(UpgradeError, '无法保留'):
            self.upgrade.restore_project_identity({'legacy_project': 'existing-project'})
        self.assertEqual((self.home / 'code/deployment.py').read_text(), '# original deployment\n')


if __name__ == '__main__':
    unittest.main()
