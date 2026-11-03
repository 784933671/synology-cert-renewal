import ast
import contextlib
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from web import startup_check as startup


class NativeStub:
    def __init__(self, home, uid):
        self.home, self.uid = home, uid
        self.prepare = Mock()
        self.run = Mock()
        self.dispatch = Mock(side_effect=lambda before_dispatch: (before_dispatch(), self.run_command())[1])

    def locked(self):
        return startup.monitor.locked(self.home / 'state/run.lock', self.uid)


class StartupCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.native = self.root / 'native'; self.native.mkdir(mode=0o700)
        self.state = self.native / 'state'; self.state.mkdir(mode=0o700)
        self.web = self.root / 'web'; self.web.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.started = '2026-11-03T03:18:00.123456789Z'
        self.now = startup.monitor.timestamp('2026-11-03T03:20:00Z')
        self.container = 'a' * 64
        self.source = NativeStub(self.native, self.uid)
        self.source.run_command = self.source.run
        self.source.run = self.source.dispatch
        self.path = self.web / 'startup-check.json'

    def checker(self, **changes):
        values = dict(native_home=self.native, web_home=self.web, task_id=7,
                      generation_id=self.container, started_at=self.started,
                      source=self.source, uid=self.uid, clock=lambda: self.now)
        values.update(changes)
        return startup.StartupCheck(**values)

    def saved(self):
        return startup.monitor.read_json(self.path, uid=self.uid)

    def completion(self, at, success=True):
        startup.monitor.write_json(self.state / 'last-result.json',
                                   {'at': at, 'success': success, 'message': 'checked'}, self.uid)

    def native_source(self):
        root = Path(startup.__file__).resolve().parents[1]
        (self.native / 'web').mkdir(mode=0o700, exist_ok=True)
        for relative in ('certctl.py', 'failure_diagnostics.py', 'run_history.py',
                         'web/host_bridge.py', 'web/access_policy.py', 'web/login_mail.py',
                         'web/observability.py', 'web/monitor.py', 'web/adaptive_schedule.py'):
            target = self.native / relative
            shutil.copyfile(str(root / relative), str(target)); target.chmod(0o600)
        source = startup.NativeTask(self.native, 7, self.uid)
        source.controller = Mock(spec=['locked', 'load', 'assert_manual_idle'])
        source.controller.locked.side_effect = self.source.locked
        startup.monitor.write_json(self.native / 'config.json', {}, self.uid)
        source.scheduler.capture = Mock()
        source.scheduler.api = Mock(return_value={
            'id': 7, 'owner': 'root', 'name': 'certificate', 'enable': True,
            'schedule': {}, 'extra': {'script': '/bin/sh ' + str(self.native / 'run-task.sh')}})
        return source

    def test_claim_is_durable_and_native_lock_is_released_before_dispatch(self):
        def dispatch():
            self.assertEqual(self.saved()['status'], 'dispatching')
            self.assertFalse(startup.monitor.lock_busy(self.state / 'run.lock', self.uid))
            self.assertTrue(startup.monitor.lock_busy(self.web / 'startup-check.lock', self.uid))
        self.source.run_command.side_effect = dispatch
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.saved()['status'], 'dispatched')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once_with()
        self.source.prepare.assert_called_once_with()

    def test_same_generation_does_not_need_dsm_to_be_available_again(self):
        self.assertEqual(self.checker().once(), 0)
        self.source.prepare.side_effect = RuntimeError('UNSAFE_COMMAND_SECRET')
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_different_start_time_and_new_container_are_distinct_generations(self):
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.checker(started_at='2026-11-03T03:19:00Z').once(), 0)
        self.assertEqual(self.checker(started_at='2026-11-03T03:19:00Z', generation_id='b' * 64).once(), 0)
        self.assertEqual(self.source.run_command.call_count, 3)

    def test_clock_rollback_does_not_skip_a_new_generation(self):
        self.assertEqual(self.checker(started_at='2026-11-03T03:19:00Z').once(), 0)
        self.now -= 3600
        self.assertEqual(self.checker(started_at='2026-11-03T02:19:00Z', generation_id='b' * 64).once(), 0)
        self.assertEqual(self.saved()['generation_id'], 'b' * 64)
        self.assertEqual(self.source.run_command.call_count, 2)

    def test_supervisor_restarts_in_same_second_are_distinct(self):
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.checker(generation_id='b' * 64).once(), 0)
        self.assertEqual(self.source.run_command.call_count, 2)

    def test_concurrent_helper_waits_for_independent_startup_lock(self):
        entered, release = threading.Event(), threading.Event()
        result = []
        def dispatch():
            entered.set()
            self.assertTrue(release.wait(3))
        self.source.run_command.side_effect = dispatch
        thread = threading.Thread(target=lambda: result.append(self.checker().once()))
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(self.checker().once(), startup.RETRY)
        finally:
            release.set(); thread.join(3)
        self.assertEqual(result, [0])
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_running_task_defers_then_its_completion_covers_startup(self):
        with startup.monitor.locked(self.state / 'run.lock', self.uid):
            self.assertEqual(self.checker().once(), startup.RETRY)
            self.assertFalse(self.path.exists())
        self.completion('2026-11-03T03:19:00Z')
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.saved()['status'], 'completed')
        self.source.run_command.assert_not_called()

    def test_running_task_without_new_completion_is_retried_normally(self):
        self.completion('2026-11-03T03:17:59Z')
        with startup.monitor.locked(self.state / 'run.lock', self.uid):
            self.assertEqual(self.checker().once(), startup.RETRY)
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_failed_daily_check_also_counts_as_a_completed_check(self):
        self.completion('2026-11-03T03:19:00Z', success=False)
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.saved()['status'], 'completed')
        self.source.run_command.assert_not_called()

    def test_previous_second_precision_result_does_not_cover_later_nano_start(self):
        self.completion('2026-11-03T03:18:00Z')
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_completion_exactly_at_start_covers_it(self):
        self.completion('2026-11-03T03:18:00Z')
        self.assertEqual(self.checker(started_at='2026-11-03T03:18:00Z').once(), 0)
        self.source.run_command.assert_not_called()

    def test_future_completion_or_clock_rollback_is_not_used_to_skip_startup(self):
        self.completion('2026-11-03T05:19:00Z')
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.checker(started_at='2026-11-03T06:18:00Z').once(), 0)
        self.assertEqual(self.source.run_command.call_count, 2)

    def test_pause_then_enable_retries_without_claim(self):
        source = self.native_source()
        source.scheduler.api.return_value['enable'] = False
        with patch.object(startup.shutil, 'which', return_value='/usr/syno/bin/synoschedtask'):
            self.assertEqual(self.checker(source=source).once(), startup.RETRY)
            self.assertFalse(self.path.exists())
            source.controller.assert_manual_idle.assert_not_called()
            source.scheduler.api.return_value['enable'] = True
            self.assertEqual(self.checker(source=source).once(), 0)
        source.scheduler.capture.assert_called_once_with(
            ['/usr/syno/bin/synoschedtask', '--run', 'id=7', 'check_time=0', 'check_status=0'], timeout=20)

    def test_pending_manual_force_request_defers_startup_check(self):
        source = self.native_source()
        source.controller.assert_manual_idle.side_effect = source.bridge.executor.Busy('queued')
        self.assertEqual(self.checker(source=source).once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        source.scheduler.capture.assert_not_called()

    def test_incomplete_configuration_transaction_defers_before_loading_config(self):
        source = self.native_source()
        transaction = self.state / 'web-transaction.json'
        startup.monitor.write_json(transaction, {'phase': 'prepared'}, self.uid)
        self.assertEqual(self.checker(source=source).once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        source.controller.load.assert_not_called()
        transaction.unlink()
        with patch.object(startup.shutil, 'which', return_value='/usr/syno/bin/synoschedtask'):
            self.assertEqual(self.checker(source=source).once(), 0)
        source.controller.load.assert_called_once()

    def test_missing_configuration_defers_before_first_install_finishes(self):
        source = self.native_source()
        (self.native / 'config.json').unlink()
        self.assertEqual(self.checker(source=source).once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        source.controller.load.assert_not_called()

    def test_invalid_configuration_prevents_dispatch(self):
        source = self.native_source()
        source.controller.load.side_effect = source.bridge.executor.Failure('SECRET')
        self.assertEqual(self.checker(source=source).once(), 1)
        self.assertFalse(self.path.exists())
        source.scheduler.capture.assert_not_called()

    def test_preclaim_command_failure_and_missing_executable_are_retryable(self):
        source = self.native_source()
        source.scheduler.api.side_effect = subprocess.TimeoutExpired(['SECRET'], 20)
        self.assertEqual(self.checker(source=source).once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        source.scheduler.api.side_effect = None
        with patch.object(startup.shutil, 'which', return_value=None):
            self.assertEqual(self.checker(source=source).once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        source.scheduler.capture.assert_not_called()

    def test_task_owner_script_and_structure_must_match_original(self):
        source = self.native_source()
        good = copy.deepcopy(source.scheduler.api.return_value)
        for changes in ({'owner': 'admin'}, {'id': 8}, {'enable': 1},
                        {'extra': {'script': '/bin/sh /tmp/other.sh'}},
                        {'extra': {'script': '/bin/sh ' + str(self.native / 'run-task.sh') + ' --force'}}):
            with self.subTest(changes=changes):
                source.scheduler.api.return_value = dict(good, **changes)
                self.assertEqual(self.checker(source=source).once(), 1)
                self.assertFalse(self.path.exists())
        source.scheduler.capture.assert_not_called()

    def test_timeout_after_scheduler_acceptance_is_unknown_and_never_replayed(self):
        source = self.native_source()
        source.scheduler.capture.side_effect = subprocess.TimeoutExpired(['SECRET_TOKEN'], 20)
        with patch.object(startup.shutil, 'which', return_value='/usr/syno/bin/synoschedtask'):
            checker = self.checker(source=source)
            self.assertEqual(checker.once(), 0)
            self.assertEqual(self.checker(source=source).once(), 0)
        self.assertEqual(self.saved()['status'], 'unknown')
        self.assertNotIn('SECRET', self.path.read_text() + checker.message)
        source.scheduler.capture.assert_called_once()

    def test_pause_during_dispatch_cannot_bypass_enabled_check(self):
        source = self.native_source()
        task = source.scheduler.api.return_value
        source.scheduler.api.side_effect = [task, dict(task, enable=False)]
        with patch.object(startup.shutil, 'which', return_value='/usr/syno/bin/synoschedtask'):
            self.assertEqual(self.checker(source=source).once(), startup.RETRY)
            self.assertFalse(self.path.exists())
            source.scheduler.capture.assert_not_called()
            source.scheduler.api.side_effect = None
            self.assertEqual(self.checker(source=source).once(), 0)
        self.assertEqual(self.saved()['status'], 'dispatched')
        source.scheduler.capture.assert_called_once()

    def test_claim_write_failure_prevents_dispatch(self):
        with patch.object(startup.monitor, 'write_json', side_effect=OSError('disk full')):
            self.assertEqual(self.checker().once(), 1)
        self.assertFalse(self.path.exists())
        self.source.run_command.assert_not_called()
        self.assertEqual(self.checker().once(), 0)

    def test_error_after_claim_replace_but_before_fsync_never_dispatches_or_replays(self):
        original = startup.monitor.write_json
        def partial(path, value, uid):
            original(path, value, uid)
            raise OSError('directory fsync failed')
        with patch.object(startup.monitor, 'write_json', side_effect=partial):
            self.assertEqual(self.checker().once(), 1)
        self.assertEqual(self.saved()['status'], 'dispatching')
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_not_called()

    def test_state_update_failure_after_acceptance_keeps_original_claim(self):
        original = startup.monitor.write_json
        def once(path, value, uid):
            if value['status'] != 'dispatching':
                raise OSError('disk full')
            original(path, value, uid)
        with patch.object(startup.monitor, 'write_json', side_effect=once):
            self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.saved()['status'], 'dispatching')
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_interruption_before_claim_allows_retry(self):
        self.source.prepare.side_effect = KeyboardInterrupt()
        self.assertEqual(self.checker().once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        self.source.prepare.side_effect = None
        self.assertEqual(self.checker().once(), 0)

    def test_interruption_while_releasing_native_lock_before_dispatch_allows_retry(self):
        original = self.source.locked
        @contextlib.contextmanager
        def interrupted_release():
            with original():
                yield
            raise KeyboardInterrupt()
        self.source.locked = interrupted_release
        self.assertEqual(self.checker().once(), startup.RETRY)
        self.assertFalse(self.path.exists())
        self.source.run_command.assert_not_called()
        self.source.locked = original
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_second_dsm_query_failure_before_command_is_retryable(self):
        source = self.native_source()
        task = source.scheduler.api.return_value
        source.scheduler.api.side_effect = [task, subprocess.TimeoutExpired(['private'], 20)]
        with patch.object(startup.shutil, 'which', return_value='/usr/syno/bin/synoschedtask'):
            self.assertEqual(self.checker(source=source).once(), startup.RETRY)
            self.assertFalse(self.path.exists())
            source.scheduler.capture.assert_not_called()
            source.scheduler.api.side_effect = None
            self.assertEqual(self.checker(source=source).once(), 0)
        self.assertEqual(self.saved()['status'], 'dispatched')
        source.scheduler.capture.assert_called_once()

    def test_interruption_during_dispatch_records_uncertain_outcome(self):
        self.source.run_command.side_effect = KeyboardInterrupt()
        self.assertEqual(self.checker().once(), 0)
        self.assertEqual(self.saved()['status'], 'unknown')
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_durable_dispatching_claim_from_crashed_process_is_not_replayed(self):
        self.assertEqual(self.checker().once(), 0)
        data = self.saved()
        data.update(status='dispatching', message=startup.MESSAGES['dispatching'])
        startup.monitor.write_json(self.path, data, self.uid)
        self.assertEqual(self.checker().once(), 0)
        self.source.run_command.assert_called_once()

    def test_state_symlink_does_not_read_or_replace_target(self):
        target = self.root / 'unrelated'; target.write_text('private')
        self.path.symlink_to(target)
        self.assertEqual(self.checker().once(), 1)
        self.assertEqual(target.read_text(), 'private')
        self.assertTrue(self.path.is_symlink())
        self.source.prepare.assert_not_called()

    def test_lock_symlink_is_rejected(self):
        target = self.root / 'unrelated'; target.write_text('private')
        (self.web / 'startup-check.lock').symlink_to(target)
        self.assertEqual(self.checker().once(), 1)
        self.source.run_command.assert_not_called()

    def test_state_hardlink_and_public_permissions_are_rejected(self):
        self.assertEqual(self.checker().once(), 0)
        os.link(str(self.path), str(self.web / 'alias'))
        self.assertEqual(self.checker().once(), 1)
        (self.web / 'alias').unlink()
        self.path.chmod(0o644)
        self.assertEqual(self.checker().once(), 1)
        self.source.run_command.assert_called_once()

    def test_duplicate_json_keys_and_wrong_types_are_not_silently_repaired(self):
        self.assertEqual(self.checker().once(), 0)
        good = self.saved()
        bad_values = [dict(good, version=True), dict(good, task_id=True), dict(good, generation='bad'),
                      dict(good, status='unsafe'), dict(good, message='SECRET'), dict(good, at=None),
                      dict(good, native_home='/unrelated'), dict(good, extra=True)]
        for value in bad_values:
            with self.subTest(value=value):
                self.path.write_text(json.dumps(value))
                self.assertEqual(self.checker().once(), 1)
        self.path.write_text('{"version":1,"version":1}')
        self.assertEqual(self.checker().once(), 1)
        self.source.run_command.assert_called_once()

    def test_last_result_invalid_or_linked_is_not_treated_as_completion(self):
        path = self.state / 'last-result.json'
        for value in ({'at': 'broken', 'success': True}, {'at': self.started, 'success': 1}, []):
            startup.monitor.write_json(path, value, self.uid)
            self.assertEqual(self.checker().once(), 1)
        path.unlink(); path.symlink_to(self.root / 'missing')
        self.assertEqual(self.checker().once(), 1)
        self.assertFalse(self.path.exists())
        self.source.run_command.assert_not_called()

    def test_unsafe_directories_and_invalid_generation_are_rejected(self):
        for value in ('short', 'A' * 64, 'a' * 63 + '\n'):
            self.assertEqual(self.checker(generation_id=value).once(), 1)
        for value in ('2026-11-03T03:18:00', '0001-01-01T00:00:00Z', 'invalid', True):
            self.assertEqual(self.checker(started_at=value).once(), 1)
        for value in (True, 0, -1, '7'):
            self.assertEqual(self.checker(task_id=value).once(), 1)
        self.web.chmod(0o755)
        self.assertEqual(self.checker().once(), 1)
        self.source.run_command.assert_not_called()

    def test_native_module_symlink_is_rejected_before_import(self):
        self.native_source()
        path = self.native / 'web/host_bridge.py'
        path.unlink(); path.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError):
            startup.NativeTask(self.native, 7, self.uid)

    def test_source_remains_python38_compatible(self):
        ast.parse(Path(startup.__file__).read_text(), feature_version=(3, 8))


if __name__ == '__main__':
    unittest.main()
