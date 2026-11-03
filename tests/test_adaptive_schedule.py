import ast
import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from web import adaptive_schedule as adaptive
from web import host_bridge


class Source:
    def __init__(self, home, uid):
        self.home = home
        self.uid = uid
        self.cert, self.candidate = home / 'current.pem', home / 'candidate.pem'
        self.cert.write_text('current'); self.candidate.write_text('current')
        self.controller = types.SimpleNamespace(
            state=home / 'state', config={'certificate_id': 'ABC123', 'domains': ['ttxli.cn']},
            load=Mock(), current_cert=lambda: self.cert, candidate=lambda: self.candidate,
            dns_cleanup_count=Mock(return_value=0), manual_renewal=Mock(return_value=None))
        self.executor = types.SimpleNamespace(
            RENEWAL_PROTECTION_FILES=('deployment-active.json', 'pending.json', 'run-baseline.json', 'import-bindings.json', 'recovery.json'),
            certificate_expiry=Mock(return_value=2000000000 + 86400 * 30),
            fingerprint=Mock(side_effect=lambda path: 'a' * 64 if path.read_text() == 'current' else 'b' * 64),
            certificate_domains=Mock(return_value=['ttxli.cn']))
        task = {'id': 7, 'name': 'cert', 'owner': 'root', 'enable': True,
                'schedule': {'date': '2026/11/3', 'date_type': 0, 'hour': 3, 'last_work_hour': 3,
                             'minute': 18, 'monthly_week': [], 'repeat_date': 1001, 'repeat_hour': 0,
                             'repeat_hour_store_config': None, 'repeat_min': 0, 'repeat_min_store_config': None,
                             'version': 4, 'week_day': '0,1,2,3,4,5,6'},
                'extra': {'script': '/bin/sh ' + str(home / 'run-task.sh'), 'notify_mail': 'mail@example.com',
                          'notify_enable': True, 'notify_if_error': True}}
        self.task = task
        self.scheduler = Mock(spec=['get', 'put'])
        self.scheduler.get.side_effect = lambda: host_bridge.Scheduler(home).validate(copy.deepcopy(self.task))
        def put(value):
            self.task = copy.deepcopy(value)
            return copy.deepcopy(value)
        self.scheduler.put.side_effect = put
        self.read_schedule = host_bridge.read_schedule
        self.write_schedule = host_bridge.write_schedule


class AdaptiveScheduleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.native = self.root / 'native'; self.native.mkdir(mode=0o700)
        self.state = self.native / 'state'; self.state.mkdir(mode=0o700)
        self.web = self.root / 'web'; self.web.mkdir(mode=0o700)
        self.uid, self.now = os.geteuid(), 2000000000
        self.source = Source(self.native, self.uid)
        self.preferences = {'success_email': 'success@example.com', 'adaptive_schedule': dict(adaptive.DEFAULT_PLAN)}
        self.write('web-preferences.json', self.preferences)
        self.success()

    def write(self, name, value):
        adaptive.monitor.write_json(self.state / name, value, self.uid)

    def success(self):
        self.write('last-result.json', {'at': adaptive.monitor.utc(self.now), 'success': True, 'fingerprint': 'a' * 64})

    def operation(self):
        return adaptive.AdaptiveSchedule(self.native, self.web, 7, self.source, self.uid, lambda: self.now)

    def saved(self):
        return adaptive.monitor.read_json(self.web / 'adaptive-schedule.json', uid=self.uid)

    def mode(self):
        return adaptive.desired_mode(self.source.controller, self.source.executor, self.uid, self.now)

    def test_48_hour_boundary_and_expired_certificate_use_hourly(self):
        for remaining, expected in ((172801, 'daily'), (172800, 'hourly'), (172799, 'hourly'), (-1, 'hourly')):
            with self.subTest(remaining=remaining):
                self.source.executor.certificate_expiry.return_value = self.now + remaining
                self.assertEqual(self.mode(), expected)

    def test_sync_changes_only_schedule_then_returns_to_daily_after_success(self):
        before = copy.deepcopy(self.source.task)
        self.source.executor.certificate_expiry.return_value = self.now + 3600
        self.assertEqual(self.operation().once(), 0)
        self.assertEqual(self.source.read_schedule(self.source.task)['mode'], 'hourly')
        for key in ('id', 'name', 'owner', 'enable', 'extra'):
            self.assertEqual(self.source.task[key], before[key])
        self.source.executor.certificate_expiry.return_value = self.now + 86400 * 30
        self.success()
        self.assertEqual(self.operation().once(), 0)
        self.assertEqual(self.source.read_schedule(self.source.task)['mode'], 'daily')
        self.assertEqual(self.source.task, before)
        self.assertEqual(self.source.scheduler.put.call_count, 2)
        self.assertEqual(self.saved()['current_mode'], 'daily')

    def test_success_result_does_not_clear_deployment_or_recovery_pending(self):
        for name in self.source.executor.RENEWAL_PROTECTION_FILES:
            self.write(name, {})
            self.assertEqual(self.mode(), 'hourly', name)
            (self.state / name).unlink()
        self.assertEqual(self.mode(), 'daily')

    def test_dns_notification_and_manual_pending_keep_hourly(self):
        self.source.controller.dns_cleanup_count.return_value = 1
        self.assertEqual(self.mode(), 'hourly')
        self.source.controller.dns_cleanup_count.return_value = 0
        self.write('success-notification.json', {'version': 1, 'certificate_id': 'ABC123', 'last_notified_fingerprint': 'a' * 64, 'pending': {'fingerprint': 'a' * 64}})
        self.assertEqual(self.mode(), 'hourly')
        self.write('success-notification.json', {'version': 1, 'certificate_id': 'ABC123', 'last_notified_fingerprint': 'a' * 64, 'pending': None})
        for request in ({'state': 'queued'}, {'state': 'running'}, {'state': 'failed', 'recovery_only': True}):
            self.source.controller.manual_renewal.return_value = request
            self.assertEqual(self.mode(), 'hourly')
        self.source.controller.manual_renewal.return_value = {'state': 'succeeded', 'recovery_only': False}
        self.assertEqual(self.mode(), 'daily')

    def test_enabled_notification_requires_confirmed_current_fingerprint(self):
        self.source.controller.config['success_notify_email'] = 'notify@example.com'
        self.assertEqual(self.mode(), 'hourly')
        notice = {'version': 1, 'certificate_id': 'ABC123', 'last_notified_fingerprint': 'b' * 64, 'pending': None}
        self.write('success-notification.json', notice)
        self.assertEqual(self.mode(), 'hourly')
        notice['last_notified_fingerprint'] = 'a' * 64
        self.write('success-notification.json', notice)
        self.assertEqual(self.mode(), 'daily')

    def test_unconfirmed_result_target_fingerprint_or_domain_never_lowers_frequency(self):
        for result in (None, {}, {'success': False}, {'success': True, 'fingerprint': 'b' * 64, 'at': adaptive.monitor.utc(self.now)},
                       {'success': True, 'fingerprint': 'a' * 64, 'at': adaptive.monitor.utc(self.now + 60)},
                       {'success': True, 'fingerprint': 'a' * 64, 'at': adaptive.monitor.utc(self.now), 'certificate_id': 'OTHER'}):
            if result is None:
                (self.state / 'last-result.json').unlink()
            else: self.write('last-result.json', result)
            self.assertEqual(self.mode(), 'hourly')
        self.success()
        self.source.executor.certificate_domains.return_value = ['other.example']
        self.assertEqual(self.mode(), 'hourly')

    def test_only_imported_or_only_issued_certificate_is_not_success(self):
        self.source.candidate.write_text('new')
        self.assertEqual(self.mode(), 'hourly')
        self.source.cert.write_text('new')
        self.assertEqual(self.mode(), 'hourly')
        self.write('last-result.json', {'at': adaptive.monitor.utc(self.now), 'success': True, 'fingerprint': 'b' * 64})
        self.assertEqual(self.mode(), 'daily')

    def test_paused_task_and_fixed_plan_are_never_enabled_or_rewritten(self):
        self.source.task['enable'] = False
        self.source.executor.certificate_expiry.return_value = self.now - 1
        self.assertEqual(self.operation().once(), 0)
        self.assertEqual(self.saved()['status'], 'paused')
        self.source.scheduler.put.assert_not_called()
        self.write('web-preferences.json', {'success_email': 'fixed@example.com'})
        self.assertEqual(self.operation().once(), 0)
        self.assertEqual(self.saved()['status'], 'disabled')
        self.source.scheduler.put.assert_not_called()

    def test_busy_run_or_transaction_defers_without_modifying_task(self):
        with adaptive.monitor.locked(self.state / 'run.lock', self.uid):
            self.assertEqual(self.operation().once(), adaptive.RETRY)
        self.write('web-transaction.json', {'phase': 'prepared'})
        self.assertEqual(self.operation().once(), adaptive.RETRY)
        self.source.scheduler.get.assert_not_called()
        self.source.scheduler.put.assert_not_called()

    def test_independent_sync_lock_prevents_parallel_writes(self):
        with adaptive.monitor.locked(self.web / 'adaptive-schedule.lock', self.uid):
            self.assertEqual(self.operation().once(), adaptive.RETRY)
        self.source.scheduler.get.assert_not_called()

    def test_foreign_schedule_is_not_overwritten(self):
        for changes in ({'minute': 19}, {'hour': 4, 'last_work_hour': 4}, {'repeat_hour': 2, 'hour': 0, 'last_work_hour': 23}):
            original = copy.deepcopy(self.source.task)
            self.source.task['schedule'].update(changes)
            self.assertEqual(self.operation().once(), 1)
            self.assertEqual(self.saved()['status'], 'conflict')
            self.source.scheduler.put.assert_not_called()
            self.source.task = original

    def test_task_identifier_owner_and_script_are_validated_before_writes(self):
        original = copy.deepcopy(self.source.task)
        for field, value in (('id', 8), ('owner', 'another-user'), ('script', '/bin/sh /other/task.sh')):
            self.source.task = copy.deepcopy(original)
            if field == 'script': self.source.task['extra']['script'] = value
            else: self.source.task[field] = value
            self.assertEqual(self.operation().once(), 1)
            self.source.scheduler.put.assert_not_called()
        self.assertNotIn('another-user', json.dumps(self.saved()))

    def test_external_change_between_initial_read_and_write_is_preserved(self):
        self.source.executor.certificate_expiry.return_value = self.now + 10
        original = copy.deepcopy(self.source.task)
        changed = copy.deepcopy(original); changed['extra']['notify_mail'] = 'new@example.com'
        self.source.scheduler.get.side_effect = [original, changed]
        self.assertEqual(self.operation().once(), 1)
        self.source.scheduler.put.assert_not_called()
        self.assertEqual(self.saved()['status'], 'conflict')

    def test_lost_write_response_is_reconciled_without_second_write(self):
        self.source.executor.certificate_expiry.return_value = self.now + 10
        def accepted(value):
            self.source.task = copy.deepcopy(value)
            raise TimeoutError('PRIVATE_SECRET')
        self.source.scheduler.put.side_effect = accepted
        self.assertEqual(self.operation().once(), 0)
        self.assertEqual(self.saved()['status'], 'hourly')
        self.source.scheduler.put.assert_called_once()
        self.assertNotIn('PRIVATE_SECRET', json.dumps(self.saved()))

    def test_known_nonwrite_failure_retries_and_unknown_change_is_not_overwritten(self):
        self.source.executor.certificate_expiry.return_value = self.now + 10
        self.source.scheduler.put.side_effect = TimeoutError('PRIVATE_SECRET')
        self.assertEqual(self.operation().once(), adaptive.RETRY)
        self.assertEqual(self.saved()['status'], 'error')
        original = copy.deepcopy(self.source.task)
        changed = copy.deepcopy(original); changed['enable'] = False
        self.source.scheduler.get.side_effect = [original, original, changed]
        self.assertEqual(self.operation().once(), 1)
        self.assertEqual(self.saved()['status'], 'conflict')
        self.assertEqual(self.source.scheduler.put.call_count, 2)

    def test_interrupted_accepted_write_is_reconciled_without_rewriting(self):
        self.source.executor.certificate_expiry.return_value = self.now + 10
        def interrupted(value):
            self.source.task = copy.deepcopy(value)
            raise KeyboardInterrupt()
        self.source.scheduler.put.side_effect = interrupted
        self.assertEqual(self.operation().once(), adaptive.RETRY)
        self.assertFalse(adaptive.monitor.lock_busy(self.state / 'run.lock', self.uid))
        self.assertEqual(self.operation().once(), 0)
        self.source.scheduler.put.assert_called_once()

    def test_termination_handler_raises_interrupt_for_subprocess_cleanup(self):
        handlers = []
        def register(sig, handler):
            handlers.append(handler)
            return 'previous'
        operation = Mock(message='safe', once=Mock(return_value=0))
        with patch.object(adaptive.os, 'geteuid', return_value=0), patch.object(adaptive.os, 'umask'), \
             patch.object(adaptive.signal, 'signal', side_effect=register), \
             patch.object(adaptive, 'AdaptiveSchedule', return_value=operation), patch('builtins.print'):
            self.assertEqual(adaptive.main(['--native-home', str(self.native), '--web-home', str(self.web), '--task-id', '7']), 0)
        with self.assertRaises(KeyboardInterrupt): handlers[0](15, None)
        self.assertEqual(handlers[-2:], ['previous', 'previous'])

    def test_noop_does_not_write_task_or_invoke_a_renewal(self):
        self.assertEqual(self.operation().once(), 0)
        self.source.scheduler.put.assert_not_called()
        self.assertFalse(hasattr(self.source.scheduler, 'run'))
        before = (self.state / 'last-result.json').read_bytes()
        for _ in range(3): self.assertEqual(self.operation().once(), 0)
        self.assertEqual((self.state / 'last-result.json').read_bytes(), before)

    def test_private_state_links_bad_json_and_bad_plan_are_rejected(self):
        for value in ({'version': 1, 'hour': True, 'minute': 18}, {'version': 1, 'hour': 24, 'minute': 18},
                      {'version': 1, 'hour': 3, 'minute': 60}, {'version': 2, 'hour': 3, 'minute': 18}):
            self.write('web-preferences.json', {'adaptive_schedule': value})
            self.assertEqual(self.operation().once(), 1)
        self.source.scheduler.put.assert_not_called()
        path = self.state / 'web-preferences.json'; path.unlink()
        outside = self.root / 'other'; outside.write_text('unchanged')
        path.symlink_to(outside)
        self.assertEqual(self.operation().once(), 1)
        self.assertEqual(outside.read_text(), 'unchanged')

    def test_duplicate_and_hardlinked_preferences_are_rejected(self):
        path = self.state / 'web-preferences.json'
        path.write_text('{"adaptive_schedule":{},"adaptive_schedule":{"version":1,"hour":3,"minute":18}}')
        self.assertEqual(self.operation().once(), 1)
        self.source.scheduler.put.assert_not_called()
        self.write('web-preferences.json', self.preferences)
        os.link(str(path), str(self.state / 'linked-preferences'))
        self.assertEqual(self.operation().once(), 1)
        self.source.scheduler.put.assert_not_called()

    def test_status_permissions_and_python38_syntax(self):
        self.assertEqual(self.operation().once(), 0)
        self.assertEqual((self.web / 'adaptive-schedule.json').stat().st_mode & 0o777, 0o600)
        ast.parse(Path(adaptive.__file__).read_text(), feature_version=(3, 8))


if __name__ == '__main__':
    unittest.main()
