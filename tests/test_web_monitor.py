import copy
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from web import monitor


def at(text):
    return monitor.timestamp(text + '+08:00')


class Source:
    def __init__(self, now):
        self.data = {'task': {'enable': True},
                     'schedule': {'mode': 'hourly', 'hour': 0, 'minute': 17, 'interval_hours': 1},
                     'last_completed': now, 'expires_at': now + 30 * 86400, 'target': 'ABC123',
                     'running': False, 'recipient': 'operator@example.com', 'delivery_enabled': True,
                     'task_ok': True, 'certificate_ok': True, 'completion_ok': True}
        self.deliver = Mock()

    def collect(self):
        return copy.deepcopy(self.data)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.native = self.root / 'native'; self.native.mkdir(mode=0o700)
        self.state = self.native / 'state'; self.state.mkdir(mode=0o700)
        self.web = self.root / 'web'; self.web.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.now = at('2026-11-03T10:00:00')
        self.mono = 0
        self.source = Source(self.now)
        self.service = self.make_monitor()

    def make_monitor(self):
        return monitor.Monitor(self.native, self.web, self.source, uid=self.uid,
                               clock=lambda: self.now, monotonic=lambda: self.mono)

    def advance(self, seconds):
        self.now += seconds; self.mono += seconds
        return self.service.tick()

    def settings(self, **changes):
        settings = dict(monitor.DEFAULT_SETTINGS, **changes)
        monitor.write_json(self.state / 'monitor-config.json', settings, self.uid)

    def codes(self, snapshot):
        return {item['code'] for item in snapshot['alerts']}

    def native_source_with_broken_completion(self):
        source = object.__new__(monitor.NativeSource)
        source.home, source.uid = self.native, self.uid
        source.scheduler = Mock()
        source.scheduler.get.return_value = {'enable': True,
            'extra': {'notify_enable': True, 'notify_mail': 'operator@example.com'}}
        source.bridge = Mock()
        source.bridge.read_schedule.return_value = self.source.data['schedule']
        source.bridge.executor.certificate_expiry.return_value = self.now + 3600
        controller = Mock(); controller.config = {'certificate_id': 'ABC123'}
        source.controller = Mock(return_value=controller)
        source.deliver = Mock()
        monitor.write_json(self.state / 'last-result.json', {'at': 'broken-time', 'success': False}, self.uid)
        self.source = source
        self.service = self.make_monitor()
        return source, controller

    def test_hourly_uses_actual_minute_and_grace_not_elapsed_period(self):
        self.service.tick()
        self.assertNotIn('task_missed', self.codes(self.advance(91 * 60)))
        result = self.advance(60)
        self.assertEqual(result['missed_runs'], 2)
        self.assertIn('task_missed', self.codes(result))
        self.assertEqual(result['next_expected_at'], monitor.utc(at('2026-11-03T12:17:00')))
        self.source.deliver.assert_called_once()

    def test_daily_schedule_crosses_midnight_and_counts_calendar_occurrences(self):
        self.source.data['schedule'] = {'mode': 'daily', 'hour': 0, 'minute': 30, 'interval_hours': 1}
        self.service.tick()
        self.assertNotIn('task_missed', self.codes(self.advance(14 * 3600 + 45 * 60)))
        self.assertIn('task_missed', self.codes(self.advance(86400)))

    def test_every_six_hours_is_aligned_to_beijing_midnight(self):
        schedule = {'mode': 'hourly', 'minute': 17, 'interval_hours': 6}
        missed, next_time = monitor.schedule_window(schedule, at('2026-11-03T01:00:00'), at('2026-11-03T12:17:00'))
        self.assertEqual(missed, 2)
        self.assertEqual(next_time, at('2026-11-03T18:17:00'))

    def test_first_install_without_history_does_not_invent_missed_runs(self):
        self.source.data['last_completed'] = None
        result = self.service.tick()
        self.assertEqual(result['missed_runs'], 0)
        self.assertNotIn('task_missed', self.codes(self.advance(16 * 60)))
        self.assertIn('task_missed', self.codes(self.advance(76 * 60)))

    def test_startup_grace_for_old_history_then_deduplicates_across_restart(self):
        self.source.data['last_completed'] -= 86400
        self.assertNotIn('task_missed', self.codes(self.service.tick()))
        self.assertIn('task_missed', self.codes(self.advance(900)))
        self.source.deliver.assert_called_once()
        self.service = self.make_monitor()
        self.service.tick(); self.advance(900); self.advance(3600)
        self.source.deliver.assert_called_once()

    def test_successful_completion_sends_one_recovery_only_after_alert(self):
        self.service.tick(); self.advance(7200)
        self.source.data['last_completed'] = self.now
        self.advance(60); self.advance(60)
        self.assertEqual(self.source.deliver.call_count, 2)
        self.assertTrue(self.source.deliver.call_args.kwargs['recovered'])
        self.service = self.make_monitor(); self.advance(900)
        self.assertEqual(self.source.deliver.call_count, 2)

    def test_resolved_unsent_alert_does_not_send_recovery(self):
        self.source.deliver.side_effect = RuntimeError('SECRET')
        self.service.tick(); result = self.advance(7200)
        self.assertEqual(result['alerts'][0]['notification_status'], 'failed')
        self.source.data['last_completed'] = self.now
        self.source.deliver.side_effect = None
        self.advance(60)
        self.assertEqual(self.source.deliver.call_count, 1)

    def test_mail_failure_backoff_persists_and_is_bounded(self):
        self.source.data['expires_at'] = self.now + 3600
        self.source.deliver.side_effect = RuntimeError('SECRET_SMTP_RESPONSE')
        first = self.service.tick()
        self.assertNotIn('SECRET', json.dumps(first))
        self.advance(59); self.assertEqual(self.source.deliver.call_count, 1)
        self.service = self.make_monitor(); self.advance(1)
        self.assertEqual(self.source.deliver.call_count, 2)
        result = self.advance(60)
        self.assertEqual(self.source.deliver.call_count, 2)
        self.assertIsNotNone(result['delivery']['last_error'])
        for _ in range(10):
            self.source.data['last_completed'] = self.now
            self.advance(3600)
        state = monitor.read_json(self.service.path, uid=self.uid)
        self.assertLessEqual(state['incidents']['certificate_expiry']['next_attempt'] - self.now, 3600)

    def test_backward_clock_retry_resumes_after_grace_without_duplicate_alert(self):
        self.source.data['expires_at'] = self.now + 3600
        expiry = self.source.data['expires_at']
        self.source.deliver.side_effect = RuntimeError('mail unavailable')
        self.service.tick()
        self.now -= 7200
        self.source.data['last_completed'] = self.now
        self.service.tick()
        self.source.deliver.side_effect = None
        result = self.advance(900)
        self.assertEqual(self.source.data['expires_at'], expiry)
        self.assertNotIn('clock_anomaly', self.codes(result))
        self.assertEqual(self.source.deliver.call_count, 2)
        self.assertFalse(self.source.deliver.call_args.kwargs['recovered'])
        self.service = self.make_monitor(); self.advance(60)
        self.assertEqual(self.source.deliver.call_count, 2)

    def test_restart_normalizes_persisted_retry_even_when_anchor_is_in_the_past(self):
        self.service.tick()
        self.now += 3 * 3600; self.mono += 3 * 3600
        self.source.data.update(last_completed=self.now, expires_at=self.now + 3600)
        expiry = self.source.data['expires_at']
        self.source.deliver.side_effect = RuntimeError('mail unavailable')
        self.service.tick()
        self.now -= 7200
        self.source.data['last_completed'] = self.now
        self.source.deliver.side_effect = None
        self.service = self.make_monitor(); self.service.tick()
        event = monitor.read_json(self.service.path, uid=self.uid)['incidents']['certificate_expiry']
        self.assertLessEqual(event['next_attempt'] - self.now, 3600)
        self.source.data['last_completed'] = self.now + 3600
        self.advance(3600)
        self.assertEqual(self.source.data['expires_at'], expiry)
        self.assertEqual(self.source.deliver.call_count, 2)
        self.service = self.make_monitor(); self.advance(60)
        self.assertEqual(self.source.deliver.call_count, 2)

    def test_recovery_retry_after_clock_rollback_is_not_a_new_alert(self):
        self.source.data['expires_at'] = self.now + 3600
        self.service.tick()
        self.source.data['expires_at'] = self.now + 30 * 86400
        self.source.deliver.side_effect = RuntimeError('mail unavailable')
        self.advance(60)
        expiry = self.source.data['expires_at']
        self.now -= 7200
        self.source.data['last_completed'] = self.now
        self.source.deliver.side_effect = None
        self.service = self.make_monitor(); self.service.tick(); self.advance(900)
        self.assertEqual(self.source.data['expires_at'], expiry)
        self.assertEqual([call.kwargs['recovered'] for call in self.source.deliver.call_args_list],
                         [False, True, True])
        self.assertNotIn('certificate_expiry', monitor.read_json(self.service.path, uid=self.uid)['incidents'])
        self.service = self.make_monitor(); self.advance(60)
        self.assertEqual(self.source.deliver.call_count, 3)

    def test_broken_completion_does_not_block_native_expiry_alert_or_recovery(self):
        source, _ = self.native_source_with_broken_completion()
        data = source.collect()
        self.assertTrue(data['task_ok'] and data['certificate_ok'])
        self.assertFalse(data['completion_ok'])
        result = self.service.tick()
        self.assertEqual(result['status'], 'unknown')
        self.assertIn('source_unavailable', self.codes(result))
        source.deliver.assert_called_once()
        self.service = self.make_monitor(); self.advance(60)
        source.deliver.assert_called_once()
        source.bridge.executor.certificate_expiry.return_value = self.now + 30 * 86400
        self.advance(60)
        self.assertEqual(source.deliver.call_count, 2)
        self.assertTrue(source.deliver.call_args.kwargs['recovered'])
        self.service = self.make_monitor(); self.advance(60)
        self.assertEqual(source.deliver.call_count, 2)

    def test_partial_completion_target_switch_does_not_recover_old_certificate(self):
        source, controller = self.native_source_with_broken_completion()
        self.service.tick(); source.deliver.assert_called_once()
        controller.config['certificate_id'] = 'NEW123'
        source.bridge.executor.certificate_expiry.return_value = self.now + 30 * 86400
        result = self.advance(60)
        self.assertNotIn('certificate_expiry', self.codes(result))
        source.deliver.assert_called_once()
        source.bridge.executor.certificate_expiry.return_value = self.now + 3600
        self.advance(60)
        self.assertEqual(source.deliver.call_count, 2)
        self.assertFalse(source.deliver.call_args.kwargs['recovered'])
        self.service = self.make_monitor(); self.advance(60)
        self.assertEqual(source.deliver.call_count, 2)

    def test_partial_completion_preserves_alert_until_certificate_can_be_read(self):
        source, _ = self.native_source_with_broken_completion()
        self.service.tick(); source.deliver.assert_called_once()
        source.bridge.executor.certificate_expiry.side_effect = ValueError('cannot read certificate')
        self.assertIn('certificate_expiry', self.codes(self.advance(60)))
        source.deliver.assert_called_once()
        source.bridge.executor.certificate_expiry.side_effect = None
        source.bridge.executor.certificate_expiry.return_value = self.now + 30 * 86400
        self.advance(60)
        self.assertEqual(source.deliver.call_count, 2)
        self.assertTrue(source.deliver.call_args.kwargs['recovered'])

    def test_partial_completion_waits_for_readable_notification_settings(self):
        source, _ = self.native_source_with_broken_completion()
        source.scheduler.get.side_effect = RuntimeError('cannot read task')
        result = self.service.tick()
        self.assertFalse(result['delivery']['enabled'])
        self.assertIsNone(result['delivery']['recipient'])
        source.deliver.assert_not_called()
        source.scheduler.get.side_effect = None
        self.advance(60); source.deliver.assert_called_once()

    def test_pausing_task_cancels_only_missed_event_not_certificate_alert(self):
        self.source.data['expires_at'] = self.now + 7200
        self.service.tick(); self.advance(7200)
        self.source.data['task']['enable'] = False
        result = self.advance(60)
        self.assertNotIn('task_missed', self.codes(result))
        self.assertIn('certificate_expiry', self.codes(result))
        self.assertEqual(result['status'], 'error')
        self.assertFalse(any(call.kwargs.get('recovered') for call in self.source.deliver.call_args_list))

    def test_expiring_to_expired_is_same_incident_without_false_recovery(self):
        self.source.data['task']['enable'] = False
        self.source.data['expires_at'] = self.now + 30
        self.service.tick(); result = self.advance(60)
        self.assertEqual(result['alerts'][0]['label'], '证书已经到期')
        self.source.deliver.assert_called_once()

    def test_disabled_failure_email_retains_panel_alert_without_mail(self):
        self.source.data['delivery_enabled'] = False
        self.source.data['expires_at'] = self.now + 30
        result = self.service.tick()
        self.assertEqual(result['alerts'][0]['notification_status'], 'disabled')
        self.assertEqual(result['delivery']['recipient'], 'o***@example.com')
        self.source.deliver.assert_not_called()
        self.source.data['delivery_enabled'] = True
        self.advance(60); self.source.deliver.assert_called_once()

    def test_monitor_disabled_is_silent_and_does_not_claim_recovery(self):
        self.source.data['expires_at'] = self.now + 3600
        self.service.tick(); self.settings(enabled=False)
        self.source.data['expires_at'] = self.now + 30 * 86400
        self.assertEqual(self.advance(60)['status'], 'disabled')
        self.source.deliver.assert_called_once()

    def test_unknown_schedule_does_not_guess_missed_runs(self):
        self.source.data['schedule'] = {'mode': 'unsupported'}
        self.service.tick(); result = self.advance(3 * 86400)
        self.assertIsNone(result['missed_runs'])
        self.assertFalse(result['schedule_supported'])
        self.assertEqual(result['status'], 'unknown')
        self.source.deliver.assert_not_called()

    def test_source_failure_and_future_record_preserve_existing_alert(self):
        self.source.data['expires_at'] = self.now + 3600
        self.service.tick()
        self.source.data.update(task_ok=False, task=None, schedule=None)
        self.assertIn('certificate_expiry', self.codes(self.advance(60)))
        self.source.data['last_completed'] = self.now + 86400
        self.assertIn('clock_anomaly', self.codes(self.advance(60)))
        self.source.deliver.assert_called_once()

    def test_forward_or_backward_clock_jump_has_grace_not_fake_recovery(self):
        self.source.data['expires_at'] = self.now + 3600
        self.service.tick(); self.now += 86400
        result = self.service.tick()
        self.assertIn('clock_anomaly', self.codes(result))
        self.assertIn('certificate_expiry', self.codes(result))
        self.source.deliver.assert_called_once()
        self.now -= 86400; self.service.tick()
        self.assertNotIn('clock_anomaly', self.codes(self.advance(900)))

    def test_running_task_has_bounded_grace(self):
        self.service.tick(); self.source.data['running'] = True
        self.assertNotIn('task_missed', self.codes(self.advance(7200)))
        self.assertIn('task_missed', self.codes(self.advance(900)))

    def test_schedule_and_target_switch_reset_missed_baseline(self):
        self.service.tick(); self.advance(7200)
        self.source.data['schedule']['minute'] = 45
        self.assertNotIn('task_missed', self.codes(self.advance(60)))
        self.assertNotIn('task_missed', self.codes(self.advance(900)))
        self.source.data['target'] = 'NEW123'
        self.assertNotIn('task_missed', self.codes(self.advance(3 * 3600)))
        self.assertNotIn('task_missed', self.codes(self.advance(900)))

    def test_target_switch_does_not_report_old_certificate_recovered(self):
        self.source.data['expires_at'] = self.now + 3600
        self.service.tick()
        self.source.data.update(target='NEW123', expires_at=self.now + 30 * 86400)
        self.advance(60)
        self.source.deliver.assert_called_once()

    def test_private_state_corruption_is_not_silently_reset(self):
        monitor.write_json(self.service.path, {'incidents': 'broken'}, self.uid)
        with self.assertRaises(ValueError):
            self.service.tick()
        self.source.deliver.assert_not_called()

    def test_parent_disappearance_exits_without_inspection_or_mail(self):
        self.source.collect = Mock()
        with patch('web.monitor.os.getppid', return_value=100), patch('web.monitor.signal.signal'):
            self.service.serve(101)
        self.source.collect.assert_not_called()

    def test_lock_excludes_duplicate_monitor(self):
        with monitor.locked(self.state / 'monitor.lock', self.uid):
            with self.assertRaises(BlockingIOError):
                self.service.serve(os.getppid())


class FileAndMailTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.uid = os.geteuid()

    def test_settings_reject_boolean_numbers_unknown_fields_and_out_of_range(self):
        for changes in ({'missed_runs': True}, {'missed_runs': 7}, {'grace_minutes': 4},
                        {'expiry_hours': 169}, {'enabled': 1}, {'extra': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                monitor.validate_settings(dict(monitor.DEFAULT_SETTINGS, **changes))

    def test_safe_files_reject_symlinks_hardlinks_public_files_and_oversize(self):
        target = self.root / 'target.json'; monitor.write_json(target, {'safe': True}, self.uid)
        path = self.root / 'link'; path.symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            monitor.read_json(path, uid=self.uid)
        with self.assertRaises(ValueError):
            monitor.write_json(path, {}, self.uid)
        path.unlink(); os.link(str(target), str(path))
        with self.assertRaises(ValueError):
            monitor.read_json(path, uid=self.uid)
        path.unlink(); target.chmod(0o644)
        with self.assertRaises(ValueError):
            monitor.read_json(target, uid=self.uid)
        target.chmod(0o600); target.write_bytes(b' ' * 300000)
        with self.assertRaises(ValueError):
            monitor.read_json(target, uid=self.uid)

    def test_mail_uses_dsm_lf_utf8_and_cleans_up_timed_out_process(self):
        source = object.__new__(monitor.NativeSource)
        source.home = self.root
        source.bridge = Mock(); source.bridge.executor.SYSTEM_PATH = '/bin'
        controller = Mock(); controller.call_local_api.return_value = {'enable_mail': True, 'sender_mail': 'sender@example.com'}
        source.controller = Mock(return_value=controller)
        process = Mock(); process.returncode = 0; process.poll.return_value = 0
        event = {'id': 'a' * 32, 'since': at('2026-11-03T10:00:00'), 'code': 'task_missed'}
        with patch('web.monitor.subprocess.Popen', return_value=process) as spawn:
            source.deliver('recipient@example.com', event)
            body = process.communicate.call_args.args[0]
            self.assertNotIn(b'\r\n', body)
            self.assertIn('证书检查任务漏跑'.encode(), body)
            self.assertEqual(spawn.call_args.args[0][-1], 'recipient@example.com')
            process.communicate.side_effect = subprocess.TimeoutExpired('ssmtp', 25)
            process.poll.return_value = None
            with self.assertRaises(subprocess.TimeoutExpired):
                source.deliver('recipient@example.com', event)
            controller.stop_process.assert_called_once_with(process)


if __name__ == '__main__':
    unittest.main()
