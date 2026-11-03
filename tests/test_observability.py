import copy
import json
from pathlib import Path
import unittest

from web.observability import snapshot, iso, MONITOR_TTL, RUNTIME_TTL


class ObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.now = 1793682000
        self.settings = {'version': 1, 'enabled': True, 'missed_runs': 2, 'grace_minutes': 15, 'expiry_hours': 24}
        self.files = {
            'runtime-health.json': {'version': 1, 'checked_at': iso(self.now),
                                   'components': [{'key': key, 'status': 'ok', 'message': '正常'}
                                                  for key in ('container', 'bridge', 'tls', 'access', 'monitor')],
                                   'container': {'running': True, 'health': 'healthy', 'restart_count': 0,
                                                 'oom_killed': False, 'started_at': iso(self.now - 60), 'uptime_seconds': 60}},
            'monitor-status.json': {'version': 1, 'checked_at': iso(self.now), 'status': 'ok',
                                    'task_enabled': True, 'schedule_supported': True,
                                    'settings': copy.deepcopy(self.settings), 'alerts': [],
                                    'delivery': {'enabled': True, 'recipient': 'o***@example.com', 'last_error': ''}},
        }

    def read(self):
        return snapshot(Path('/private/project'), lambda path, default: self.files.get(path.name, default),
                        lambda value, limit: value.replace('fixture-sensitive', '[已隐藏]')[:limit],
                        self.settings, self.now)

    def test_fresh_health_keeps_real_container_and_monitor_states(self):
        value = self.read()
        self.assertFalse(value['runtime']['stale'])
        self.assertFalse(value['monitor']['stale'])
        self.assertEqual([item['status'] for item in value['runtime']['components']], ['ok'] * 5)
        self.assertEqual(value['runtime']['container']['uptime_seconds'], 60)

    def test_stale_runtime_cannot_display_old_green_health(self):
        self.now += RUNTIME_TTL + 1
        value = self.read()
        self.assertTrue(value['runtime']['stale'])
        self.assertTrue(all(item['status'] == 'unknown' for item in value['runtime']['components']))
        self.assertFalse(value['monitor']['stale'])

    def test_dead_monitor_does_not_become_green_from_live_supervisor(self):
        self.files['monitor-status.json']['checked_at'] = iso(self.now - MONITOR_TTL - 1)
        value = self.read()
        self.assertFalse(value['runtime']['stale'])
        self.assertTrue(value['monitor']['stale'])
        self.assertEqual(value['monitor']['status'], 'unknown')
        self.assertEqual(value['runtime']['components'][-1]['status'], 'unknown')

    def test_unapplied_configuration_marks_monitor_snapshot_stale(self):
        self.settings['expiry_hours'] = 12
        self.assertTrue(self.read()['monitor']['stale'])

    def test_future_snapshot_is_not_treated_as_indefinitely_fresh(self):
        self.files['runtime-health.json']['checked_at'] = iso(self.now + 60)
        self.assertTrue(self.read()['runtime']['stale'])

    def test_pause_does_not_hide_expiry_incident(self):
        self.files['monitor-status.json'].update(task_enabled=False, status='warning', alerts=[
            {'code': 'certificate_expiry', 'label': '证书临近到期', 'since': iso(self.now),
             'message': '剩余12小时', 'notification_status': 'sent'}])
        value = self.read()['monitor']
        self.assertFalse(value['task_enabled'])
        self.assertEqual(value['status'], 'warning')
        self.assertEqual(value['alerts'][0]['code'], 'certificate_expiry')

    def test_private_fields_and_unknown_events_never_reach_snapshot(self):
        self.files['upgrade-state.json'] = {'phase': 'complete', 'backup': '/private/fixture-sensitive', 'old_image': 'private-image'}
        self.files['deployment-state.json'] = {'status': 'running', 'stage': 'running', 'at': self.now,
                                               'message': 'fixture-sensitive', 'pid': 42, 'secret_key': 'hidden'}
        self.files['runtime-health.json']['raw_docker_inspect'] = {'Env': ['SECRET=fixture-sensitive']}
        value = self.read()
        payload = json.dumps(value)
        self.assertNotIn('fixture-sensitive', payload)
        self.assertNotIn('private-image', payload)
        self.assertNotIn('secret_key', payload)
        self.assertEqual(value['upgrade'], {'phase': 'complete', 'label': '升级完成'})

    def test_malformed_nested_fields_degrade_to_unknown(self):
        self.files['runtime-health.json'].update(components=[{'key': {}}, {'key': 'tls', 'status': []}], container={'uptime_seconds': float('nan')})
        self.files['monitor-status.json'].update(status=[], delivery=[], alerts={})
        self.files['upgrade-state.json'] = {'phase': {}}
        value = self.read()
        self.assertEqual(value['monitor']['status'], 'unknown')
        self.assertIsNone(value['runtime']['container']['uptime_seconds'])
        self.assertIsNone(value['upgrade'])

    def test_absent_snapshots_are_unknown_and_events_are_bounded(self):
        self.files.clear()
        self.files['deployment-events.json'] = {'items': [
            {'at': iso(self.now), 'category': 'maintenance', 'status': 'stopping', 'stage': 'shutdown', 'message': '升级切换'}
        ] * 120}
        value = self.read()
        self.assertTrue(value['runtime']['stale'])
        self.assertTrue(value['monitor']['stale'])
        self.assertEqual(len(value['events']), 100)
        self.assertEqual(value['events'][0]['category'], 'maintenance')

    def test_failed_rollback_is_visible_and_huge_numbers_do_not_break_other_checks(self):
        self.files['upgrade-state.json'] = {'phase': 'rollback_failed'}
        self.files['runtime-health.json']['container']['uptime_seconds'] = 10 ** 1000
        value = self.read()
        self.assertEqual(value['upgrade']['phase'], 'rollback_failed')
        self.assertIsNone(value['runtime']['container']['uptime_seconds'])
        self.assertEqual(value['runtime']['components'][0]['status'], 'ok')


if __name__ == '__main__':
    unittest.main()
