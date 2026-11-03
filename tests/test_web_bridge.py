import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('web_host_bridge_tests', Path(__file__).resolve().parents[1] / 'web/host_bridge.py')
bridge_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge_module)
executor = bridge_module.executor


def config():
    return {'version': 1, 'deployment_method': 'local_api', 'certificate_id': 'ABC123',
            'certificate_description': 'NAS certificate', 'domains': ['ttxli.cn', 'www.ttxli.cn'],
            'email': 'operator@example.com', 'secret_id': 'SECRET_ID_NEVER_RETURN',
            'secret_key': 'SECRET_KEY_NEVER_RETURN', 'renew_before_days': 2,
            'success_notify_email': 'success@example.com',
            'probes': [{'host': '127.0.0.1', 'port': 5001, 'server_name': 'ttxli.cn'}]}


def task(home):
    return {'id': 7, 'name': 'ttxli.cn 证书自动续期', 'owner': 'root', 'real_owner': None, 'enable': True,
            'schedule': {'date': '2026/10/30', 'date_type': 0, 'hour': 0, 'last_work_hour': 23,
                         'minute': 17, 'monthly_week': [], 'repeat_date': 1001, 'repeat_hour': 1,
                         'repeat_hour_store_config': None, 'repeat_min': 0,
                         'repeat_min_store_config': None, 'version': 4, 'week_day': '0,1,2,3,4,5,6'},
            'extra': {'notify_enable': True, 'notify_if_error': True,
                      'notify_mail': 'failure@example.com', 'script': '/bin/sh ' + str(home / 'run-task.sh')}}


class FakeScheduler:
    def __init__(self, home):
        self.task = task(home)
        self.writes = []
        self.runs = 0
        self.fail_write = None

    def get(self):
        return copy.deepcopy(self.task)

    def put(self, value):
        self.writes.append(copy.deepcopy(value))
        self.task = copy.deepcopy(value)
        if self.fail_write is not None:
            self.fail_write(len(self.writes))
        return self.get()

    def run(self):
        self.runs += 1


class BridgeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name) / 'home'
        self.home.mkdir(mode=0o700)
        (self.home / 'state').mkdir(mode=0o700)
        self.archive = Path(temporary.name) / 'archive'
        self.archive.mkdir()
        for identifier in ('ABC123', 'DEF456'):
            (self.archive / identifier).mkdir()
            (self.archive / identifier / 'cert.pem').write_text('fixture')
        executor.save_json(self.archive / 'INFO', {
            'ABC123': {'desc': 'NAS certificate', 'services': [{'service': 'DSM'}]},
            'DEF456': {'desc': 'Other certificate', 'services': []}})
        executor.save_json(self.home / 'config.json', config())
        self.initial_notice = {'version': 1, 'certificate_id': 'ABC123',
                               'last_notified_fingerprint': 'a' * 64, 'pending': None}
        executor.save_json(self.home / 'state/success-notification.json', self.initial_notice)
        self.scheduler = FakeScheduler(self.home)
        original_private = executor.private
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(executor, 'private', side_effect=lambda path, directory=False, uid=0:
                          original_private(path, directory, os.getuid())).start()
        mock.patch.object(executor, 'certificate_domains', return_value=['ttxli.cn', 'www.ttxli.cn']).start()
        mock.patch.object(executor, 'fingerprint', return_value='a' * 64).start()
        mock.patch.object(executor, 'certificate_expiry', return_value=int(time.time()) + 86400 * 89).start()
        self.preflight = mock.Mock()
        self.controllers = []

        def factory():
            controller = executor.Controller(self.home, self.archive)
            controller.preflight = lambda *args, **kwargs: (self.preflight(), controller.metadata())[1]
            controller.dns_cleanup_count = lambda: 0
            controller.verify_probes = mock.Mock()
            controller.run = mock.Mock(side_effect=AssertionError('不得绕过原 DSM 任务'))
            self.controllers.append(controller)
            return controller

        self.bridge = bridge_module.Bridge(self.home, factory, self.scheduler, uid=os.getuid())

    def params(self):
        current = self.bridge.settings_get()
        keys = ('revision', 'certificate_id', 'email', 'renew_before_days', 'probes', 'schedule', 'notifications')
        result = {key: copy.deepcopy(current[key]) for key in keys}
        result['schedule'].pop('editable')
        return result

    def request(self, method, params=None):
        return self.bridge.dispatch({'method': method, 'params': params or {}})

    def read_config(self):
        return executor.read_json(self.home / 'config.json')

    def test_settings_only_returns_safe_fields_and_existing_domain_order(self):
        response = self.request('settings.get')
        self.assertTrue(response['ok'])
        payload = json.dumps(response)
        self.assertNotIn(config()['secret_id'], payload)
        self.assertNotIn(config()['secret_key'], payload)
        self.assertEqual(response['data']['schedule']['mode'], 'hourly')
        self.assertEqual(len(response['data']['certificates']), 2)

    def test_successful_update_keeps_notice_baseline_and_never_runs_certificate_job(self):
        params = self.params()
        params.update(renew_before_days=3, secret_id='NEW_SECRET_ID', secret_key='NEW_SECRET_KEY')
        params['notifications'].update(success_email='other@example.com', failure_email='new@example.com')
        params['schedule'].update(mode='daily', hour=4, minute=25)
        result = self.request('settings.update', params)
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.read_config()['renew_before_days'], 3)
        self.assertEqual(self.read_config()['secret_key'], 'NEW_SECRET_KEY')
        self.assertNotIn('NEW_SECRET', json.dumps(result))
        self.assertEqual(result['data']['schedule']['mode'], 'daily')
        self.assertNotEqual(result['data']['revision'], params['revision'])
        self.assertEqual(self.scheduler.task['extra']['notify_mail'], 'new@example.com')
        self.assertTrue(self.scheduler.task['extra']['notify_if_error'])
        self.assertEqual(executor.read_json(self.home / 'state/success-notification.json'), self.initial_notice)
        self.assertFalse(self.bridge.transaction.exists())
        self.assertEqual(self.scheduler.runs, 0)
        for controller in self.controllers:
            controller.run.assert_not_called()
        self.assertFalse(self.scheduler.writes[0]['enable'])
        self.assertTrue(self.scheduler.writes[-1]['enable'])
        backup = next((self.home / 'state/web-backups').glob('*/snapshot.json'))
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)

    def test_preflight_failure_restores_config_and_created_notification_state(self):
        params = self.params()
        previous_config = (self.home / 'config.json').read_bytes()
        previous_notice = (self.home / 'state/success-notification.json').read_bytes()
        previous_task = self.scheduler.get()
        def fail():
            executor.save_json(self.home / 'state/success-notification.json', {'broken': True})
            raise executor.Failure('upstream secret=' + config()['secret_key'])
        self.preflight.side_effect = fail
        params['renew_before_days'] = 4
        result = self.request('settings.update', params)
        self.assertFalse(result['ok'])
        self.assertIn('恢复', result['error']['message'])
        self.assertNotIn(config()['secret_key'], json.dumps(result))
        self.assertEqual((self.home / 'config.json').read_bytes(), previous_config)
        self.assertEqual((self.home / 'state/success-notification.json').read_bytes(), previous_notice)
        self.assertEqual(self.scheduler.task, previous_task)
        self.assertFalse(self.bridge.transaction.exists())

    def test_dsm_enable_failure_after_commit_finishes_forward(self):
        params = self.params()
        params['renew_before_days'] = 9
        previous = self.scheduler.get()
        self.scheduler.fail_write = lambda count: (_ for _ in ()).throw(OSError('DSM mismatch')) if count == 2 else None
        result = self.request('settings.update', params)
        self.assertFalse(result['ok'])
        self.assertEqual(self.read_config()['renew_before_days'], 9)
        self.assertEqual(executor.read_json(self.bridge.transaction)['phase'], 'committed')
        self.scheduler.fail_write = None
        self.bridge.recover()
        self.assertEqual(self.scheduler.task, previous)
        self.assertFalse(self.bridge.transaction.exists())

    def test_failed_rollback_blocks_further_actions_and_restart_recovers(self):
        params = self.params()
        params['renew_before_days'] = 9
        previous = self.scheduler.get()
        self.preflight.side_effect = executor.Failure('before commit')
        self.scheduler.fail_write = lambda count: (_ for _ in ()).throw(OSError('persistent failure')) if count >= 2 else None
        result = self.request('settings.update', params)
        self.assertFalse(result['ok'])
        self.assertTrue(self.bridge.transaction.exists())
        self.assertFalse(self.request('run')['ok'])
        self.scheduler.fail_write = None
        self.bridge.recover()
        self.assertEqual(self.read_config(), config())
        self.assertEqual(self.scheduler.task, previous)
        self.assertFalse(self.bridge.transaction.exists())

    def test_revision_changes_when_external_task_configuration_changes(self):
        params = self.params()
        self.scheduler.task['schedule']['minute'] = 32
        result = self.request('settings.update', params)
        self.assertEqual(result['error']['code'], 'stale_revision')
        self.assertEqual(self.scheduler.writes, [])

    def test_all_recovery_markers_prevent_save_and_are_preserved_byte_for_byte(self):
        params = self.params()
        for name in bridge_module.PROTECTION_FILES:
            with self.subTest(name=name):
                path = self.home / 'state' / name
                executor.save_json(path, {'protected': 'unchanged'})
                before = path.read_bytes()
                result = self.request('settings.update', params)
                self.assertEqual(result['error']['code'], 'conflict')
                self.assertEqual(path.read_bytes(), before)
                path.unlink()
        self.assertEqual(self.scheduler.writes, [])

    def test_pending_mail_prevents_disabling_or_switching_target(self):
        params = self.params()
        state = dict(self.initial_notice, pending={'fingerprint': 'b' * 64})
        executor.save_json(self.home / 'state/success-notification.json', state)
        params['notifications']['success_enabled'] = False
        params['certificate_id'] = 'DEF456'
        result = self.request('settings.update', params)
        self.assertEqual(result['error']['code'], 'conflict')
        self.assertEqual(executor.read_json(self.home / 'state/success-notification.json'), state)

    def test_valid_target_switch_reinitializes_notice_only_and_uses_existing_metadata(self):
        params = self.params()
        params['certificate_id'] = 'DEF456'
        result = self.request('settings.update', params)
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.read_config()['certificate_description'], 'Other certificate')
        self.assertEqual(executor.read_json(self.home / 'state/success-notification.json')['certificate_id'], 'DEF456')

    def test_management_host_blocks_uncovered_target_before_task_pause(self):
        self.bridge.management_host = 'ttxli.cn'
        with mock.patch.object(executor, 'certificate_domains', side_effect=lambda path:
                               ['other.example.com'] if path.parent.name == 'DEF456' else config()['domains']):
            params = self.params()
            params.update(certificate_id='DEF456', probes=[{'host': '127.0.0.1', 'port': 5001, 'server_name': 'other.example.com'}])
            choices = self.bridge.settings_get()['certificates']
            self.assertFalse(next(item for item in choices if item['id'] == 'DEF456')['selectable'])
            result = self.request('settings.update', params)
        self.assertEqual(result['error']['code'], 'validation')
        self.assertIn('管理域名', result['error']['message'])
        self.assertEqual(self.scheduler.writes, [])
        self.preflight.assert_not_called()
        self.assertFalse(self.bridge.transaction.exists())

    def test_management_host_accepts_wildcard_cover_and_requires_trusted_probe(self):
        self.bridge.management_host = 'www.ttxli.cn'
        with mock.patch.object(executor, 'certificate_domains', side_effect=lambda path:
                               ['*.ttxli.cn'] if path.parent.name == 'DEF456' else config()['domains']):
            params = self.params()
            params.update(certificate_id='DEF456', probes=[{'host': '127.0.0.1', 'port': 5001, 'server_name': 'www.ttxli.cn'}])
            result = self.request('settings.update', params)
        self.assertTrue(result['ok'], result)
        self.assertTrue(any(controller.verify_probes.call_args == mock.call('a' * 64, attempts=1, verify_chain=True)
                            for controller in self.controllers))

    def test_current_target_remains_editable_with_management_host(self):
        self.bridge.management_host = 'ttxli.cn'
        result = self.request('settings.update', self.params())
        self.assertTrue(result['ok'], result)

    def test_expired_management_certificate_is_rejected_before_any_mutation(self):
        self.bridge.management_host = 'ttxli.cn'
        params = self.params()
        with mock.patch.object(executor, 'certificate_expiry', return_value=int(time.time()) - 1):
            result = self.request('settings.update', params)
        self.assertEqual(result['error']['code'], 'validation')
        self.assertIn('过期', result['error']['message'])
        self.assertEqual(self.scheduler.writes, [])

    def test_untrusted_management_certificate_rolls_back_before_commit(self):
        self.bridge.management_host = 'ttxli.cn'
        params = self.params()
        original_factory = self.bridge.controller_factory
        def factory():
            controller = original_factory()
            controller.verify_probes.side_effect = executor.Failure('untrusted certificate')
            return controller
        self.bridge.controller_factory = factory
        result = self.request('settings.update', params)
        self.assertEqual(result['error']['code'], 'validation')
        self.assertIn('可信', result['error']['message'])
        self.assertEqual(self.read_config(), config())
        self.assertFalse(self.bridge.transaction.exists())

    def interrupted_committed_update(self):
        params = self.params()
        params['renew_before_days'] = 7
        real_unlink = Path.unlink
        def interrupt(path, *args, **kwargs):
            if path == self.bridge.transaction:
                raise SystemExit('crash before journal removal')
            return real_unlink(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', new=interrupt), self.assertRaises(SystemExit):
            self.bridge.settings_update(params)

    def test_committed_recovery_preserves_new_deployment_and_notification_pending(self):
        self.interrupted_committed_update()
        notice = dict(self.initial_notice, pending={'fingerprint': 'b' * 64, 'completed_at': executor.now()})
        notice_path = self.home / 'state/success-notification.json'
        pending_path = self.home / 'state/pending.json'
        executor.save_json(notice_path, notice)
        executor.save_json(pending_path, {'fingerprint': 'b' * 64})
        before = notice_path.read_bytes(), pending_path.read_bytes()
        self.bridge.recover()
        self.assertEqual(self.read_config()['renew_before_days'], 7)
        self.assertEqual((notice_path.read_bytes(), pending_path.read_bytes()), before)
        self.assertFalse(self.bridge.transaction.exists())

    def test_committed_recovery_refuses_changed_config_without_overwriting_any_state(self):
        self.interrupted_committed_update()
        altered = self.read_config()
        altered['email'] = 'changed@example.com'
        executor.save_json(self.home / 'config.json', altered)
        writes = len(self.scheduler.writes)
        with self.assertRaises(bridge_module.BridgeError):
            self.bridge.recover()
        self.assertEqual(self.read_config(), altered)
        self.assertEqual(len(self.scheduler.writes), writes)
        self.assertTrue(self.bridge.transaction.exists())

    def test_atomic_commit_write_reported_failure_still_finishes_forward(self):
        params = self.params()
        params['renew_before_days'] = 6
        original = self.bridge.commit_decision
        def committed_then_error(*args):
            original(*args)
            raise OSError('directory fsync failed after replace')
        self.bridge.commit_decision = committed_then_error
        result = self.request('settings.update', params)
        self.assertFalse(result['ok'])
        self.assertEqual(self.read_config()['renew_before_days'], 6)
        self.assertFalse(self.scheduler.task['enable'])
        self.bridge.recover()
        self.assertTrue(self.scheduler.task['enable'])
        self.assertEqual(self.read_config()['renew_before_days'], 6)

    def test_alive_bridge_retries_committed_recovery_and_preserves_prepared_journal(self):
        self.interrupted_committed_update()
        self.assertTrue(self.bridge.recovery_due())
        self.bridge.retry_recovery()
        self.assertFalse(self.bridge.transaction.exists())
        self.assertEqual(self.read_config()['renew_before_days'], 7)
        executor.save_json(self.bridge.transaction, {'phase': 'prepared'})
        self.bridge.recovery_attempt_at = -float('inf')
        self.bridge.retry_recovery()
        self.assertTrue(self.bridge.transaction.exists())
        self.assertFalse(self.bridge.recovery_due())

    def test_prepared_recovery_refuses_new_execution_or_notification_progress(self):
        controller = self.bridge.controller()
        self.bridge.snapshot(controller, self.scheduler.get())
        executor.save_json(self.home / 'state/last-result.json', {'at': executor.now(), 'success': True})
        with self.assertRaises(bridge_module.BridgeError):
            self.bridge.recover()
        self.assertTrue(self.bridge.transaction.exists())
        self.assertEqual(self.scheduler.writes, [])

    def test_invalid_and_injected_inputs_do_not_start_transaction(self):
        cases = [
            {'certificate_id': '../../etc/passwd'}, {'email': 'x@example.com\nBcc: thief@example.com'},
            {'renew_before_days': True}, {'renew_before_days': 31}, {'secret_key': '$(id)', 'secret_id': 'AKID'},
            {'secret_id': 'ONLY_ONE'}, {'command': 'rm -rf /'},
            {'probes': [{'host': '--output=/tmp/x', 'port': 443, 'server_name': 'ttxli.cn'}]},
            {'probes': [{'host': '127.0.0.1', 'port': True, 'server_name': 'ttxli.cn'}]},
            {'probes': [{'host': '127.0.0.1', 'port': 443, 'server_name': 'other.example.com'}]},
        ]
        for change in cases:
            with self.subTest(change=change):
                params = self.params()
                params.update(change)
                result = self.request('settings.update', params)
                self.assertFalse(result['ok'], result)
                self.assertFalse(self.bridge.transaction.exists())
        self.assertEqual(self.scheduler.writes, [])
        self.preflight.assert_not_called()

    def test_unknown_schedule_is_read_only(self):
        self.scheduler.task['schedule']['week_day'] = '1,2,3,4,5'
        params = self.params()
        self.assertEqual(params['schedule']['mode'], 'unsupported')
        params['schedule']['mode'] = 'hourly'
        result = self.request('settings.update', params)
        self.assertEqual(result['error']['code'], 'conflict')

    def test_shared_executor_lock_blocks_settings_and_manual_run(self):
        controller = self.bridge.controller()
        params = self.params()
        with controller.locked():
            self.assertEqual(self.request('run')['error']['code'], 'busy')
            self.assertEqual(self.request('settings.update', params)['error']['code'], 'busy')
            self.assertEqual(self.request('check')['error']['code'], 'busy')
        self.assertEqual(self.scheduler.runs, 0)
        self.assertTrue(self.request('check')['ok'])
        self.wait_for_check()

    def test_manual_run_preserves_disabled_schedule_and_deduplicates_requests(self):
        self.scheduler.task['enable'] = False
        self.assertTrue(self.request('run')['ok'])
        self.assertEqual(self.scheduler.runs, 1)
        self.assertFalse(self.scheduler.task['enable'])
        self.assertEqual(self.request('run')['error']['code'], 'busy')
        self.assertEqual(self.scheduler.runs, 1)

    def test_run_start_reservation_blocks_check_and_save_even_if_trigger_times_out(self):
        params = self.params()
        self.scheduler.run = mock.Mock(side_effect=OSError('may have started'))
        self.assertFalse(self.request('run')['ok'])
        self.assertEqual(self.request('check')['error']['code'], 'busy')
        self.assertEqual(self.request('settings.update', params)['error']['code'], 'busy')
        self.assertEqual(self.scheduler.writes, [])
        self.assertEqual(self.request('run')['error']['code'], 'busy')
        self.assertEqual(self.scheduler.runs, 0)

    def wait_for_check(self):
        deadline = time.monotonic() + 3
        while self.bridge.check_state['running'] and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertFalse(self.bridge.check_state['running'])

    def test_check_is_async_and_holds_single_instance_lock_until_completed(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def preflight():
            entered.set()
            release.wait(3)
        self.preflight.side_effect = preflight
        self.assertTrue(self.request('check')['ok'])
        self.assertTrue(entered.wait(1))
        self.assertTrue(self.bridge.check_state['running'])
        self.assertEqual(self.request('check')['error']['code'], 'busy')
        self.assertEqual(self.request('run')['error']['code'], 'busy')
        release.set()
        self.wait_for_check()
        self.assertTrue(self.bridge.check_state['last_result']['success'])
        self.assertEqual(self.scheduler.runs, 0)

    def test_bridge_shutdown_waits_for_already_running_async_check(self):
        entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.preflight.side_effect = lambda: (entered.set(), release.wait(3))
        self.assertTrue(self.request('check')['ok'])
        self.assertTrue(entered.wait(1))
        shutdown = threading.Event()
        shutdown.set()
        def stop():
            bridge_module.serve_requests(mock.Mock(), self.bridge, shutdown)
            stopped.set()
        worker = threading.Thread(target=stop)
        worker.start()
        self.assertFalse(stopped.wait(.03))
        release.set()
        worker.join(2)
        self.assertTrue(stopped.is_set())

    def test_check_error_and_last_result_are_redacted_and_allowlisted(self):
        secret = config()['secret_key']
        self.preflight.side_effect = executor.Failure('无法访问 SecretKey=' + secret)
        self.assertTrue(self.request('check')['ok'])
        self.wait_for_check()
        executor.save_json(self.home / 'state/last-result.json', {
            'at': executor.now(), 'success': False, 'message': 'SecretKey=' + secret,
            'raw_config': config(), 'command': 'private-command',
            'failure': {'stage_label': 'DNS 验证', 'summary': secret, 'arbitrary_secret': secret}})
        result = self.request('status')
        self.assertTrue(result['ok'], result)
        encoded = json.dumps(result)
        self.assertNotIn(secret, encoded)
        self.assertNotIn('raw_config', encoded)
        self.assertNotIn('private-command', encoded)
        self.assertNotIn('arbitrary_secret', encoded)

    def make_archive(self):
        root = self.home / 'state/failures'
        root.mkdir(mode=0o700, exist_ok=True)
        directory = root / ('failure-20261030T101700Z-' + '1' * 32)
        directory.mkdir(mode=0o700, exist_ok=True)
        executor.save_json(directory / 'complete.json', {'version': 1})
        executor.save_json(directory / 'report.json', {'stage_label': 'DNSPod 创建验证记录',
                           'summary': 'UnauthorizedOperation', 'code': 'UnauthorizedOperation',
                           'at': executor.now(), 'unknown': config()})
        bridge_module.atomic_bytes(directory / 'acme.log', ('SecretKey=' + config()['secret_key']).encode())
        return directory

    def test_failure_archives_are_redacted_and_report_fields_are_allowlisted(self):
        directory = self.make_archive()
        result = self.request('failures.get', {'id': directory.name})
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(result['data']['logs']), 1)
        self.assertNotIn(config()['secret_key'], json.dumps(result))
        self.assertNotIn('unknown', result['data']['report'])
        self.assertEqual(len(self.request('failures.list')['data']['items']), 1)

    def test_archive_traversal_directory_and_file_symlinks_are_rejected(self):
        directory = self.make_archive()
        for identifier in ('../config.json', str(directory), 'failure-../../etc/passwd'):
            self.assertFalse(self.request('failures.get', {'id': identifier})['ok'])
        log = directory / 'acme.log'
        log.unlink()
        log.symlink_to(self.home / 'config.json')
        result = self.request('failures.get', {'id': directory.name})
        self.assertFalse(result['ok'])
        self.assertNotIn(config()['secret_key'], json.dumps(result))
        link = directory.parent / ('failure-20261030T111700Z-' + '2' * 32)
        link.symlink_to(directory, target_is_directory=True)
        self.assertFalse(self.request('failures.get', {'id': link.name})['ok'])
        self.assertEqual(len(self.request('failures.list')['data']['items']), 1)

    def test_unknown_rpc_method_or_unexpected_params_are_rejected(self):
        for method, params in [('exec', {'command': 'id'}), ('run', {'force': True}),
                               ('status', {'path': '/etc/passwd'}), ('failures.get', {'id': 'x', 'path': '/'})]:
            self.assertEqual(self.request(method, params)['error']['code'], 'invalid_request')

    def test_security_update_is_versioned_and_does_not_modify_certificate_or_task(self):
        path=self.home/'access/access.json'
        policy=bridge_module.access_policy.initialize_policy(path,owner_uid=os.getuid(),gid=os.getgid())
        self.bridge.access_policy_path=path
        self.bridge.policy_gid=os.getgid()
        before=self.read_config();schedule=self.scheduler.get()
        result=self.request('security.update',{'access_mode':'public','revision':policy['revision']})
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['data']['mode'],'public')
        self.assertNotEqual(result['data']['revision'],policy['revision'])
        self.assertEqual(self.read_config(),before)
        self.assertEqual(self.scheduler.get(),schedule)
        self.assertEqual(self.scheduler.runs,0)
        stale=self.request('security.update',{'access_mode':'lan','revision':policy['revision']})
        self.assertEqual(stale['error']['code'],'stale_revision')
        back=self.request('security.update',{'access_mode':'lan','revision':result['data']['revision']})
        self.assertTrue(back['ok']);self.assertEqual(back['data']['mode'],'lan')

    def test_security_update_rejects_arbitrary_paths_and_unknown_modes(self):
        for params in [{'access_mode':'public','revision':'a'*32,'path':'/etc/passwd'},
                       {'access_mode':'anything','revision':'a'*32}, {'access_mode':'public','revision':None}]:
            self.assertEqual(self.request('security.update',params)['error']['code'],'validation')
        self.assertEqual(self.request('security.update',{'access_mode':'public','revision':'a'*32})['error']['code'],'unavailable')

    def test_security_update_corrupt_policy_is_not_silently_reinitialized(self):
        path=self.home/'access/access.json'
        policy=bridge_module.access_policy.initialize_policy(path,owner_uid=os.getuid(),gid=os.getgid())
        self.bridge.access_policy_path=path;self.bridge.policy_gid=os.getgid()
        path.write_text('{invalid')
        result=self.request('security.update',{'access_mode':'public','revision':policy['revision']})
        self.assertEqual(result['error']['code'],'unavailable')
        self.assertEqual(path.read_text(),'{invalid')


class TransportTests(unittest.TestCase):
    def exchange(self, payload, uid=10100, timeout=1, bridge=None):
        client, server = socket.socketpair()
        bridge = bridge or mock.Mock(dispatch=mock.Mock(return_value={'ok': True, 'data': {'safe': True}}))
        worker = threading.Thread(target=bridge_module.handle_connection,
                                  args=(server, bridge), kwargs={'identify': lambda _: uid, 'timeout': timeout})
        worker.start()
        client.settimeout(2)
        try:
            try:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            except BrokenPipeError:
                pass
            data = bytearray()
            while True:
                part = client.recv(8192)
                if not part:
                    break
                data.extend(part)
        finally:
            client.close()
            worker.join(2)
        return json.loads(data), bridge

    def test_rpc_peer_uid_and_exact_request_framing(self):
        payload = b'{"method":"status","params":{}}\n'
        result, bridge = self.exchange(payload)
        self.assertTrue(result['ok'])
        bridge.dispatch.assert_called_once_with({'method': 'status', 'params': {}})
        result, bridge = self.exchange(payload, uid=9999)
        self.assertEqual(result['error']['code'], 'forbidden')
        bridge.dispatch.assert_not_called()

    def test_duplicate_keys_oversize_incomplete_and_multiple_requests_are_rejected(self):
        for payload in (b'{"method":"status","method":"run","params":{}}\n',
                        b'x' * (bridge_module.MAX_REQUEST + 1), b'{"method":',
                        b'{"method":"status","params":{}}\n{"method":"run","params":{}}\n', b'{"v":NaN}\n'):
            with self.subTest(length=len(payload)):
                result, bridge = self.exchange(payload)
                self.assertFalse(result['ok'])
                bridge.dispatch.assert_not_called()

    def test_slow_action_returns_bounded_timeout_without_cancelling_transaction(self):
        done = threading.Event()
        def dispatch(_):
            time.sleep(.15)
            done.set()
            return {'ok': True, 'data': {}}
        result, _ = self.exchange(b'{"method":"status","params":{}}\n', timeout=.02,
                                  bridge=mock.Mock(dispatch=dispatch))
        self.assertEqual(result['error']['code'], 'unavailable')
        self.assertTrue(done.wait(1))

    def test_daemon_lock_is_exclusive_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'daemon.lock'
            with bridge_module.daemon_lock(path, os.getuid()):
                with self.assertRaises(bridge_module.BridgeError) as error:
                    with bridge_module.daemon_lock(path, os.getuid()):
                        pass
                self.assertEqual(error.exception.code, 'busy')
            link = Path(name) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                with bridge_module.daemon_lock(link, os.getuid()):
                    pass


class LifecycleTests(unittest.TestCase):
    def test_parent_mismatch_stops_accepting_and_drains_work(self):
        server, bridge = mock.Mock(), mock.Mock()
        with mock.patch.object(bridge_module.os, 'getppid', return_value=123):
            bridge_module.serve_requests(server, bridge, threading.Event(), parent_pid=456)
        server.accept.assert_not_called()
        server.close.assert_called_once()
        bridge.wait_idle.assert_called_once()

    def test_parent_is_checked_again_after_accept_timeout(self):
        server, bridge = mock.Mock(), mock.Mock()
        server.accept.side_effect = socket.timeout()
        with mock.patch.object(bridge_module.os, 'getppid', side_effect=[456, 1]):
            bridge_module.serve_requests(server, bridge, threading.Event(), parent_pid=456)
        self.assertEqual(server.accept.call_count, 1)
        bridge.wait_idle.assert_called_once()

    def test_unconfigured_parent_does_not_restrict_existing_service(self):
        server, bridge, shutdown = mock.Mock(), mock.Mock(), threading.Event()
        def accept():
            shutdown.set()
            raise socket.timeout()
        server.accept.side_effect = accept
        with mock.patch.object(bridge_module.os, 'getppid', side_effect=AssertionError('无父PID参数不检查父进程')):
            bridge_module.serve_requests(server, bridge, shutdown)
        server.accept.assert_called_once()

    def test_closed_work_group_rejects_new_requests_and_waits_for_started_transaction(self):
        group = bridge_module.WorkGroup()
        entered, release, completed = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def transaction():
            entered.set()
            release.wait(3)
            completed.set()
        self.assertTrue(group.start(transaction))
        self.assertTrue(entered.wait(1))
        group.close()
        self.assertFalse(group.start(lambda: None))
        stopped = threading.Event()
        waiter = threading.Thread(target=lambda: (group.wait(), stopped.set()))
        waiter.start()
        self.assertFalse(stopped.wait(.03))
        release.set()
        waiter.join(2)
        self.assertTrue(completed.is_set())
        self.assertTrue(stopped.is_set())

    def test_cli_parent_pid_is_optional_and_forwarded_when_given(self):
        for args, expected in (([], None), (['--parent-pid', '12345'], 12345)):
            with mock.patch.object(bridge_module.os, 'geteuid', return_value=0), \
                 mock.patch.object(bridge_module.os, 'umask'), \
                 mock.patch.object(bridge_module.signal, 'signal'), \
                 mock.patch.dict(os.environ), \
                 mock.patch.object(bridge_module, 'serve') as serve:
                self.assertEqual(bridge_module.main(['--management-host', 'ttxli.cn'] + args), 0)
                self.assertEqual(serve.call_args.args[-1], expected)


class SchedulerTests(unittest.TestCase):
    def test_fixed_task_only_and_readback_mismatch_is_an_error(self):
        scheduler = bridge_module.Scheduler(Path('/private/cert'))
        value = task(Path('/private/cert'))
        scheduler.api = mock.Mock(side_effect=[{}, dict(value, enable=False)])
        with self.assertRaises(bridge_module.BridgeError):
            scheduler.put(value)
        args = scheduler.api.call_args_list[0].args
        self.assertEqual(args[:3], ('SYNO.Core.TaskScheduler.Root', 'set', 4))
        self.assertEqual(args[3]['real_owner'], 'tangtao')
        self.assertNotIn('type', args[3])
        value['extra']['script'] += '; id'
        with self.assertRaises(bridge_module.BridgeError):
            scheduler.validate(value)

    def test_run_is_fixed_argv_without_shell_or_forced_renewal(self):
        capture = mock.Mock()
        scheduler = bridge_module.Scheduler(Path('/private/cert'), capture)
        scheduler.get = mock.Mock(return_value=task(Path('/private/cert')))
        with mock.patch.object(bridge_module.shutil, 'which', return_value='/usr/syno/bin/synoschedtask'):
            scheduler.run()
        self.assertEqual(capture.call_args.args[0], ['/usr/syno/bin/synoschedtask', '--run', 'id=7', 'check_time=0', 'check_status=0'])


if __name__ == '__main__':
    unittest.main()
