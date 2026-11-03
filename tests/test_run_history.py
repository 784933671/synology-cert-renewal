import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('history_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl
history = certctl.history_module


class RunHistoryStorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.state.chmod(0o700)
        self.wall, self.monotonic = 1800000000.0, 1000.0
        self.store = history.RunHistory(self.state, uid=os.getuid(), clock=lambda: self.wall,
                                       monotonic=lambda: self.monotonic, alive=lambda owner: True)

    def start(self, **kwargs):
        return self.store.start('routine', ['ttxli.cn', '*.ttxli.cn'], 'ABC123', **kwargs)

    def path(self, recorder):
        return self.state / 'runs' / (recorder.record['id'] + '.json')

    def tick(self, seconds):
        self.wall += seconds
        self.monotonic += seconds

    def test_live_detail_and_completed_durations_but_list_has_only_summary(self):
        recorder = self.start()
        recorder.begin('preflight', '核对配置')
        self.tick(2.5)
        current = self.store.get(recorder.record['id'])
        self.assertEqual(current['status'], 'running')
        self.assertEqual(current['duration_seconds'], 2.5)
        self.assertEqual(current['stages'][0]['status'], 'running')
        self.assertEqual(current['stages'][0]['duration_seconds'], 2.5)
        self.assertIsNone(current['stages'][0]['finished_at'])
        recorder.finish('preflight')
        recorder.observe('dns_validation', 'unknown', '没有独立的 DNS 起止时间证据')
        self.tick(1.5)
        recorder.result('succeeded', '检查通过')
        detail = self.store.get(recorder.record['id'])
        self.assertEqual(detail['duration_seconds'], 4)
        self.assertEqual(detail['stages'][0]['duration_seconds'], 2.5)
        self.assertEqual(detail['stages'][1]['status'], 'unknown')
        for field in ('started_at', 'finished_at', 'duration_seconds'):
            self.assertIsNone(detail['stages'][1][field])
        listing = self.store.list()
        self.assertEqual(listing['items'][0]['stages'], [])
        self.assertEqual(listing['total'], 1)
        self.assertIsNone(listing['warning'])
        self.assertEqual(stat.S_IMODE(self.path(recorder).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.state / 'runs').stat().st_mode), 0o700)
        public = json.dumps(detail)
        self.assertNotIn('_owner', public)
        self.assertNotIn('_monotonic', public)
        self.assertNotIn('pid', public)

    def test_sensitive_values_and_paths_never_reach_disk_or_public_detail(self):
        secret = 'SECRET-ID-MUST-NOT-LEAK'
        recorder = self.start(secrets=(secret,), summary='验证 ' + secret)
        recorder.begin('issuance', secret + ' /volume1/private/config.json /volume1/证书/密钥 https://invalid.example/token')
        recorder.finish('issuance', 'failed', 'Authorization: Bearer token-not-public')
        recorder.result('failed', '读取 C:\\private\\config.json 失败')
        raw = self.path(recorder).read_text()
        for value in (secret, '/volume1/private/config.json', 'https://invalid.example/token',
                      'token-not-public', 'private\\\\config.json', '证书/密钥'):
            self.assertNotIn(value, raw)
        self.assertNotIn(secret, json.dumps(self.store.get(recorder.record['id'])))

    def test_disappeared_process_is_interrupted_without_inventing_death_time(self):
        recorder = self.start()
        recorder.begin('issuance')
        self.tick(90)
        self.store.alive = lambda owner: False
        detail = self.store.get(recorder.record['id'])
        self.assertEqual(detail['status'], 'interrupted')
        self.assertEqual(detail['stages'][0]['status'], 'interrupted')
        for value in (detail, detail['stages'][0]):
            self.assertIsNone(value['finished_at'])
            self.assertIsNone(value['duration_seconds'])
        self.assertEqual(json.loads(self.path(recorder).read_text())['status'], 'running')

    def test_pid_reuse_does_not_make_old_execution_look_alive(self):
        identity = '00000000-0000-0000-0000-000000000000:123'
        with mock.patch.object(history, '_identity', return_value=identity + '4'):
            self.assertFalse(history._alive({'pid': os.getpid(), 'tid': threading.get_native_id(), 'identity': identity}))
        with mock.patch.object(history.os, 'kill', side_effect=ProcessLookupError()):
            self.assertFalse(history._alive({'pid': 999999, 'tid': 999999, 'identity': None}))

    def test_completed_worker_with_failed_terminal_write_does_not_remain_running(self):
        self.store.alive = history._alive
        records, errors = [], []
        def check_worker():
            try:
                recorder = self.store.start('check')
                records.append(recorder.record['id'])
                recorder.begin('preflight')
                recorder.finish('preflight')
                with mock.patch.object(self.store, '_save', side_effect=OSError('disk-full')):
                    with self.assertRaises(OSError):
                        recorder.result('succeeded', '已完成')
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=check_worker)
        worker.start()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.tick(99900)
        detail = self.store.get(records[0])
        self.assertEqual(detail['status'], 'interrupted')
        self.assertIsNone(detail['duration_seconds'])
        self.assertEqual(detail['stages'][0]['status'], 'succeeded')
        self.assertIsNone(detail['finished_at'])

    def test_success_cannot_mark_an_unfinished_stage_successful(self):
        recorder = self.start()
        recorder.begin('deployment')
        recorder.result('succeeded', '结果已返回但阶段证据不完整')
        self.assertEqual(self.store.get(recorder.record['id'])['stages'][0]['status'], 'unknown')

    def test_rejects_traversal_bad_pagination_and_invalid_identifiers(self):
        for identifier in ('../config', '/etc/passwd', 'run-20279999T000000Z-' + 'a' * 32, None):
            with self.subTest(identifier=identifier), self.assertRaises(history.HistoryError):
                self.store.get(identifier)
        for offset, limit in ((-1, 20), (True, 20), (0, 51), (0, True), (0, 0)):
            with self.subTest(offset=offset, limit=limit), self.assertRaises(history.HistoryError):
                self.store.list(offset, limit)
        self.assertEqual(self.store.list()['total'], 0)
        self.assertFalse((self.state / 'runs').exists())

    def test_rejects_symlinks_hardlinks_public_permissions_and_oversized_files(self):
        recorder = self.start()
        target = self.path(recorder)
        original = target.read_bytes()
        for attack in ('symlink', 'hardlink', 'permissions', 'oversized'):
            with self.subTest(attack=attack):
                target.unlink()
                outside = self.state / 'outside'
                outside.write_bytes(original)
                outside.chmod(0o600)
                if attack == 'symlink':
                    target.symlink_to(outside)
                elif attack == 'hardlink':
                    os.link(outside, target)
                else:
                    target.write_bytes(b'x' * (history.MAX_FILE_BYTES + 1) if attack == 'oversized' else original)
                    target.chmod(0o644 if attack == 'permissions' else 0o600)
                with self.assertRaises(history.HistoryError):
                    self.store.get(recorder.record['id'])
                target.unlink()
                outside.unlink()
                target.write_bytes(original)
                target.chmod(0o600)
        target.unlink()
        (self.state / 'runs').rmdir()
        (self.state / 'runs').symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(history.HistoryError):
            self.store.list()

    def test_malformed_records_are_rejected_instead_of_projecting_partial_success(self):
        recorder = self.start()
        recorder.begin('preflight')
        base = copy.deepcopy(recorder.record)
        def missing_owner(value):
            del value['_owner']['identity']
        def missing_stage(value):
            del value['stages'][0]['finished_at']
        def invalid_stage(value):
            value['stages'] = [None]
        def invalid_timer(value):
            value['_monotonic'] = float('nan')
        for change in (missing_owner, missing_stage, invalid_stage, invalid_timer):
            with self.subTest(change=change.__name__):
                value = copy.deepcopy(base)
                change(value)
                self.path(recorder).write_text(json.dumps(value))
                with self.assertRaises(history.HistoryError):
                    self.store.get(recorder.record['id'])
        recorder.record['id'] = '../escape'
        with self.assertRaises(history.HistoryError):
            recorder.save()
        self.assertFalse((self.state / 'escape.json').exists())

    def test_direct_detail_rejects_fifo_without_waiting_for_a_writer(self):
        recorder = self.start()
        self.path(recorder).unlink()
        os.mkfifo(str(self.path(recorder)), 0o600)
        with self.assertRaises(history.HistoryError):
            self.store.get(recorder.record['id'])

    def test_actual_500_run_limit_pagination_and_thirty_day_retention(self):
        first = None
        # Seed private valid files so the boundary is checked without 500 unrelated fsync cycles.
        template = self.start()
        for number in range(500):
            value = copy.deepcopy(template.record)
            value['id'] = value['id'][:21] + format(number, '032x')
            if first is None:
                first = value['id']
            path = self.state / 'runs' / (value['id'] + '.json')
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        self.tick(1)
        latest = self.start()
        self.assertEqual(len(list((self.state / 'runs').glob('*.json'))), 500)
        page = self.store.list(490, 20)
        self.assertEqual(page['total'], 500)
        self.assertEqual(len(page['items']), 10)
        self.tick(history.RETENTION_SECONDS + 1)
        self.assertEqual(self.store.list()['total'], 0)
        with self.assertRaises(history.HistoryNotFound):
            self.store.get(latest.record['id'])
        self.start()
        self.assertEqual(len(list((self.state / 'runs').glob('*.json'))), 1)

    def test_write_failure_is_visible_and_recovery_preserves_in_memory_stages(self):
        recorder = self.start()
        before = self.path(recorder).read_bytes()
        with mock.patch.object(history.os, 'replace', side_effect=OSError('disk-failure-secret')):
            with self.assertRaises(OSError):
                recorder.begin('issuance', '申请已开始')
        self.assertEqual(self.path(recorder).read_bytes(), before)
        self.store.note_error()
        warning = self.state / 'run-history-error.json'
        before = warning.read_bytes()
        self.tick(10)
        self.store.note_error()
        self.assertEqual(warning.read_bytes(), before)
        self.assertEqual(self.store.list()['warning'], history.HISTORY_WARNING)
        recorder.finish('issuance', 'succeeded')
        recorder.result('succeeded', '写入恢复')
        result = self.store.get(recorder.record['id'])
        self.assertEqual(result['stages'][0]['status'], 'succeeded')
        self.assertEqual(result['stages'][0]['duration_seconds'], 10)
        self.assertEqual(result['stages'][1]['stage'], 'history')
        self.assertEqual(result['stages'][1]['status'], 'failed')
        self.assertIsNone(self.store.list()['warning'])
        self.assertFalse(warning.exists())
        self.assertNotIn('disk-failure-secret', self.path(recorder).read_text())
        self.assertEqual(list((self.state / 'runs').glob('.write-*')), [])

    def test_corrupt_warning_is_rejected_and_not_returned_as_raw_error(self):
        marker = self.state / 'run-history-error.json'
        marker.write_text('{"warning":"secret-data"}')
        marker.chmod(0o600)
        with self.assertRaisesRegex(history.HistoryError, '警告内容无效'):
            self.store.list()
        marker.unlink()
        marker.symlink_to(self.state / 'other')
        with self.assertRaises(history.HistoryError):
            self.store.list()


class RunHistoryBusinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURES.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURES.CertificateTests.tearDownClass)

    def setUp(self):
        self.fixture = FIXTURES.CertificateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.configure_runtime_mocks()
        self.controller = self.fixture.controller
        self.controller.config['renew_before_days'] = 2
        self.fixture.prepare_candidate('old')
        self.store = history.RunHistory(self.controller.state, uid=os.getuid())

    def detail(self):
        return self.store.get(self.controller.history_recorder.record['id'])

    def stage(self, name):
        return [entry for entry in self.detail()['stages'] if entry['stage'] == name]

    def issue_and_deploy(self, arguments):
        if arguments[0] in ('--renew', '--issue'):
            live = self.detail()
            self.assertEqual(live['status'], 'running')
            self.assertEqual(self.stage('issuance')[-1]['status'], 'running')
            self.assertEqual(self.stage('deployment'), [])
            self.fixture.prepare_candidate('new')
        else:
            self.assertEqual(arguments[0], '--deploy')
            self.fixture.install_current('new')
        return 0

    def request(self):
        with self.controller.locked():
            return self.controller.request_manual_renewal()

    def test_ordinary_outside_window_check_is_recorded_as_skip_without_false_dns_success(self):
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不得签发'))
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(self.detail()['kind'], 'routine')
        self.assertEqual(self.detail()['status'], 'skipped')
        for name in ('issuance', 'dns_validation', 'deployment', 'notification'):
            self.assertEqual(self.stage(name)[-1]['status'], 'skipped')
        self.assertEqual(self.stage('tls_verify')[-1]['status'], 'succeeded')
        self.assertEqual(self.detail()['domains'], ['ttxli.cn', '*.ttxli.cn'])
        self.assertEqual(self.detail()['certificate_id'], 'ABC123')

    def test_due_renewal_records_real_boundaries_but_no_invented_dns_timing(self):
        self.fixture.install_current('short')
        self.fixture.prepare_candidate('short')
        self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
        self.controller.run()
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list], ['--renew', '--deploy'])
        self.assertEqual(self.detail()['status'], 'succeeded')
        for name in ('issuance', 'deployment', 'tls_verify', 'dns_cleanup_check'):
            self.assertEqual(self.stage(name)[-1]['status'], 'succeeded')
            self.assertIsNotNone(self.stage(name)[-1]['started_at'])
        dns = self.stage('dns_validation')[-1]
        self.assertEqual(dns['status'], 'unknown')
        self.assertIsNone(dns['duration_seconds'])
        self.assertIsNone(dns['started_at'])

    def test_forced_request_record_and_following_routine_check_do_not_reissue(self):
        self.request()
        self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
        self.controller.run()
        self.assertEqual(self.detail()['kind'], 'forced')
        self.assertEqual(self.detail()['status'], 'succeeded')
        self.assertIn('--force', self.controller.invoke_acme.call_args_list[0].args[0])
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertEqual(self.detail()['status'], 'skipped')
        self.assertEqual(self.store.list()['total'], 2)

    def test_dns_failure_exposes_classification_without_output_or_credentials(self):
        self.request()
        def denied(arguments):
            self.controller.acme_events = [{'stage': 'dns_create', 'action': 'CreateRecord',
                                          'code': 'UnauthorizedOperation.NoPermission',
                                          'category': 'permission'}]
            self.controller.acme_evidence = self.controller.config['secret_key']
            return 1
        self.controller.invoke_acme = mock.Mock(side_effect=denied)
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual(self.detail()['status'], 'failed')
        self.assertEqual(self.stage('dns_validation')[-1]['status'], 'failed')
        self.assertIn('权限', self.stage('dns_validation')[-1]['message'])
        self.assertIsNone(self.stage('dns_validation')[-1]['duration_seconds'])
        self.assertEqual(self.stage('deployment')[-1]['status'], 'skipped')
        self.assertNotIn(self.controller.config['secret_key'], json.dumps(self.detail()))
        self.assertTrue(self.controller.manual_renewal()['force_consumed'])

    def test_process_interruption_and_recovery_are_separate_and_do_not_replay_force(self):
        self.request()
        self.controller.invoke_acme = mock.Mock(side_effect=SystemExit('killed-secret-value'))
        with self.assertRaises(SystemExit):
            self.controller.run()
        interrupted_id = self.detail()['id']
        self.assertEqual(self.detail()['status'], 'interrupted')
        self.assertEqual(self.stage('issuance')[-1]['status'], 'interrupted')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不得重放'))
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(self.detail()['kind'], 'recovery')
        self.assertEqual(self.stage('issuance')[-1]['status'], 'skipped')
        self.assertEqual(self.store.get(interrupted_id)['status'], 'interrupted')
        self.assertEqual(self.store.list()['total'], 2)

    def test_history_failure_does_not_replay_issuance_or_skip_tls_cleanup(self):
        self.request()
        calls = []
        def renew(arguments):
            calls.append(arguments[0])
            if arguments[0] == '--renew':
                self.fixture.prepare_candidate('new')
            else:
                self.fixture.install_current('new')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=renew)
        with mock.patch.object(history.RunHistory, '_save', side_effect=OSError('private-disk-error')):
            self.controller.run()
        self.assertEqual(calls, ['--renew', '--deploy'])
        self.assertEqual(self.controller.manual_renewal()['state'], 'succeeded')
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertEqual(self.store.list()['warning'], history.HISTORY_WARNING)
        self.controller.run()
        self.assertEqual(calls, ['--renew', '--deploy'])
        self.assertIsNone(self.store.list()['warning'])
        self.assertEqual(self.detail()['status'], 'skipped')

    def test_midrun_history_write_failure_retains_stages_and_does_not_repeat_force(self):
        self.request()
        def acme(arguments):
            if arguments[0] == '--renew':
                self.fixture.prepare_candidate('new')
            else:
                self.fixture.install_current('new')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=acme)
        original_save = history.RunHistory._save
        failed = []
        def save(store, record, prune=False):
            if not failed and any(stage['stage'] == 'issuance' and stage['status'] == 'running'
                                  for stage in record['stages']):
                failed.append(True)
                raise OSError('one-private-write-failed')
            return original_save(store, record, prune=prune)
        with mock.patch.object(history.RunHistory, '_save', new=save):
            self.controller.run()
        self.assertEqual(failed, [True])
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertEqual(self.detail()['status'], 'succeeded')
        self.assertEqual(self.stage('history')[-1]['status'], 'failed')
        self.assertEqual(self.stage('deployment')[-1]['status'], 'succeeded')
        self.assertEqual(self.stage('dns_cleanup_check')[-1]['status'], 'succeeded')
        self.assertIsNone(self.store.list()['warning'])
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)

    def test_notification_failure_then_retry_records_actual_outcomes_without_reissuing(self):
        self.controller.config['success_notify_email'] = 'operator@example.com'
        self.request()
        self.controller.invoke_acme = mock.Mock(side_effect=self.issue_and_deploy)
        self.controller.deliver_success_notification = mock.Mock(side_effect=certctl.Failure('SMTP unavailable'))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        failed_id = self.detail()['id']
        self.assertEqual(self.detail()['status'], 'failed')
        self.assertEqual(self.stage('notification')[-1]['status'], 'failed')
        self.assertEqual(self.stage('deployment')[-1]['status'], 'succeeded')
        self.controller.deliver_success_notification.side_effect = None
        self.controller.run()
        self.assertEqual(self.controller.invoke_acme.call_count, 2)
        self.assertEqual(self.controller.deliver_success_notification.call_count, 2)
        self.assertEqual(self.detail()['kind'], 'recovery')
        self.assertEqual(self.stage('notification')[-1]['status'], 'succeeded')
        self.assertEqual(self.stage('issuance')[-1]['status'], 'skipped')
        self.assertEqual(self.store.get(failed_id)['status'], 'failed')

    def test_cleanup_failure_and_real_local_retry_have_separate_history(self):
        helper = self.controller.home / 'dns_cleanup.py'
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'dns_cleanup.py', helper)
        helper.chmod(0o600)
        journal = self.controller.state / 'dns-cleanup.json'
        certctl.save_json(journal, {'version': 1, 'entries': [{
            'name': '_acme-challenge.ttxli.cn', 'value': 'local-history-test-value',
            'created_at': certctl.time.time()}]})
        script = self.controller.home / 'dns_cleanup_retry.sh'
        script.write_text('exit 1\n')
        script.chmod(0o600)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不应申请'))
        with self.assertRaises(certctl.Failure):
            self.controller.run()
        self.assertEqual(self.stage('dns_cleanup')[-1]['status'], 'failed')
        self.assertEqual(self.stage('dns_cleanup_check')[-1]['status'], 'failed')
        self.assertEqual(self.detail()['kind'], 'recovery')
        script.write_text('exec "$CERTCTL_PYTHON" -I "$CERTCTL_HOME/dns_cleanup.py" '
                          '"$CERTCTL_HOME" done _acme-challenge.ttxli.cn local-history-test-value deleted\n')
        self.controller.run()
        self.controller.invoke_acme.assert_not_called()
        self.assertEqual(self.stage('dns_cleanup')[-1]['status'], 'succeeded')
        self.assertEqual(self.stage('dns_cleanup_check')[-1]['status'], 'succeeded')
        self.assertEqual(self.detail()['status'], 'succeeded')
        self.assertEqual(self.controller.dns_cleanup_count(), 0)
        self.assertNotIn('local-history-test-value', json.dumps(self.detail()))

    def test_readonly_check_api_has_check_kind_and_skips_all_mutation_stages(self):
        self.controller.begin_history('check')
        self.controller.history_stage('preflight', message='只读检查')
        self.controller.preflight()
        self.controller.history_stage('preflight', 'succeeded', '检查通过')
        self.controller.finish_history('succeeded', '只读检查通过')
        self.assertEqual(self.detail()['kind'], 'check')
        self.assertEqual(self.detail()['status'], 'succeeded')
        for name in ('issuance', 'deployment', 'dns_validation', 'notification'):
            self.assertEqual(self.stage(name)[-1]['status'], 'skipped')

    def test_logging_interruption_remains_a_cancellation_and_not_a_hidden_success(self):
        self.controller.begin_history()
        with mock.patch.object(self.controller.history_recorder, 'begin', side_effect=InterruptedError()):
            with self.assertRaises(InterruptedError):
                self.controller.history_stage('issuance')


if __name__ == '__main__':
    unittest.main()
