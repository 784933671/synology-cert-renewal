import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'failure_reporting_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


class FailureReportingTests(unittest.TestCase):
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
        self.controller.config.update(deployment_method='local_api', renew_before_days=2,
                                      success_notify_email='operator@example.com')
        self.controller.system_check = mock.Mock()
        self.controller.deliver_success_notification = mock.Mock()
        self.controller.deploy_local_api = mock.Mock(
            side_effect=lambda before: self.fixture.install_current('new'))
        self.fixture.install_current('short')
        self.fixture.prepare_candidate('short')

    def run_main(self):
        output = io.StringIO()
        # 只替换CLI的root门禁，归档模块仍以真实测试进程用户检查文件归属。
        cli_os = types.SimpleNamespace(**vars(os))
        cli_os.geteuid = lambda: 0
        with mock.patch.object(certctl, 'Controller', return_value=self.controller), \
             mock.patch.object(certctl, 'os', cli_os), \
             mock.patch.object(certctl.signal, 'signal'), \
             mock.patch.object(certctl, 'SYSTEM_PATH', os.environ['PATH']), \
             mock.patch.dict(os.environ), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = certctl.main(['--home', str(self.controller.home), 'run'])
        return status, output.getvalue()

    def fake_acme(self, text, events=(), status=1):
        script = '#!/bin/sh\n'
        script += "printf '%s\\n' " + shlex.quote(text) + '\n'
        for event in events:
            script += ("printf '%s\\n' " + shlex.quote(json.dumps(event)) +
                       ' >> "$CERTCTL_DIAGNOSTIC_FILE"\n')
        script += 'exit ' + str(status) + '\n'
        path = self.controller.acme / 'acme.sh'
        path.write_text(script)
        path.chmod(0o600)

    def result(self):
        return certctl.read_json(self.controller.state / 'last-result.json')

    def failure(self):
        result = self.result()
        self.assertIs(result['success'], False)
        failure = result['failure']
        for key in ('stage', 'stage_label', 'category', 'code', 'summary', 'hint', 'evidence'):
            self.assertTrue(failure[key], key)
        return failure

    def archived_reports(self):
        return sorted((self.controller.state / 'failures').glob('*/report.json'))

    def assert_reported(self, stage):
        status, output = self.run_main()
        self.assertEqual(status, 1, output)
        report = self.failure()
        self.assertEqual(report['stage'], stage)
        for label in ('失败阶段：', '错误摘要：', '错误码：', '处理建议：'):
            self.assertIn(label, output)
        self.assertIn('失败记录：' if report['archive_path'] else '日志留存：', output)
        if report['archive_path']:
            self.assertIn(report['archive_path'], output)
            self.assertTrue(Path(report['archive_path']).is_dir())
        self.assertIn(report['stage_label'], output)
        self.assertIn(report['summary'], output)
        self.controller.deliver_success_notification.assert_not_called()
        return report, output

    def test_dns_api_error_is_shown_in_task_mail_and_retained_with_its_operation(self):
        self.fake_acme('Error adding TXT record to domain: _acme-challenge.ttxli.cn', [
            {'stage': 'dns_create', 'action': 'CreateRecord',
             'category': 'api', 'code': 'UnauthorizedOperation'}])
        report, output = self.assert_reported('dns_create')
        self.assertEqual(report['code'], 'UnauthorizedOperation')
        self.assertIn('UnauthorizedOperation', output)
        self.assertTrue(report['archive_path'])
        archived = self.archived_reports()
        self.assertEqual(len(archived), 1)
        self.assertEqual(certctl.read_json(archived[0])['stage'], 'dns_create')
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()),
                         certctl.fingerprint(self.fixture.fixtures / 'short.pem'))
        for path in [archived[0].parent] + list(archived[0].parent.rglob('*')):
            self.assertFalse(stat.S_IMODE(path.stat().st_mode) & 0o077, str(path))

    def test_acme_logs_distinguish_propagation_challenge_and_ca_failure_stages(self):
        cases = [
            ('dns_propagation', "Let's check each DNS record now.\nNot valid yet, let's wait for 10 seconds then check the next one.\nTimed out waiting for DNS."),
            ('acme_challenge', 'Verifying: ttxli.cn\nttxli.cn: Invalid status. Verification error details: DNS problem: NXDOMAIN'),
            ('ca_request', 'Error creating new order.\n{"type":"urn:ietf:params:acme:error:rateLimited"}'),
            ('ca_finalize', 'Verification finished, beginning signing.\nSigning failed. Finalize code was not 200.'),
            ('ca_download', 'Downloading cert.\nSigning failed. Could not download cert: https://ca.example/cert/id'),
        ]
        for stage, text in cases:
            with self.subTest(stage=stage):
                self.fake_acme(text)
                self.assert_reported(stage)
        self.assertEqual(len(self.archived_reports()), len(cases))

    def test_cleanup_error_does_not_hide_the_primary_dns_creation_failure(self):
        self.fake_acme('Error adding TXT record\nRemoving DNS records.', [
            {'stage': 'dns_create', 'action': 'CreateRecord', 'category': 'api', 'code': 'UnauthorizedOperation'},
            {'stage': 'dns_cleanup', 'action': 'DeleteRecord', 'category': 'network', 'code': 'NETWORK_ERROR'},
        ])
        report, _ = self.assert_reported('dns_create')
        self.assertEqual(report['code'], 'UnauthorizedOperation')

    def test_unrecognized_acme_error_is_explicitly_unknown(self):
        self.fake_acme('The external service stopped without a recognized diagnostic.')
        report, _ = self.assert_reported('acme_unknown')
        self.assertIn('UNKNOWN', report['code'])

    def test_old_acme_log_cannot_misclassify_a_new_preflight_failure(self):
        (self.controller.state / 'acme-last.log').write_text(
            'Verifying: old.example\nChallenge error: old diagnostic must not be reused\n')
        self.controller.preflight.side_effect = certctl.Failure('配置目录权限不正确')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('不能启动签发'))
        report, output = self.assert_reported('preflight')
        self.assertNotEqual(report['evidence'], 'acme_log')
        self.assertNotIn('old diagnostic', output)
        self.controller.invoke_acme.assert_not_called()

    def test_previous_dns_event_is_not_reused_for_a_later_ca_request_failure(self):
        self.fake_acme('Error adding TXT record', [
            {'stage': 'dns_create', 'action': 'CreateRecord',
             'category': 'api', 'code': 'UnauthorizedOperation'}])
        self.assert_reported('dns_create')
        self.fake_acme('Error creating new order.')
        report, output = self.assert_reported('ca_request')
        self.assertNotEqual(report['code'], 'UnauthorizedOperation')
        self.assertNotIn('UnauthorizedOperation', output)
        self.assertEqual(len(self.archived_reports()), 2)

    def test_log_open_failure_cannot_capture_or_classify_previous_acme_output(self):
        self.fake_acme('unused')
        output_file = self.controller.state / 'acme-last.log'
        output_file.write_text('Downloading cert.\nprevious run failure must not be copied\n')
        output_file.chmod(0o600)
        real_open = Path.open

        def open_file(path, mode='r', *args, **kwargs):
            if path == output_file and mode == 'wb':
                raise OSError('cannot truncate log')
            return real_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, 'open', new=open_file):
            status, output = self.run_main()
        self.assertEqual(status, 1, output)
        report = self.failure()
        self.assertNotEqual(report['stage'], 'ca_download')
        self.assertNotEqual(report['evidence'], 'acme_log')
        material = output + ''.join(path.read_text() for path in Path(report['archive_path']).rglob('*')
                                    if path.is_file())
        self.assertNotIn('previous run failure must not be copied', material)
        self.controller.deploy_local_api.assert_not_called()

    def test_cleanup_log_open_failure_does_not_archive_previous_cleanup_output(self):
        self.controller.dns_cleanup_count = mock.Mock(return_value=1)
        helper = self.controller.home / 'dns_cleanup_retry.sh'
        helper.write_text('#!/bin/sh\nexit 0\n')
        helper.chmod(0o600)
        output_file = self.controller.state / 'dns-cleanup-last.log'
        output_file.write_text('previous cleanup failure must not be copied\n')
        output_file.chmod(0o600)
        real_open = Path.open

        def open_file(path, mode='r', *args, **kwargs):
            if path == output_file and mode == 'wb':
                raise OSError('cannot truncate log')
            return real_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, 'open', new=open_file):
            report, output = self.assert_reported('dns_cleanup')
        material = output + ''.join(path.read_text() for path in Path(report['archive_path']).rglob('*')
                                    if path.is_file())
        self.assertNotIn('previous cleanup failure must not be copied', material)
        self.controller.deploy_local_api.assert_not_called()

    def test_exception_text_is_redacted_before_task_output_and_result_are_written(self):
        secret = self.controller.config['secret_key']
        self.controller.preflight.side_effect = certctl.Failure('预检查失败：' + secret)
        report, output = self.assert_reported('preflight')
        materials = output + json.dumps(self.result())
        for path in Path(report['archive_path']).rglob('*'):
            if path.is_file():
                materials += path.read_text()
        self.assertNotIn(secret, materials)

    def test_repeated_failures_keep_separate_logs_and_success_does_not_erase_them(self):
        self.fake_acme('Verifying: ttxli.cn\nChallenge error: first-failure-marker')
        self.assert_reported('acme_challenge')
        original = self.archived_reports()[0].parent
        original_files = {str(path.relative_to(original)): path.read_bytes()
                          for path in original.rglob('*') if path.is_file()}
        self.fake_acme('Downloading cert.\nCould not download cert: second-failure-marker')
        self.assert_reported('ca_download')
        self.assertEqual(len(self.archived_reports()), 2)
        self.fixture.install_current('old')
        self.fixture.prepare_candidate('old')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不得签发'))
        status, output = self.run_main()
        self.assertEqual(status, 0, output)
        self.assertTrue(self.result()['success'])
        self.assertEqual(len(self.archived_reports()), 2)
        self.assertEqual(original_files, {str(path.relative_to(original)): path.read_bytes()
                                         for path in original.rglob('*') if path.is_file()})
        self.controller.deliver_success_notification.assert_not_called()

    def test_mail_result_and_archived_logs_are_redacted_before_persistence(self):
        token = 'EXAMPLE_DNS_CHALLENGE_TOKEN_THAT_MUST_NOT_LEAK'
        auth = 'EXAMPLE_BEARER_CREDENTIAL_THAT_MUST_NOT_LEAK'
        sid = 'EXAMPLE_DSM_SESSION_THAT_MUST_NOT_LEAK'
        private_key = (self.fixture.fixtures / 'old.key').read_text()
        details = ('Tencent_SecretId={secret_id}\nTencent_SecretKey={secret_key}\n'
                   'Authorization: Bearer {auth}\nAdding TXT value: {token}\n'
                   'Cookie: id={sid}\n{private_key}\n'
                   'Verifying: ttxli.cn\nChallenge error: failure\n').format(
                       secret_id=self.controller.config['secret_id'],
                       secret_key=self.controller.config['secret_key'], auth=auth,
                       token=token, sid=sid, private_key=private_key)
        self.fake_acme(details)
        report, output = self.assert_reported('acme_challenge')
        materials = output + json.dumps(self.result())
        folder = Path(report['archive_path'])
        for path in folder.rglob('*'):
            if path.is_file():
                materials += path.read_text()
        forbidden = [self.controller.config['secret_id'], self.controller.config['secret_key'],
                     token, auth, sid, private_key.splitlines()[1]]
        for value in forbidden:
            self.assertNotIn(value, materials)
        self.assertIn('REDACTED', materials)

    def test_archive_failure_keeps_original_stage_and_failure_exit_code(self):
        self.fake_acme('Error creating new order.')
        with mock.patch.object(certctl.diagnostics, 'archive_failure', side_effect=OSError('disk unavailable')):
            report, output = self.assert_reported('ca_request')
        self.assertIsNone(report['archive_path'])
        self.assertTrue(report['archive_error'])
        self.assertIn('日志', output)

    def test_archive_symlink_cannot_redirect_saved_failure_logs(self):
        external = self.fixture.root / 'outside'
        external.mkdir(mode=0o700)
        (external / 'keep.txt').write_text('unchanged')
        (self.controller.state / 'failures').symlink_to(external, target_is_directory=True)
        self.fake_acme('Error creating new order.')
        report, _ = self.assert_reported('ca_request')
        self.assertIsNone(report['archive_path'])
        self.assertTrue(report['archive_error'])
        self.assertEqual([p.name for p in external.iterdir()], ['keep.txt'])
        self.assertEqual((external / 'keep.txt').read_text(), 'unchanged')

    def successful_renewal(self):
        def issue(arguments):
            self.assertEqual(arguments[0], '--renew')
            self.fixture.prepare_candidate('new')
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=issue)

    def test_dsm_import_failure_is_separate_from_acme_issuance_failure(self):
        self.successful_renewal()
        self.controller.deploy_local_api.side_effect = certctl.Failure('DSM 导入失败')
        self.assert_reported('dsm_deploy')
        self.assertTrue((self.controller.state / 'pending.json').exists())

    def test_tls_verification_failure_reports_tls_stage_and_keeps_pending_deployment(self):
        self.successful_renewal()
        self.controller.verify_probes = mock.Mock(side_effect=certctl.Failure('HTTPS 证书链验证失败'))
        self.assert_reported('tls_verify')
        self.assertTrue((self.controller.state / 'pending.json').exists())
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)

    def test_cleanup_failure_is_reported_after_valid_certificate_deployment(self):
        self.successful_renewal()
        self.controller.retry_dns_cleanup = mock.Mock(return_value=False)
        self.assert_reported('dns_cleanup')
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)
        self.assertFalse((self.controller.state / 'pending.json').exists())
        notice = certctl.read_json(self.controller.state / 'success-notification.json')
        self.assertEqual(notice['pending']['fingerprint'], self.fixture.new_fingerprint)

    def test_success_mail_failure_is_classified_and_retried_without_reissuing(self):
        self.successful_renewal()
        self.controller.deliver_success_notification.side_effect = certctl.Failure('邮件程序暂时不可用')
        status, output = self.run_main()
        self.assertEqual(status, 1, output)
        report = self.failure()
        self.assertEqual(report['stage'], 'success_notification')
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertTrue(self.archived_reports())
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('只应重试通知'))
        self.controller.deploy_local_api = mock.Mock(side_effect=AssertionError('不应重复导入'))
        self.controller.deliver_success_notification.side_effect = None
        status, output = self.run_main()
        self.assertEqual(status, 0, output)
        self.assertEqual(self.controller.deliver_success_notification.call_count, 2)
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(len(self.archived_reports()), 1)

    def test_acme_timeout_stops_process_group_and_retains_current_operation_log(self):
        self.fake_acme('unused')
        process = mock.Mock(pid=654321)
        process.wait.side_effect = [subprocess.TimeoutExpired('acme', 1200), 0]
        process.poll.return_value = 0
        real_popen = subprocess.Popen
        def launch(command, *args, **kwargs):
            if command[:2] == ['/bin/sh', str(self.controller.acme / 'acme.sh')]:
                kwargs['stdout'].write(b'Verifying: ttxli.cn\ntimeout trace saved\n')
                return process
            return real_popen(command, *args, **kwargs)
        with mock.patch.object(certctl.subprocess, 'Popen', side_effect=launch), \
             mock.patch.object(certctl.os, 'killpg') as killpg:
            report, output = self.assert_reported('acme_challenge')
        killpg.assert_called_once_with(process.pid, signal.SIGTERM)
        self.assertIn('超时', output)
        material = ''.join(path.read_text() for path in Path(report['archive_path']).rglob('*') if path.is_file())
        self.assertIn('timeout trace saved', material)
        archived = certctl.read_json(Path(report['archive_path']) / 'report.json')
        self.assertEqual(archived['code'], report['code'])

    def test_normal_check_does_not_archive_or_send_mail(self):
        self.fixture.install_current('old')
        self.fixture.prepare_candidate('old')
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不得签发'))
        status, output = self.run_main()
        self.assertEqual(status, 0, output)
        self.assertTrue(self.result()['success'])
        self.assertFalse(self.archived_reports())
        self.assertNotIn('失败阶段：', output)
        self.controller.deliver_success_notification.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
