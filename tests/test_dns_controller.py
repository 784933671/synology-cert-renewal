import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'dns_controller_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl
ROOT = Path(__file__).resolve().parents[1]
CHALLENGE = '_acme-challenge.ttxli.cn'
TXT_VALUE = 'offline-controller-validation-token-12345'


class DnsControllerTests(unittest.TestCase):
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
        self.controller.config.update(deployment_method='local_api', renew_before_days=2)
        helper = self.controller.home / 'dns_cleanup.py'
        shutil.copyfile(ROOT / 'dns_cleanup.py', helper)
        helper.chmod(0o600)
        self.journal = self.controller.state / 'dns-cleanup.json'
        self.retry_script = self.controller.home / 'dns_cleanup_retry.sh'

    def track(self):
        certctl.save_json(self.journal, {'version': 1, 'entries': [{
            'name': CHALLENGE, 'value': TXT_VALUE, 'created_at': time.time()}]})

    def cleanup_result(self, success):
        script = '#!/bin/sh\n'
        if success:
            script += ('exec "$CERTCTL_PYTHON" -I "$CERTCTL_HOME/dns_cleanup.py" '
                       '"$CERTCTL_HOME" done ' + shlex.quote(CHALLENGE) + ' ' +
                       shlex.quote(TXT_VALUE) + ' deleted\n')
        else:
            script += 'exit 1\n'
        self.retry_script.write_text(script)
        self.retry_script.chmod(0o600)

    def main_run(self):
        output = io.StringIO()
        with mock.patch.object(certctl, 'Controller', return_value=self.controller), \
             mock.patch.object(certctl.os, 'geteuid', return_value=0), \
             mock.patch.object(certctl.signal, 'signal'), \
             mock.patch.object(certctl, 'SYSTEM_PATH', os.environ['PATH']), \
             mock.patch.dict(os.environ), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = certctl.main(['--home', str(self.controller.home), 'run'])
        self.assertNotIn(self.controller.config['secret_id'], output.getvalue())
        self.assertNotIn(self.controller.config['secret_key'], output.getvalue())
        return result

    def issuing(self, operation, leave_cleanup=False):
        def acme(arguments):
            self.assertEqual(arguments[0], operation)
            self.fixture.prepare_candidate('new')
            if leave_cleanup:
                self.track()
            return 0
        self.controller.invoke_acme = mock.Mock(side_effect=acme)
        self.controller.deploy_local_api = mock.Mock(
            side_effect=lambda before: self.fixture.install_current('new'))

    def assert_deployed(self):
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()),
                         self.fixture.new_fingerprint)
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertFalse((self.controller.state / 'run-baseline.json').exists())
        self.assertFalse((self.controller.state / 'import-bindings.json').exists())

    def test_issuance_success_with_cleanup_pending_deploys_but_returns_failure_then_retries_only_cleanup(self):
        self.issuing('--issue', leave_cleanup=True)
        self.assertEqual(self.main_run(), 1)
        self.controller.invoke_acme.assert_called_once()
        self.controller.deploy_local_api.assert_called_once()
        self.assert_deployed()
        result = certctl.read_json(self.controller.state / 'last-result.json')
        self.assertFalse(result['success'])
        self.assertIn('DNS', result['message'])
        self.assertEqual(self.controller.dns_cleanup_count(), 1)

        self.cleanup_result(True)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不得再次签发'))
        self.controller.deploy_local_api = mock.Mock(side_effect=AssertionError('已部署证书不得重复导入'))
        self.assertEqual(self.main_run(), 0)
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(self.controller.dns_cleanup_count(), 0)
        self.assert_deployed()
        self.assertTrue(certctl.read_json(self.controller.state / 'last-result.json')['success'])

    def test_existing_cleanup_failure_does_not_prevent_due_renewal_and_deployment(self):
        self.fixture.install_current('short')
        self.fixture.prepare_candidate('short')
        self.track()
        self.cleanup_result(False)
        self.issuing('--renew')
        self.assertEqual(self.main_run(), 1)
        self.controller.invoke_acme.assert_called_once()
        self.controller.deploy_local_api.assert_called_once()
        self.assert_deployed()
        self.assertEqual(self.controller.dns_cleanup_count(), 1)
        self.assertFalse(certctl.read_json(self.controller.state / 'last-result.json')['success'])

    def test_cleanup_failure_outside_window_keeps_reporting_without_acme_or_import(self):
        self.fixture.prepare_candidate('old')
        self.track()
        self.cleanup_result(False)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不得签发'))
        self.controller.deploy_local_api = mock.Mock(side_effect=AssertionError('证书相同无需导入'))
        self.assertEqual(self.main_run(), 1)
        self.assertEqual(self.main_run(), 1)
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(self.controller.dns_cleanup_count(), 1)
        self.assertFalse(certctl.read_json(self.controller.state / 'last-result.json')['success'])

    def test_empty_queue_skips_cleanup_subprocess(self):
        with mock.patch.object(certctl.subprocess, 'Popen') as popen:
            self.assertEqual(self.controller.dns_cleanup_count(), 0)
            self.assertTrue(self.controller.retry_dns_cleanup())
        popen.assert_not_called()

    def test_zero_cleanup_exit_cannot_hide_records_still_in_queue(self):
        self.fixture.prepare_candidate('old')
        self.track()
        self.retry_script.write_text('#!/bin/sh\nexit 0\n')
        self.retry_script.chmod(0o600)
        self.controller.invoke_acme = mock.Mock(side_effect=AssertionError('窗口外不得签发'))
        self.controller.deploy_local_api = mock.Mock(side_effect=AssertionError('无需重复导入'))
        self.assertEqual(self.main_run(), 1)
        self.controller.invoke_acme.assert_not_called()
        self.controller.deploy_local_api.assert_not_called()
        self.assertEqual(self.controller.dns_cleanup_count(), 1)

    def test_malformed_queue_is_not_treated_as_clean(self):
        certctl.save_json(self.journal, {'version': 1, 'entries': [
            {'name': CHALLENGE, 'value': TXT_VALUE}]})
        with self.assertRaises(certctl.Failure):
            self.controller.dns_cleanup_count()

    def test_cleanup_timeout_terminates_process_group_without_credentials_in_arguments(self):
        self.track()
        self.cleanup_result(False)
        process = mock.Mock(pid=123456)
        process.wait.side_effect = [subprocess.TimeoutExpired('cleanup', 180), 0]
        process.poll.return_value = 0
        with mock.patch.object(self.controller, 'dns_cleanup_count', return_value=1), \
             mock.patch.object(certctl.subprocess, 'Popen', return_value=process) as popen, \
             mock.patch.object(certctl.os, 'killpg') as killpg:
            self.assertFalse(self.controller.retry_dns_cleanup())
        killpg.assert_called_once_with(process.pid, signal.SIGTERM)
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=180), mock.call(timeout=10)])
        arguments = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(arguments, ['/bin/sh', str(self.retry_script)])
        self.assertTrue(options['start_new_session'])
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        for key in ('secret_id', 'secret_key'):
            self.assertNotIn(self.controller.config[key], ' '.join(arguments))
        self.assertEqual(options['env']['Tencent_SecretId'], self.controller.config['secret_id'])
        self.assertEqual(options['env']['Tencent_SecretKey'], self.controller.config['secret_key'])
        self.assertEqual(stat.S_IMODE((self.controller.state / 'dns-cleanup-last.log').stat().st_mode), 0o600)
        self.assertEqual(self.controller.dns_cleanup_count(), 1)

    def test_cleanup_timeout_escalates_to_kill_for_unresponsive_process_group(self):
        self.track()
        self.cleanup_result(False)
        process = mock.Mock(pid=123456)
        process.wait.side_effect = [subprocess.TimeoutExpired('cleanup', 180),
                                    subprocess.TimeoutExpired('cleanup', 10), 0]
        process.poll.side_effect = [None, 0]
        with mock.patch.object(self.controller, 'dns_cleanup_count', return_value=1), \
             mock.patch.object(certctl.subprocess, 'Popen', return_value=process), \
             mock.patch.object(certctl.os, 'killpg') as killpg:
            self.assertFalse(self.controller.retry_dns_cleanup())
        self.assertEqual(killpg.call_args_list, [mock.call(process.pid, signal.SIGTERM),
                                               mock.call(process.pid, signal.SIGKILL)])
        self.assertEqual(self.controller.dns_cleanup_count(), 1)

    def test_operation_environment_does_not_inherit_proxy_or_credential_overrides(self):
        inherited = {'HTTP_PROXY': 'http://proxy.invalid', 'https_proxy': 'http://proxy.invalid',
                     'ALL_PROXY': 'socks5://proxy.invalid', 'DEBUG': '3', 'SYNO_CREATE': '1',
                     'Tencent_SecretId': 'WRONG_ID', 'Tencent_SecretKey': 'WRONG_KEY',
                     'CERTCTL_HOME': '/tmp/wrong-home'}
        with mock.patch.dict(os.environ, inherited):
            env = self.controller.operation_environment()
        for key in ('HTTP_PROXY', 'https_proxy', 'ALL_PROXY', 'DEBUG', 'SYNO_CREATE'):
            self.assertNotIn(key, env)
        self.assertEqual(env['Tencent_SecretId'], self.controller.config['secret_id'])
        self.assertEqual(env['Tencent_SecretKey'], self.controller.config['secret_key'])
        self.assertEqual(env['CERTCTL_HOME'], str(self.controller.home))
        self.assertEqual(env['CERTCTL_PYTHON'], certctl.sys.executable)


if __name__ == '__main__':
    unittest.main()
