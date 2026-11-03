"""可选离线集成测试：ACME_TEST_SOURCE 指向固定版本 acme.sh 源码目录。"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'certificate_fixtures', Path(__file__).with_name('test_certctl.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


@unittest.skipUnless(os.environ.get('ACME_TEST_SOURCE'), '未指定 ACME_TEST_SOURCE，跳过离线 ACME 集成测试')
class AcmeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(os.environ['ACME_TEST_SOURCE']).expanduser()
        cls.source = source / 'acme.sh' if source.is_dir() else source
        version = subprocess.run(['/bin/sh', str(cls.source), '--version'],
                                 check=True, capture_output=True, text=True, timeout=20).stdout
        if not re.search(r'(?m)^v' + re.escape(certctl.ACME_VERSION) + r'\s*$', version):
            raise AssertionError('集成测试需要与安装器相同的固定 acme.sh 版本')
        FIXTURES.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURES.CertificateTests.tearDownClass)

    def setUp(self):
        self.fixture = FIXTURES.CertificateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.configure_runtime_mocks()
        self.controller = self.fixture.controller
        self.controller.system_check = mock.Mock()
        self.controller.temp_user_exists = mock.Mock(return_value=False)
        shutil.copyfile(self.source, self.controller.acme / 'acme.sh')
        (self.controller.acme / 'account.conf').write_text("NO_ARI='1'\n")

        # 即使出现意外分支，也不允许调用真实 HTTP 客户端。
        guard = self.fixture.root / 'network-guard'
        guard.mkdir()
        self.network_calls = guard / 'calls'
        for command in ('curl', 'wget'):
            executable = guard / command
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$0" >> "$(dirname "$0")/calls"\nexit 99\n')
            executable.chmod(0o700)
        patch = mock.patch.object(certctl, 'SYSTEM_PATH', str(guard) + ':' + certctl.SYSTEM_PATH)
        patch.start()
        self.addCleanup(patch.stop)

    def damaged_pending(self):
        self.fixture.prepare_candidate('new')
        conf = self.controller.candidate_dir() / 'ttxli.cn.conf'
        with conf.open('a') as handle:
            handle.write("Le_NextRenewTime='{}'\nLe_NextRenewTimeStr='future'\n"
                         "Le_DeployHook='synology_dsm'\n".format(int(time.time()) + 30 * 86400))
        (self.controller.candidate_dir() / 'fullchain.cer').write_text('TRUNCATED\n')
        (self.controller.candidate_dir() / 'ttxli.cn.csr').write_text('INVALID CSR\n')
        certctl.save_json(self.controller.state / 'pending.json', {
            'fingerprint': certctl.fingerprint(self.controller.candidate()), 'at': certctl.now()})
        return conf

    def test_real_renew_skips_damaged_candidate_before_saved_renewal_time(self):
        conf = self.damaged_pending()
        result = self.controller.invoke_acme(['--renew', '-d', 'ttxli.cn'])
        self.assertEqual(result, 2)
        self.assertIn('Skipping. Next renewal time is:',
                      (self.controller.state / 'acme-last.log').read_text())
        self.assertNotIn('Le_DeployHook=', conf.read_text())
        with self.assertRaises(certctl.Failure):
            self.controller.candidate_valid()
        self.assertFalse(self.network_calls.exists())
        self.assertFalse(self.controller.marker.exists())

    def test_fixed_policy_migrates_stale_schedule_and_real_acme_skips_offline(self):
        self.controller.config['renew_before_days'] = 2
        self.fixture.prepare_candidate('old')
        conf = self.controller.candidate_dir() / 'ttxli.cn.conf'
        with conf.open('a') as handle:
            handle.write("Le_RenewalDays='60'\nLe_NextRenewTime='1'\n"
                         "Le_NextRenewTimeStr='old overdue schedule'\n")
        result = self.controller.invoke_acme(['--renew', '-d', 'ttxli.cn'])
        self.assertEqual(result, 2)
        text = conf.read_text()
        self.assertIn("Le_RenewalDays='-2'", text)
        match = re.search(r"(?m)^Le_NextRenewTime='([0-9]+)'$", text)
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(1)), certctl.certificate_expiry(self.controller.candidate()) - 172800)
        self.assertIn('Skipping. Next renewal time is:',
                      (self.controller.state / 'acme-last.log').read_text())
        self.assertFalse(self.network_calls.exists())
        self.assertFalse(self.controller.marker.exists())
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.old_fingerprint)

    def test_real_force_flag_bypasses_future_window_and_reaches_issue_once(self):
        self.controller.config['renew_before_days'] = 2
        self.fixture.prepare_candidate('old')
        self.controller.prepare_acme_config()
        marker = self.fixture.root / 'issue-calls'
        harness = self.fixture.root / 'force-harness.sh'
        # 使用未改动的固定源码，只把实际签发边界替换为离线记录器。
        harness.write_text('acme_source="$1"\nacme_home="$2"\nissue_marker="$3"\nforce_arg="$4"\n'
                           '. "$acme_source" --version\n'
                           'issue() { printf "%s\\n" "$*" >> "$issue_marker"; return 1; }\n'
                           'if [ "$force_arg" = yes ]; then set -- --force; else set --; fi\n'
                           'main --home "$acme_home" --config-home "$acme_home" '
                           '--server https://acme-v02.api.letsencrypt.org/directory --renew -d ttxli.cn "$@"\n')
        environment = self.controller.operation_environment()
        environment['NO_ARI'] = '1'
        command = ['/bin/sh', str(harness), str(self.source), str(self.controller.acme), str(marker)]
        normal = subprocess.run(command + ['no'], env=environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(normal.returncode, 2, normal.stdout + normal.stderr)
        self.assertFalse(marker.exists())
        forced = subprocess.run(command + ['yes'], env=environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(forced.returncode, 1, forced.stdout + forced.stderr)
        self.assertEqual(len(marker.read_text().splitlines()), 1)
        self.assertIn('dns_tencent', marker.read_text())
        self.assertNotIn('Skipping. Next renewal time is:', forced.stdout + forced.stderr)
        self.assertFalse(self.network_calls.exists())

    def test_run_reissues_damaged_pending_before_saved_renewal_time(self):
        self.damaged_pending()
        real_popen = subprocess.Popen
        commands = []

        def process(command, *args, **kwargs):
            if len(command) < 2 or command[:2] != ['/bin/sh', str(self.controller.acme / 'acme.sh')]:
                return real_popen(command, *args, **kwargs)
            commands.append(command)
            if '--renew' in command:
                return real_popen(command, *args, **kwargs)
            if '--issue' in command:
                self.assertFalse(self.controller.candidate_dir().exists())
                self.assertIn('--dns', command)
                self.assertEqual(command[command.index('--dns') + 1], 'dns_tencent')
                domains = [command[index + 1] for index, value in enumerate(command) if value == '-d']
                self.assertEqual(domains, self.controller.config['domains'])
                self.fixture.prepare_candidate('new')
            elif '--deploy' in command:
                self.controller.candidate_valid()
                self.assertEqual(certctl.fingerprint(self.controller.current_cert()),
                                 self.fixture.old_fingerprint)
                self.fixture.install_current('new')
            else:
                self.fail('非预期 ACME 命令：' + repr(command))
            return mock.Mock(wait=mock.Mock(return_value=0), poll=mock.Mock(return_value=0))

        with mock.patch.object(certctl.subprocess, 'Popen', side_effect=process):
            self.controller.run()
        self.assertEqual(len(commands), 2)
        self.assertIn('--issue', commands[0])
        self.assertIn('--deploy', commands[1])
        self.assertFalse(any('--force' in command for command in commands))
        self.assertEqual(certctl.fingerprint(self.controller.current_cert()), self.fixture.new_fingerprint)
        self.assertTrue(certctl.read_json(self.controller.state / 'last-result.json')['success'])
        self.assertFalse((self.controller.state / 'pending.json').exists())
        self.assertFalse(self.controller.marker.exists())
        self.assertFalse(self.network_calls.exists())
        preserved = list(self.controller.state.rglob('ttxli.cn.conf'))
        self.assertEqual(len(preserved), 1)
        self.assertIn("Le_NextRenewTimeStr='future'", preserved[0].read_text())
        self.assertNotIn('Le_DeployHook=', preserved[0].read_text())
        self.assertEqual((preserved[0].parent / 'fullchain.cer').read_text(), 'TRUNCATED\n')
        self.assertEqual((preserved[0].parent / 'ttxli.cn.csr').read_text(), 'INVALID CSR\n')


if __name__ == '__main__':
    unittest.main()
