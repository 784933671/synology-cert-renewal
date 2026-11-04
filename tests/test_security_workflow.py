"""安全 CI 的不可放宽约束；YAML 语法另由 actionlint 校验。"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SecurityWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / '.github/workflows/security.yml').read_text()
        cls.commands = cls.workflow.replace('\\\n', '')

    def test_actions_are_immutable_and_workflow_has_no_write_credentials(self):
        actions = re.findall(r'^\s+(?:- )?uses:\s*(\S+)', self.workflow, re.M)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r'^[A-Za-z0-9_./-]+@[0-9a-f]{40}$')
        permission_blocks = re.findall(r'^ *permissions:\n((?: +[^\n]+\n)+)', self.workflow, re.M)
        self.assertEqual(len(permission_blocks), 1)
        self.assertEqual(permission_blocks[0].strip(), 'contents: read')
        self.assertNotIn('pull_request_target', self.workflow)
        self.assertNotIn('secrets.', self.workflow)
        self.assertNotRegex(self.workflow, r'(?m)^\s*continue-on-error:\s*true')
        self.assertNotIn('|| true', self.workflow)

    def test_audits_cover_all_dependencies_and_fail_on_findings(self):
        npm = next(line.strip() for line in self.commands.splitlines() if line.strip().startswith('npm audit '))
        tokens = shlex.split(npm)
        self.assertTrue({'--include=dev', '--include=optional', '--include=peer', '--audit-level=high'}.issubset(tokens))
        python = next(line.strip() for line in self.commands.splitlines() if line.strip().startswith('python -m pip_audit '))
        tokens = shlex.split(python)
        self.assertIn('--strict', tokens)
        self.assertIn('--require-hashes', tokens)
        self.assertEqual(tokens[tokens.index('-r') + 1], 'web/requirements.txt')
        self.assertNotIn('--ignore-vuln', tokens)
        for line in self.commands.splitlines():
            if line.strip().startswith('python -m pip install '):
                self.assertIn('--require-hashes', shlex.split(line.strip()))
        trivy = self.workflow.split('uses: aquasecurity/trivy-action@', 1)[1].split('      - name:', 1)[0]
        for constraint in ('severity: HIGH,CRITICAL', 'ignore-unfixed: false', "exit-code: '1'",
                           'scan-type: image', 'vuln-type: os,library', 'TRIVY_IGNOREFILE: /dev/null'):
            self.assertIn(constraint, trivy)
        image = re.search(r'(?m)^\s+image-ref:\s*(\S+)', trivy).group(1)
        self.assertIn('--tag ' + image + ' web', self.workflow)

    def test_push_pull_request_weekly_and_manual_checks_remain_enabled(self):
        trigger = self.workflow.split('\non:\n', 1)[1].split('\npermissions:', 1)[0]
        for event in ('push', 'pull_request', 'schedule', 'workflow_dispatch'):
            self.assertRegex(trigger, r'(?m)^  ' + event + ':')
        self.assertRegex(trigger, r"cron: '[0-9]+ [0-9]+ \* \* [0-6]'")
        self.assertIn('ACME_TEST_SOURCE=', self.workflow)
        self.assertIn('sha256sum --check --strict', self.workflow)
        self.assertIn('807da6498377ee5e0cf43a78091f46f12dc59a89', self.workflow)
        self.assertIn('ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220', self.workflow)

    def test_trivy_install_uses_verified_official_release_and_bounded_retries(self):
        installer = self.workflow.split('        id: trivy-install\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('https://github.com/aquasecurity/trivy/releases/download/', installer)
        self.assertNotIn('get.trivy.dev', self.workflow)
        self.assertRegex(installer, r'(?m)^          TRIVY_SHA256: [0-9a-f]{64}$')
        for option in ('--fail', '--retry 4', '--retry-all-errors', '--retry-max-time 180',
                       '--connect-timeout 15', '--max-time 120', 'sha256sum --check --strict'):
            self.assertIn(option, installer)
        self.assertLess(installer.index('sha256sum --check --strict'), installer.index('tar -xzf'))
        self.assertIn("skip-setup-trivy: 'true'", self.workflow)
        self.assertIn('TRIVY_CMD: ${{ steps.trivy-install.outputs.binary }}', self.workflow)

    def test_trivy_download_or_checksum_failure_never_extracts_or_publishes_binary(self):
        installer = self.workflow.split('        id: trivy-install\n', 1)[1].split('      - name:', 1)[0]
        script = textwrap.dedent(installer.split('        run: |\n', 1)[1])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / 'bin'
            commands.mkdir()
            for name, content in {
                'curl': '#!/bin/sh\nexit "$CURL_STATUS"\n',
                'sha256sum': '#!/bin/sh\ncat >/dev/null\nexit "$SHA_STATUS"\n',
                'tar': '#!/bin/sh\ntouch "$RUNNER_TEMP/extracted"\nexit 99\n',
            }.items():
                path = commands / name
                path.write_text(content)
                path.chmod(0o700)
            for download_status, checksum_status in (('6', '0'), ('0', '1')):
                with self.subTest(download=download_status, checksum=checksum_status):
                    environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ.get('PATH', ''),
                        RUNNER_TEMP=str(root), TRIVY_VERSION='0.76.1', TRIVY_SHA256='0' * 64,
                        GITHUB_OUTPUT=str(root / 'outputs'), CURL_STATUS=download_status, SHA_STATUS=checksum_status)
                    result = subprocess.run(['bash', '-euo', 'pipefail', '-c', script], env=environment,
                                            cwd=root, capture_output=True, text=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((root / 'extracted').exists())
                    self.assertFalse((root / 'outputs').exists())

    def test_dependabot_covers_every_ecosystem_weekly_without_automatic_merge(self):
        config = (ROOT / '.github/dependabot.yml').read_text()
        updates = re.split(r'^  - package-ecosystem:\s*', config, flags=re.M)[1:]
        pairs = set()
        for block in updates:
            ecosystem = block.splitlines()[0].strip()
            directory = re.search(r'^    directory:\s*(\S+)', block, re.M).group(1)
            pairs.add((ecosystem, directory))
            self.assertRegex(block, r'(?m)^      interval: weekly$')
            self.assertRegex(block, r'(?m)^    open-pull-requests-limit: [1-5]$')
        self.assertEqual(pairs, {('npm', '/web/frontend'), ('pip', '/web'), ('pip', '/.github'),
                                 ('docker', '/web'), ('github-actions', '/')})
        self.assertNotIn('auto-merge', config)


if __name__ == '__main__':
    unittest.main()
