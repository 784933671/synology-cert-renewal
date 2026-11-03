import ast
import io
import json
import os
import pty
import re
from pathlib import Path
import select
import signal
import subprocess
import shlex
import tarfile
import tempfile
import types
import termios
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bootstrap-private.sh').read_text()
PYTHON = SCRIPT.split("<<'CERT_BOOTSTRAP_PY'\n", 1)[1].rsplit('\nCERT_BOOTSTRAP_PY', 1)[0]
boot = types.ModuleType('private_bootstrap_test')
exec(compile(PYTHON, str(ROOT / 'bootstrap-private.sh'), 'exec'), vars(boot))
FILES = {'setup.sh': b'#!/bin/sh\nexit 0\n', 'install.sh': b'#!/bin/sh\n', 'web/setup.py': b'pass\n'}
REVISION = 'a' * 40
TOKEN = 'github_pat_' + 'x' * 50


def manifest(files=FILES):
    return {name: {'sha': boot.blob_sha(data), 'size': len(data)} for name, data in files.items()}


def archive(path, files=FILES, extra=None):
    with tarfile.open(path, 'w:gz') as output:
        for name, data in files.items():
            info = tarfile.TarInfo('repo/' + name); info.size = len(data)
            output.addfile(info, io.BytesIO(data))
        if extra:
            output.addfile(extra)
    path.chmod(0o600)


class PrivateBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.base = self.root / 'cache'
        self.client = Mock(token=TOKEN)
        self.client.revision.return_value = REVISION
        self.client.manifest.return_value = manifest()
        self.client.archive.side_effect = lambda sha, path: archive(path)
        self.install_state = self.root / 'install.json'
        self.installer = boot.Installer(self.client, self.base, self.install_state)

    def source(self):
        with self.installer.locked():
            return self.installer.source()

    def test_shell_help_and_python38_syntax(self):
        ast.parse(PYTHON, feature_version=(3, 8))
        for args in (['sh', '-n', str(ROOT / 'bootstrap-private.sh')],
                     ['sh', str(ROOT / 'bootstrap-private.sh'), '--help']):
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)

    def test_pins_download_to_commit_and_validates_every_blob(self):
        source = self.source()
        self.client.manifest.assert_called_once_with(REVISION)
        self.client.archive.assert_called_once()
        self.assertEqual(self.client.archive.call_args.args[0], REVISION)
        for name, data in FILES.items():
            self.assertEqual((source / name).read_bytes(), data)
            self.assertEqual((source / name).stat().st_mode & 0o777, 0o600)

    def test_interrupted_install_reuses_same_source_even_if_main_moves(self):
        first = self.source()
        self.client.revision.side_effect = AssertionError('must not fetch new version')
        self.assertEqual(self.source(), first)
        self.client.archive.assert_called_once()

    def test_tampered_cache_is_never_executed(self):
        source = self.source()
        (source / 'setup.sh').write_text('malicious')
        with self.assertRaises(boot.BootstrapError): self.source()

    def test_missing_or_extra_cached_file_is_rejected(self):
        source = self.source()
        (source / 'extra.py').write_text('pass'); (source / 'extra.py').chmod(0o600)
        with self.assertRaises(boot.BootstrapError): self.source()
        (source / 'extra.py').unlink(); (source / 'setup.sh').unlink()
        with self.assertRaises(boot.BootstrapError): self.source()

    def test_cache_and_receipt_symlinks_cannot_be_followed(self):
        external = self.root / 'external'; external.mkdir(mode=0o700)
        self.base.symlink_to(external, target_is_directory=True)
        with self.assertRaises(boot.BootstrapError): self.source()
        self.base.unlink(); self.source()
        self.installer.receipt.unlink(); self.installer.receipt.symlink_to(self.install_state)
        self.install_state.write_text('{}'); self.install_state.chmod(0o600)
        with self.assertRaises(boot.BootstrapError): self.source()

    def test_concurrent_bootstrap_does_not_start_second_download(self):
        with self.installer.locked():
            with self.assertRaises(BlockingIOError): self.source()
        self.client.revision.assert_not_called()

    def test_other_incomplete_installer_cannot_mix_versions(self):
        self.install_state.write_text('{"complete":false}'); self.install_state.chmod(0o600)
        with self.assertRaises(boot.BootstrapError): self.source()
        self.client.revision.assert_not_called()

    def test_completed_existing_install_can_download_upgrade(self):
        self.install_state.write_text('{"complete":true}'); self.install_state.chmod(0o600)
        self.assertTrue(self.source().is_dir())
        self.assertEqual(json.loads(self.install_state.read_text()), {'complete': True})

    def test_duplicate_or_invalid_receipt_is_rejected(self):
        self.source()
        for body in ('{"version":1,"version":1,"revision":"' + REVISION + '"}',
                     json.dumps({'version': True, 'revision': REVISION}),
                     json.dumps({'version': 1, 'revision': '../../outside'})):
            self.installer.receipt.write_text(body)
            with self.assertRaises(boot.BootstrapError): self.source()

    def test_archive_checksum_failure_preserves_empty_install_state(self):
        self.client.archive.side_effect = lambda sha, path: archive(path, dict(FILES, **{'web/setup.py': b'evil\n'}))
        with self.assertRaises(boot.BootstrapError): self.source()
        self.assertFalse(self.installer.receipt.exists())
        self.assertFalse((self.base / REVISION).exists())

    def test_archive_links_and_traversal_are_rejected_without_outside_writes(self):
        cases = []
        for name in ('repo/../../escape', '/root/outside', 'repo//duplicate'):
            cases.append(tarfile.TarInfo(name))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            entry = tarfile.TarInfo('repo/link'); entry.type = kind; entry.linkname = '/outside'
            cases.append(entry)
        for index, extra in enumerate(cases):
            with self.subTest(name=extra.name, kind=extra.type):
                path = self.root / ('archive-' + str(index)); archive(path, extra=extra)
                target = self.root / ('extract-' + str(index)); target.mkdir(mode=0o700)
                with self.assertRaises(boot.BootstrapError): boot.extract_verified(path, target, manifest())
        self.assertFalse((self.root / 'escape').exists())

    def test_truncated_tree_symlink_modes_and_oversize_files_are_rejected(self):
        client = boot.GitHub(TOKEN)
        tree = {'truncated': False, 'tree': [dict(path=name, type='blob', mode='100644', **value)
                                            for name, value in manifest().items()]}
        for mutate in (lambda d: d.update(truncated=True),
                       lambda d: d['tree'][0].update(mode='120000'),
                       lambda d: d['tree'][0].update(size=boot.MAX_FILE + 1)):
            data = json.loads(json.dumps(tree)); mutate(data)
            with patch.object(client, 'json', return_value=data), self.assertRaises(boot.BootstrapError):
                client.manifest(REVISION)

    def test_archive_redirect_never_forwards_token(self):
        client = boot.GitHub(TOKEN)
        error = urllib.error.HTTPError(boot.API, 302, '', {'Location': 'https://codeload.github.com/repo/signed'}, None)
        response = io.BytesIO(b'archive')
        client.opener.open = Mock(side_effect=[error, response])
        client.archive(REVISION, self.root / 'download')
        first, second = [call.args[0] for call in client.opener.open.call_args_list]
        self.assertEqual(first.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertIsNone(second.get_header('Authorization'))

    def test_authentication_and_redirect_hosts_are_restricted(self):
        client = boot.GitHub(TOKEN); client.opener.open = Mock()
        for url, auth in (('http://api.github.com/x', True), ('https://evil.example/x', True),
                          ('https://api.github.com@evil.example/x', True), ('https://codeload.github.com:444/x', False)):
            with self.subTest(url=url), self.assertRaises(boot.BootstrapError): client.open(url, auth)
        client.opener.open.assert_not_called()

    def test_tokens_cannot_inject_headers(self):
        for token in ('', 'short', TOKEN + '\nX-Header: injected', TOKEN + '"', TOKEN + ' '):
            with self.assertRaises(boot.BootstrapError): boot.GitHub(token)

    def test_success_uses_execution_copy_and_never_persists_token(self):
        paths = []
        def run(args, **kwargs):
            paths.append(args)
            copied = Path(args[1]).parent
            self.assertNotEqual(copied, self.base / REVISION / 'source')
            (copied / '__pycache__').mkdir()
            (copied / '__pycache__/test.pyc').write_bytes(b'cache')
            return types.SimpleNamespace(returncode=0)
        self.installer.runner = run
        with patch.object(self.installer, 'dependencies'), patch.object(boot, 'open', create=True, return_value=io.StringIO()) as tty:
            self.assertEqual(self.installer.run(), 0)
        tty.assert_called_once_with('/dev/tty', 'r')
        self.assertIsNone(self.client.token)
        self.assertFalse(self.installer.receipt.exists())
        self.installer.cached(REVISION)
        self.assertNotIn(TOKEN, repr(paths))
        self.assertTrue(all(TOKEN.encode() not in p.read_bytes() for p in self.base.rglob('*') if p.is_file()))

    def test_failed_install_keeps_pinned_receipt(self):
        self.installer.runner = Mock(return_value=types.SimpleNamespace(returncode=1))
        with patch.object(self.installer, 'dependencies'), patch.object(boot, 'open', create=True, return_value=io.StringIO()):
            self.assertEqual(self.installer.run(), 1)
        self.assertEqual(boot.read_private(self.installer.receipt)['revision'], REVISION)
        self.installer.cached(REVISION)

    def run_setup_in_terminal(self, exit_code):
        import fcntl
        files = dict(FILES, **{'setup.sh': (
            '#!/bin/sh\n[ -t 0 ] || exit 31\nprintf "SETUP_INPUT_READY\\n"\n'
            'IFS= read -r answer\n[ "$answer" = continue ] || exit 32\n'
            'printf "SETUP_FINISHED\\n"\nexit ' + str(exit_code) + '\n').encode()})
        self.client.manifest.return_value = manifest(files)
        self.client.archive.side_effect = lambda sha, path: archive(path, files)
        self.source()
        program = (
            'import sys, types\n'
            'namespace = {"__name__": "bootstrap_pty_fixture"}\n'
            'exec(' + repr(PYTHON) + ', namespace)\n'
            'installer = namespace["Installer"](types.SimpleNamespace(token=None), '
            + repr(str(self.base)) + ', ' + repr(str(self.install_state)) + ')\n'
            'installer.dependencies = lambda: None\n'
            'sys.exit(installer.run())\n')
        master, slave = pty.openpty()
        def own_terminal():
            os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        process = subprocess.Popen([os.sys.executable, '-I', '-c', program], stdin=slave, stdout=slave,
                                   stderr=slave, preexec_fn=own_terminal)
        output = b''; sent = False; deadline = time.monotonic() + 8
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    output += os.read(master, 4096)
                if not sent and b'SETUP_INPUT_READY' in output:
                    os.write(master, b'continue\n'); sent = True
                if process.poll() is not None:
                    while select.select([master], [], [], 0)[0]:
                        chunk = os.read(master, 4096)
                        if not chunk:
                            break
                        output += chunk
                    break
            self.assertIsNotNone(process.poll(), 'setup terminal flow timed out')
            self.assertEqual(process.returncode, exit_code, output.decode(errors='replace'))
            self.assertIn(b'SETUP_FINISHED', output)
            self.assertFalse(list(self.base.glob('.execute-*')))
            self.installer.cached(REVISION)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3); os.close(master); os.close(slave)

    def test_real_terminal_setup_accepts_input_and_clears_receipt_on_success(self):
        self.run_setup_in_terminal(0)
        self.assertFalse(self.installer.receipt.exists())

    def test_real_terminal_failed_setup_keeps_same_source_for_retry(self):
        self.run_setup_in_terminal(7)
        self.assertEqual(boot.read_private(self.installer.receipt)['revision'], REVISION)
        self.client.revision.side_effect = AssertionError('must not fetch new version')
        self.assertEqual(self.source(), self.base / REVISION / 'source')

    def test_cached_source_digest_matches_existing_installer_after_execution_copy(self):
        from web.setup import Wizard
        from web.setup_upgrade import copy_payload
        payload = self.root / 'payload'; payload.mkdir(mode=0o700)
        copy_payload(ROOT, payload / 'web')
        for name in ('setup.sh', 'install.sh', 'certctl.py', 'run_history.py', 'failure_diagnostics.py',
                     'dns_cleanup.py', 'dns_cleanup_retry.sh', 'dns_tencent_tracked.sh'):
            (payload / name).write_bytes((ROOT / name).read_bytes())
        files = {path.relative_to(payload).as_posix(): path.read_bytes()
                 for path in payload.rglob('*') if path.is_file()}
        self.client.manifest.return_value = manifest(files)
        self.client.archive.side_effect = lambda sha, path: archive(path, files)
        source = self.source()
        state = self.root / 'setup-state'; state.mkdir(mode=0o700)
        expected = Wizard(source=ROOT, state=state).source_digest()
        self.assertEqual(Wizard(source=source, state=state).source_digest(), expected)
        copied = self.root / 'execution'
        boot.shutil.copytree(source, copied)
        self.assertEqual(Wizard(source=copied, state=state).source_digest(), expected)

    def test_usable_docker_is_not_reinstalled_or_restarted(self):
        self.installer.runner = Mock(return_value=types.SimpleNamespace(returncode=0))
        self.installer.dependencies()
        self.assertEqual([x.args[0] for x in self.installer.runner.call_args_list],
                         [['/usr/local/bin/docker', 'info'], ['/usr/local/bin/docker', 'compose', 'version']])

    def test_missing_package_manager_does_not_download_external_docker(self):
        self.installer.runner = Mock(side_effect=FileNotFoundError())
        with patch.object(boot.shutil, 'which', return_value=None), self.assertRaises(boot.BootstrapError):
            self.installer.dependencies()

    def package_fixture(self, existing=None, supports_install=True, install_ok=True):
        packages = self.root / 'packages'; packages.mkdir()
        version = self.root / 'VERSION'; version.write_text('productversion="7.4.1"\n')
        if existing:
            (packages / existing).mkdir()
        state = {'installed': bool(existing), 'started': False}
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[0].endswith('/docker'):
                if not state['installed']:
                    raise FileNotFoundError()
                return types.SimpleNamespace(returncode=0 if state['started'] else 1)
            if args[1] == '--help':
                return types.SimpleNamespace(returncode=0, stdout='install_from_server' if supports_install else '')
            if args[1] == 'install_from_server':
                state['installed'] = install_ok
                return types.SimpleNamespace(returncode=0 if install_ok else 1)
            if args[1] == 'start':
                state['started'] = state['installed']
                return types.SimpleNamespace(returncode=0 if state['started'] else 1)
            self.fail('unexpected package operation')
        self.installer.runner = run
        real_path = Path
        def path(value):
            return {'/var/packages': packages, '/etc.defaults/VERSION': version}.get(str(value), real_path(value))
        return calls, patch.object(boot, 'Path', side_effect=path), patch.object(boot.shutil, 'which', return_value='/usr/syno/bin/synopkg')

    def test_missing_docker_installs_from_official_package_manager_then_verifies(self):
        calls, paths, package_tool = self.package_fixture()
        with paths, package_tool:
            self.installer.dependencies()
        self.assertIn(['/usr/syno/bin/synopkg', 'install_from_server', 'ContainerManager'], calls)
        self.assertIn(['/usr/syno/bin/synopkg', 'start', 'ContainerManager'], calls)
        self.assertEqual(calls[-1], ['/usr/local/bin/docker', 'compose', 'version'])

    def test_existing_stopped_docker_starts_without_reinstallation(self):
        calls, paths, package_tool = self.package_fixture(existing='Docker')
        with paths, package_tool:
            self.installer.dependencies()
        self.assertIn(['/usr/syno/bin/synopkg', 'start', 'Docker'], calls)
        self.assertFalse(any('install_from_server' in x for x in calls))

    def test_unsupported_or_failed_package_install_does_not_run_setup(self):
        for supports, succeeds in ((False, True), (True, False)):
            with self.subTest(supports=supports, succeeds=succeeds):
                if (self.root / 'packages').exists():
                    (self.root / 'packages').rmdir()
                calls, paths, package_tool = self.package_fixture(supports_install=supports, install_ok=succeeds)
                with paths, package_tool, self.assertRaises(boot.BootstrapError):
                    self.installer.dependencies()
                self.assertFalse(any('start' in x for x in calls))

    def test_documented_command_has_valid_shell_and_no_embedded_secret(self):
        command = (ROOT / 'PRIVATE-INSTALL.md').read_text().split('```sh\n', 1)[1].split('\n```', 1)[0]
        self.assertEqual(len(command.splitlines()), 1)
        args = shlex.split(command)
        self.assertEqual(args[:3], ['sudo', 'sh', '-c'])
        self.assertEqual(subprocess.run(['sh', '-n', '-c', args[3]], capture_output=True).returncode, 0)
        self.assertIn('unset cert_install_token', args[3])
        self.assertIn('-K -', args[3])
        self.assertNotIn(' -L ', args[3])
        self.assertNotIn(TOKEN, command)

    def terminal_command(self, download_failure=False, cancel=False):
        import fcntl
        command = (ROOT / 'PRIVATE-INSTALL.md').read_text().split('```sh\n', 1)[1].split('\n```', 1)[0]
        body = shlex.split(command)[3].replace('test -f /etc.defaults/VERSION', 'true')
        body = body.replace('/tmp/cert-bootstrap.', str(self.root / 'download-'))
        body = 'printf "BODY_PID:%s\\n" "$$"; ' + body
        binary = self.root / 'bin'; binary.mkdir(exist_ok=True)
        fake = binary / 'curl'
        fake.write_text('#!' + os.path.realpath(os.sys.executable) + '\n'
                        'import os,sys\nfrom pathlib import Path\n'
                        'token=' + repr(TOKEN) + '\n'
                        'assert token not in repr(sys.argv) and token not in repr(dict(os.environ))\n'
                        'assert "cert_install_token" not in os.environ\n'
                        'assert sys.stdin.read()==\'header = "Authorization: Bearer \' + token + \'"\\n\'\n'
                        + ('sys.exit(22)\n' if download_failure else
                           'Path(sys.argv[sys.argv.index("-o")+1]).write_text("#!/bin/sh\\nIFS= read -r credential\\n[ \\\"$credential\\\" = ' + TOKEN + ' ] || exit 9\\nprintf BOOTSTRAP_READY\\n")\n'))
        fake.chmod(0o700)
        master, slave = pty.openpty()
        def own_terminal():
            os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'], cert_install_token='inherited-must-be-unset')
        wrapper = 'original=$(stty -g); sh -c "$1"; code=$?; [ "$(stty -g)" = "$original" ] && printf "TTY_RESTORED\\n"; exit "$code"'
        process = subprocess.Popen(['sh', '-c', wrapper, 'terminal-test', body], stdin=slave, stdout=slave, stderr=slave,
                                   preexec_fn=own_terminal, env=env)
        output = b''; sent = False; deadline = time.monotonic() + 8
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    chunk = os.read(master, 4096)
                    if chunk:
                        output += chunk
                if not sent and 'GitHub 只读令牌'.encode() in output:
                    # 提示在 stty 前输出；等到终端确实禁用回显才输入。
                    if not termios.tcgetattr(slave)[3] & termios.ECHO:
                        if cancel:
                            os.kill(int(re.search(rb'BODY_PID:(\d+)', output).group(1)), signal.SIGINT)
                        else:
                            os.write(master, (TOKEN + '\n').encode())
                        sent = True
                if process.poll() is not None:
                    while select.select([master], [], [], 0)[0]:
                        chunk = os.read(master, 4096)
                        if not chunk:
                            break
                        output += chunk
                    break
            self.assertIsNotNone(process.poll(), 'terminal flow timed out')
            self.assertIn(b'TTY_RESTORED', output)
            self.assertNotIn(TOKEN.encode(), output)
            self.assertFalse(list(self.root.glob('download-*')))
            return process.returncode, output
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3); os.close(master); os.close(slave)

    def test_one_command_keeps_token_hidden_and_delivers_it_only_through_pipe(self):
        code, output = self.terminal_command()
        self.assertEqual(code, 0, output)
        self.assertIn(b'BOOTSTRAP_READY', output)

    def test_download_failure_restores_terminal_and_cleans_files(self):
        code, output = self.terminal_command(download_failure=True)
        self.assertEqual(code, 22, output)
        self.assertNotIn(b'BOOTSTRAP_READY', output)

    def test_cancellation_during_hidden_input_restores_terminal(self):
        code, output = self.terminal_command(cancel=True)
        self.assertEqual(code, 130, output)


if __name__ == '__main__':
    unittest.main()
