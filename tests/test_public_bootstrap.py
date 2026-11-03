import contextlib
import io
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error

from tests.test_private_bootstrap import ROOT, REVISION, boot


LOADER = (ROOT / 'bootstrap.sh').read_text()


class PublicBootstrapTests(unittest.TestCase):
    def test_anonymous_api_does_not_use_environment_credentials(self):
        client = boot.GitHub()
        client.opener.open = Mock(return_value=io.BytesIO(b'{}'))
        with patch.dict(os.environ, GH_TOKEN='environment-secret', GITHUB_TOKEN='other-secret'):
            client.open(boot.API + '/commits/main')
        request = client.opener.open.call_args.args[0]
        self.assertIsNone(request.get_header('Authorization'))
        self.assertEqual(request.full_url, boot.API + '/commits/main')

    def test_anonymous_archive_redirect_uses_no_authorization(self):
        client = boot.GitHub()
        error = urllib.error.HTTPError(boot.API, 302, '', {'Location': 'https://codeload.github.com/repo/archive'}, None)
        client.opener.open = Mock(side_effect=[error, io.BytesIO(b'archive')])
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'source.tar.gz'
            client.archive(REVISION, target)
            self.assertEqual(target.read_bytes(), b'archive')
        self.assertTrue(all(call.args[0].get_header('Authorization') is None
                            for call in client.opener.open.call_args_list))

    def test_public_mode_never_requests_a_token_and_preserves_installer_exit(self):
        with patch.object(sys, 'argv', ['bootstrap-private.sh', '--public']), \
                patch.object(boot.getpass, 'getpass', side_effect=AssertionError('no token prompt')), \
                patch.object(boot, 'Installer') as installer:
            installer.return_value.run.return_value = 7
            self.assertEqual(boot.main(), 7)
            self.assertIsNone(installer.call_args.args[0].token)

    def test_public_http_failure_does_not_prompt_or_expose_response(self):
        for code in (403, 404, 429):
            output = io.StringIO()
            error = urllib.error.HTTPError(boot.API, code, 'private-response', {}, None)
            with self.subTest(code=code), patch.object(sys, 'argv', ['bootstrap-private.sh', '--public']), \
                    patch.object(boot.getpass, 'getpass', side_effect=AssertionError('no fallback prompt')), \
                    patch.object(boot.Installer, 'run', side_effect=error), contextlib.redirect_stderr(output):
                self.assertEqual(boot.main(), 1)
            self.assertIn('HTTP ' + str(code), output.getvalue())
            self.assertNotIn('private-response', output.getvalue())
            self.assertNotIn('令牌', output.getvalue())


class PublicLoaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / 'bin'
        self.binary.mkdir()
        self.record = self.root / 'executed'
        self.downloads = self.root / 'downloads'
        self.script = LOADER.replace('[ "$(id -u)" = 0 ]', 'true')
        self.script = self.script.replace('[ -f /etc.defaults/VERSION ]', 'true')
        self.script = self.script.replace('/tmp/synology-cert-bootstrap.', str(self.root / 'download-'))
        self.environment = dict(os.environ, PATH=str(self.binary) + ':' + os.environ['PATH'])

    def fake_download(self, payload=None, download_exit=0):
        if payload is None:
            payload = '#!/bin/sh\n[ "$1" = --public ] || exit 9\nprintf ok > ' + str(self.record) + '\n'
        curl = self.binary / 'curl'
        curl.write_text('#!' + os.path.realpath(sys.executable) + '\n'
                        'import sys\nfrom pathlib import Path\n'
                        'args = sys.argv[1:]\n'
                        'assert args[args.index("--proto")+1] == "=https"\n'
                        'assert args[args.index("--proto-redir")+1] == "=https"\n'
                        'assert "-H" not in args and "-K" not in args\n'
                        'Path(' + repr(str(self.downloads)) + ').write_text("requested")\n'
                        'Path(args[args.index("-o")+1]).write_text(' + repr(payload) + ')\n'
                        'sys.exit(' + str(download_exit) + ')\n')
        curl.chmod(0o700)

    def run_loader(self, source=None):
        result = subprocess.run(['sh'], input=self.script if source is None else source,
                                text=True, capture_output=True, env=self.environment, timeout=10)
        self.assertFalse(list(self.root.glob('download-*')))
        return result

    def test_complete_piped_loader_downloads_then_executes_public_mode(self):
        self.fake_download()
        result = self.run_loader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.record.read_text(), 'ok')

    def test_failed_download_never_executes_even_if_payload_was_written(self):
        self.fake_download(download_exit=22)
        result = self.run_loader()
        self.assertEqual(result.returncode, 22)
        self.assertFalse(self.record.exists())

    def test_invalid_downloaded_script_is_not_partially_executed(self):
        self.fake_download('printf unsafe > ' + str(self.record) + '\nif\n')
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertFalse(self.record.exists())

    def test_truncated_outer_download_cannot_start_installation(self):
        self.fake_download()
        for marker in ('cert_bootstrap_dir=$(mktemp', '\ncert_bootstrap "$@"'):
            with self.subTest(marker=marker):
                self.run_loader(self.script[:self.script.index(marker)])
                self.assertFalse(self.downloads.exists())
                self.assertFalse(self.record.exists())

    def test_installer_failure_is_preserved_and_temporary_files_are_removed(self):
        self.fake_download('#!/bin/sh\nexit 7\n')
        self.assertEqual(self.run_loader().returncode, 7)

    def test_piped_loader_leaves_terminal_available_for_the_installer(self):
        import fcntl
        self.fake_download('#!/bin/sh\nexec </dev/tty\nprintf "INPUT_READY\\n"\n'
                           'IFS= read -r answer\n[ "$answer" = continue ] || exit 9\n'
                           'printf ok > ' + str(self.record) + '\n')
        master, slave = pty.openpty()
        def own_terminal():
            os.setsid()
            fcntl.ioctl(1, termios.TIOCSCTTY, 0)
        process = subprocess.Popen(['sh'], stdin=subprocess.PIPE, stdout=slave, stderr=slave,
                                   env=self.environment, preexec_fn=own_terminal)
        process.stdin.write(self.script.encode())
        process.stdin.close()
        output = b''
        sent = False
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and process.poll() is None:
                if select.select([master], [], [], 0.05)[0]:
                    output += os.read(master, 4096)
                if not sent and b'INPUT_READY' in output:
                    os.write(master, b'continue\n')
                    sent = True
            self.assertEqual(process.poll(), 0, output.decode(errors='replace'))
            self.assertEqual(self.record.read_text(), 'ok')
            self.assertFalse(list(self.root.glob('download-*')))
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            os.close(master)
            os.close(slave)

    def test_shell_syntax_help_and_non_nas_guard(self):
        script = str(ROOT / 'bootstrap.sh')
        self.assertEqual(subprocess.run(['sh', '-n', script], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(['sh', script, '--help'], capture_output=True).returncode, 0)
        guarded = LOADER.replace('[ "$(id -u)" = 0 ]', 'true')
        guarded = guarded.replace('[ -f /etc.defaults/VERSION ]', 'false')
        self.assertNotEqual(self.run_loader(guarded).returncode, 0)
        self.assertFalse(self.downloads.exists())

    def test_documented_command_is_short_and_matches_the_public_entrypoint(self):
        document = (ROOT / 'PUBLIC-INSTALL.md').read_text()
        command = document.split('```sh\n', 1)[1].split('\n```', 1)[0]
        self.assertEqual(command, 'curl -fsSL https://raw.githubusercontent.com/784933671/synology-cert-renewal/main/bootstrap.sh | sudo sh')
        self.assertLess(len(command), 120)
        self.assertEqual(subprocess.run(['sh', '-n', '-c', command], capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
