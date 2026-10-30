import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]


class InstallationTests(unittest.TestCase):
    def install(self, checksum_valid=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / 'acme.tar.gz'
        commit = 'fixed-source-test'
        original_hook = b'#!/bin/sh\n# upstream test hook\n'
        with tarfile.open(archive, 'w:gz') as output:
            for name, data in [('acme.sh', b'#!/bin/sh\n'),
                               ('dnsapi/dns_tencent.sh', original_hook),
                               ('deploy/synology_dsm.sh', b'#!/bin/sh\n')]:
                item = tarfile.TarInfo('acme.sh-' + commit + '/' + name)
                item.size = len(data)
                output.addfile(item, io.BytesIO(data))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest() if checksum_valid else '0' * 64
        script = (SOURCE / 'install.sh').read_text().split("<<'PY'\n")[-1].rsplit('\nPY', 1)[0]
        installed = root / 'installed'
        result = subprocess.run([sys.executable, '-I', '-', str(root), str(SOURCE), str(installed),
                                 sys.executable, commit, checksum], input=script, text=True,
                                capture_output=True, timeout=30)
        return installed, original_hook, result

    def test_installer_preserves_upstream_and_installs_managed_cleanup_files(self):
        base, original_hook, result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((base / 'acme/dnsapi/dns_tencent_upstream.sh').read_bytes(), original_hook)
        self.assertEqual((base / 'acme/dnsapi/dns_tencent.sh').read_bytes(),
                         (SOURCE / 'dns_tencent_tracked.sh').read_bytes())
        for name in ('certctl.py', 'failure_diagnostics.py', 'dns_cleanup.py', 'dns_cleanup_retry.sh'):
            self.assertEqual((base / name).read_bytes(), (SOURCE / name).read_bytes())
        for path in [base] + list(base.rglob('*')):
            self.assertFalse(stat.S_IMODE(path.stat().st_mode) & 0o077, str(path))
        self.assertTrue(os.access(base / 'run-task.sh', os.X_OK))

    def test_bad_archive_checksum_does_not_install_partial_files(self):
        base, _, result = self.install(checksum_valid=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(base.exists())


if __name__ == '__main__':
    unittest.main()
