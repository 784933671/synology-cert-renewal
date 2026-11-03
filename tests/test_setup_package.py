import hashlib
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from web.setup_upgrade import copy_payload, UpgradeError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('cert_package', ROOT / 'scripts/package.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        copy_payload(ROOT, self.source / 'web')
        for name in PACKAGE.ROOT_FILES:
            shutil.copyfile(ROOT / name, self.source / name)

    def test_package_excludes_runtime_credentials_and_verifies_manifest(self):
        (self.source / 'config.json').write_text('live-secret')
        (self.source / 'web/login-email.json').write_text('private-mail-policy')
        (self.source / 'web/data').mkdir()
        (self.source / 'web/data/auth.sqlite3').write_bytes(b'private-login-data')
        target = self.root / 'install.zip'
        count, digest = PACKAGE.package(self.source, target)
        self.assertEqual(digest, hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertIn(digest, target.with_suffix('.zip.sha256').read_text())
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
            self.assertEqual(count, len(names))
            self.assertIn('synology-cert-manager/setup.sh', names)
            self.assertIn('synology-cert-manager/web/setup.py', names)
            for path in ('run_history.py', 'web/monitor.py', 'web/observability.py', 'web/startup_check.py'):
                self.assertIn('synology-cert-manager/' + path, names)
            self.assertFalse(any('auth.sqlite3' in x or 'login-email.json' in x or x.endswith('/config.json') for x in names))
            manifest = archive.read('synology-cert-manager/SHA256SUMS').decode()
            for line in manifest.splitlines():
                expected, name = line.split('  ', 1)
                self.assertEqual(expected, hashlib.sha256(archive.read('synology-cert-manager/' + name)).hexdigest())

    def test_root_source_symlink_is_rejected(self):
        (self.source / 'setup.sh').unlink()
        (self.source / 'setup.sh').symlink_to(ROOT / 'setup.sh')
        with self.assertRaises(UpgradeError):
            PACKAGE.package(self.source, self.root / 'install.zip')


if __name__ == '__main__':
    unittest.main()
