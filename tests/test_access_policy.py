import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from web import access_policy as policy


class AccessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / 'access/access.json'
        self.uid, self.gid = os.getuid(), os.getgid()
        self.current = policy.initialize_policy(self.path, owner_uid=self.uid, gid=self.gid)

    def read(self, path=None):
        return policy.read_policy(path or self.path, owner_uid=self.uid)

    def write(self, mode, revision=None):
        return policy.write_policy(self.path, mode, revision or self.current['revision'], owner_uid=self.uid, gid=self.gid)

    def test_initialization_defaults_lan_and_preserves_existing_choice(self):
        self.assertEqual(self.current['mode'], 'lan')
        self.assertEqual(len(self.current['revision']), 32)
        changed = self.write('public')
        self.assertEqual(policy.initialize_policy(self.path, 'lan', self.uid, self.gid), changed)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o750)
        self.assertEqual(self.path.stat().st_gid, self.gid)

    def test_cas_rejects_stale_revision_and_same_mode_keeps_revision(self):
        self.assertEqual(self.write('lan'), self.current)
        changed = self.write('public')
        self.assertNotEqual(changed['revision'], self.current['revision'])
        with self.assertRaises(policy.PolicyConflict):
            self.write('lan')
        self.assertEqual(self.read(), changed)
        self.assertEqual(self.write('public', changed['revision']), changed)

    def test_concurrent_writers_cannot_overwrite_same_revision(self):
        barrier = threading.Barrier(2)
        def save():
            barrier.wait()
            try:
                return self.write('public')
            except policy.PolicyConflict:
                return 'conflict'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: save(), range(2)))
        self.assertEqual(sum(isinstance(item, dict) for item in results), 1)
        self.assertEqual(results.count('conflict'), 1)
        self.assertEqual(self.read()['mode'], 'public')

    def test_invalid_modes_extra_fields_duplicate_keys_and_oversize_rejected(self):
        malformed = [
            {'mode': 'all', 'revision': 'a' * 32}, {'mode': 'public', 'revision': 'x'},
            {'mode': 'public', 'revision': 'a' * 32, 'command': 'anything'},
            {'mode': ['public'], 'revision': 'a' * 32}, [],
        ]
        for value in malformed:
            with self.subTest(value=value):
                self.path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): self.read()
        for text in ['{"mode":"lan","mode":"public","revision":"' + 'a' * 32 + '"}', 'x' * 4097]:
            self.path.write_text(text)
            with self.assertRaises(ValueError): self.read()
        for mode in ['all', '', None, ['public']]:
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.write(mode)

    def test_files_missing_or_unsafe_permissions_fail_closed(self):
        with self.assertRaises(ValueError):
            policy.read_policy(self.path, owner_uid=self.uid + 1)
        for mode in (0o660, 0o644, 0o777):
            self.path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.read()
        self.path.chmod(0o640)
        self.path.parent.chmod(0o770)
        with self.assertRaises(ValueError): self.read()
        self.path.parent.chmod(0o750)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError): self.read()

    def test_links_and_path_escape_are_rejected(self):
        saved = self.root / 'original.json'
        self.path.rename(saved)
        self.path.symlink_to(saved)
        with self.assertRaises(OSError): self.read()
        self.path.unlink()
        self.path.hardlink_to(saved)
        with self.assertRaises(ValueError): self.read()
        self.path.unlink()
        saved.rename(self.path)
        alias = self.root / 'alias'
        alias.symlink_to(self.path.parent, target_is_directory=True)
        with self.assertRaises(OSError): self.read(alias / 'access.json')
        for path in [Path('relative/access.json'), self.root / '../access.json']:
            with self.subTest(path=path), self.assertRaises(ValueError): policy.read_policy(path, owner_uid=self.uid)

    def test_failed_atomic_replace_retains_previous_policy_and_cleans_temporary(self):
        with patch('web.access_policy.os.replace', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError): self.write('public')
        self.assertEqual(self.read(), self.current)
        self.assertEqual(list(self.path.parent.glob('.policy-*')), [])

    def test_applied_state_is_independent_and_unchanged_state_does_not_write(self):
        self.assertEqual(policy.write_applied(self.path, self.current, self.uid, self.gid), self.current)
        applied = self.path.with_name('applied.json')
        self.assertEqual(self.read(applied), self.current)
        with patch('web.access_policy.os.replace') as replace:
            policy.write_applied(self.path, self.current, self.uid, self.gid)
            replace.assert_not_called()
        changed = self.write('public')
        self.assertEqual(self.read(applied), self.current)
        policy.write_applied(self.path, changed, self.uid, self.gid)
        self.assertEqual(self.read(applied), changed)

    def test_initialization_with_private_umask_retains_container_group_access(self):
        other = self.root / 'second/access.json'
        previous = os.umask(0o077)
        try: policy.initialize_policy(other, owner_uid=self.uid, gid=self.gid)
        finally: os.umask(previous)
        self.assertEqual(other.stat().st_mode & 0o777, 0o640)
        self.assertEqual(other.parent.stat().st_mode & 0o777, 0o750)


if __name__ == '__main__':
    unittest.main()
