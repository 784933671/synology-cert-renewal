import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

from web import container_entry


class ProjectReadyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'project-ready.json'
        self.now = 1000
        self.write({'version': 1, 'ready': True, 'expires_at': self.now + 25})
        original = os.fstat

        def root_stat(descriptor):
            value = list(original(descriptor))
            value[4] = 0
            return os.stat_result(value)

        owner = patch('web.container_entry.os.fstat', side_effect=root_stat)
        owner.start()
        self.addCleanup(owner.stop)

    def write(self, value):
        self.path.write_text(json.dumps(value))
        self.path.chmod(0o640)

    def test_current_private_root_grant_accepts_and_uses_wall_clock_by_default(self):
        self.assertTrue(container_entry.project_ready(self.path, self.now))
        with patch('web.container_entry.time.time', return_value=self.now):
            self.assertTrue(container_entry.project_ready(self.path))

    def test_missing_malformed_or_oversized_grant_keeps_listener_closed(self):
        for text in ('', '{broken', 'null', '[]', 'x' * 1025):
            with self.subTest(text=text[:10]):
                self.path.write_text(text)
                self.assertFalse(container_entry.project_ready(self.path, self.now))
        self.path.unlink()
        self.assertFalse(container_entry.project_ready(self.path, self.now))

    def test_expired_unreasonable_or_non_numeric_expiry_is_rejected(self):
        for expiry in (self.now - 0.01, self.now + 30.01, float('nan'), float('inf'),
                       -float('inf'), True, False, str(self.now + 20), None, 10 ** 1000):
            with self.subTest(expiry=repr(expiry)[:30]):
                self.write({'version': 1, 'ready': True, 'expires_at': expiry})
                self.assertFalse(container_entry.project_ready(self.path, self.now))
        for expiry in (self.now, self.now + 30):
            self.write({'version': 1, 'ready': True, 'expires_at': expiry})
            self.assertTrue(container_entry.project_ready(self.path, self.now))

    def test_strict_schema_and_boolean_ready_are_required(self):
        valid = {'version': 1, 'ready': True, 'expires_at': self.now + 25}
        for value in (dict(valid, ready=False), dict(valid, ready=1), dict(valid, ready='true'),
                      dict(valid, version=True), dict(valid, version=2), dict(valid, extra='ignored'),
                      {'version': 1, 'ready': True}):
            with self.subTest(value=value):
                self.write(value)
                self.assertFalse(container_entry.project_ready(self.path, self.now))

    def test_non_root_or_writable_grant_is_rejected(self):
        for mode in (0o660, 0o646, 0o666):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                self.assertFalse(container_entry.project_ready(self.path, self.now))
        self.path.chmod(0o640)
        value = list(self.path.stat())
        value[4] = 10100
        with patch('web.container_entry.os.fstat', return_value=os.stat_result(value)):
            self.assertFalse(container_entry.project_ready(self.path, self.now))

    def test_symlink_directory_and_hardlink_are_rejected(self):
        target = self.path.with_name('target.json')
        self.path.rename(target)
        self.path.symlink_to(target)
        self.assertFalse(container_entry.project_ready(self.path, self.now))
        self.path.unlink()
        self.path.mkdir()
        self.assertFalse(container_entry.project_ready(self.path, self.now))
        self.path.rmdir()
        os.link(target, self.path)
        self.assertFalse(container_entry.project_ready(self.path, self.now))


class ProjectEntryTests(unittest.TestCase):
    def run_entry(self, grants, sleep_count, materials=None, shutdown_on_worker_stop=False):
        handlers = {}
        sleeps = []
        children = [Mock(), Mock()]
        for child in children:
            child.poll.return_value = None
        if shutdown_on_worker_stop:
            children[0].wait.side_effect = lambda **_: handlers[signal.SIGTERM](None, None)

        def on_signal(sig, callback):
            handlers[sig] = callback

        def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) >= sleep_count:
                handlers[signal.SIGTERM](None, None)

        material = materials or [(Path('/tls/versions/a/cert'), Path('/tls/versions/a/key'))]
        with patch.dict(os.environ, CERTWEB_PROJECT_MODE='1'), \
                patch('web.container_entry.project_ready', side_effect=grants), \
                patch('web.container_entry.material', side_effect=material) as load, \
                patch('web.container_entry.signal.signal', side_effect=on_signal), \
                patch('web.container_entry.time.sleep', side_effect=sleep), \
                patch('web.container_entry.subprocess.Popen', side_effect=children) as spawn, \
                patch('sys.stderr'):
            result = container_entry.main()
        return result, load, spawn, children, sleeps

    def test_closed_gate_does_not_load_tls_or_bind_and_sigterm_exits(self):
        result, load, spawn, _, sleeps = self.run_entry([False, False, False], 3)
        self.assertEqual(result, 0)
        load.assert_not_called()
        spawn.assert_not_called()
        self.assertEqual(sleeps, [1, 1, 1])

    def test_opens_after_host_is_ready_and_stops_worker_on_shutdown(self):
        result, load, spawn, children, _ = self.run_entry([False, False, True, True], 3)
        self.assertEqual(result, 0)
        load.assert_called_once()
        spawn.assert_called_once()
        self.assertEqual(spawn.call_args.kwargs['env']['CERTWEB_TLS_CERT'], '/tls/versions/a/cert')
        children[0].terminate.assert_called_once()
        children[0].wait.assert_called_once_with(timeout=20)

    def test_revoked_grant_stops_worker_and_keeps_container_alive_without_rebinding(self):
        result, load, spawn, children, sleeps = self.run_entry([True, True, False, False, False], 4)
        self.assertEqual(result, 0)
        load.assert_called_once()
        spawn.assert_called_once()
        children[0].terminate.assert_called_once()
        self.assertEqual(sleeps, [1, 1, 1, 1])

    def test_renewed_grant_restarts_same_tls_generation_after_revocation(self):
        pair = (Path('/tls/versions/a/cert'), Path('/tls/versions/a/key'))
        result, load, spawn, children, _ = self.run_entry([True, True, False, True, True], 3, [pair, pair])
        self.assertEqual(result, 0)
        self.assertEqual(load.call_count, 2)
        self.assertEqual(spawn.call_count, 2)
        for child in children:
            child.terminate.assert_called_once()

    def test_project_waits_for_initial_tls_instead_of_exiting(self):
        pair = (Path('/tls/versions/a/cert'), Path('/tls/versions/a/key'))
        result, load, spawn, children, _ = self.run_entry([True, True, True], 2, [ValueError('private'), pair])
        self.assertEqual(result, 0)
        self.assertEqual(load.call_count, 2)
        spawn.assert_called_once()
        children[0].terminate.assert_called_once()

    def test_expiry_during_initial_tls_load_never_opens_listener(self):
        result, load, spawn, _, _ = self.run_entry([True, False, False], 2)
        self.assertEqual(result, 0)
        load.assert_called_once()
        spawn.assert_not_called()

    def test_revocation_while_stopping_old_tls_worker_does_not_start_replacement(self):
        first = (Path('/tls/versions/a/cert'), Path('/tls/versions/a/key'))
        second = (Path('/tls/versions/b/cert'), Path('/tls/versions/b/key'))
        result, load, spawn, children, _ = self.run_entry(
            [True, True, True, False, False], 3, [first, second])
        self.assertEqual(result, 0)
        self.assertEqual(load.call_count, 2)
        spawn.assert_called_once()
        children[0].terminate.assert_called_once()
        children[1].terminate.assert_not_called()

    def test_shutdown_while_stopping_tls_worker_never_starts_replacement(self):
        first = (Path('/tls/versions/a/cert'), Path('/tls/versions/a/key'))
        second = (Path('/tls/versions/b/cert'), Path('/tls/versions/b/key'))
        result, _, spawn, children, _ = self.run_entry(
            [True, True, True], 10, [first, second], shutdown_on_worker_stop=True)
        self.assertEqual(result, 0)
        spawn.assert_called_once()
        children[0].terminate.assert_called_once()
        children[1].terminate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
