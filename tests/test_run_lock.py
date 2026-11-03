import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('run_lock_fixtures', Path(__file__).with_name('test_forced_renewal.py'))
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
certctl = FIXTURES.certctl


@contextlib.contextmanager
def cli(controller):
    cli_os = types.SimpleNamespace(**vars(os))
    cli_os.geteuid = lambda: 0
    previous_mask = os.umask(0o077)
    output = io.StringIO()
    try:
        with mock.patch.object(certctl, 'Controller', return_value=controller), \
             mock.patch.object(certctl, 'os', cli_os), \
             mock.patch.object(certctl.signal, 'signal'), \
             mock.patch.object(certctl, 'SYSTEM_PATH', os.environ['PATH']), \
             mock.patch.dict(os.environ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            yield cli_os, output
    finally:
        os.umask(previous_mask)


class RunLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name) / 'native'
        self.home.mkdir(mode=0o700)
        (self.home / 'state').mkdir(mode=0o700)
        self.controller = certctl.Controller(self.home)
        original_private = certctl.private
        uid = os.geteuid()
        patch = mock.patch.object(certctl, 'private', side_effect=lambda path, directory=False:
                                  original_private(path, directory, uid))
        patch.start(); self.addCleanup(patch.stop)
        for name in ('config.json', 'state/run.lock', 'state/last-result.json',
                     'state/pending.json', 'state/manual-renewal.json'):
            path = self.home / name
            path.write_text('{"original":true}')
            path.chmod(0o600)
        self.controller.run = mock.Mock()
        self.controller.begin_history = mock.Mock()
        self.controller.history_stage = mock.Mock()
        self.controller.finish_history = mock.Mock()
        self.controller.cleanup_diagnostics = mock.Mock()
        self.controller.report_failure = mock.Mock(wraps=self.controller.report_failure)

    def files(self):
        return {str(path.relative_to(self.home)): path.read_bytes()
                for path in self.home.rglob('*') if path.is_file()}

    def run_main(self, command='run'):
        return certctl.main(['--home', str(self.home), command])

    def test_cli_only_run_uses_sixty_second_wait(self):
        for name in ('assert_manual_idle', 'load', 'preflight', 'log', 'history_context',
                     'configure', 'release_manual_protection', 'retire_manual_target', 'status'):
            setattr(self.controller, name, mock.Mock())
        with cli(self.controller), mock.patch.object(self.controller, 'locked', wraps=self.controller.locked) as locked:
            for command in ('check', 'status', 'configure', 'run'):
                self.assertEqual(self.run_main(command), 0)
        self.assertEqual([call.kwargs.get('wait_seconds', 0) for call in locked.call_args_list], [0, 0, 0, 60])

    def test_default_lock_still_rejects_busy_without_sleep(self):
        with self.controller.locked(), mock.patch.object(certctl.time, 'sleep') as sleep:
            with self.assertRaises(certctl.Busy):
                with self.controller.locked():
                    self.fail('busy lock acquired')
        sleep.assert_not_called()

    def test_real_short_lock_is_released_before_cli_runs(self):
        ready, release = threading.Event(), threading.Event()
        errors = []
        def holder():
            try:
                with self.controller.locked():
                    ready.set()
                    release.wait(3)
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=holder)
        worker.start()
        self.assertTrue(ready.wait(2))
        original_sleep = time.sleep
        def retry_sleep(seconds):
            self.controller.run.assert_not_called()
            release.set()
            original_sleep(min(seconds, 0.02))
        try:
            with cli(self.controller), mock.patch.object(certctl.time, 'sleep', side_effect=retry_sleep) as sleep:
                self.assertEqual(self.run_main(), 0)
            self.assertTrue(sleep.called)
            self.controller.run.assert_called_once()
            self.assertFalse(errors)
        finally:
            release.set(); worker.join(3)
        self.assertFalse(worker.is_alive())

    def test_monotonic_timeout_does_not_execute_or_modify_renewal_state(self):
        before = self.files()
        clock = [0.0]
        def advance(seconds):
            clock[0] += seconds
        with self.controller.locked(), cli(self.controller), \
             mock.patch.object(certctl, 'RUN_LOCK_WAIT_SECONDS', 1, create=True), \
             mock.patch.object(certctl.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(certctl.time, 'time', side_effect=AssertionError('wall clock used')), \
             mock.patch.object(certctl.time, 'sleep', side_effect=advance):
            self.assertEqual(self.run_main(), 0)
        self.assertEqual(clock[0], 1)
        self.controller.run.assert_not_called()
        self.controller.report_failure.assert_not_called()
        self.assertEqual(before, self.files())

    def test_waiting_cancellation_never_archives_over_the_running_tasks_state(self):
        before = self.files()
        for error in (KeyboardInterrupt(), InterruptedError('terminated')):
            with self.subTest(error=type(error).__name__), self.controller.locked(), cli(self.controller), \
                 mock.patch.object(certctl.time, 'sleep', side_effect=error):
                self.assertEqual(self.run_main(), 1)
            self.controller.run.assert_not_called()
            self.controller.report_failure.assert_not_called()
            self.controller.cleanup_diagnostics.assert_not_called()
            self.assertEqual(before, self.files())

    def test_sigterm_during_wait_uses_interrupt_handler_without_state_changes(self):
        before = self.files()
        with self.controller.locked(), cli(self.controller), \
             mock.patch.object(certctl.time, 'sleep', side_effect=lambda _: certctl.interrupted(signal.SIGTERM, None)):
            self.assertEqual(self.run_main(), 1)
        self.controller.report_failure.assert_not_called()
        self.assertEqual(before, self.files())

    def test_lock_open_failure_does_not_write_failure_result_without_ownership(self):
        before = self.files()
        with cli(self.controller) as (cli_os, output), \
             mock.patch.object(cli_os, 'open', side_effect=PermissionError('private-lock-details')):
            self.assertEqual(self.run_main(), 1)
        self.controller.run.assert_not_called()
        self.controller.report_failure.assert_not_called()
        self.assertNotIn('private-lock-details', output.getvalue())
        self.assertEqual(before, self.files())

    def test_execution_failure_is_reported_while_the_lock_is_owned(self):
        self.controller.run.side_effect = certctl.Failure('execution failed')
        def report(_error):
            with self.assertRaises(certctl.Busy):
                with self.controller.locked():
                    self.fail('failure was archived outside lock')
            return 1
        self.controller.report_failure.side_effect = report
        with cli(self.controller):
            self.assertEqual(self.run_main(), 1)
        self.controller.report_failure.assert_called_once()
        self.controller.cleanup_diagnostics.assert_called_once()

    def test_archive_failure_is_not_retried_after_the_lock_has_been_released(self):
        self.controller.run.side_effect = certctl.Failure('execution failed')
        self.controller.report_failure.side_effect = OSError('disk unavailable')
        with cli(self.controller):
            self.assertEqual(self.run_main(), 1)
        self.controller.report_failure.assert_called_once()


class ConcurrentRenewalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURES.FIXTURES.CertificateTests.setUpClass()
        cls.addClassCleanup(FIXTURES.FIXTURES.CertificateTests.tearDownClass)

    def setUp(self):
        self.fixture = FIXTURES.ForcedRenewalTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.controller = self.fixture.controller

    def test_waiting_second_run_remains_exclusive_and_does_not_replay_force(self):
        self.fixture.request()
        issuing, waiting, release = threading.Event(), threading.Event(), threading.Event()
        errors, results = [], []
        def issue_and_deploy(arguments):
            if arguments[0] in ('--renew', '--issue'):
                issuing.set()
                if not release.wait(3):
                    raise AssertionError('issuer not released')
            return self.fixture.issue_and_deploy(arguments)
        self.controller.invoke_acme = mock.Mock(side_effect=issue_and_deploy)
        real_run = self.controller.run
        self.controller.run = mock.Mock(wraps=real_run)
        original_sleep = time.sleep
        def retry_sleep(seconds):
            waiting.set()
            original_sleep(min(seconds, 0.02))
        def run():
            try:
                results.append(certctl.main(['--home', str(self.controller.home), 'run']))
            except BaseException as error:
                errors.append(error)
        first, second = threading.Thread(target=run), threading.Thread(target=run)
        with cli(self.controller), mock.patch.object(certctl.time, 'sleep', side_effect=retry_sleep):
            try:
                first.start(); self.assertTrue(issuing.wait(3))
                second.start(); self.assertTrue(waiting.wait(2))
                self.controller.run.assert_called_once()
                release.set()
                first.join(3); second.join(3)
            finally:
                release.set()
                first.join(3)
                if second.ident is not None: second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(results, [0, 0])
        self.assertEqual(self.controller.run.call_count, 2)
        self.assertEqual([call.args[0][0] for call in self.controller.invoke_acme.call_args_list], ['--renew', '--deploy'])
        self.assertEqual(self.fixture.state()['state'], 'succeeded')


if __name__ == '__main__':
    unittest.main()
