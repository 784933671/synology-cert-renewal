import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from web.setup_tasks import TaskSetup
from web.host_bridge import BridgeError


class TaskApi:
    def __init__(self, home):
        self.home = home
        self.tasks = {}
        self.calls = []
        self.fail_create = None
        self.defaults = {'id': -1, 'type': 'script', 'owner': 'root', 'real_owner': 'root', 'enable': True,
                         'schedule': {'date': '2026/11/3', 'date_type': 0, 'hour': 0, 'last_work_hour': 0,
                                      'minute': 0, 'monthly_week': [], 'repeat_date': 1001, 'repeat_hour': 0,
                                      'repeat_hour_store_config': None, 'repeat_min': 0,
                                      'repeat_min_store_config': None, 'version': 4, 'week_day': '0,1,2,3,4,5,6'},
                         'extra': {'script': ''}}

    def api(self, api, method, version, params):
        self.calls.append((api, method, version, copy.deepcopy(params)))
        if method == 'list':
            rows = [{'id': key, **{k: value[k] for k in ('name', 'owner', 'type')}} for key, value in sorted(self.tasks.items())]
            return {'tasks': rows[params['start']:params['start'] + params['limit']], 'total': len(rows)}
        if method == 'get':
            return copy.deepcopy(self.defaults if params['id'] == -1 else self.tasks[params['id']])
        if method == 'create':
            if self.fail_create == 'before':
                raise RuntimeError('response lost')
            identifier = max(self.tasks, default=30) + 1
            self.tasks[identifier] = dict(copy.deepcopy(params), id=identifier)
            if self.fail_create == 'after':
                raise RuntimeError('response lost')
            return {}  # DSM GUI does not depend on a create response ID.
        if method == 'set':
            self.tasks[params['id']].update(copy.deepcopy(params))
            return {}
        raise AssertionError((api, method, params))

    def existing(self, identifier=7, enabled=True):
        value = copy.deepcopy(self.defaults)
        value.update(id=identifier, name='原自动续期', enable=enabled)
        value['schedule']['minute'] = 18
        value['extra'] = {'script': '/bin/sh ' + str(self.home / 'run-task.sh'), 'notify_mail': 'old@example.com'}
        self.tasks[identifier] = value
        return value


class TaskSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.home = self.root / 'native';self.home.mkdir(mode=0o700)
        self.api = TaskApi(self.home)
        self.setup = TaskSetup(self.home, self.api, self.root / 'task.json', uid=os.getuid())

    def test_new_task_uses_dsm_defaults_and_stays_disabled_until_activation(self):
        task = self.setup.ensure('admin@example.com')
        self.assertEqual(task['id'], 31)
        self.assertFalse(task['enable'])
        self.assertEqual(task['schedule']['minute'], 17)
        self.assertEqual(task['schedule']['repeat_hour'], 1)
        self.assertEqual(task['schedule']['date'], self.api.defaults['schedule']['date'])
        self.assertEqual(task['extra']['notify_mail'], 'admin@example.com')
        self.assertTrue(task['extra']['notify_if_error'])
        self.assertTrue(self.setup.activate(31)['enable'])
        self.assertEqual(sum(call[1] == 'create' for call in self.api.calls), 1)
        self.assertEqual(sum(call[1] == 'set' for call in self.api.calls), 1)
        self.assertEqual((self.root / 'task.json').stat().st_mode & 0o777, 0o600)

    def test_completed_activation_does_not_override_later_user_changes(self):
        task = self.setup.ensure('admin@example.com')
        self.setup.activate(task['id'])
        self.api.tasks[task['id']]['enable'] = False
        self.api.tasks[task['id']]['schedule']['minute'] = 18
        before = copy.deepcopy(self.api.tasks[task['id']])
        self.assertEqual(self.setup.activate(task['id']), before)
        self.assertEqual(sum(call[1] == 'set' for call in self.api.calls), 1)

    def test_existing_task_is_preserved_including_disabled_schedule_and_email(self):
        before = copy.deepcopy(self.api.existing(enabled=False))
        self.assertEqual(self.setup.ensure('new@example.com'), before)
        self.assertEqual(self.setup.activate(7), before)
        self.assertFalse(any(call[1] in ('create', 'set') for call in self.api.calls))

    def test_other_tasks_are_not_adopted_or_modified(self):
        foreign = self.api.existing()
        foreign['extra']['script'] += '; id'
        unrelated = copy.deepcopy(foreign)
        created = self.setup.ensure('admin@example.com')
        self.assertNotEqual(created['id'], 7)
        self.assertEqual(self.api.tasks[7], unrelated)

    def test_multiple_exact_tasks_block_without_creating_or_modifying(self):
        self.api.existing(7);self.api.existing(13)
        with self.assertRaises(ValueError):self.setup.ensure('admin@example.com')
        self.assertFalse(any(call[1] in ('create', 'set') for call in self.api.calls))

    def test_lost_create_response_is_reconciled_by_unique_name_without_recreating(self):
        self.api.fail_create = 'after'
        with self.assertRaises(RuntimeError):self.setup.ensure('admin@example.com')
        self.api.fail_create = None
        task = self.setup.ensure('admin@example.com')
        self.assertEqual(task['id'], 31)
        self.assertFalse(task['enable'])
        self.assertEqual(sum(call[1] == 'create' for call in self.api.calls), 1)

    def test_unknown_create_without_observed_task_does_not_retry(self):
        self.api.fail_create = 'before'
        with self.assertRaises(RuntimeError):self.setup.ensure('admin@example.com')
        self.api.fail_create = None
        with self.assertRaises(ValueError):self.setup.ensure('admin@example.com')
        self.assertEqual(sum(call[1] == 'create' for call in self.api.calls), 1)

    def test_changed_new_task_and_changed_ownership_are_not_enabled(self):
        task = self.setup.ensure('admin@example.com')
        self.api.tasks[task['id']]['extra']['notify_mail'] = 'someone@example.com'
        with self.assertRaises(ValueError):self.setup.activate(task['id'])
        self.assertFalse(self.api.tasks[task['id']]['enable'])
        self.api.tasks[task['id']]['owner'] = 'another-user'
        with self.assertRaises(ValueError):self.setup.activate(task['id'])
        self.assertFalse(any(call[1] == 'set' for call in self.api.calls))

    def test_lost_create_cannot_adopt_foreign_nonce_or_changed_payload(self):
        self.api.fail_create = 'after'
        with self.assertRaises(RuntimeError):self.setup.ensure('admin@example.com')
        self.api.tasks[31]['schedule']['minute'] = 19
        with self.assertRaises(ValueError):self.setup.ensure('admin@example.com')
        self.assertEqual(sum(call[1] == 'create' for call in self.api.calls), 1)

    def test_list_pagination_and_invalid_metadata_do_not_hide_duplicate(self):
        for identifier in range(1, 102):
            task = self.api.existing(identifier)
            task['owner'] = 'ordinary-user'
        self.api.existing(102)
        self.assertEqual(self.setup.ensure('admin@example.com')['id'], 102)
        self.assertEqual([call[3]['start'] for call in self.api.calls if call[1] == 'list'], [0, 100])

    def test_invalid_email_and_symlinked_state_do_not_mutate_tasks(self):
        for email in ('-x@example.com', 'a@example.com\nb@example.com', 'bad'):
            with self.assertRaises(ValueError):self.setup.ensure(email)
        target = self.root / 'other';target.write_text('{}')
        self.setup.state_path.symlink_to(target)
        with self.assertRaises((OSError, BridgeError)):self.setup.ensure('admin@example.com')
        self.assertFalse(any(call[1] in ('create', 'set') for call in self.api.calls))


SPEC = importlib.util.spec_from_file_location('portable_install', Path(__file__).resolve().parents[1] / 'web/install-web.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.native = self.root / 'native';self.native.mkdir(mode=0o700)
        for name in ('config.json', 'certctl.py'):(self.native / name).write_text('{}')
        self.source = self.root / 'source';self.source.mkdir(mode=0o700)
        self.sources = ['Dockerfile', 'compose.yaml', 'deployment.py', 'host_bridge.py', 'login_mail.py',
                        'access_policy.py', 'backend/app.py', 'frontend/package.json']
        for name in self.sources:
            path = self.source / name;path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}')
        self.args = argparse.Namespace(home=self.root / 'managed', native_home=self.native, bind='10.10.10.37',
                                       network=['10.10.10.0/24'], deny=['10.10.10.1'], port=18443,
                                       task_id=31, origin='https://nas.example.com:18443', access_mode='lan')
        for patcher in (mock.patch.object(installer, '__file__', str(self.source / 'install-web.py')),
                        mock.patch.object(installer, 'private_root'),
                        mock.patch.object(installer, 'load_config'),
                        mock.patch.object(installer, 'initialize_policy'),
                        mock.patch.object(installer.os, 'chown'), mock.patch('builtins.print')):
            patcher.start();self.addCleanup(patcher.stop)

    def test_invalid_task_and_origin_fail_before_any_installation_write(self):
        for key, value in (('task_id', 0), ('origin', 'http://nas.example.com:18443')):
            with self.subTest(key=key):
                args = copy.copy(self.args);setattr(args, key, value)
                with self.assertRaises(ValueError):installer.prepare(args)
                self.assertFalse(self.args.home.exists());self.assertFalse((self.native / 'web').exists())

    def test_copy_failure_does_not_leave_installation_or_bridge(self):
        with mock.patch.object(installer.shutil, 'copyfile', side_effect=OSError('copy failed')):
            with self.assertRaises(OSError):installer.prepare(self.args)
        self.assertFalse(self.args.home.exists());self.assertFalse((self.native / 'web').exists())
        self.assertFalse(list(self.root.glob('.managed-prepare-*')))

    def test_resume_restores_missing_bridge_without_touching_database_or_runtime(self):
        installer.prepare(self.args)
        credential = self.args.home / 'data/auth.sqlite3';credential.write_bytes(b'keep-auth-data')
        (self.native / 'web/login_mail.py').unlink()
        installer.prepare(self.args)
        self.assertEqual(credential.read_bytes(), b'keep-auth-data')
        self.assertEqual((self.native / 'web/login_mail.py').read_bytes(), b'{}')
        self.assertEqual(json.loads((self.args.home / 'deployment.json').read_text())['task_id'], 31)

    def test_unknown_existing_directory_and_changed_source_are_not_overwritten(self):
        self.args.home.mkdir();sentinel=self.args.home / 'user-data';sentinel.write_text('keep')
        with self.assertRaises((ValueError, OSError)):installer.prepare(self.args)
        self.assertEqual(sentinel.read_text(), 'keep')
        sentinel.unlink();self.args.home.rmdir()
        installer.prepare(self.args)
        (self.source / 'host_bridge.py').write_text('changed')
        with self.assertRaises(ValueError):installer.prepare(self.args)
        self.assertEqual((self.native / 'web/host_bridge.py').read_text(), '{}')

    def test_runtime_secrets_are_not_copied_to_build_context(self):
        for name in ('login-email.json', 'deployment.json', 'credentials.json'):(self.source / name).write_text('SECRET')
        (self.source / 'data').mkdir();(self.source / 'data/auth.sqlite3').write_text('SECRET')
        installer.prepare(self.args)
        installed = [str(path.relative_to(self.args.home / 'code')) for path in (self.args.home / 'code').rglob('*') if path.is_file()]
        self.assertEqual(set(installed), set(self.sources))


if __name__ == '__main__':
    unittest.main()
