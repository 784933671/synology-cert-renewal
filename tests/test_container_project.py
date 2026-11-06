import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from web import container_project as project


class ContainerProjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.home = self.root / 'manager'
        self.home.mkdir(mode=0o700)
        self.native = self.root / 'native'
        self.native.mkdir(mode=0o700)
        configuration = self.home / 'deployment.json'
        configuration.write_text(json.dumps({'native_home': str(self.native)}))
        configuration.chmod(0o600)
        self.directory = self.root / 'container-project'
        self.uid = os.getuid()
        self.manifest = {
            'name': 'synology-cert-web',
            'services': {'certweb': {
                'image': 'synology-cert-web:local',
                'build': {'context': str(self.home / 'code')},
                'container_name': 'synology-cert-web',
                'labels': {'io.github.784933671.certweb.managed': 'true'},
                'network_mode': 'host', 'user': '10100:10100', 'read_only': True,
                'init': True, 'restart': 'no', 'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges:true'],
                'mem_limit': 402653184, 'cpuset': '0',
                'ulimits': {'nproc': {'soft': 96, 'hard': 96}},
                'healthcheck': {'test': ['CMD', 'python', '-m', 'web.healthcheck'],
                                'interval': '30s', 'timeout': '6s', 'retries': 3},
                'environment': {'CERTWEB_DATA_DIR': '/data', 'CERTWEB_BIND': '10.10.10.37',
                                'CERTWEB_ORIGIN': 'https://nas.example.com:18443'},
                'volumes': [{'type': 'bind', 'source': str(self.home / name), 'target': '/' + name,
                             'read_only': name != 'data'} for name in ('data', 'bridge', 'tls', 'access')],
            }},
        }
        self.image = 'sha256:' + 'a' * 64
        self.runner = Mock(side_effect=lambda args, **kwargs:
                           self.image if args[1:3] == ['image', 'inspect'] else json.dumps(self.manifest))

    def export(self, name='synology-cert-web'):
        return project.export_project(self.home, self.directory, name, self.runner, self.uid)

    def manifest_path(self):
        return self.directory / project.PROJECT_FILE

    def test_render_resolves_environment_and_preserves_runtime_restrictions(self):
        content = project.render_project(self.home, 'synology-cert-web', self.runner)
        result = json.loads(content)
        expected = copy.deepcopy(self.manifest['services']['certweb'])
        expected.pop('build')
        expected['environment']['CERTWEB_PROJECT_MODE'] = '1'
        self.assertEqual(result['services']['certweb'], expected)
        self.assertNotIn('name', result)
        self.assertNotIn(b'${', content)
        self.assertEqual(result[project.PROJECT_MARKER], {
            'version': 1, 'home': str(self.home), 'name': 'synology-cert-web'})
        self.runner.assert_called_once_with([
            project.DOCKER, 'compose', '--project-name', 'synology-cert-web', '--env-file',
            str(self.home / 'deployment.env'), '-f', str(self.home / 'code/compose.yaml'),
            'config', '--format', 'json'], timeout=90)

    def test_render_accepts_explicit_staged_code(self):
        code = self.root / 'new-code'
        project.render_project(self.home, 'cert-project', self.runner, code=code)
        self.assertIn(str(code / 'compose.yaml'), self.runner.call_args.args[0])

    def test_render_requires_absolute_canonical_deployment_paths(self):
        for home, code in ((Path('relative-home'), None), (self.home, Path('relative-code'))):
            with self.subTest(home=home, code=code), self.assertRaises(ValueError):
                project.render_project(home, 'cert-project', self.runner, code)
        self.runner.assert_not_called()

    def test_export_records_private_stable_project_and_refreshes_same_descriptor(self):
        descriptor = self.export('cert-project')
        self.assertEqual(descriptor, {'version': 1, 'name': 'cert-project', 'directory': str(self.directory)})
        self.assertEqual(project.load_project(self.home, self.uid), descriptor)
        self.assertEqual(self.export('cert-project'), descriptor)
        self.manifest['services']['certweb']['environment']['CERTWEB_PORT'] = '19443'
        self.assertEqual(project.refresh_project(self.home, self.runner, self.uid), descriptor)
        self.assertEqual(json.loads(self.manifest_path().read_text())['services']['certweb']['environment']['CERTWEB_PORT'], '19443')
        for path in (self.manifest_path(), self.home / project.PROJECT_STATE):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(self.directory.iterdir()), [self.manifest_path()])

    def test_project_compose_uses_registered_name_and_file_without_environment(self):
        descriptor = self.export('cert-project')
        command = project.project_compose(self.home, descriptor, 'up', '-d', '--no-build')
        self.assertEqual(command, [project.DOCKER, 'compose', '--project-name', 'cert-project',
                                   '-f', str(self.manifest_path()), 'up', '-d', '--no-build'])
        self.assertNotIn('--env-file', command)

    def test_prepare_is_read_only_and_commit_does_not_call_docker(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        self.assertEqual(sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')), before)
        self.assertIsInstance(prepared[1], bytes)
        with self.assertRaises(TypeError):
            prepared[0]['directory'] = str(self.root / 'different-project')
        self.runner.reset_mock()
        descriptor = project.commit_project(self.home, prepared, self.uid)
        self.assertEqual(descriptor, prepared[0])
        self.assertEqual(project.load_project(self.home, self.uid), descriptor)
        self.runner.assert_not_called()

    def test_prepare_checks_local_image_before_render_or_any_file_mutation(self):
        for image in ('', 'sha256:invalid', 'not-an-image'):
            with self.subTest(image=image):
                runner = Mock(return_value=image)
                with self.assertRaisesRegex(project.ProjectImageError, 'synology-cert-web:local'):
                    project.prepare_project(self.home, self.directory, 'cert-project', runner, self.uid)
                self.assertEqual(runner.call_count, 1)
                self.assertFalse(self.directory.exists())
                self.assertFalse((self.home / project.PROJECT_STATE).exists())
        runner = Mock(side_effect=RuntimeError('private-docker-error-details'))
        with self.assertRaises(project.ProjectImageError) as failure:
            project.prepare_project(self.home, self.directory, 'cert-project', runner, self.uid)
        self.assertEqual(str(failure.exception), project.IMAGE_ERROR)

    def test_capture_is_read_only_and_new_project_rollback_is_idempotent(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        self.assertEqual(sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')), before)
        with self.assertRaises(AttributeError):
            snapshot.name = 'changed'
        project.commit_project(self.home, prepared, self.uid)
        project.restore_project_state(self.home, snapshot, self.uid)
        project.restore_project_state(self.home, snapshot, self.uid)
        self.assertFalse(self.directory.exists())
        self.assertIsNone(project.load_project(self.home, self.uid))

    def test_rollback_restores_existing_project_bytes_and_permissions(self):
        descriptor = self.export('cert-project')
        state = self.home / project.PROJECT_STATE
        previous = {path: path.read_bytes() for path in (self.manifest_path(), state)}
        self.manifest['services']['certweb']['environment']['CERTWEB_PORT'] = '19443'
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        project.commit_project(self.home, prepared, self.uid)
        self.assertNotEqual(self.manifest_path().read_bytes(), previous[self.manifest_path()])
        project.restore_project_state(self.home, snapshot, self.uid)
        project.restore_project_state(self.home, snapshot, self.uid)
        self.assertEqual(project.load_project(self.home, self.uid), descriptor)
        for path, content in previous.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rollback_preserves_preexisting_empty_directory(self):
        self.directory.mkdir(mode=0o750)
        self.directory.chmod(0o750)
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        project.commit_project(self.home, prepared, self.uid)
        project.restore_project_state(self.home, snapshot, self.uid)
        self.assertTrue(self.directory.is_dir())
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o750)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_partial_metadata_commit_can_rollback_even_after_keyboard_interrupt(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        real_atomic = project._atomic
        def interrupt(path, content):
            if path.name == project.PROJECT_STATE:
                raise KeyboardInterrupt()
            real_atomic(path, content)
        with patch.object(project, '_atomic', side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            project.commit_project(self.home, prepared, self.uid)
        self.assertTrue(self.manifest_path().exists())
        self.assertFalse((self.home / project.PROJECT_STATE).exists())
        project.restore_project_state(self.home, snapshot, self.uid)
        self.assertFalse(self.directory.exists())
        self.assertIsNone(project.load_project(self.home, self.uid))

    def test_rollback_keeps_owned_file_from_preexisting_interrupted_export(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        self.directory.mkdir(mode=0o700)
        self.manifest_path().write_bytes(prepared[1])
        self.manifest_path().chmod(0o600)
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        project.commit_project(self.home, prepared, self.uid)
        project.restore_project_state(self.home, snapshot, self.uid)
        self.assertEqual(self.manifest_path().read_bytes(), prepared[1])
        self.assertFalse((self.home / project.PROJECT_STATE).exists())

    def test_rollback_does_not_remove_unrelated_file_added_to_new_directory(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        project.commit_project(self.home, prepared, self.uid)
        foreign = self.directory / 'keep.txt'
        foreign.write_text('keep')
        project.restore_project_state(self.home, snapshot, self.uid)
        self.assertEqual(foreign.read_text(), 'keep')
        self.assertFalse(self.manifest_path().exists())

    def test_rollback_refuses_foreign_manifest_or_metadata_before_any_mutation(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        snapshot = project.capture_project_state(self.home, prepared, self.uid)
        project.commit_project(self.home, prepared, self.uid)
        state = self.home / project.PROJECT_STATE
        original = {path: path.read_bytes() for path in (self.manifest_path(), state)}
        for path in original:
            with self.subTest(path=path):
                path.write_bytes(b'foreign-change')
                before = {value: value.read_bytes() for value in original}
                with self.assertRaises(ValueError):
                    project.restore_project_state(self.home, snapshot, self.uid)
                self.assertEqual({value: value.read_bytes() for value in original}, before)
                path.write_bytes(original[path])
        self.manifest_path().unlink()
        self.manifest_path().symlink_to(state)
        with self.assertRaises(ValueError):
            project.restore_project_state(self.home, snapshot, self.uid)
        self.assertEqual(state.read_bytes(), original[state])

    def test_commit_revalidates_foreign_changes_since_read_only_prepare(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        self.directory.mkdir(mode=0o700)
        foreign = self.directory / 'docker-compose.yml'
        foreign.write_text('foreign-project')
        foreign.chmod(0o600)
        with self.assertRaises(ValueError):
            project.commit_project(self.home, prepared, self.uid)
        self.assertEqual(foreign.read_text(), 'foreign-project')
        self.assertFalse((self.home / project.PROJECT_STATE).exists())

    def test_commit_rejects_modified_prepared_descriptor_or_content(self):
        prepared = project.prepare_project(self.home, self.directory, 'cert-project', self.runner, self.uid)
        wrong = dict(prepared[0], name='different-project')
        for value in ((wrong, prepared[1]), (prepared[0], b'broken-json'),
                      (dict(prepared[0], version=True), prepared[1])):
            with self.subTest(prepared=value), self.assertRaises(ValueError):
                project.commit_project(self.home, value, self.uid)
        self.assertFalse(self.directory.exists())
        self.assertFalse((self.home / project.PROJECT_STATE).exists())

    def test_legacy_deployment_without_metadata_is_unchanged(self):
        self.assertIsNone(project.load_project(self.home, self.uid))
        self.assertIsNone(project.refresh_project(self.home, self.runner, self.uid))
        self.runner.assert_not_called()

    def test_foreign_directory_and_project_file_are_preserved(self):
        self.directory.mkdir(mode=0o700)
        path = self.directory / 'docker-compose.yml'
        original = b'services: {foreign: {image: example:latest}}\n'
        path.write_bytes(original)
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.export()
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse((self.home / project.PROJECT_STATE).exists())
        self.runner.assert_not_called()

    def test_nonempty_destination_and_different_registered_project_are_rejected(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / 'foreign.txt').write_text('preserve')
        with self.assertRaises(ValueError):
            self.export()
        (self.directory / 'foreign.txt').unlink()
        descriptor = self.export()
        original = self.manifest_path().read_bytes()
        with self.assertRaises(ValueError):
            self.export('different-project')
        with self.assertRaises(ValueError):
            project.export_project(self.home, self.root / 'another', descriptor['name'], self.runner, self.uid)
        self.assertEqual(self.manifest_path().read_bytes(), original)

    def test_invalid_names_are_rejected_before_docker_or_file_mutation(self):
        for name in ('', 'BadName', '-project', '_project', 'project/name', 'a' * 65, True, None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.export(name)
        self.assertFalse(self.directory.exists())
        self.runner.assert_not_called()

    def test_project_location_cannot_overlap_runtime_or_native_directories(self):
        for directory in (self.home, self.root, self.home / 'code', self.home / 'code/project',
                          self.home / 'data', self.home / 'tls', self.home / 'bridge',
                          self.home / 'access', self.home / 'upgrades', self.native,
                          self.native / 'project', Path('relative-project')):
            with self.subTest(directory=directory), self.assertRaises(ValueError):
                project.export_project(self.home, directory, 'cert-project', self.runner, self.uid)
        self.runner.assert_not_called()

    def test_stable_dedicated_home_subdirectory_is_allowed(self):
        descriptor = project.export_project(self.home, self.home / 'container-project',
                                            'cert-project', self.runner, self.uid)
        self.assertEqual(project.load_project(self.home, self.uid), descriptor)

    def test_symbolic_project_or_metadata_paths_are_rejected(self):
        actual = self.root / 'actual'
        actual.mkdir(mode=0o700)
        self.directory.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.export()
        self.directory.unlink()
        state = self.home / project.PROJECT_STATE
        state.symlink_to(self.root / 'missing-state')
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.directory.exists())

    def test_unsafe_destination_owner_or_permissions_are_rejected(self):
        self.directory.mkdir(mode=0o777)
        self.directory.chmod(0o777)
        with self.assertRaises(ValueError):
            self.export()
        self.directory.chmod(0o700)
        with self.assertRaises(ValueError):
            project.export_project(self.home, self.directory, 'cert-project', self.runner, self.uid + 1)
        self.runner.assert_not_called()

    def test_metadata_manifest_tampering_and_nonprivate_files_are_rejected(self):
        self.export()
        state = self.home / project.PROJECT_STATE
        original_state, original_manifest = state.read_bytes(), self.manifest_path().read_bytes()
        for content in (b'broken-json', b'[]', b'{"version": true, "name": "x", "directory": "/tmp"}'):
            state.write_bytes(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                project.load_project(self.home, self.uid)
        state.write_bytes(original_state)
        content = json.loads(original_manifest)
        content[project.PROJECT_MARKER]['home'] = '/somebody/else'
        self.manifest_path().write_text(json.dumps(content))
        with self.assertRaises(ValueError):
            project.load_project(self.home, self.uid)
        self.manifest_path().write_bytes(original_manifest)
        broken = json.loads(original_manifest)
        broken['services']['certweb']['volumes'][0]['source'] = '/another/data'
        self.manifest_path().write_text(json.dumps(broken))
        with self.assertRaises(ValueError):
            project.load_project(self.home, self.uid)
        self.manifest_path().write_bytes(original_manifest)
        for path in (state, self.manifest_path()):
            path.chmod(0o644)
            with self.subTest(path=path), self.assertRaises(ValueError):
                project.load_project(self.home, self.uid)
            path.chmod(0o600)

    def test_hardlinked_project_file_is_rejected(self):
        self.export()
        os.link(str(self.manifest_path()), str(self.directory / 'hardlink'))
        with self.assertRaises(ValueError):
            project.load_project(self.home, self.uid)

    def test_relative_wrong_or_writable_secret_mounts_are_rejected(self):
        for patch_value in ({'source': 'relative-data'}, {'source': '/another/data'},
                            {'target': '/unknown'}, {'type': 'volume'}):
            manifest = copy.deepcopy(self.manifest)
            manifest['services']['certweb']['volumes'][0].update(patch_value)
            with self.subTest(patch=patch_value), self.assertRaises(ValueError):
                project.render_project(self.home, 'cert-project', Mock(return_value=json.dumps(manifest)))
        manifest = copy.deepcopy(self.manifest)
        manifest['services']['certweb']['volumes'][1]['read_only'] = False
        with self.assertRaises(ValueError):
            project.render_project(self.home, 'cert-project', Mock(return_value=json.dumps(manifest)))

    def test_manifest_cannot_relax_runtime_isolation_or_replace_entrypoint(self):
        original = self.export()
        content = json.loads(self.manifest_path().read_text())
        for field, value in (('network_mode', 'bridge'), ('user', '0:0'), ('read_only', False),
                             ('init', False), ('restart', 'always'), ('cap_drop', []),
                             ('security_opt', []), ('privileged', True), ('cap_add', ['SYS_ADMIN']),
                             ('entrypoint', ['sh']), ('command', ['sh']), ('group_add', ['0']),
                             ('use_api_socket', True)):
            with self.subTest(field=field):
                changed = copy.deepcopy(content)
                changed['services']['certweb'][field] = value
                self.manifest_path().write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    project.load_project(self.home, self.uid)
        self.manifest_path().write_text(json.dumps(content))
        self.assertEqual(project.load_project(self.home, self.uid), original)

    def test_readonly_mount_flags_must_be_actual_booleans(self):
        for index, value in ((0, 'false'), (1, 'true'), (2, 1), (3, 'false')):
            with self.subTest(index=index, value=value):
                content = copy.deepcopy(self.manifest)
                content['services']['certweb']['volumes'][index]['read_only'] = value
                with self.assertRaises(ValueError):
                    project.render_project(self.home, 'cert-project', Mock(return_value=json.dumps(content)))

    def test_malformed_unresolved_or_unexpected_config_is_rejected(self):
        for content in ('not-json', '[]', '{"services":{}}'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                project.render_project(self.home, 'cert-project', Mock(return_value=content))
        self.manifest['services']['certweb']['environment']['CERTWEB_BIND'] = '${UNRESOLVED}'
        with self.assertRaises(ValueError):
            project.render_project(self.home, 'cert-project', self.runner)
        self.assertFalse(self.directory.exists())

    def test_export_rejects_bare_dollar_interpolation_in_rendered_values(self):
        self.manifest['services']['certweb']['environment']['EXAMPLE'] = '$VALUE'
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.directory.exists())
        self.assertFalse((self.home / project.PROJECT_STATE).exists())

    def test_failed_render_does_not_create_project_or_leak_error_details(self):
        runner = Mock(side_effect=[self.image, RuntimeError('test-private-runtime-details')])
        with self.assertRaises(ValueError) as captured:
            project.export_project(self.home, self.directory, 'cert-project', runner, self.uid)
        self.assertEqual(str(captured.exception), project.ERROR)
        self.assertFalse(self.directory.exists())
        self.assertFalse((self.home / project.PROJECT_STATE).exists())

    def test_interrupted_metadata_commit_can_resume_owned_project_file(self):
        real_atomic = project._atomic
        def interrupt(path, content):
            if path.name == project.PROJECT_STATE:
                raise OSError('interrupted')
            real_atomic(path, content)
        with patch.object(project, '_atomic', side_effect=interrupt), self.assertRaises(ValueError):
            self.export()
        self.assertTrue(self.manifest_path().exists())
        self.assertFalse((self.home / project.PROJECT_STATE).exists())
        descriptor = self.export()
        self.assertEqual(project.load_project(self.home, self.uid), descriptor)


if __name__ == '__main__':
    unittest.main()
