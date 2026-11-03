import copy
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

from web.network_guard import NetworkGuard, GuardError, validate_network
from web import tls_sync, deployment, container_entry


class FirewallMemory:
    def __init__(self):
        self.rules = {4:[['-P','INPUT','ACCEPT'],['-N','INPUT_FIREWALL'],['-A','INPUT','-j','INPUT_FIREWALL']],
                      6:[['-P','INPUT','ACCEPT']]}
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        version = 6 if 'ip6tables' in command[0] else 4
        args = command[3:]
        rules = self.rules[version]
        if args == ['-S']:
            return '\n'.join(shlex.join(rule) for rule in rules)
        if args[0] == '-N':
            rules.append(args)
        elif args[0] == '-F':
            rules[:] = [r for r in rules if r[:2] != ['-A',args[1]]]
        elif args[0] == '-A':
            rules.append(args)
        elif args[0] == '-I':
            index=next((i for i,r in enumerate(rules) if r[:2]==['-A',args[1]]),len(rules))
            rules.insert(index,['-A',args[1]]+args[3:])
        elif args[0] == '-D':
            rules.remove(['-A']+args[1:])
        else:
            raise AssertionError(command)
        return ''


class NetworkBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.firewall=FirewallMemory()
        self.guard=NetworkGuard('10.10.10.37',['10.10.10.0/24'],['10.10.10.1'],18443,run=self.firewall)

    def test_requires_narrow_lan_and_excludes_gateway_not_nas(self):
        for bind,networks,denied in [('0.0.0.0',['10.10.10.0/24'],['10.10.10.1']),('10.10.10.37',['0.0.0.0/0'],['10.10.10.1']),('10.10.10.37',['10.0.0.0/8'],['10.10.10.1']),('10.10.10.37',['10.10.10.0/24'],[]),('10.10.10.37',['10.10.10.0/24'],['10.10.10.37']),('10.10.10.37',['10.10.10.0/24'],['10.2.0.1'])]:
            with self.subTest(bind=bind,networks=networks,denied=denied),self.assertRaises(ValueError):
                validate_network(bind,networks,denied,18443)

    def test_install_preserves_dsm_rules_and_blocks_ipv6(self):
        self.assertFalse(self.guard.valid())
        self.guard.install()
        self.assertTrue(self.guard.valid())
        self.assertIn(['-A','INPUT','-j','INPUT_FIREWALL'],self.firewall.rules[4])
        self.assertIn(['-N','INPUT_FIREWALL'],self.firewall.rules[4])
        _,_,rules=self.guard.desired(6)
        self.assertEqual(rules,[['-A','CERTWEB6_INPUT','-j','DROP']])
        _,_,rules=self.guard.desired(4)
        self.assertEqual(rules[0],['-A','CERTWEB_INPUT','-s','10.10.10.1/32','-j','DROP'])
        self.assertEqual(rules[-1],['-A','CERTWEB_INPUT','-j','DROP'])

    def test_reordered_or_flushed_rules_are_not_considered_safe(self):
        self.guard.install()
        self.firewall.rules[4].insert(0,['-A','INPUT_FIREWALL','-j','ACCEPT'])
        self.assertFalse(self.guard.valid())
        self.guard.install()
        self.assertTrue(self.guard.valid())
        self.firewall.rules[6]=[['-P','INPUT','ACCEPT']]
        self.assertFalse(self.guard.valid())

    def test_dsm_hook_precedes_existing_accept_and_removes_legacy_jump(self):
        self.firewall.rules[4] += [['-A','INPUT_FIREWALL','-j','ACCEPT'],['-N','DEFAULT_INPUT'],
                                  ['-A','INPUT','-j','DEFAULT_INPUT'],['-A','DEFAULT_INPUT','-p','tcp','-j','CERTWEB_INPUT']]
        self.guard.install()
        self.assertTrue(self.guard.valid())
        hook=[r for r in self.firewall.rules[4] if r[:2]==['-A','INPUT_FIREWALL']]
        self.assertEqual(hook[0][-2:],['-j','CERTWEB_INPUT'])
        self.assertEqual(hook[-1],['-A','INPUT_FIREWALL','-j','ACCEPT'])
        self.assertFalse(any(r[:2]==['-A','DEFAULT_INPUT'] and r[-1]=='CERTWEB_INPUT' for r in self.firewall.rules[4]))

    def test_unknown_dsm_entry_cannot_be_silently_bypassed(self):
        self.firewall.rules[4].insert(0,['-A','INPUT','-j','ACCEPT'])
        self.assertFalse(self.guard.valid())
        with self.assertRaises(GuardError):self.guard.install()

    def test_reinstallation_has_no_duplicate_jump_and_no_global_flush(self):
        self.guard.install()
        original=copy.deepcopy(self.firewall.rules)
        self.guard.install()
        self.assertEqual(original,self.firewall.rules)
        for args in self.firewall.calls:
            if '-F' in args:
                self.assertEqual(len(args),5)
                self.assertIn(args[-1],['CERTWEB_INPUT','CERTWEB6_INPUT'])

    def test_readback_failure_does_not_claim_success(self):
        with patch.object(self.guard,'valid',return_value=False),self.assertRaises(GuardError):
            self.guard.install()

    def test_public_mode_removes_lan_source_filters_and_preserves_ipv6_block(self):
        self.guard.install()
        self.guard.access_mode='public'
        self.assertFalse(self.guard.valid())
        self.guard.install()
        self.assertTrue(self.guard.valid())
        self.assertEqual([r for r in self.firewall.rules[4] if r[:2]==['-A','CERTWEB_INPUT']],
                         [['-A','CERTWEB_INPUT','-j','ACCEPT']])
        self.assertEqual([r for r in self.firewall.rules[6] if r[:2]==['-A','CERTWEB6_INPUT']],
                         [['-A','CERTWEB6_INPUT','-j','DROP']])
        self.guard.access_mode='lan'
        self.assertFalse(self.guard.valid())
        self.guard.install()
        self.assertTrue(self.guard.valid())
        self.assertIn(['-A','CERTWEB_INPUT','-s','10.10.10.1/32','-j','DROP'],self.firewall.rules[4])

    def test_invalid_access_mode_never_modifies_firewall(self):
        self.guard.access_mode='anything'
        with self.assertRaises(GuardError):self.guard.install()
        self.assertTrue(all(c[3:]==['-S'] for c in self.firewall.calls))


class TLSSynchronizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated=tempfile.TemporaryDirectory()
        cls.fixture=Path(cls.generated.name)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=ttxli.cn','-addext','subjectAltName=DNS:ttxli.cn','-keyout',str(cls.fixture/'privkey.pem'),'-out',str(cls.fixture/'fullchain.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.generated.cleanup()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.home=self.root/'native';self.home.mkdir();(self.home/'state').mkdir()
        (self.home/'config.json').write_text(json.dumps({'certificate_id':'target'}))
        self.archive=self.root/'archive';self.source=self.archive/'target';self.source.mkdir(parents=True)
        for name in ['privkey.pem','fullchain.pem']:shutil.copy2(str(self.fixture/name),str(self.source/name))
        self.tls=self.root/'tls';self.tls.mkdir()
        self.chown=patch('web.tls_sync.os.chown');self.chown.start();self.addCleanup(self.chown.stop)
        trust=patch.dict(os.environ,{'SSL_CERT_FILE':str(self.fixture/'fullchain.pem')})
        trust.start();self.addCleanup(trust.stop)

    def sync(self,hostname='ttxli.cn'):
        return tls_sync.sync_tls(self.home,self.tls,hostname,archive=self.archive)

    def test_private_umask_preserves_container_read_permissions(self):
        previous=os.umask(0o077)
        try:self.assertTrue(self.sync())
        finally:os.umask(previous)
        self.assertEqual((self.tls/'versions').stat().st_mode&0o777,0o750)
        for name in ['current.cert','current.key']:
            path=(self.tls/name).resolve()
            self.assertEqual(path.stat().st_mode&0o777,0o640)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o750)
        self.assertFalse(self.sync())

    def test_interrupted_alias_creation_is_repaired_next_time(self):
        self.sync()
        (self.tls/'current.cert').unlink()
        (self.tls/'current.key').unlink()
        self.assertFalse(self.sync())
        self.assertTrue((self.tls/'current.cert').is_file())
        self.assertTrue((self.tls/'current.key').is_file())

    def test_cached_material_rechecks_hostname_and_integrity(self):
        self.sync()
        with self.assertRaises(ValueError):self.sync('wrong.example.test')
        (self.tls/'current.cert').resolve().write_text('not a certificate')
        with self.assertRaises(ValueError):self.sync()

    def test_invalid_or_mismatched_new_material_preserves_current(self):
        self.sync();before=os.readlink(str(self.tls/'current'))
        (self.source/'privkey.pem').write_text('invalid private key')
        with self.assertRaises(Exception):self.sync()
        self.assertEqual(os.readlink(str(self.tls/'current')),before)

    def test_native_running_lock_prevents_partial_certificate_copy(self):
        with tls_sync.native_lock(self.home),self.assertRaises(tls_sync.TLSBusy):self.sync()
        self.assertFalse((self.tls/'current').exists())

    def test_archive_traversal_and_symlink_rejected(self):
        (self.home/'config.json').write_text(json.dumps({'certificate_id':'../target'}))
        with self.assertRaises(ValueError):self.sync()
        (self.home/'config.json').write_text(json.dumps({'certificate_id':'target'}))
        path=self.source/'fullchain.pem';path.unlink();path.symlink_to(self.fixture/'fullchain.pem')
        with self.assertRaises(OSError):self.sync()


class DeploymentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.config={'home':str(self.home),'native_home':str(self.home/'native'),'bind':'10.10.10.37','networks':['10.10.10.0/24'],'denied':['10.10.10.1'],'port':18443,'origin':'https://ttxli.cn:18443','hostname':'ttxli.cn'}
        self.service=deployment.Deployment(self.config,self.home/'deployment.json')

    def test_bridge_receives_configured_task_id_and_legacy_defaults_to_seven(self):
        for configured, expected in ((None, '7'), (31, '31')):
            if configured is None:
                self.service.config.pop('task_id', None)
            else:
                self.service.config['task_id'] = configured
            self.service.bridge = None
            with patch('web.deployment.subprocess.Popen') as spawn:
                self.service.start_bridge()
            command = spawn.call_args.args[0]
            self.assertEqual(command[command.index('--task-id') + 1], expected)

    def test_deployment_config_accepts_dynamic_id_and_defaults_legacy_to_seven(self):
        home = self.home.resolve();native = home / 'native';native.mkdir(mode=0o700)
        path = home / 'deployment.json'
        config = {key: value for key, value in self.config.items() if key != 'hostname'}
        config.update(home=str(home), native_home=str(native))
        original_stat = Path.stat
        def root_stat(path, **kwargs):
            value = list(original_stat(path, **kwargs));value[4] = 0
            return os.stat_result(value)
        for identifier, expected in ((None, 7), (31, 31), (False, None), (0, None)):
            if identifier is None:config.pop('task_id', None)
            else:config['task_id'] = identifier
            path.write_text(json.dumps(config));path.chmod(0o600)
            with patch.object(Path, 'stat', autospec=True, side_effect=root_stat):
                if expected is None:
                    with self.assertRaises(ValueError):deployment.load_config(path)
                else:
                    self.assertEqual(deployment.load_config(path)['task_id'], expected)

    def test_task_identifier_and_management_origin_are_validated(self):
        self.assertEqual(deployment.validate_task_id(31), 31)
        for value in (0, -1, True, '31', 1.1, 2 ** 31):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deployment.validate_task_id(value)
        self.assertEqual(deployment.validate_origin('https://nas.example.com:18443', 18443),
                         ('nas.example.com:18443', 'nas.example.com'))
        for value in ('http://nas.example.com:18443', 'https://10.0.0.1:18443',
                      'https://nas.example.com:18443/path', 'https://user@nas.example.com:18443'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deployment.validate_origin(value, 18443)

    def test_failed_docker_stop_requires_verified_emergency_shutdown(self):
        self.service.container=Mock(return_value={'State':{'Running':True}})
        self.service.command=Mock(side_effect=RuntimeError('failed'))
        with patch.object(self.service,'emergency_stop',return_value=False),self.assertRaises(RuntimeError):
            self.service.stop_container()
        with patch.object(self.service,'emergency_stop',return_value=True):self.service.stop_container()

    def test_unknown_or_reused_pid_never_killed(self):
        self.service.last_container={'Id':'a'*64,'State':{'Pid':23456}}
        with patch('web.deployment.Path.read_text',return_value='another-container'),patch('web.deployment.Path.exists',return_value=True),patch('web.deployment.os.kill') as kill:
            self.assertFalse(self.service.emergency_stop());kill.assert_not_called()

    def test_shutdown_requires_container_cgroup_identity(self):
        self.service.last_container={'Id':'a'*64,'State':{'Pid':23456}}
        with patch('web.deployment.Path.read_text',side_effect=['0::/docker/'+'a'*64,FileNotFoundError()]),patch('web.deployment.os.kill') as kill:
            self.assertTrue(self.service.emergency_stop());kill.assert_called_once()

    def test_runtime_never_starts_container_after_firewall_error(self):
        self.service.guard.valid=Mock(side_effect=GuardError('failure'))
        self.service.stop_container=Mock()
        self.service.compose=Mock()
        self.service.log=Mock(side_effect=lambda *_:setattr(self.service,'stopping',True))
        with patch('web.deployment.read_policy',return_value={'mode':'lan','revision':'a'*32}):
            self.service.serve()
        self.service.compose.assert_not_called()
        self.service.stop_container.assert_called()

    def test_access_mode_applied_only_after_container_stop_and_rule_validation(self):
        events=[]
        policy={'mode':'public','revision':'a'*32}
        self.service.guard.valid=Mock(return_value=False)
        self.service.stop_container=Mock(side_effect=lambda:events.append('stop'))
        self.service.guard.install=Mock(side_effect=lambda:events.append('rules'))
        with patch('web.deployment.read_policy',return_value=policy),patch('web.deployment.write_applied',side_effect=lambda *_:events.append('applied')):
            self.assertEqual(self.service.apply_access_policy(),policy)
        self.assertEqual(events,['stop','rules','applied'])
        self.assertEqual(self.service.guard.access_mode,'public')

    def test_failed_rules_do_not_claim_new_mode_applied(self):
        self.service.guard.valid=Mock(return_value=False)
        self.service.stop_container=Mock()
        self.service.guard.install=Mock(side_effect=GuardError('failed'))
        with patch('web.deployment.read_policy',return_value={'mode':'public','revision':'a'*32}),patch('web.deployment.write_applied') as applied,self.assertRaises(GuardError):
            self.service.apply_access_policy()
        applied.assert_not_called()

    def test_missing_policy_keeps_container_closed(self):
        self.service.stop_container=Mock()
        self.service.compose=Mock()
        self.service.log=Mock(side_effect=lambda *_:setattr(self.service,'stopping',True))
        with patch('web.deployment.read_policy',side_effect=FileNotFoundError):
            self.service.serve()
        self.service.compose.assert_not_called()
        self.service.stop_container.assert_called()

    def test_final_shutdown_failure_preserves_blocked_state_and_returns_failure(self):
        self.service.stopping=True
        self.service.stop_container=Mock(side_effect=RuntimeError('container still running'))
        with patch('web.deployment.signal.signal'),patch('builtins.print'):
            self.assertEqual(self.service.serve(),1)
        state=json.loads((self.home/'deployment-state.json').read_text())
        self.assertEqual(state['status'],'blocked')
        self.assertIn('无法确认管理容器已关闭',state['message'])
        self.assertFalse((self.home/'supervisor.pid').exists())

    def test_stop_command_rechecks_container_after_supervisor_exits(self):
        (self.home/'supervisor.pid').write_text(json.dumps({'pid':23456}))
        self.service.stop_container=Mock(side_effect=RuntimeError('container still running'))
        self.service.log=Mock()
        with patch('web.deployment.os.geteuid',return_value=0),patch('web.deployment.os.umask'),patch('web.deployment.load_config',return_value=self.config),patch('web.deployment.process_matches',side_effect=[True,False]),patch('web.deployment.os.kill') as kill,patch('web.deployment.Deployment',return_value=self.service),patch('sys.stderr'):
            self.assertEqual(deployment.main(['--config',str(self.home/'deployment.json'),'stop']),1)
        kill.assert_called_once_with(23456,deployment.signal.SIGTERM)
        self.service.stop_container.assert_called_once()
        self.service.log.assert_not_called()

    def test_monitor_is_separate_child_with_fixed_task_and_no_wait_on_start(self):
        (self.home / 'code').mkdir(); (self.home / 'code/monitor.py').write_text('')
        child = Mock(); child.poll.return_value = None
        self.service.config['task_id'] = 31
        with patch('web.deployment.subprocess.Popen', return_value=child) as spawn:
            self.service.start_monitor(); self.service.start_monitor()
        spawn.assert_called_once()
        command = spawn.call_args.args[0]
        self.assertEqual(command[command.index('--task-id') + 1], '31')
        self.assertEqual(command[command.index('--parent-pid') + 1], str(os.getpid()))
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        child.wait.assert_not_called(); child.communicate.assert_not_called()

    def test_failed_monitor_spawn_is_bounded_and_does_not_stop_service(self):
        (self.home / 'code').mkdir(); (self.home / 'code/monitor.py').write_text('')
        current = [0]; self.service.clock = lambda: current[0]
        self.service.stop_container = Mock()
        with patch('web.deployment.subprocess.Popen', side_effect=OSError('private detail')) as spawn:
            self.service.start_monitor(); self.service.start_monitor()
            current[0] = 59; self.service.start_monitor()
            self.assertEqual(spawn.call_count, 1)
            current[0] = 60; self.service.start_monitor()
            self.assertEqual(spawn.call_count, 2)
        self.service.stop_container.assert_not_called()

    def test_shutdown_stops_container_before_waiting_on_monitor(self):
        self.service.stopping = True
        events = []
        self.service.stop_container = Mock(side_effect=lambda: events.append('container'))
        self.service.stop_startup_check = Mock(side_effect=lambda: events.append('startup'))
        self.service.stop_schedule_sync = Mock(side_effect=lambda: events.append('schedule'))
        self.service.stop_monitor = Mock(side_effect=lambda: events.append('monitor'))
        with patch('web.deployment.signal.signal'), patch('builtins.print'):
            self.service.serve()
        self.assertEqual(events, ['container', 'schedule', 'startup', 'monitor'])

    def test_monitor_shutdown_kills_child_after_bounded_timeout(self):
        child = Mock(); child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('monitor', 15), 0]
        self.service.monitor = child; self.service.stop_monitor()
        child.terminate.assert_called_once(); child.kill.assert_called_once()
        self.assertEqual([call.kwargs['timeout'] for call in child.wait.call_args_list], [15, 5])

    def test_deployment_events_are_bounded_deduplicated_and_latest_first(self):
        self.service.phase = 'docker'
        with patch('builtins.print'):
            for index in range(110):
                self.service.log('waiting', '固定状态 {}'.format(index))
            self.service.log('waiting', '固定状态 109')
        data = json.loads((self.home / 'deployment-events.json').read_text())
        self.assertEqual(len(data['items']), 100)
        self.assertEqual(data['items'][0]['message'], '固定状态 109')
        self.assertEqual(data['items'][0]['category'], 'fault')
        self.assertEqual(set(data['items'][0]), {'at', 'category', 'status', 'stage', 'message'})

    def test_upgrade_maintenance_requires_live_lock_not_stale_journal_or_exit_zero(self):
        self.service.phase = 'shutdown'
        deployment.health_monitor.write_json(self.home / 'upgrade-state.json',
                                            {'version': 1, 'phase': 'prepared', 'work': 'upgrade-' + 'a' * 32}, os.geteuid())
        self.service.record_event('stopped', '固定停止摘要')
        data = json.loads((self.home / 'deployment-events.json').read_text())
        self.assertEqual(data['items'][0]['category'], 'info')
        with deployment.health_monitor.locked(self.home / 'upgrade.lock', os.geteuid()):
            self.service.record_event('stopping', '固定维护摘要')
        data = json.loads((self.home / 'deployment-events.json').read_text())
        self.assertEqual(data['items'][0]['category'], 'maintenance')
        with deployment.health_monitor.locked(self.home / 'upgrade.lock', os.geteuid()):
            self.service.record_event('stopped', '维护停服已确认')
        data = json.loads((self.home / 'deployment-events.json').read_text())
        self.assertEqual(data['items'][0]['category'], 'maintenance')
        with deployment.health_monitor.locked(self.home / 'upgrade.lock', os.geteuid()):
            self.service.record_event('blocked', '维护停服无法确认')
        data = json.loads((self.home / 'deployment-events.json').read_text())
        self.assertEqual(data['items'][0]['category'], 'fault')
        with deployment.health_monitor.locked(self.home / 'upgrade.lock', os.geteuid()):
            self.service.phase = 'docker'
            self.service.record_event('waiting', '固定非维护摘要')
        data = json.loads((self.home / 'deployment-events.json').read_text())
        self.assertEqual(data['items'][0]['category'], 'fault')

    def test_corrupt_events_do_not_break_reporting_or_stop_safety(self):
        deployment.health_monitor.write_json(self.home / 'deployment-events.json', {'version': 1, 'items': [None]}, os.geteuid())
        self.service.phase = 'policy'
        with patch('builtins.print'):
            self.assertTrue(self.service.report('stopping', '固定安全摘要'))


class StartupStabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        (self.home / 'data').mkdir();(self.home / 'data/auth.sqlite3').write_bytes(b'configured')
        (self.home / 'tls').mkdir();(self.home / 'tls/current.cert').write_bytes(b'previously-validated')
        self.now, self.running = 0, False
        config = {'home': str(self.home), 'native_home': str(self.home / 'native'), 'bind': '10.10.10.37',
                  'networks': ['10.10.10.0/24'], 'denied': ['10.10.10.1'], 'port': 18443,
                  'origin': 'https://nas.example.com:18443', 'hostname': 'nas.example.com'}
        self.service = deployment.Deployment(config, self.home / 'deployment.json', clock=lambda: self.now)
        self.service.guard.valid = Mock(return_value=True)
        self.service.guard.install = Mock(side_effect=lambda: setattr(self.service.guard.valid, 'return_value', True))
        self.service.start_bridge = Mock()
        self.service.bridge_ready = Mock(return_value=True)
        self.service.container = Mock(side_effect=lambda: {'State': {'Running': self.running, 'Restarting': False}})
        self.service.compose = Mock(side_effect=lambda *_: setattr(self, 'running', True))
        def stop():
            self.running = False;self.service.started = False;self.service.ready_since = None
        self.service.stop_container = Mock(side_effect=stop)
        self.events = []
        original_log = self.service.log
        def log(status, message):
            self.events.append((self.service.phase, status, message));original_log(status, message)
        self.service.log = log
        self.policy = {'mode': 'lan', 'revision': 'a' * 32}
        self.sync = Mock(return_value=False)
        for patcher in (patch('web.deployment.read_policy', side_effect=lambda _: dict(self.policy)),
                        patch('web.deployment.write_applied'), patch('web.deployment.sync_tls', self.sync),
                        patch('builtins.print')):
            patcher.start();self.addCleanup(patcher.stop)

    def tick(self, when):
        self.now = when;self.service.reconcile()

    def test_start_requires_full_continuous_sixty_seconds(self):
        self.tick(0);self.tick(59)
        self.service.compose.assert_not_called()
        self.tick(60)
        self.service.compose.assert_called_once_with('up', '-d', '--no-build')
        self.assertTrue(self.running)
        self.assertEqual(json.loads((self.home / 'deployment-state.json').read_text())['stage'], 'running')

    def test_rule_repair_resets_window_and_records_stop_reason(self):
        self.tick(0)
        self.service.guard.valid.return_value = False
        self.tick(50)
        self.assertEqual(self.service.ready_since, 50)
        self.service.stop_container.assert_called_once()
        self.assertTrue(any(stage == 'policy' and status == 'stopping' and '防火墙规则变化' in message
                            for stage, status, message in self.events))
        self.tick(100);self.service.compose.assert_not_called()
        self.tick(110);self.service.compose.assert_called_once()

    def test_revision_change_restarts_wait_without_stopping_an_already_running_service(self):
        self.tick(0);self.policy['revision'] = 'b' * 32;self.tick(40)
        self.tick(99);self.service.compose.assert_not_called()
        self.tick(100);self.assertTrue(self.running)
        self.policy['revision'] = 'c' * 32;self.tick(110)
        self.service.stop_container.assert_not_called()
        self.assertTrue(self.running)
        self.assertEqual(self.service.compose.call_count, 1)

    def test_bridge_flapping_cannot_accumulate_short_ready_periods(self):
        self.tick(0);self.service.bridge_ready.return_value = False;self.tick(50)
        self.assertIsNone(self.service.ready_since)
        self.service.bridge_ready.return_value = True;self.tick(70);self.tick(120)
        self.service.compose.assert_not_called()
        self.tick(130);self.service.compose.assert_called_once()

    def test_bridge_rebuild_resets_window_and_logs_why_container_is_stopped(self):
        self.tick(0)
        previous = Mock();previous.poll.return_value = 1
        replacement = Mock();replacement.poll.return_value = None
        self.service.bridge = previous
        self.service.start_bridge = deployment.Deployment.start_bridge.__get__(self.service)
        with patch('web.deployment.subprocess.Popen', return_value=replacement):
            self.tick(50)
        self.assertEqual(self.service.ready_since, 50)
        self.service.stop_container.assert_called_once()
        self.assertTrue(any(stage == 'bridge' and '桥接进程已退出' in message for stage, _, message in self.events))
        self.tick(100);self.service.compose.assert_not_called()
        self.tick(110);self.service.compose.assert_called_once()

    def test_tls_busy_blocks_start_clock_but_does_not_interrupt_existing_container(self):
        self.tick(0);self.sync.side_effect = deployment.TLSBusy;self.tick(50)
        self.assertIsNone(self.service.ready_since)
        self.sync.side_effect = None;self.tick(60);self.tick(119)
        self.service.compose.assert_not_called()
        self.tick(120);self.assertTrue(self.running)
        self.sync.side_effect = deployment.TLSBusy;self.tick(130)
        self.assertTrue(self.running);self.service.stop_container.assert_not_called()

    def test_tls_material_change_resets_the_window(self):
        self.tick(0);self.sync.return_value = True;self.tick(50)
        self.sync.return_value = False;self.tick(100)
        self.service.compose.assert_not_called()
        self.tick(110);self.service.compose.assert_called_once()

    def test_existing_running_container_is_not_restarted_for_stability_wait(self):
        self.running = True;self.tick(0);self.tick(10)
        self.service.stop_container.assert_not_called();self.service.compose.assert_not_called()
        self.assertTrue(self.service.started)
        self.assertIsNone(self.service.ready_since)

    def test_health_snapshot_has_only_safe_container_fields(self):
        self.service.container.side_effect = None
        self.service.container.return_value = {'RestartCount': 3, 'Config': {'Env': ['SECRET=value']},
            'State': {'Running': True, 'Restarting': False, 'OOMKilled': True,
                      'StartedAt': '2026-11-01T00:00:00.123456789Z', 'Health': {'Status': 'healthy', 'Log': ['PRIVATE_LOG']},
                      'Error': 'PRIVATE_ERROR'}}
        self.tick(0)
        data = json.loads((self.home / 'runtime-health.json').read_text())
        self.assertEqual(data['container']['restart_count'], 3)
        self.assertTrue(data['container']['oom_killed'])
        self.assertEqual(data['container']['health'], 'healthy')
        self.assertEqual({item['key'] for item in data['components']}, {'container', 'bridge', 'tls', 'access', 'monitor'})
        self.assertNotIn('PRIVATE', json.dumps(data)); self.assertNotIn('SECRET', json.dumps(data))

    def test_health_snapshot_failure_cannot_interrupt_firewall_protection(self):
        self.running = True; self.service.guard.valid.return_value = False
        with patch('web.deployment.health_monitor.write_json', side_effect=OSError('disk full')):
            self.tick(0)
        self.service.stop_container.assert_called_once()
        self.assertFalse(self.running)

    def test_start_failure_consumes_window_and_errors_are_fixed_safe_text(self):
        self.tick(0)
        self.service.compose.side_effect = RuntimeError('DO_NOT_LOG_PASSWORD')
        self.tick(60)
        self.assertIsNone(self.service.ready_since)
        state = json.loads((self.home / 'deployment-state.json').read_text())
        self.assertEqual((state['status'], state['stage']), ('blocked', 'start'))
        self.assertNotIn('DO_NOT_LOG_PASSWORD', str(self.events) + str(state))
        self.service.compose.side_effect = lambda *_: setattr(self, 'running', True)
        self.tick(70);self.tick(129)
        self.assertEqual(self.service.compose.call_count, 1)
        self.tick(130);self.assertEqual(self.service.compose.call_count, 2)

    def test_immediate_exit_after_compose_is_not_reported_running_or_immediately_restarted(self):
        self.service.compose.side_effect = None
        self.tick(0);self.tick(60)
        self.assertFalse(self.running)
        self.assertEqual(json.loads((self.home / 'deployment-state.json').read_text())['status'], 'blocked')
        self.tick(70);self.tick(129)
        self.assertEqual(self.service.compose.call_count, 1)

    def test_docker_failure_resets_ready_time_and_records_stage(self):
        self.tick(0)
        self.service.container.side_effect = RuntimeError('DO_NOT_LOG_DOCKER_DETAIL')
        self.tick(50)
        state = json.loads((self.home / 'deployment-state.json').read_text())
        self.assertEqual((state['stage'], state['status']), ('docker', 'blocked'))
        self.assertNotIn('DO_NOT_LOG_DOCKER_DETAIL', str(self.events) + str(state))
        self.service.container.side_effect = lambda: {'State': {'Running': self.running, 'Restarting': False}}
        self.tick(60);self.tick(119);self.service.compose.assert_not_called()
        self.tick(120);self.service.compose.assert_called_once()

    def test_observed_container_exit_requires_a_new_full_window(self):
        self.tick(0);self.tick(60);self.tick(70)
        self.running = False;self.tick(100);self.tick(159)
        self.assertEqual(self.service.compose.call_count, 1)
        self.assertTrue(any('管理容器已退出' in message for _, _, message in self.events))
        self.tick(160);self.assertEqual(self.service.compose.call_count, 2)

    def test_log_state_write_failure_cannot_prevent_firewall_safety_stop(self):
        self.running = True;self.service.guard.valid.return_value = False
        with patch('web.deployment.private_json', side_effect=OSError('disk-full-detail')):
            self.tick(0)
        self.service.stop_container.assert_called_once()
        self.assertFalse(self.running);self.assertIsNone(self.service.ready_since)
        self.service.compose.assert_not_called()
        self.assertNotIn('disk-full-detail', str(self.events))

    def test_broken_logging_does_not_skip_exception_or_shutdown_stop(self):
        self.service.log = Mock(side_effect=BrokenPipeError('closed-output-detail'))
        self.service.guard.valid.side_effect = GuardError('private-error-detail')
        self.tick(0)
        self.service.stop_container.assert_called_once()
        self.service.stop_container.reset_mock();self.service.stopping = True
        with patch('web.deployment.signal.signal'):
            self.assertEqual(self.service.serve(), 0)
        self.service.stop_container.assert_called_once()
        self.assertFalse((self.home / 'supervisor.pid').exists())

    def test_bridge_rebuild_stops_even_if_reason_cannot_be_logged(self):
        self.service.log = Mock(side_effect=OSError('disk full'))
        previous = Mock();previous.poll.return_value = 1
        replacement = Mock();replacement.poll.return_value = None
        self.service.bridge = previous
        with patch('web.deployment.subprocess.Popen', return_value=replacement):
            deployment.Deployment.start_bridge(self.service)
        self.service.stop_container.assert_called_once()
        self.assertIs(self.service.bridge, replacement)

    def test_shutdown_requested_during_checks_never_starts_container(self):
        self.tick(0)
        def stop_requested():
            self.service.stopping = True
            return {'State': {'Running': False, 'Restarting': False}}
        self.service.container.side_effect = stop_requested
        self.tick(60)
        self.service.compose.assert_not_called()

    def test_cannot_start_if_starting_log_fails(self):
        self.tick(0)
        self.service.log = Mock(side_effect=OSError('disk full'))
        self.tick(60)
        self.service.compose.assert_not_called();self.assertIsNone(self.service.ready_since)

    def test_waiting_loop_keeps_polling_delay(self):
        calls = []
        def reconcile():
            calls.append(True)
            if len(calls) == 2:self.service.stopping = True
        self.service.reconcile = reconcile
        with patch('web.deployment.signal.signal'), patch('web.deployment.time.sleep') as sleep:
            self.assertEqual(self.service.serve(), 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleep.call_count, 10)

    def test_startup_renewal_is_dispatched_before_expired_tls_blocks_container(self):
        (self.home / 'code').mkdir(); (self.home / 'code/startup_check.py').write_text('')
        self.sync.side_effect = ValueError('expired certificate')
        child = Mock(); child.poll.return_value = None
        original = self.service.reconcile
        def reconcile_once():
            self.assertIs(self.service.startup_check, child)
            original()
            self.service.stopping = True
        self.service.reconcile = reconcile_once
        with patch('web.deployment.subprocess.Popen', return_value=child) as spawn, patch('web.deployment.signal.signal'):
            self.assertEqual(self.service.serve(), 0)
        spawn.assert_called_once()
        self.service.compose.assert_not_called()
        self.assertTrue(any(stage == 'tls' and status == 'blocked' for stage, status, _ in self.events))


class StartupRenewalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.code = self.home / 'code'; self.code.mkdir()
        self.script = self.code / 'startup_check.py'; self.script.write_text('')
        self.now = 0
        config = {'home': str(self.home), 'native_home': str(self.home / 'native'), 'task_id': 31,
                  'bind': '10.10.10.37', 'networks': ['10.10.10.0/24'], 'denied': ['10.10.10.1'], 'port': 18443}
        self.service = deployment.Deployment(config, self.home / 'deployment.json', clock=lambda: self.now)
        self.service.phase = 'running'
        self.service.health = dict.fromkeys(('bridge', 'tls', 'access'), 'ok')
        self.initial = ('c' * 64, '2026-11-03T07:16:58.108106+00:00')
        self.service.startup_requested_generation = self.initial
        self.item = {'Id': 'a' * 64, 'State': {'Running': True, 'Restarting': False,
                     'StartedAt': '2026-11-03T07:17:58.108106777Z', 'Health': {'Status': 'healthy'}}}
        self.service.observed_container = self.item
        self.child = Mock(); self.child.poll.return_value = None
        patcher = patch('web.deployment.subprocess.Popen', return_value=self.child)
        self.spawn = patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch('builtins.print'); patcher.start(); self.addCleanup(patcher.stop)

    def tick(self, when):
        self.now = when; self.service.start_startup_check()

    def test_one_child_for_supervisor_generation_and_first_container_baseline(self):
        self.tick(0); self.tick(10)
        self.spawn.assert_called_once()
        command = self.spawn.call_args.args[0]
        self.assertEqual(command, [deployment.sys.executable, '-I', str(self.script),
            '--native-home', str(self.home / 'native'), '--web-home', str(self.home),
            '--task-id', '31', '--generation-id', self.initial[0], '--started-at', self.initial[1]])
        self.assertTrue(self.spawn.call_args.kwargs['start_new_session'])
        self.child.wait.assert_not_called(); self.child.communicate.assert_not_called()
        self.child.poll.return_value = 0
        self.tick(20); self.tick(100)
        self.spawn.assert_called_once()

    def test_initial_check_does_not_depend_on_https_or_container_health(self):
        self.service.phase = 'tls'
        self.service.health = {'tls': 'error'}
        self.service.observed_container = None
        self.tick(0)
        self.spawn.assert_called_once()
        self.child.poll.return_value = 0; self.tick(10)
        self.service.observed_container = self.item
        self.item['State']['Health']['Status'] = 'starting'; self.tick(20)
        self.item['State']['Health']['Status'] = 'healthy'; self.tick(30)
        self.spawn.assert_called_once()

    def test_invalid_container_generations_do_not_override_initial_startup(self):
        for item in (None, {}, {'State': None}, {'Id': '../secret', 'State': self.item['State']},
                     {'Id': 'a' * 64, 'State': dict(self.item['State'], StartedAt=None)}):
            self.service.observed_container = item; self.tick(0)
        self.assertIsNone(self.service.startup_container_generation)
        self.assertEqual(self.service.startup_generation, self.initial)
        self.spawn.assert_called_once()

    def test_before_supervisor_lock_and_during_shutdown_never_spawn(self):
        self.service.startup_requested_generation = None
        self.tick(0)
        with deployment.health_monitor.locked(self.home / 'supervisor.lock', os.geteuid()):
            self.assertEqual(self.service.serve(), 0)
        self.assertIsNone(self.service.startup_requested_generation)
        self.service.startup_requested_generation = self.initial
        self.service.observed_container = self.item
        self.service.stopping = True; self.tick(0)
        self.spawn.assert_not_called()

    def test_tls_worker_reload_and_supervisor_poll_never_duplicate_completed_generation(self):
        self.tick(0); self.child.poll.return_value = 0; self.tick(10)
        self.item['State']['Pid'] = 12345
        self.service.health['tls'] = 'warning'; self.tick(20)
        self.service.health['tls'] = 'ok'
        self.item['State']['Pid'] = 23456; self.tick(100)
        self.spawn.assert_called_once()

    def test_container_restart_or_recreate_dispatches_each_new_generation(self):
        self.tick(0); self.child.poll.return_value = 0; self.tick(10)
        self.item['State']['StartedAt'] = '2026-11-03T08:17:58.108106778Z'
        self.tick(20); self.tick(30)
        self.item['Id'] = 'b' * 64; self.tick(40)
        self.assertEqual(self.spawn.call_count, 3)

    def test_retryable_paused_or_busy_result_waits_sixty_seconds(self):
        self.tick(0); self.child.poll.return_value = 75
        self.tick(10); self.tick(59); self.spawn.assert_called_once()
        self.tick(60); self.assertEqual(self.spawn.call_count, 2)
        self.tick(61); self.tick(119); self.assertEqual(self.spawn.call_count, 2)
        self.tick(120); self.assertEqual(self.spawn.call_count, 3)

    def test_terminal_or_ambiguous_exit_is_never_replayed_in_same_generation(self):
        for result in (1, 2, -15):
            with self.subTest(result=result):
                self.item['Id'] = ('%064x' % (result + 100))
                self.child.poll.return_value = None; self.tick(0)
                calls = self.spawn.call_count
                self.child.poll.return_value = result; self.tick(10); self.tick(300)
                self.assertEqual(self.spawn.call_count, calls)

    def test_spawn_failure_or_missing_script_retries_without_stopping_container(self):
        self.service.stop_container = Mock()
        self.spawn.side_effect = OSError('PRIVATE_ERROR')
        self.tick(0); self.tick(59); self.spawn.assert_called_once()
        self.tick(60); self.assertEqual(self.spawn.call_count, 2)
        self.spawn.side_effect = None
        self.script.unlink(); self.tick(120)
        self.assertEqual(self.spawn.call_count, 2)
        self.script.write_text(''); self.tick(179)
        self.assertEqual(self.spawn.call_count, 2)
        self.tick(180); self.assertEqual(self.spawn.call_count, 3)
        self.service.stop_container.assert_not_called()
        self.assertFalse((self.home / 'deployment-state.json').exists())

    def test_unsafe_script_never_executes_as_root(self):
        self.script.chmod(0o666); self.tick(0)
        self.script.unlink(); self.script.symlink_to('/dev/null'); self.tick(60)
        self.spawn.assert_not_called()

    def test_new_generation_cancels_old_child_without_blocking_safety_loop(self):
        self.tick(0)
        self.item['State']['StartedAt'] = '2026-11-03T08:17:58.108106777Z'
        self.tick(10); self.child.terminate.assert_called_once()
        self.tick(14); self.child.kill.assert_not_called()
        self.tick(15); self.child.kill.assert_called_once()
        self.tick(20); self.child.kill.assert_called_once()
        self.child.wait.assert_not_called(); self.spawn.assert_called_once()
        self.child.poll.return_value = -15; self.tick(30)
        self.assertEqual(self.spawn.call_count, 2)

    def test_shutdown_terminates_then_kills_child_with_bounded_wait(self):
        self.tick(0)
        self.child.wait.side_effect = [subprocess.TimeoutExpired('startup', 5), 0]
        self.service.stop_startup_check()
        self.child.terminate.assert_called_once(); self.child.kill.assert_called_once()
        self.assertEqual([call.kwargs['timeout'] for call in self.child.wait.call_args_list], [5, 5])


class AdaptiveScheduleProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        code = self.home / 'code'; code.mkdir()
        self.script = code / 'adaptive_schedule.py'; self.script.write_text('')
        self.now = 0
        config = {'home': str(self.home), 'native_home': str(self.home / 'native'), 'task_id': 31,
                  'bind': '10.10.10.37', 'networks': ['10.10.10.0/24'], 'denied': ['10.10.10.1'], 'port': 18443}
        self.service = deployment.Deployment(config, self.home / 'deployment.json', clock=lambda: self.now)
        self.service.startup_requested_generation = ('f' * 64, '2026-11-03T07:00:00Z')
        self.child = Mock(); self.child.poll.return_value = None
        patcher = patch('web.deployment.subprocess.Popen', return_value=self.child)
        self.spawn = patcher.start(); self.addCleanup(patcher.stop)

    def tick(self, when):
        self.now = when; self.service.start_schedule_sync()

    def test_one_fixed_helper_per_minute_and_never_overlaps(self):
        self.tick(0); self.tick(59); self.tick(60)
        self.spawn.assert_called_once()
        self.child.poll.return_value = 0
        self.tick(60)
        self.assertEqual(self.spawn.call_count, 2)
        self.tick(61); self.assertEqual(self.spawn.call_count, 2)
        args = self.spawn.call_args.args[0]
        self.assertEqual(args, [deployment.sys.executable, '-I', str(self.script),
                               '--native-home', str(self.home / 'native'), '--web-home', str(self.home), '--task-id', '31'])
        self.assertNotIn('--run', args)

    def test_no_sync_before_supervisor_ownership_or_after_shutdown(self):
        self.service.startup_requested_generation = None
        self.tick(0)
        self.service.startup_requested_generation = ('a' * 64, '2026-11-03T07:00:00Z')
        self.service.stopping = True; self.tick(60)
        self.spawn.assert_not_called()

    def test_long_helper_is_terminated_reaped_and_retried_without_blocking(self):
        self.tick(0); self.tick(119); self.child.terminate.assert_not_called()
        self.tick(120); self.child.terminate.assert_called_once()
        self.tick(124); self.child.kill.assert_not_called()
        self.tick(125); self.child.kill.assert_called_once()
        self.tick(130); self.child.kill.assert_called_once()
        self.child.wait.assert_not_called(); self.spawn.assert_called_once()
        self.child.poll.return_value = -9; self.tick(140)
        self.assertEqual(self.spawn.call_count, 2)

    def test_prelaunch_failure_is_bounded_and_does_not_stop_container(self):
        self.service.stop_container = Mock()
        self.spawn.side_effect = OSError('PRIVATE_DETAIL')
        self.tick(0); self.tick(59); self.spawn.assert_called_once()
        self.tick(60); self.assertEqual(self.spawn.call_count, 2)
        self.spawn.side_effect = None; self.script.chmod(0o666)
        self.tick(120); self.assertEqual(self.spawn.call_count, 2)
        self.script.unlink(); self.script.symlink_to('/dev/null')
        self.tick(180); self.assertEqual(self.spawn.call_count, 2)
        self.service.stop_container.assert_not_called()

    def test_failure_exit_retries_next_minute_without_touching_original_task(self):
        self.tick(0)
        self.child.poll.return_value = 1; self.tick(10)
        self.spawn.assert_called_once()
        self.tick(60); self.assertEqual(self.spawn.call_count, 2)

    def test_shutdown_reaps_sync_with_bounded_wait(self):
        self.tick(0)
        self.child.wait.side_effect = [subprocess.TimeoutExpired('sync', 5), 0]
        self.service.stop_schedule_sync()
        self.child.terminate.assert_called_once(); self.child.kill.assert_called_once()
        self.assertEqual([x.kwargs['timeout'] for x in self.child.wait.call_args_list], [5, 5])


class ContainerTLSReloadTests(unittest.TestCase):
    def test_invalid_generation_preserves_worker_then_valid_generation_reloads_once(self):
        first=Mock();second=Mock()
        first.poll.return_value=None;second.poll.return_value=None
        handlers={};sleeps=[0]
        def on_signal(number,callback):handlers[number]=callback
        def sleep(_):
            sleeps[0]+=1
            if sleeps[0]>=11:handlers[container_entry.signal.SIGTERM](None,None)
        old=(Path('/tls/versions/old/fullchain.pem'),Path('/tls/versions/old/privkey.pem'))
        new=(Path('/tls/versions/new/fullchain.pem'),Path('/tls/versions/new/privkey.pem'))
        with patch('web.container_entry.material',side_effect=[old,ValueError('invalid'),new]),patch('web.container_entry.signal.signal',side_effect=on_signal),patch('web.container_entry.time.sleep',side_effect=sleep),patch('web.container_entry.subprocess.Popen',side_effect=[first,second]) as spawn:
            self.assertEqual(container_entry.main(),0)
        self.assertEqual(spawn.call_count,2)
        self.assertEqual(spawn.call_args_list[0].kwargs['env']['CERTWEB_TLS_CERT'],str(old[0]))
        self.assertEqual(spawn.call_args_list[1].kwargs['env']['CERTWEB_TLS_KEY'],str(new[1]))
        first.terminate.assert_called_once();second.terminate.assert_called_once()

    def test_invalid_initial_material_keeps_listener_closed(self):
        with patch('web.container_entry.material',side_effect=ValueError('invalid')),patch('web.container_entry.signal.signal'),patch('web.container_entry.subprocess.Popen') as spawn,patch('sys.stderr'):
            self.assertEqual(container_entry.main(),1)
            spawn.assert_not_called()

    def test_cross_generation_pointer_race_is_rejected(self):
        with patch('web.container_entry.Path.resolve',side_effect=[Path('/tls/versions/a/fullchain.pem'),Path('/tls/versions/b/privkey.pem')]),self.assertRaises(ValueError):
            container_entry.material()

    def test_terminated_worker_is_reaped(self):
        child=Mock();child.poll.return_value=None
        child.wait.side_effect=[subprocess.TimeoutExpired('worker',20),0]
        container_entry.stop(child)
        child.terminate.assert_called_once();child.kill.assert_called_once()


if __name__=='__main__':unittest.main()
