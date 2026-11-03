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
