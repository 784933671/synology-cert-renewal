import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dns_cleanup', ROOT / 'dns_cleanup.py')
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)
NAME = '_acme-challenge.ttxli.cn'
VALUE = 'a' * 43


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.state = self.home / 'state'
        self.state.mkdir(mode=0o700)
        self.path = self.state / 'dns-cleanup.json'

    def test_track_is_private_idempotent_and_survives_process_exit(self):
        for _ in range(2):
            subprocess.run([sys.executable, '-I', str(ROOT / 'dns_cleanup.py'), str(self.home),
                            'track', NAME, VALUE], check=True, capture_output=True)
        data = json.loads(self.path.read_text())
        self.assertEqual(len(data['entries']), 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(data['entries'][0]['name'], NAME)

    def test_uncertain_create_is_retained_until_empty_grace_passes(self):
        cleanup.journal_command(self.home, 'track', [NAME, VALUE])
        with self.assertRaises(cleanup.CleanupError):
            cleanup.journal_command(self.home, 'done', [NAME, VALUE, ''])
        with mock.patch.object(cleanup.time, 'time', return_value=time.time() + cleanup.EMPTY_GRACE + 1):
            cleanup.journal_command(self.home, 'done', [NAME, VALUE, ''])
        self.assertEqual(json.loads(self.path.read_text())['entries'], [])

    def test_successful_delete_can_clear_recent_entry(self):
        cleanup.journal_command(self.home, 'track', [NAME, VALUE])
        cleanup.journal_command(self.home, 'done', [NAME, VALUE, 'deleted'])
        self.assertEqual(json.loads(self.path.read_text())['entries'], [])

    def test_bad_scope_or_value_never_creates_journal(self):
        for name, value in [('ttxli.cn', VALUE), (NAME, 'x\nrm -rf /'),
                            ('_acme-challenge.a;bad.cn', VALUE), (NAME, '"')]:
            with self.subTest(name=name, value=value), self.assertRaises(cleanup.CleanupError):
                cleanup.journal_command(self.home, 'track', [name, value])
        self.assertFalse(self.path.exists())

    def test_corrupt_or_public_or_symlink_journal_fails_closed(self):
        self.path.write_text('invalid json')
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            cleanup.journal_command(self.home, 'count', [])
        self.path.write_text('{"version":1,"entries":[]}')
        self.path.chmod(0o644)
        with self.assertRaises(cleanup.CleanupError):
            cleanup.journal_command(self.home, 'count', [])
        self.path.unlink()
        self.path.symlink_to(self.state / 'other')
        with self.assertRaises(cleanup.CleanupError):
            cleanup.journal_command(self.home, 'count', [])

    def test_record_page_requires_success_and_exact_txt_name_and_value(self):
        records = [
            {'RecordId': 1, 'Name': '_acme-challenge', 'Value': VALUE, 'Type': 'TXT'},
            {'RecordId': 2, 'Name': '_acme-challenge.www', 'Value': VALUE, 'Type': 'TXT'},
            {'RecordId': 3, 'Name': '_acme-challenge', 'Value': 'b' * 43, 'Type': 'TXT'},
            {'RecordId': 4, 'Name': '_acme-challenge', 'Value': VALUE, 'Type': 'CNAME'},
        ]
        raw = json.dumps({'Response': {'RequestId': 'fixture', 'RecordList': records}})
        self.assertEqual(cleanup.record_page(raw, '_acme-challenge', VALUE), (4, [1]))
        for raw in ('{}', '{"Response":{"RecordList":[]}}',
                    '{"Response":{"RequestId":"x","Error":{"Code":"AuthFailure"}}}'):
            with self.subTest(raw=raw), self.assertRaises(cleanup.CleanupError):
                cleanup.record_page(raw, '_acme-challenge', VALUE)

    def test_only_specific_no_records_error_counts_as_empty(self):
        raw = json.dumps({'Response': {'RequestId': 'fixture', 'Error': {
            'Code': 'ResourceNotFound.NoDataOfRecord'}}})
        self.assertEqual(cleanup.record_page(raw, '_acme-challenge', VALUE), (0, []))
        with self.assertRaises(cleanup.CleanupError):
            cleanup.response_data(raw)


FAKE_API = r'''
import json, os, pathlib, sys
home=pathlib.Path(os.environ['CERTCTL_HOME'])
p=home/'cloud.json'
s=json.loads(p.read_text())
action=sys.argv[1]
query=json.loads(sys.argv[2])
s['calls'].append([action,query])
response={'RequestId':'offline-request'}
exit_code=0
if action == 'CreateRecord':
    pending=json.loads((home/'state/dns-cleanup.json').read_text())['entries']
    if not any(x['name']=='_acme-challenge.ttxli.cn' and x['value']==query['Value'] for x in pending):
        raise SystemExit('create attempted before journal persistence')
    rid=max([x['RecordId'] for x in s['records']]+[0])+1
    s['records'].append({'RecordId':rid,'Name':query['SubDomain'],'Value':query['Value'],'Type':'TXT'})
    response['RecordId']=rid
    if s.get('lost_create_response'):
        exit_code=1
elif action == 'DescribeRecordList':
    if query['Domain'] == 'ttxli.cn':
        response['TotalCount']=len(s['records'])
        response['RecordList']=s['records']
    else:
        response['Error']={'Code':'ResourceNotFound.NoDataOfDomain','Message':'no such zone'}
elif action == 'DescribeRecordFilterList':
    mode=s.get('list_error')
    if mode:
        response['Error']={'Code':mode,'Message':'fixture error'}
    else:
        # Deliberately return broad results: client must still match name, value and type.
        rows=s['records']
        offset=query['Offset']
        response['RecordList']=rows[offset:offset+query['Limit']]
        response['RecordCountInfo']={'TotalCount':len(rows),'ListCount':len(response['RecordList'])}
elif action == 'DeleteRecord':
    if s.get('delete_error'):
        response['Error']={'Code':'AuthFailure','Message':'fixture error'}
    elif not s.get('stale_delete'):
        s['records']=[x for x in s['records'] if x['RecordId']!=query['RecordId']]
else:
    raise SystemExit('unexpected network action: '+action)
p.write_text(json.dumps(s))
print(json.dumps({'Response':response}))
raise SystemExit(exit_code)
'''

FAKE_FUNCTIONS = r'''
_get_root() { _domain=ttxli.cn; _sub_domain=${1%.ttxli.cn}; }
_tencent_rest() { response=$("$CERTCTL_PYTHON" "$CERTCTL_HOME/fake-api.py" "$1" "$query"); }
_saveaccountconf_mutable() { :; }
_readaccountconf_mutable() { :; }
'''

MINIMAL_UPSTREAM = r'''
_add_record_query() { query="{\"Domain\":\"$1\",\"SubDomain\":\"$2\",\"Value\":\"$3\"}"; }
_delete_record_query() { query="{\"Domain\":\"$_domain\",\"RecordId\":$1}"; }
'''


class HookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / 'state').mkdir(mode=0o700)
        self.dns = self.home / 'acme/dnsapi'
        self.dns.mkdir(parents=True, mode=0o700)
        for name in ('dns_cleanup.py', 'dns_cleanup_retry.sh'):
            shutil.copyfile(ROOT / name, self.home / name)
        shutil.copyfile(ROOT / 'dns_tencent_tracked.sh', self.dns / 'dns_tencent.sh')
        (self.dns / 'dns_tencent_upstream.sh').write_text(MINIMAL_UPSTREAM + FAKE_FUNCTIONS)
        (self.home / 'acme/acme.sh').write_text('_initpath() { :; }\n')
        (self.home / 'fake-api.py').write_text(FAKE_API)
        self.env = dict(os.environ, CERTCTL_HOME=str(self.home), CERTCTL_PYTHON=sys.executable,
                        Tencent_SecretId='fixture-id', Tencent_SecretKey='fixture-key')
        self.cloud = self.home / 'cloud.json'
        self.set_cloud([])

    def set_cloud(self, records, **kwargs):
        self.cloud.write_text(json.dumps(dict(records=records, calls=[], **kwargs)))

    def get_cloud(self):
        return json.loads(self.cloud.read_text())

    def entries(self):
        path = self.home / 'state/dns-cleanup.json'
        return json.loads(path.read_text())['entries'] if path.exists() else []

    def hook(self, operation):
        script = '. "$CERTCTL_HOME/acme/dnsapi/dns_tencent.sh"\ndns_tencent_' + operation + ' "$1" "$2"\n'
        return subprocess.run(['/bin/sh', '-c', script, 'fixture', NAME, VALUE], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def retry(self):
        return subprocess.run(['/bin/sh', str(self.home / 'dns_cleanup_retry.sh')], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def record(self, rid, **changes):
        return dict({'RecordId': rid, 'Name': '_acme-challenge', 'Value': VALUE, 'Type': 'TXT'}, **changes)

    def test_creation_is_journaled_before_api_and_cleans_normally(self):
        self.assertEqual(self.hook('add').returncode, 0)
        self.assertEqual(len(self.entries()), 1)
        result = self.hook('rm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries(), [])
        self.assertEqual(self.get_cloud()['records'], [])

    def test_lost_create_response_remains_retryable(self):
        self.set_cloud([], lost_create_response=True)
        self.assertEqual(self.hook('add').returncode, 1)
        self.assertEqual(len(self.entries()), 1)
        self.assertEqual(len(self.get_cloud()['records']), 1)
        self.assertEqual(self.retry().returncode, 0)
        self.assertEqual(self.entries(), [])

    def test_delete_failure_survives_and_retry_does_not_create_certificate_or_txt(self):
        self.set_cloud([self.record(1)], delete_error=True)
        self.assertEqual(self.hook('rm').returncode, 1)
        self.assertEqual(len(self.entries()), 1)
        state = self.get_cloud()
        state['delete_error'] = False
        state['calls'] = []
        self.cloud.write_text(json.dumps(state))
        result = self.retry()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries(), [])
        self.assertNotIn('CreateRecord', [x[0] for x in self.get_cloud()['calls']])

    def test_list_permission_error_is_not_treated_as_absent(self):
        self.set_cloud([self.record(1)], list_error='AuthFailure')
        result = self.hook('rm')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.entries()), 1)
        self.assertEqual(len(self.get_cloud()['records']), 1)
        self.assertNotIn('DeleteRecord', [x[0] for x in self.get_cloud()['calls']])

    def test_duplicate_txt_and_pagination_preserve_other_records(self):
        records = [self.record(i) for i in range(1, 103)]
        unrelated = [self.record(201, Value='b' * 43), self.record(202, Name='_acme-challenge.www'),
                     self.record(203, Type='CNAME')]
        self.set_cloud(records + unrelated)
        result = self.hook('rm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.get_cloud()['records'], unrelated)
        self.assertEqual(self.entries(), [])
        pages = [x[1]['Offset'] for x in self.get_cloud()['calls'] if x[0] == 'DescribeRecordFilterList']
        self.assertIn(100, pages)

    def test_successful_delete_response_with_still_present_record_keeps_pending(self):
        self.set_cloud([self.record(1)], stale_delete=True)
        self.assertEqual(self.hook('rm').returncode, 1)
        self.assertEqual(len(self.entries()), 1)

    def test_empty_recent_journal_waits_and_old_absent_record_clears(self):
        cleanup.journal_command(self.home, 'track', [NAME, VALUE])
        self.assertEqual(self.retry().returncode, 1)
        path = self.home / 'state/dns-cleanup.json'
        data = json.loads(path.read_text())
        data['entries'][0]['created_at'] -= 600
        cleanup.write_json(path, data)
        self.assertEqual(self.retry().returncode, 0)
        self.assertEqual(self.entries(), [])

    def test_retry_empty_does_not_load_acme_or_contact_network(self):
        (self.home / 'acme/acme.sh').write_text('exit 99\n')
        self.assertEqual(self.retry().returncode, 0)
        self.assertEqual(self.get_cloud()['calls'], [])

    @unittest.skipUnless(os.environ.get('ACME_TEST_SOURCE'), '需要固定版本 acme.sh 离线集成源码')
    def test_real_retry_initializes_pinned_client_and_preserves_upstream_api_contract(self):
        source = Path(os.environ['ACME_TEST_SOURCE'])
        acme = source / 'acme.sh' if source.is_dir() else source
        shutil.copyfile(acme, self.home / 'acme/acme.sh')
        upstream = self.dns / 'dns_tencent_upstream.sh'
        shutil.copyfile(acme.parent / 'dnsapi/dns_tencent.sh', upstream)
        with upstream.open('a') as handle:
            handle.write('\n_post() { "$CERTCTL_PYTHON" "$CERTCTL_HOME/fake-api.py" "${_H5#*: }" "$1"; }\n')
        guard = self.home / 'network-guard'
        guard.mkdir()
        for client in ('curl', 'wget'):
            executable = guard / client
            executable.write_text('#!/bin/sh\nprintf called > "$CERTCTL_HOME/network-called"\nexit 99\n')
            executable.chmod(0o700)
        self.env['PATH'] = str(guard) + ':' + os.environ['PATH']
        self.set_cloud([self.record(1), self.record(2, Value='b' * 43)])
        cleanup.journal_command(self.home, 'track', [NAME, VALUE])
        result = self.retry()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries(), [])
        self.assertEqual(self.get_cloud()['records'], [self.record(2, Value='b' * 43)])
        self.assertFalse((self.home / 'network-called').exists())
        self.assertIn('DescribeRecordList', [item[0] for item in self.get_cloud()['calls']])

    @unittest.skipUnless(os.environ.get('ACME_TEST_SOURCE'), '需要固定版本 acme.sh 离线集成源码')
    def test_real_acme_swallowed_cleanup_error_still_leaves_durable_journal(self):
        source = Path(os.environ['ACME_TEST_SOURCE'])
        acme = source / 'acme.sh' if source.is_dir() else source
        shutil.copyfile(acme.parent / 'dnsapi/dns_tencent.sh', self.dns / 'dns_tencent_upstream.sh')
        self.set_cloud([self.record(1)], delete_error=True)
        # Source the real pinned client; override transport only, never use a network client.
        script = 'set -- :\n. "' + str(acme) + '"\n' + '''
. "$CERTCTL_HOME/acme/dnsapi/dns_tencent.sh"
''' + FAKE_FUNCTIONS + '''
_stopserver() { :; }
_restoreApache() { :; }
_restoreNginx() { :; }
dns_entries="ttxli.cn,_acme-challenge.ttxli.cn,,dns_tencent,''' + VALUE + ''',"
dns_entries="$dns_entries$CERTCTL_HOME/acme/dnsapi/dns_tencent.sh"
# The hook is sourced again by _clearupdns; append transport overrides to retained fixture source.
_clearup
printf 'cleanup_exit=%s\\n' "$?"
'''
        with (self.dns / 'dns_tencent_upstream.sh').open('a') as handle:
            handle.write(FAKE_FUNCTIONS)
        result = subprocess.run(['/bin/sh', '-c', script], env=self.env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('cleanup_exit=0', result.stdout)
        self.assertEqual(len(self.entries()), 1)
        state = self.get_cloud()
        state['delete_error'] = False
        self.cloud.write_text(json.dumps(state))
        result = self.retry()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.entries(), [])


if __name__ == '__main__':
    unittest.main()
