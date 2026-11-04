"""接口额度、临时封禁、共享 NAT 救援和升级回归。"""
import io
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from web.backend.__main__ import main
from web.backend.abuse import DEFAULT_LIMITS, MAX_BLOCKS, MAX_BUCKETS
from web.backend.app import COOKIE
from web.backend.auth import AuthStore, IDLE_SECONDS, token_hash
from web.backend.security import OPERATIONS as API_OPERATIONS
from web.login_mail import OPERATIONS as MAIL_OPERATIONS
from tests import test_web_security as security_fixture

IP = security_fixture.IP


def configure(store, **values):
    limits = {**DEFAULT_LIMITS, **values}
    with store.transaction() as connection:
        connection.execute('UPDATE abuse_policy SET limits=? WHERE id=1', (json.dumps(limits),))
    return limits


def block(store, ip=IP, token=''):
    limits = store.abuse_settings()['limits']
    for _ in range(limits['ip_requests_per_minute'] + limits['block_after_violations']):
        result = store.check_abuse(ip, token, 'GET', '/api/status')
    return result


class AbuseStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='certweb-abuse-')
        self.root = Path(self.tmp.name)
        self.now = [1700000000.0]
        self.store = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        configure(self.store, ip_requests_per_minute=120, session_requests_per_minute=60, block_after_violations=5)

    def tearDown(self):
        self.tmp.cleanup()

    def test_stepup_operation_allowlists_match_host_mail_labels(self):
        self.assertEqual(set(API_OPERATIONS.values()), set(MAIL_OPERATIONS))

    def test_persistent_ban_has_fixed_expiry_and_refills_after_expiry(self):
        result = block(self.store)
        self.assertEqual((result.code, result.retry_after), ('ip_temporarily_blocked', 300))
        reopened = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        self.now[0] += 101
        result = reopened.check_abuse(IP, '', 'GET', '/api/status')
        self.assertEqual(result.retry_after, 199)
        listed = reopened.abuse_blocks(IP)['items']
        self.assertEqual(len(listed), 1)
        self.assertTrue(listed[0]['current'])
        self.assertEqual(listed[0]['retry_after'], 199)
        self.now[0] += 199
        self.assertIsNone(reopened.check_abuse(IP, '', 'GET', '/api/status'))
        self.assertEqual(reopened.abuse_blocks(IP), {'items': []})

    def test_tokens_refill_and_isolated_excess_does_not_ban(self):
        for _ in range(120):
            self.assertIsNone(self.store.check_abuse(IP, '', 'GET', '/api/status'))
        self.assertEqual(self.store.check_abuse(IP, '', 'GET', '/api/status').retry_after, 1)
        self.now[0] += 1
        for _ in range(2):
            self.assertIsNone(self.store.check_abuse(IP, '', 'GET', '/api/status'))
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})

    def test_rejected_requests_before_block_are_atomic_across_store_instances(self):
        other = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        stores = (self.store, other)
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda number: stores[number % 2].check_abuse(IP, '', 'GET', '/api/status'), range(140)))
        self.assertEqual(sum(item is None for item in results), 120)
        self.assertEqual(sum(item is not None and item.code == 'rate_limited' for item in results), 4)
        self.assertEqual(len(self.store.abuse_blocks(IP)['items']), 1)

    def test_clock_rollback_discards_short_lived_state(self):
        block(self.store)
        self.now[0] -= 3600
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})
        self.assertIsNone(self.store.check_abuse(IP, '', 'GET', '/api/status'))
        self.now[0] += 7200
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})

    def test_bucket_capacity_reserves_recovery_space_and_expires(self):
        with patch('web.backend.abuse.MAX_BUCKETS', 8), patch('web.backend.abuse.RECOVERY_BUCKETS', 4):
            for number in range(4):
                self.assertIsNone(self.store.check_abuse('10.10.1.' + str(number + 1), '', 'GET', '/api/status'))
            limited = self.store.check_abuse(IP, '', 'GET', '/api/status')
            self.assertEqual((limited.code, limited.retry_after), ('rate_limited', 120))
            for number in range(4):
                self.assertIsNone(self.store.check_abuse('10.10.1.' + str(number + 1), '', 'GET', '/api/session'))
            self.assertEqual(self.store.check_abuse(IP, '', 'GET', '/api/session').code, 'rate_limited')
            with self.store.transaction() as connection:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM abuse_buckets').fetchone()[0], 8)
            self.now[0] += 120
            self.assertIsNone(self.store.check_abuse(IP, '', 'GET', '/api/status'))
            with self.store.transaction() as connection:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM abuse_buckets').fetchone()[0], 1)
        self.assertEqual(MAX_BUCKETS, 4096)

    def test_block_capacity_is_bounded_without_displacing_existing_bans(self):
        with patch('web.backend.abuse.MAX_BLOCKS', 2):
            for ip in ('10.10.1.1', '10.10.1.2', '10.10.1.3'):
                block(self.store, ip)
            items = self.store.abuse_blocks(IP)['items']
            self.assertEqual({item['ip'] for item in items}, {'10.10.1.1', '10.10.1.2'})
            self.assertEqual(self.store.check_abuse('10.10.1.3', '', 'GET', '/api/status').code, 'rate_limited')
        self.assertEqual(MAX_BLOCKS, 1024)

    def test_forged_cookies_do_not_allocate_session_buckets(self):
        for number in range(100):
            self.store.check_abuse(IP, str(number).zfill(43), 'GET', '/api/status')
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM abuse_buckets').fetchone()[0], 1)

    def test_recovery_quota_is_bounded_and_never_creates_ip_bans(self):
        for _ in range(60):
            self.assertIsNone(self.store.check_abuse(IP, '', 'GET', '/api/session'))
        self.assertEqual(self.store.check_abuse(IP, '', 'GET', '/api/session').retry_after, 1)
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})
        self.now[0] += 1
        self.assertIsNone(self.store.check_abuse(IP, '', 'GET', '/api/session'))

    def test_cli_rescue_clears_target_only_and_keeps_policy(self):
        block(self.store)
        block(self.store, '10.10.10.25')
        settings = self.store.abuse_settings()
        with patch.dict(os.environ, {'CERTWEB_DATA_DIR': str(self.root / 'data')}), patch('sys.stdout', new=io.StringIO()):
            # CLI 使用真实时钟；与测试里的封禁时间对齐后再检查选择性清除。
            with patch('web.backend.__main__.AuthStore', return_value=self.store):
                self.assertEqual(main(['clear-abuse-blocks', '--ip', IP]), 0)
                self.assertEqual([item['ip'] for item in self.store.abuse_blocks(IP)['items']], ['10.10.10.25'])
                self.assertEqual(main(['clear-abuse-blocks']), 0)
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})
        self.assertEqual(self.store.abuse_settings(), settings)
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM abuse_buckets').fetchone()[0], 0)


class AbuseApiTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = security_fixture.WebSecurityTests.asyncSetUp
    asyncTearDown = security_fixture.WebSecurityTests.asyncTearDown
    make_client = security_fixture.WebSecurityTests.make_client
    post = security_fixture.WebSecurityTests.post
    start = security_fixture.WebSecurityTests.start
    grant = security_fixture.WebSecurityTests.grant
    other_session = security_fixture.WebSecurityTests.other_session

    async def test_defaults_and_access_require_valid_session(self):
        result = await self.client.get('/api/abuse')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()['limits'], DEFAULT_LIMITS)
        self.assertRegex(result.json()['revision'], r'^[0-9a-f]{32}$')
        async with self.make_client() as anonymous:
            for path in ('/api/abuse', '/api/abuse/blocks'):
                result = await anonymous.get(path)
                self.assertEqual((result.status_code, result.json()['error']['code']), (401, 'unauthorized'))

    async def test_settings_require_stepup_exact_body_and_revision(self):
        body = (await self.client.get('/api/abuse')).json()
        body['limits']['block_seconds'] = 600
        result = await self.client.put('/api/abuse', json=body, headers=self.headers)
        self.assertEqual(result.status_code, 428)
        headers = await self.grant('/api/abuse', body, 'PUT')
        changed = {**body, 'limits': {**body['limits'], 'block_seconds': 900}}
        self.assertEqual((await self.client.put('/api/abuse', json=changed, headers=headers)).status_code, 428)
        result = await self.client.put('/api/abuse', json=body, headers=headers)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['limits']['block_seconds'], 600)
        self.assertNotEqual(result.json()['revision'], body['revision'])
        self.assertEqual((await self.client.put('/api/abuse', json=body, headers=headers)).status_code, 428)
        self.now[0] += 61
        stale_headers = await self.grant('/api/abuse', body, 'PUT')
        self.assertEqual((await self.client.put('/api/abuse', json=body, headers=stale_headers)).status_code, 409)

    async def test_validation_rejects_booleans_excesses_and_unknown_keys(self):
        original = (await self.client.get('/api/abuse')).json()
        for key, value in (('ip_requests_per_minute', 119), ('session_requests_per_minute', 1201),
                           ('block_after_violations', True), ('block_seconds', 1801), ('block_seconds', 0)):
            body = {**original, 'limits': {**original['limits'], key: value}}
            self.assertEqual((await self.client.put('/api/abuse', json=body, headers=self.headers)).status_code, 400)
        self.assertEqual((await self.post('abuse/unblock', {'ip': '::1'})).status_code, 400)
        self.assertEqual((await self.post('abuse/unblock', {'ip': IP, 'all': True})).status_code, 400)
        self.assertEqual((await self.client.get('/api/abuse')).json(), original)

    async def test_session_limit_does_not_ban_shared_nat_or_other_sessions(self):
        configure(self.store, ip_requests_per_minute=600, session_requests_per_minute=60)
        for _ in range(60):
            self.assertEqual((await self.client.get('/api/status')).status_code, 200)
        for _ in range(30):
            result = await self.client.get('/api/status')
            self.assertEqual((result.status_code, result.json()['error']['code']), (429, 'rate_limited'))
            self.assertEqual(result.headers['retry-after'], str(result.json()['error']['retry_after']))
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})
        self.assertIsNotNone(self.store.session(self.token, False))
        token, _ = self.other_session(IP)
        async with self.make_client() as other:
            other.cookies.set(COOKIE, token)
            self.assertEqual((await other.get('/api/status')).status_code, 200)

    async def test_own_ban_recovery_stepup_and_unblock_work(self):
        configure(self.store, ip_requests_per_minute=120, session_requests_per_minute=60, block_after_violations=5)
        block(self.store)
        result = await self.client.get('/api/status')
        self.assertEqual((result.status_code, result.json()['error']['code']), (429, 'ip_temporarily_blocked'))
        self.assertEqual(result.json()['error']['retry_after'], 300)
        self.assertEqual((await self.client.get('/api/session')).status_code, 200)
        listed = (await self.client.get('/api/abuse/blocks')).json()['items']
        self.assertEqual([(item['ip'], item['current']) for item in listed], [(IP, True)])
        self.assertEqual((await self.post('abuse/unblock', {'ip': IP})).status_code, 428)
        headers = await self.grant('/api/abuse/unblock', {'ip': IP})
        result = await self.post('abuse/unblock', {'ip': IP}, headers)
        self.assertEqual(result.json(), {'ok': True, 'removed': True})
        self.assertEqual((await self.client.get('/api/status')).status_code, 200)
        self.assertEqual((await self.post('abuse/unblock', {'ip': IP}, headers)).status_code, 428)

    async def test_blocked_anonymous_can_login_and_recover_without_consuming_existing_session_quota(self):
        configure(self.store, ip_requests_per_minute=120, session_requests_per_minute=60, block_after_violations=5)
        block(self.store)
        self.now[0] += 61
        async with self.make_client() as other:
            result = await other.post('/api/login', json={'username': 'admin', 'password': security_fixture.PASSWORD},
                                      headers={'Origin': security_fixture.ORIGIN})
            self.assertEqual(result.status_code, 202)
            result = await other.post('/api/login/verify', json={'code': self.bridge.code('auth.code.send')},
                                      headers={'Origin': security_fixture.ORIGIN})
            self.assertEqual(result.status_code, 200)
        for _ in range(70):
            self.store.check_abuse(IP, '', 'GET', '/api/session')
        self.assertEqual((await self.client.get('/api/abuse/blocks')).status_code, 200)
        self.assertEqual((await self.client.get('/api/stepup/challenge')).status_code, 200)

    async def test_healthcheck_static_and_bridge_execution_are_outside_abuse_state(self):
        block(self.store)
        with self.store.transaction() as connection:
            before = [tuple(row) for row in connection.execute('SELECT * FROM abuse_buckets')]
        async with self.make_client('127.0.0.1') as local:
            for _ in range(100):
                self.assertEqual((await local.get('/healthz')).json(), {'ok': True})
        # 不在仓库创建静态文件；缺少资源仍应是404而非封禁429。
        self.assertEqual((await self.client.get('/security')).status_code, 404)
        self.assertEqual(await self.bridge.call('run'), {'accepted': True})
        with self.store.transaction() as connection:
            self.assertEqual([tuple(row) for row in connection.execute('SELECT * FROM abuse_buckets')], before)

    async def test_routine_polling_and_run_check_do_not_require_extra_stepup(self):
        for _ in range(12):
            for path in ('status', 'health', 'monitor', 'security-alerts', 'sessions', 'abuse', 'abuse/blocks'):
                self.assertEqual((await self.client.get('/api/' + path)).status_code, 200)
            self.now[0] += 5
        for action in ('run', 'check'):
            self.assertEqual((await self.post('actions/' + action)).status_code, 200)
        self.assertEqual(self.store.abuse_blocks(IP), {'items': []})
        self.assertNotIn('auth.stepup.send', [method for method, _ in self.bridge.calls])

    async def test_polling_does_not_extend_idle_and_expired_session_is_401(self):
        with self.store.transaction() as connection:
            initial = connection.execute('SELECT last_seen FROM sessions WHERE token_hash=?', (token_hash(self.token),)).fetchone()[0]
        self.now[0] += IDLE_SECONDS - 1
        for path in ('/api/abuse', '/api/abuse/blocks'):
            self.assertEqual((await self.client.get(path)).status_code, 200)
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT last_seen FROM sessions WHERE token_hash=?', (token_hash(self.token),)).fetchone()[0], initial)
        self.now[0] += 1
        result = await self.client.get('/api/abuse')
        self.assertEqual((result.status_code, result.json()['error']['code']), (401, 'unauthorized'))

    async def test_upgrade_preserves_credentials_email_policy_and_existing_sessions(self):
        with self.store.transaction() as connection:
            before = dict(connection.execute('SELECT * FROM users').fetchone())
            for table in ('abuse_policy', 'abuse_buckets', 'abuse_blocks'):
                connection.execute('DROP TABLE ' + table)
        upgraded = AuthStore(self.store.path.parent, clock=lambda: self.now[0])
        self.assertEqual(upgraded.abuse_settings()['limits'], DEFAULT_LIMITS)
        self.assertIsNotNone(upgraded.session(self.token, False))
        with upgraded.transaction() as connection:
            self.assertEqual(dict(connection.execute('SELECT * FROM users').fetchone()), before)
        self.assertEqual((await self.post('actions/run')).status_code, 200)


if __name__ == '__main__':
    unittest.main()
