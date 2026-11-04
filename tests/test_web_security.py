"""敏感操作、持久安全提醒和会话撤销的真实 API 与并发回归。"""
import asyncio
import ctypes
import os
import socket
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

import httpx

from web.backend.app import COOKIE, create_app
from web.backend.auth import AuthStore, IDLE_SECONDS, token_hash
from web.backend.bridge import BridgeClient, BridgeError
from web.backend.config import Config
from web.backend.mfa import MfaError
from web.backend.security import dispatch_security_alert, operation_digest
from tests.test_web_api import settings_payload

ORIGIN = 'https://ttxli.cn:18443'
IP = '10.10.10.24'
PASSWORD = 'fixture-password-security-42'
VERSION = 'a' * 32


class SecurityBridge:
    def __init__(self):
        self.calls = []
        self.error = None
        self.wait = None
        self.entered = asyncio.Event()

    async def call(self, method, params=None):
        self.calls.append((method, dict(params or {})))
        if method.startswith('auth.'):
            self.entered.set()
            if self.wait:
                await self.wait.wait()
            if self.error:
                raise self.error
        return {'accepted': True}

    def code(self, method='auth.stepup.send'):
        return [params['code'] for name, params in self.calls if name == method][-1]


class WebSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='certweb-security-')
        self.root = Path(self.tmp.name)
        self.now = [1700000000.0]
        self.store = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        self.store.initialize('admin', PASSWORD)
        self.store.configure_email_login('admin', 'owner@example.com', VERSION)
        with self.store.transaction() as connection:
            connection.execute('UPDATE users SET must_change=0')
        self.config = Config(data_dir=self.root / 'data', origin=ORIGIN,
                             allowed_hosts=('ttxli.cn:18443',), allowed_networks=('10.10.10.0/24',))
        self.bridge = SecurityBridge()
        self.app = create_app(self.config, self.store, self.bridge)
        self.client = self.make_client()
        result = await self.client.post('/api/login', json={'username': 'admin', 'password': PASSWORD}, headers={'Origin': ORIGIN})
        self.assertEqual(result.status_code, 202, result.text)
        result = await self.client.post('/api/login/verify', json={'code': self.bridge.code('auth.code.send')}, headers={'Origin': ORIGIN})
        self.assertEqual(result.status_code, 200, result.text)
        self.headers = {'Origin': ORIGIN, 'X-CSRF-Token': result.json()['csrf_token']}
        self.token = self.client.cookies.get(COOKIE)
        self.bridge.calls.clear()

    async def asyncTearDown(self):
        await self.client.aclose()
        self.tmp.cleanup()

    def make_client(self, ip=IP):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app, client=(ip, 43210)), base_url=ORIGIN)

    async def post(self, path, data=None, headers=None):
        return await self.client.post('/api/' + path, json={} if data is None else data, headers=self.headers if headers is None else headers)

    async def start(self, path='/api/actions/renew', body=None, method='POST'):
        return await self.post('stepup/start', {'method': method, 'path': path, 'body': {} if body is None else body})

    async def grant(self, path='/api/actions/renew', body=None, method='POST'):
        started = await self.start(path, body, method)
        self.assertEqual(started.status_code, 200, started.text)
        verified = await self.post('stepup/verify', {'challenge_id': started.json()['challenge_id'], 'code': self.bridge.code()})
        self.assertEqual(verified.status_code, 200, verified.text)
        return {**self.headers, 'X-Step-Up-Token': verified.json()['token']}

    def other_session(self, ip='10.10.10.25'):
        with self.store.transaction() as connection:
            token, current = self.store._new_session(connection, 'admin', 2, VERSION)
        self.store.record_login(token, ip, 'Mozilla Macintosh')
        return token, current

    def count(self, table):
        with self.store.transaction() as connection:
            return connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def alert_items(self):
        return self.store.alerts_list(self.token)['items']

    async def test_sensitive_routes_fail_closed_before_bridge_but_renew_checks_continue(self):
        requests = [('PUT', '/api/settings', settings_payload()),
                    ('PUT', '/api/monitor', {'revision': 'a' * 64, 'enabled': True, 'missed_runs': 2, 'grace_minutes': 15, 'expiry_hours': 24}),
                    ('POST', '/api/actions/renew', {}), ('POST', '/api/sessions/revoke', {'id': 'b' * 32}),
                    ('POST', '/api/sessions/revoke-others', {}),
                    ('POST', '/api/password', {'current_password': PASSWORD, 'new_password': PASSWORD + 'new'})]
        for method, path, body in requests:
            result = await self.client.request(method, path, json=body, headers=self.headers)
            self.assertEqual((result.status_code, result.json()['error']['code']), (428, 'stepup_required'), result.text)
        self.assertEqual(self.bridge.calls, [])
        for action in ('run', 'check'):
            self.assertEqual((await self.post('actions/' + action)).status_code, 200)
        self.assertEqual([name for name, _ in self.bridge.calls], ['run', 'check'])

    async def test_immediate_stepup_is_separate_from_login_quota_and_exact_single_use(self):
        headers = await self.grant('/api/settings', settings_payload(), 'PUT')
        changed = settings_payload()
        changed['renew_before_days'] = 3
        result = await self.client.put('/api/settings', json=changed, headers=headers)
        self.assertEqual(result.status_code, 428)
        result = await self.client.put('/api/settings', json=settings_payload(), headers=headers)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual((await self.client.put('/api/settings', json=settings_payload(), headers=headers)).status_code, 428)
        self.assertEqual([name for name, _ in self.bridge.calls].count('settings.update'), 1)

    async def test_canonical_body_order_matches_but_operation_and_ip_do_not(self):
        body = settings_payload()
        headers = await self.grant('/api/settings', body, 'PUT')
        self.assertEqual((await self.post('actions/renew', headers=headers)).status_code, 428)
        async with self.make_client('10.10.10.26') as other:
            other.cookies.set(COOKIE, self.token)
            self.assertEqual((await other.put('/api/settings', json=body, headers=headers)).status_code, 410)
        result = await self.client.put('/api/settings', json=dict(reversed(list(body.items()))), headers=headers)
        self.assertEqual(result.status_code, 200)

    async def test_start_recovery_idempotent_without_duplicate_mail_and_replacement_revokes_old(self):
        first = await self.start()
        second = await self.start()
        self.assertEqual(first.json(), second.json())
        self.assertEqual(len(self.bridge.calls), 1)
        code = self.bridge.code()
        self.now[0] += 61
        replacement = await self.start('/api/sessions/revoke-others')
        self.assertNotEqual(first.json()['challenge_id'], replacement.json()['challenge_id'])
        self.assertEqual((await self.post('stepup/verify', {'challenge_id': first.json()['challenge_id'], 'code': code})).status_code, 410)

    async def test_resend_preserves_error_budget_and_does_not_extend_lifetime(self):
        started = await self.start()
        identifier = started.json()['challenge_id']
        wrong = '111111' if self.bridge.code() != '111111' else '222222'
        for _ in range(4):
            self.assertEqual((await self.post('stepup/verify', {'challenge_id': identifier, 'code': wrong})).status_code, 400)
        self.now[0] += 61
        resent = await self.post('stepup/resend', {'challenge_id': identifier})
        self.assertEqual(resent.json()['expires_in'], 239)
        wrong = '111111' if self.bridge.code() != '111111' else '222222'
        self.assertEqual((await self.post('stepup/verify', {'challenge_id': identifier, 'code': wrong})).status_code, 410)
        self.assertEqual((await self.post('stepup/verify', {'challenge_id': identifier, 'code': self.bridge.code()})).status_code, 410)
        self.assertEqual((await self.post('stepup/resend', {'challenge_id': identifier})).status_code, 410)

    async def test_grant_expires_without_renewing_and_unknown_verify_result_cannot_reissue(self):
        started = await self.start()
        body = {'challenge_id': started.json()['challenge_id'], 'code': self.bridge.code()}
        first = await self.post('stepup/verify', body)
        self.assertEqual((await self.post('stepup/verify', body)).status_code, 410)
        self.now[0] += 120
        result = await self.post('actions/renew', headers={**self.headers, 'X-Step-Up-Token': first.json()['token']})
        self.assertEqual(result.status_code, 428)
        self.assertNotIn('renew', [name for name, _ in self.bridge.calls])

    async def test_concurrent_verification_and_business_requests_have_one_winner(self):
        started = await self.start()
        body = {'challenge_id': started.json()['challenge_id'], 'code': self.bridge.code()}
        verified = await asyncio.gather(self.post('stepup/verify', body), self.post('stepup/verify', body))
        self.assertEqual(sorted(item.status_code for item in verified), [200, 410])
        token = next(item.json()['token'] for item in verified if item.status_code == 200)
        headers = {**self.headers, 'X-Step-Up-Token': token}
        results = await asyncio.gather(self.post('actions/renew', headers=headers), self.post('actions/renew', headers=headers))
        self.assertEqual(sorted(item.status_code for item in results), [200, 428])
        self.assertEqual([name for name, _ in self.bridge.calls].count('renew'), 1)

    async def test_proof_survives_restart_and_cross_process_consumers_have_one_winner(self):
        headers = await self.grant()
        second = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        third = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        barrier = threading.Barrier(2)
        def consume(store):
            barrier.wait()
            try:
                store.consume_stepup(self.token, IP, 'POST', '/api/actions/renew', {}, headers['X-Step-Up-Token'])
                return True
            except MfaError:
                return False
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(consume, (second, third)))
        self.assertEqual(sum(results), 1)

    async def test_session_limit_removes_old_grants_without_extending_other_sessions(self):
        await self.grant()
        for value in range(20):
            self.other_session('10.10.10.%d' % (100 + value))
        self.assertIsNone(self.store.session(self.token))
        self.assertEqual(self.count('sessions'), 20)
        self.assertEqual(self.count('stepup_challenges'), 0)

    async def test_wrong_session_or_duplicate_token_header_cannot_consume_proof(self):
        headers = await self.grant()
        token, current = self.other_session()
        async with self.make_client() as other:
            other.cookies.set(COOKIE, token)
            other_headers = {**headers, 'X-CSRF-Token': current['csrf_token']}
            self.assertEqual((await other.post('/api/actions/renew', json={}, headers=other_headers)).status_code, 410)
        duplicate = list(headers.items()) + [('x-step-up-token', headers['X-Step-Up-Token'])]
        self.assertEqual((await self.post('actions/renew', headers=duplicate)).status_code, 400)
        self.assertEqual((await self.post('actions/renew', headers=headers)).status_code, 200)

    async def test_send_failure_and_cancellation_invalidate_delivered_code(self):
        self.bridge.error = BridgeError('unavailable')
        self.assertEqual((await self.start()).status_code, 503)
        failed = (await self.client.get('/api/stepup/challenge')).json()
        self.assertEqual(failed['expires_in'], 0)
        self.assertEqual((await self.post('stepup/verify', {'challenge_id': failed['challenge_id'], 'code': self.bridge.code()})).status_code, 410)
        self.bridge.error = None
        self.now[0] += 61
        self.bridge.wait = asyncio.Event()
        self.bridge.entered.clear()
        task = asyncio.create_task(self.post('stepup/resend', {'challenge_id': failed['challenge_id']}))
        await self.bridge.entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual((await self.post('stepup/verify', {'challenge_id': failed['challenge_id'], 'code': self.bridge.code()})).status_code, 410)
        self.bridge.wait = None

    async def test_cancel_racing_delivery_does_not_resurrect_challenge(self):
        self.bridge.wait = asyncio.Event()
        self.bridge.entered.clear()
        task = asyncio.create_task(self.start())
        await self.bridge.entered.wait()
        meta = (await self.client.get('/api/stepup/challenge')).json()
        self.assertEqual((await self.post('stepup/cancel', {'challenge_id': meta['challenge_id']})).status_code, 200)
        self.bridge.wait.set()
        await task
        self.assertEqual((await self.client.get('/api/stepup/challenge')).json(), {'verification_required': False})
        self.assertEqual((await self.post('stepup/verify', {'challenge_id': meta['challenge_id'], 'code': self.bridge.code()})).status_code, 410)

    async def test_logout_policy_change_and_password_rotation_revoke_pending_grants(self):
        for mutation in ('logout', 'policy', 'password'):
            with self.subTest(mutation=mutation):
                if mutation != 'logout':
                    self.now[0] += 61
                    token, current = self.other_session(IP)
                else:
                    token = self.token
                delivery = self.store.start_stepup(token, IP, 'POST', '/api/actions/renew', {})
                self.store.finish_stepup(token, IP, delivery, True)
                proof = self.store.verify_stepup(token, IP, delivery.challenge_id, delivery.code)['token']
                if mutation == 'logout':
                    self.store.logout(token)
                elif mutation == 'policy':
                    self.store.configure_email_login('admin', 'owner@example.com', VERSION)
                    with self.store.transaction() as connection:
                        connection.execute('UPDATE login_security SET verified=1')
                else:
                    self.assertTrue(self.store.change_password('admin', PASSWORD, PASSWORD + '-changed', token))
                with self.assertRaises(MfaError) as error:
                    self.store.consume_stepup(token, IP, 'POST', '/api/actions/renew', {}, proof)
                self.assertEqual(error.exception.status, 401)

    async def test_unverified_or_disabled_email_never_bypasses_stepup(self):
        with self.store.transaction() as connection:
            connection.execute('UPDATE login_security SET verified=0')
        self.assertEqual((await self.start()).json()['error']['code'], 'email_security_required')
        self.store.configure_email_login('admin', enabled=False)
        token, current = self.store.login('admin', PASSWORD)
        self.client.cookies.clear()
        self.client.cookies.set(COOKIE, token)
        self.headers['X-CSRF-Token'] = current['csrf_token']
        self.assertEqual((await self.post('actions/renew')).status_code, 403)
        self.assertEqual(self.bridge.calls, [])
        self.assertEqual((await self.post('actions/run')).status_code, 200)

    async def test_normal_password_change_requires_otp_and_rotates_sessions(self):
        old = self.token
        other, _ = self.other_session()
        body = {'current_password': PASSWORD, 'new_password': PASSWORD + '-changed'}
        headers = await self.grant('/api/password', body)
        changed = await self.post('password', body, headers)
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertIsNone(self.store.session(old))
        self.assertIsNone(self.store.session(other))
        self.assertNotEqual(self.client.cookies.get(COOKIE), old)

    async def test_sessions_metadata_safe_ids_and_background_polls_do_not_extend_idle(self):
        token, _ = self.other_session()
        listed = (await self.client.get('/api/sessions')).json()['items']
        self.assertEqual(len(listed), 2)
        self.assertEqual(sum(item['current'] for item in listed), 1)
        self.assertEqual({item['ip'] for item in listed}, {IP, '10.10.10.25'})
        self.assertNotIn(token, json.dumps(listed))
        self.assertNotIn(token_hash(token), json.dumps(listed))
        for item in listed:
            self.assertRegex(item['id'], r'^[0-9a-f]{32}$')
            self.assertTrue(item['created_at'].endswith('Z'))
        self.now[0] += IDLE_SECONDS - 1
        for path in ('sessions', 'security-alerts', 'stepup/challenge'):
            self.assertEqual((await self.client.get('/api/' + path)).status_code, 200)
        self.now[0] += 1
        self.assertEqual((await self.client.get('/api/sessions')).status_code, 401)

    async def test_revoke_other_session_cancels_its_grant_and_revoke_self_clears_cookie(self):
        other, _ = self.other_session()
        delivery = self.store.start_stepup(other, IP, 'POST', '/api/actions/renew', {})
        self.store.finish_stepup(other, IP, delivery, True)
        proof = self.store.verify_stepup(other, IP, delivery.challenge_id, delivery.code)['token']
        self.now[0] += 61
        headers = await self.grant('/api/sessions/revoke-others')
        result = await self.post('sessions/revoke-others', headers=headers)
        self.assertEqual(result.json(), {'ok': True, 'current_revoked': False})
        with self.assertRaises(MfaError):
            self.store.consume_stepup(other, IP, 'POST', '/api/actions/renew', {}, proof)
        self.now[0] += 61
        identifier = self.store.sessions_list(self.token)['items'][0]['id']
        body = {'id': identifier}
        headers = await self.grant('/api/sessions/revoke', body)
        result = await self.post('sessions/revoke', body, headers)
        self.assertEqual(result.json(), {'ok': True, 'current_revoked': True})
        self.assertIsNone(self.client.cookies.get(COOKIE))

    async def test_revoke_and_grant_consumption_are_serialized_across_store_instances(self):
        other, _ = self.other_session()
        delivery = self.store.start_stepup(other, IP, 'POST', '/api/actions/renew', {})
        self.store.finish_stepup(other, IP, delivery, True)
        proof = self.store.verify_stepup(other, IP, delivery.challenge_id, delivery.code)['token']
        second = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        barrier = threading.Barrier(2)
        def consume():
            barrier.wait()
            try:
                second.consume_stepup(other, IP, 'POST', '/api/actions/renew', {}, proof)
                return 'consumed'
            except MfaError:
                return 'revoked'
        def revoke():
            barrier.wait()
            self.store.logout(other)
        with ThreadPoolExecutor(2) as pool:
            first, done = pool.submit(consume), pool.submit(revoke)
            self.assertIn(first.result(), ('consumed', 'revoked'))
            done.result()
        self.assertIsNone(self.store.session(other))
        with self.assertRaises(MfaError):
            second.consume_stepup(other, IP, 'POST', '/api/actions/renew', {}, proof)

    async def test_new_source_alert_fixed_payload_deduped_and_durable(self):
        self.assertEqual(len(self.alert_items()), 1)
        self.store.record_login(self.token, IP, 'python-httpx')
        self.assertEqual(len(self.alert_items()), 1)
        self.store.record_login(self.token, '10.10.10.99', 'iPhone Mobile')
        self.assertEqual(len(self.alert_items()), 2)
        restarted = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        await dispatch_security_alert(restarted, self.bridge)
        method, params = self.bridge.calls[-1]
        self.assertEqual(method, 'auth.security.send')
        self.assertEqual(set(params), {'event_id', 'event_type', 'policy_version', 'at', 'source_ip', 'device'})
        self.assertEqual(params['event_type'], 'new_login')
        self.assertEqual([item['status'] for item in self.alert_items()].count('sent'), 1)

    async def test_mail_failure_retries_same_event_and_does_not_affect_actions_or_login(self):
        self.bridge.error = BridgeError('unavailable')
        self.assertTrue(await dispatch_security_alert(self.store, self.bridge))
        first = self.bridge.calls[-1][1]
        self.assertEqual(self.alert_items()[0]['status'], 'pending')
        self.assertFalse(await dispatch_security_alert(self.store, self.bridge))
        self.assertEqual((await self.post('actions/run')).status_code, 200)
        self.assertEqual((await self.client.get('/api/session')).status_code, 200)
        self.now[0] += 60
        self.bridge.error = None
        self.assertTrue(await dispatch_security_alert(self.store, self.bridge))
        self.assertEqual(self.bridge.calls[-1][1], first)
        self.assertEqual(self.alert_items()[0]['status'], 'sent')

    async def test_outbox_cancellation_and_stale_worker_completion_do_not_duplicate_claim(self):
        self.bridge.wait = asyncio.Event()
        self.bridge.entered.clear()
        task = asyncio.create_task(dispatch_security_alert(self.store, self.bridge))
        await self.bridge.entered.wait()
        first_params = self.bridge.calls[-1][1]
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNone(self.store.claim_alert())
        with self.store.transaction() as connection:
            old_lease = connection.execute('SELECT lease FROM security_alerts').fetchone()[0]
        self.now[0] += 120
        claim = self.store.claim_alert()
        self.assertEqual(claim['params'], first_params)
        self.store.finish_alert(claim['id'], old_lease, True)
        self.assertEqual(self.alert_items()[0]['status'], 'sending')
        self.store.finish_alert(claim['id'], claim['lease'], True)
        self.assertEqual(self.alert_items()[0]['status'], 'sent')
        self.bridge.wait = None

    async def test_password_and_email_code_failures_trigger_one_deduplicated_alert(self):
        for _ in range(5):
            self.store.record_login_failure('admin', IP, '')
        self.assertEqual([item['event_type'] for item in self.alert_items()].count('login_failures'), 1)
        self.now[0] += 901
        self.store.session(self.token)
        async with self.make_client() as attacker:
            started = await attacker.post('/api/login', json={'username': 'admin', 'password': PASSWORD}, headers={'Origin': ORIGIN})
            self.assertEqual(started.status_code, 202)
            code = self.bridge.code('auth.code.send')
            wrong = '111111' if code != '111111' else '222222'
            for _ in range(5):
                await attacker.post('/api/login/verify', json={'code': wrong}, headers={'Origin': ORIGIN})
        self.assertEqual([item['event_type'] for item in self.alert_items()].count('login_failures'), 2)
        for _ in range(10):
            self.store.record_login_failure('nobody', IP, '')
        self.assertEqual([item['event_type'] for item in self.alert_items()].count('login_failures'), 2)

    async def test_policy_change_does_not_send_queued_alert_to_changed_email(self):
        self.store.configure_email_login('admin', 'changed@example.com', 'b' * 32)
        self.assertFalse(await dispatch_security_alert(self.store, self.bridge))
        self.assertEqual(self.bridge.calls, [])
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT status FROM security_alerts').fetchone()[0], 'failed')

    async def test_new_email_policy_isolates_event_deduplication_and_known_sources(self):
        self.store.record_security_change(self.token, IP, '')
        self.store.configure_email_login('admin', 'changed@example.com', 'b' * 32)
        with self.store.transaction() as connection:
            connection.execute('UPDATE login_security SET verified=1')
            token, _ = self.store._new_session(connection, 'admin', 2, 'b' * 32)
        self.store.record_security_change(token, IP, '')
        self.store.record_login(token, IP, 'python-httpx')
        with self.store.transaction() as connection:
            rows = connection.execute('SELECT policy_version,event_type FROM security_alerts').fetchall()
        self.assertEqual(sorted(tuple(row) for row in rows), sorted([
            (VERSION, 'new_login'), (VERSION, 'security_change'),
            ('b' * 32, 'new_login'), ('b' * 32, 'security_change')]))
        self.store.record_security_change(token, IP, '')
        self.store.record_login(token, IP, 'python-httpx')
        self.assertEqual(self.count('security_alerts'), 4)
        claim = self.store.claim_alert()
        self.assertEqual(claim['params']['policy_version'], 'b' * 32)
        self.assertEqual(claim['params']['source_ip'], IP)

    async def test_alert_storage_is_bounded_and_pending_count_includes_beyond_list_page(self):
        with self.store.transaction() as connection:
            policy = self.store._email_policy(connection, 'admin')
            for value in range(205):
                self.store._queue_alert(connection, 'admin', policy, 'new_login', '10.1.%d.%d' % (value // 255, value % 255), 'unknown')
        result = self.store.alerts_list(self.token)
        self.assertEqual(self.count('security_alerts'), 200)
        self.assertEqual(len(result['items']), 50)
        self.assertEqual(result['pending_count'], 200)
        self.now[0] += 31 * 86400
        self.assertIsNone(self.store.claim_alert())
        self.assertEqual(self.count('security_alerts'), 0)

    async def test_eighth_outbox_attempt_preserves_live_lease_with_second_worker(self):
        with self.store.transaction() as connection:
            connection.execute('UPDATE security_alerts SET attempts=7')
        claim = self.store.claim_alert()
        second = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        self.assertIsNone(second.claim_alert())
        self.store.finish_alert(claim['id'], claim['lease'], True)
        self.assertEqual(self.alert_items()[0]['status'], 'sent')

    async def test_request_digest_is_session_keyed_including_password_body(self):
        body = {'current_password': PASSWORD, 'new_password': PASSWORD + '-changed'}
        _, first = operation_digest('POST', '/api/password', body, self.token)
        other, _ = self.other_session()
        _, second = operation_digest('POST', '/api/password', body, other)
        self.assertNotEqual(first, second)
        self.assertEqual(first, operation_digest('POST', '/api/password', dict(reversed(list(body.items()))), self.token)[1])

    async def test_old_database_migrates_preserving_password_email_policy_and_sessions(self):
        with self.store.transaction() as connection:
            for name in ('session_id', 'source_ip', 'device'):
                connection.execute('ALTER TABLE sessions DROP COLUMN ' + name)
            for name in ('stepup_challenges', 'stepup_attempts', 'known_login_sources', 'security_failures', 'security_alerts'):
                connection.execute('DROP TABLE ' + name)
        upgraded = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        self.assertTrue(upgraded.credentials_valid('admin', PASSWORD))
        self.assertTrue(upgraded.session(self.token)['email_verification_enabled'])
        items = upgraded.sessions_list(self.token)['items']
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['device'], 'unknown')
        self.assertEqual(items[0]['ip'], '')
        self.assertRegex(items[0]['id'], '^[a-f0-9]{32}$')

    async def test_no_code_grant_password_or_business_secret_persisted(self):
        body = settings_payload()
        body.update(secret_id='fixture-sensitive-id-812', secret_key='fixture-sensitive-key-412')
        headers = await self.grant('/api/settings', body, 'PUT')
        with self.store.transaction() as connection:
            saved = '\n'.join(connection.iterdump())
        for secret in (PASSWORD, self.token, self.bridge.code(), headers['X-Step-Up-Token'], body['secret_id'], body['secret_key']):
            self.assertNotIn(secret, saved)

    async def test_stepup_send_quota_survives_database_reopen_and_invalid_path_never_sends(self):
        for path in ('/api/actions/run', '/api/anything', 'https://evil.invalid/api/settings'):
            self.assertEqual((await self.start(path)).status_code, 400)
        self.assertEqual(self.bridge.calls, [])
        first = await self.start()
        self.store.cancel_stepup(self.token, first.json()['challenge_id'])
        reopened = AuthStore(self.root / 'data', clock=lambda: self.now[0])
        with self.assertRaises(MfaError) as error:
            reopened.start_stepup(self.token, IP, 'POST', '/api/actions/renew', {})
        self.assertEqual(error.exception.status, 429)

    async def test_security_record_storage_failure_is_observable_and_does_not_fail_action(self):
        headers = await self.grant('/api/settings', settings_payload(), 'PUT')
        with patch.object(self.store, 'record_security_change', side_effect=sqlite3.OperationalError('fixture error')), self.assertLogs('web.backend.app', level='ERROR') as logs:
            result = await self.client.put('/api/settings', json=settings_payload(), headers=headers)
        self.assertEqual(result.status_code, 200)
        self.assertNotIn('fixture error', '\n'.join(logs.output))

    async def test_lifespan_starts_and_cancels_alert_worker(self):
        async with self.app.app.router.lifespan_context(self.app.app):
            for _ in range(100):
                if self.alert_items()[0]['status'] == 'sent':
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(self.alert_items()[0]['status'], 'sent')
        self.assertEqual([name for name, _ in self.bridge.calls].count('auth.security.send'), 1)


class SecurityBridgeWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_unix_client_allows_only_fixed_security_mail_methods(self):
        with tempfile.TemporaryDirectory(prefix='secwire-', dir='/tmp') as directory:
            socket = str(Path(directory) / 'bridge.sock')
            requests = []
            async def handle(reader, writer):
                requests.append(json.loads(await reader.readline()))
                writer.write(b'{"ok":true,"data":{"accepted":true}}\n')
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            server = await asyncio.start_unix_server(handle, path=socket)
            try:
                client = BridgeClient(socket)
                for method in ('auth.stepup.send', 'auth.security.send'):
                    self.assertEqual(await client.call(method, {'fixture': True}), {'accepted': True})
                with self.assertRaises(BridgeError):
                    await client.call('auth.mail.any', {'to': 'evil@example.com'})
                self.assertEqual([item['method'] for item in requests], ['auth.stepup.send', 'auth.security.send'])
            finally:
                server.close()
                await server.wait_closed()

    async def test_real_socket_host_dispatch_and_mailer_validate_contract_and_deduplicate(self):
        from web import host_bridge
        from web.backend.security import utc

        with tempfile.TemporaryDirectory(prefix='mailwire-', dir='/tmp') as directory:
            home = Path(directory)
            for name in ('web', 'state'):
                (home / name).mkdir(mode=0o700)
            policy = home / 'web/login-email.json'
            policy.write_text(json.dumps({'recipient': 'owner@example.com', 'policy_version': VERSION}))
            policy.chmod(0o600)
            controller = Mock()
            controller.call_local_api.return_value = {'enable_mail': True, 'sender_mail': 'sender@example.com'}
            controller.locked.side_effect = AssertionError('mail must not acquire certificate lock')
            bridge = host_bridge.Bridge(home, lambda: controller, uid=os.getuid(), management_host='example.com')
            now = 1700000000
            bridge.login_mail.clock = lambda: now
            proc = Mock(returncode=0)
            proc.poll.return_value = 0
            socket_path = str(home / 'bridge.sock')
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_path)
            server.listen(4)
            server.settimeout(0.1)
            stop = threading.Event()
            errors = []

            def identify(connection):
                if hasattr(socket, 'SO_PEERCRED') or hasattr(connection, 'getpeereid'):
                    return host_bridge.peer_uid(connection)
                # macOS CPython 未暴露 socket.getpeereid，仍用系统实际对端身份。
                uid, gid = ctypes.c_uint(), ctypes.c_uint()
                if ctypes.CDLL(None, use_errno=True).getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
                    raise OSError(ctypes.get_errno(), 'getpeereid')
                return uid.value

            def serve():
                while not stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    try:
                        host_bridge.handle_connection(connection, bridge, allowed_uid=os.getuid(), identify=identify)
                    except Exception as error:
                        errors.append(error)

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                with patch('web.login_mail.subprocess.Popen', return_value=proc) as smtp:
                    client = BridgeClient(socket_path)
                    stepup = {'code': '024681', 'policy_version': VERSION, 'operation': 'password.change'}
                    self.assertEqual(await client.call('auth.stepup.send', stepup), {'accepted': True})
                    event = {'event_id': 'b' * 32, 'event_type': 'new_login', 'policy_version': VERSION,
                             'at': utc(now), 'source_ip': IP, 'device': 'desktop'}
                    self.assertEqual(await client.call('auth.security.send', event), {'accepted': True})
                    self.assertEqual(smtp.call_count, 2)
                    # 使用新宿主实例及同一状态目录，模拟成功邮件回执丢失后重启重试。
                    bridge = host_bridge.Bridge(home, lambda: controller, uid=os.getuid(), management_host='example.com')
                    bridge.login_mail.clock = lambda: now
                    self.assertEqual(await client.call('auth.security.send', event), {'accepted': True})
                    self.assertEqual(smtp.call_count, 2)
                    for method, payload in (
                        ('auth.stepup.send', {**stepup, 'email': 'attacker@example.com'}),
                        ('auth.security.send', {**event, 'body': 'arbitrary message'}),
                        ('auth.security.send', {**event, 'policy_version': 'c' * 32}),
                    ):
                        with self.assertRaises(BridgeError):
                            await client.call(method, payload)
                    self.assertEqual(smtp.call_count, 2)
                    for call in smtp.call_args_list:
                        self.assertEqual(call.args[0][-1], 'owner@example.com')
                    controller.locked.assert_not_called()
            finally:
                stop.set()
                server.close()
                await asyncio.to_thread(worker.join, 2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
