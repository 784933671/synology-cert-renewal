"""网页登录的操作授权、会话可见性与持久安全提醒。"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import time
from dataclasses import dataclass

from .mfa import MfaError, digest, masked_email

OPERATIONS = {
    ('PUT', '/api/settings'): 'settings.update',
    ('PUT', '/api/security'): 'security.update',
    ('PUT', '/api/monitor'): 'monitor.update',
    ('POST', '/api/actions/renew'): 'renew',
    ('POST', '/api/password'): 'password.change',
    ('POST', '/api/sessions/revoke'): 'sessions.revoke',
    ('POST', '/api/sessions/revoke-others'): 'sessions.revoke_others',
}
CODE_TTL = 300
GRANT_TTL = 120
MAX_ATTEMPTS = 5


def utc(value):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(value))


def device_kind(agent):
    value = str(agent or '')[:512].lower()
    if any(item in value for item in ('ipad', 'tablet')):
        return 'tablet'
    if any(item in value for item in ('mobile', 'iphone', 'android')):
        return 'mobile'
    if any(item in value for item in ('windows', 'macintosh', 'x11', 'linux')):
        return 'desktop'
    return 'other' if value else 'unknown'


def address(value):
    return str(ipaddress.ip_address(value))


def operation_digest(method, path, body, session_token):
    if not isinstance(method, str) or not isinstance(path, str):
        raise MfaError(400, 'invalid_request', '操作内容不正确')
    operation = OPERATIONS.get((method, path))
    if operation is None or not isinstance(body, dict):
        raise MfaError(400, 'invalid_request', '该操作不支持二次验证')
    try:
        encoded = json.dumps([method, path, body], sort_keys=True, ensure_ascii=True,
                             separators=(',', ':'), allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError):
        raise MfaError(400, 'invalid_request', '操作内容不正确') from None
    if len(encoded) > 128 * 1024:
        raise MfaError(413, 'body_too_large', '操作内容过大')
    return operation, hmac.new(session_token.encode('ascii'), b'operation:' + encoded, hashlib.sha256).hexdigest()


@dataclass(frozen=True, repr=False)
class StepupDelivery:
    challenge_id: str
    code: str
    generation: str
    policy_version: str
    operation: str


class SecurityMixin:
    def _security_schema(self, connection):
        existing = {row[1] for row in connection.execute('PRAGMA table_info(sessions)')}
        for name, declaration in {'session_id': "TEXT NOT NULL DEFAULT ''", 'source_ip': "TEXT NOT NULL DEFAULT ''",
                                  'device': "TEXT NOT NULL DEFAULT 'unknown'"}.items():
            if name not in existing:
                connection.execute(f'ALTER TABLE sessions ADD COLUMN {name} {declaration}')
        for row in connection.execute("SELECT token_hash FROM sessions WHERE session_id='' OR session_id IS NULL").fetchall():
            connection.execute('UPDATE sessions SET session_id=? WHERE token_hash=?', (secrets.token_hex(16), row[0]))
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS stepup_challenges (
                id TEXT PRIMARY KEY, session_hash TEXT NOT NULL, ip_hash TEXT NOT NULL,
                auth_version INTEGER NOT NULL, policy_version TEXT NOT NULL,
                operation TEXT NOT NULL, request_hash TEXT NOT NULL, created REAL NOT NULL,
                expires REAL NOT NULL, code_mac TEXT NOT NULL, generation TEXT NOT NULL,
                last_sent REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL,
                grant_hash TEXT NOT NULL DEFAULT '', grant_expires REAL NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS stepup_session ON stepup_challenges(session_hash);
            CREATE TABLE IF NOT EXISTS stepup_attempts (session_hash TEXT NOT NULL, at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS known_login_sources (
                username TEXT NOT NULL, source_hash TEXT NOT NULL, at REAL NOT NULL,
                PRIMARY KEY(username,source_hash));
            CREATE TABLE IF NOT EXISTS security_failures (username TEXT NOT NULL, ip_hash TEXT NOT NULL, at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS security_alerts (
                id TEXT PRIMARY KEY, username TEXT NOT NULL, event_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL, policy_version TEXT NOT NULL, at REAL NOT NULL,
                source_ip TEXT NOT NULL, device TEXT NOT NULL, status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL,
                lease TEXT NOT NULL DEFAULT '', lease_until REAL NOT NULL DEFAULT 0);
        ''')

    def _secure_session(self, connection, token, require_email=True, allow_change=False):
        row, policy = self._session_row(connection, token)
        if row is None:
            raise MfaError(401, 'unauthorized', '登录已失效，请重新登录')
        if row['must_change'] and not allow_change:
            raise MfaError(403, 'password_change_required', '首次登录请先修改管理员密码')
        if require_email and (not policy or not policy['verified']):
            raise MfaError(403, 'email_security_required', '敏感操作需要已验证的登录邮箱，请由管理员在 NAS 私有终端配置并重新登录')
        return row, policy

    def _stepup_row(self, connection, token, ip, challenge_id=None):
        session, policy = self._secure_session(connection, token)
        if challenge_id is not None and (not isinstance(challenge_id, str) or not re.fullmatch(r'[0-9a-f]{32}', challenge_id)):
            raise MfaError(410, 'stepup_expired', '二次验证已失效，请重新发起操作')
        row = connection.execute('SELECT * FROM stepup_challenges WHERE session_hash=?' +
                                 (' AND id=?' if challenge_id is not None else '') + ' ORDER BY created DESC LIMIT 1',
                                 (digest(token), challenge_id) if challenge_id is not None else (digest(token),)).fetchone()
        if (not row or not row['created'] <= self.clock() < row['expires']
                or row['auth_version'] != session['auth_version'] or row['policy_version'] != policy['policy_version']
                or not hmac.compare_digest(row['ip_hash'], digest(address(ip)))):
            raise MfaError(410, 'stepup_expired', '二次验证已失效，请重新发起操作')
        return row, session, policy

    def _stepup_meta(self, row, policy):
        return {'verification_required': True, 'challenge_id': row['id'],
                'email_masked': masked_email(policy['email']), 'operation': row['operation'],
                'expires_in': max(0, math.ceil(row['expires'] - self.clock())) if row['state'] == 'ready' else 0,
                'resend_after': max(0, math.ceil(row['last_sent'] + 60 - self.clock()))}

    def _reserve_stepup_email(self, connection, username, ip, now):
        buckets = (("stepup:all", 900, 40), ("stepup:all", 86400, 200),
                   ("stepup:user:" + digest(username), 900, 5), ("stepup:user:" + digest(username), 3600, 10),
                   ("stepup:user:" + digest(username), 86400, 20),
                   ("stepup:ip:" + digest(ip), 900, 10))
        connection.execute("DELETE FROM email_sends WHERE at<?", (now - 86400,))
        recent = connection.execute("SELECT MAX(at) FROM email_sends WHERE bucket=?", ("stepup:user:" + digest(username),)).fetchone()[0]
        if recent is not None and now < recent + 60:
            raise MfaError(429, 'rate_limited', '操作验证码已发送，请稍后再试')
        for bucket, window, limit in buckets:
            count = connection.execute('SELECT COUNT(*) FROM email_sends WHERE bucket=? AND at>?', (bucket, now - window)).fetchone()[0]
            if count >= limit:
                raise MfaError(429, 'rate_limited', '操作验证码发送过于频繁，请稍后重试')
        connection.executemany('INSERT INTO email_sends(bucket,at) VALUES(?,?)', [(bucket, now) for bucket in dict.fromkeys(item[0] for item in buckets)])

    def start_stepup(self, token, ip, method, path, body):
        operation, request_hash = operation_digest(method, path, body, token)
        with self.transaction() as connection:
            session, policy = self._secure_session(connection, token)
            now = self.clock()
            connection.execute('DELETE FROM stepup_challenges WHERE expires<=?', (now,))
            previous = connection.execute('SELECT * FROM stepup_challenges WHERE session_hash=? ORDER BY created DESC LIMIT 1', (digest(token),)).fetchone()
            if (previous and previous['created'] <= now < previous['expires']
                    and previous['auth_version'] == session['auth_version'] and previous['policy_version'] == policy['policy_version']
                    and previous['request_hash'] == request_hash and previous['ip_hash'] == digest(address(ip))
                    and previous['state'] in ('ready', 'sending', 'failed') and previous['attempts'] < MAX_ATTEMPTS):
                return self._stepup_meta(previous, policy)
            connection.execute('DELETE FROM stepup_attempts WHERE at<?', (now - 900,))
            if connection.execute('SELECT COUNT(*) FROM stepup_attempts WHERE session_hash=?', (digest(token),)).fetchone()[0] >= 5:
                raise MfaError(429, 'rate_limited', '二次验证发起过于频繁，请稍后重试')
            self._reserve_stepup_email(connection, session['username'], address(ip), now)
            connection.execute('INSERT INTO stepup_attempts VALUES(?,?)', (digest(token), now))
            connection.execute('DELETE FROM stepup_challenges WHERE session_hash=?', (digest(token),))
            identifier, generation, code = secrets.token_hex(16), secrets.token_hex(16), f'{secrets.randbelow(1000000):06d}'
            mac = self._code_mac(token, generation, code)
            connection.execute('INSERT INTO stepup_challenges(id,session_hash,ip_hash,auth_version,policy_version,operation,request_hash,created,expires,code_mac,generation,last_sent,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                               (identifier, digest(token), digest(address(ip)), session['auth_version'], policy['policy_version'], operation, request_hash,
                                now, now + CODE_TTL, mac, generation, now, 'sending'))
            return StepupDelivery(identifier, code, generation, policy['policy_version'], operation)

    def stepup_status(self, token, ip):
        with self.transaction() as connection:
            try:
                row, _, policy = self._stepup_row(connection, token, ip)
            except MfaError as error:
                if error.code == 'stepup_expired':
                    return {'verification_required': False}
                raise
            return self._stepup_meta(row, policy) if row['state'] in ('sending', 'ready', 'failed') else {'verification_required': False}

    def resend_stepup(self, token, ip, identifier):
        with self.transaction() as connection:
            row, session, policy = self._stepup_row(connection, token, ip, identifier)
            now = self.clock()
            if row['state'] not in ('sending', 'ready', 'failed') or row['attempts'] >= MAX_ATTEMPTS:
                raise MfaError(410, 'stepup_expired', '二次验证已失效，请重新发起操作')
            if now < row['last_sent'] + 60:
                raise MfaError(429, 'rate_limited', '验证码已发送，请稍后再试')
            self._reserve_stepup_email(connection, session['username'], address(ip), now)
            generation, code = secrets.token_hex(16), f'{secrets.randbelow(1000000):06d}'
            connection.execute("UPDATE stepup_challenges SET state='sending',generation=?,code_mac=?,last_sent=? WHERE id=?",
                               (generation, self._code_mac(token, generation, code), now, identifier))
            return StepupDelivery(identifier, code, generation, policy['policy_version'], row['operation'])

    def finish_stepup(self, token, ip, delivery, success):
        with self.transaction() as connection:
            connection.execute("UPDATE stepup_challenges SET state=?,code_mac=CASE WHEN ? THEN code_mac ELSE '' END WHERE id=? AND session_hash=? AND generation=? AND state='sending'",
                               ('ready' if success else 'failed', int(success), delivery.challenge_id, digest(token), delivery.generation))
            self._audit(connection, 'stepup.send', success, '操作验证码已发送' if success else '操作验证码发送未完成')
        return self.stepup_status(token, ip)

    def invalidate_stepup(self, token, delivery):
        with self.transaction() as connection:
            connection.execute("UPDATE stepup_challenges SET state='failed',code_mac='' WHERE id=? AND session_hash=? AND generation=? AND state IN ('sending','ready')",
                               (delivery.challenge_id, digest(token), delivery.generation))

    def cancel_stepup(self, token, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
            raise MfaError(400, 'invalid_request', '操作验证标识不正确')
        with self.transaction() as connection:
            self._secure_session(connection, token)
            connection.execute('DELETE FROM stepup_challenges WHERE id=? AND session_hash=?', (identifier, digest(token)))

    def verify_stepup(self, token, ip, identifier, code):
        error, result = None, None
        with self.transaction() as connection:
            row, _, _ = self._stepup_row(connection, token, ip, identifier)
            if row['state'] != 'ready' or row['attempts'] >= MAX_ATTEMPTS:
                error = MfaError(410, 'stepup_expired', '二次验证已失效，请重新发起操作')
            elif not isinstance(code, str) or not re.fullmatch(r'[0-9]{6}', code) or not hmac.compare_digest(row['code_mac'], self._code_mac(token, row['generation'], code)):
                connection.execute('UPDATE stepup_challenges SET attempts=attempts+1 WHERE id=?', (identifier,))
                if row['attempts'] + 1 >= MAX_ATTEMPTS:
                    connection.execute("UPDATE stepup_challenges SET state='locked',code_mac='' WHERE id=?", (identifier,))
                error = MfaError(400 if row['attempts'] + 1 < MAX_ATTEMPTS else 410,
                                 'invalid_code' if row['attempts'] + 1 < MAX_ATTEMPTS else 'stepup_expired',
                                 '验证码不正确，请重新输入' if row['attempts'] + 1 < MAX_ATTEMPTS else '验证码错误次数过多，请重新发起操作')
            else:
                grant = secrets.token_urlsafe(32)
                connection.execute("UPDATE stepup_challenges SET state='verified',code_mac='',grant_hash=?,grant_expires=? WHERE id=?",
                                   (digest(grant), min(row['expires'], self.clock() + GRANT_TTL), identifier))
                result = {'token': grant, 'expires_in': min(GRANT_TTL, max(0, math.floor(row['expires'] - self.clock())))}
            self._audit(connection, 'stepup.verify', error is None, '敏感操作验证通过' if error is None else '敏感操作验证未通过')
        if error:
            raise error
        return result

    def _consume_stepup(self, connection, token, ip, method, path, body, grant):
        _, request_hash = operation_digest(method, path, body, token)
        self._secure_session(connection, token)
        if not isinstance(grant, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', grant):
            raise MfaError(428, 'stepup_required', '该操作需要再次验证身份')
        row, session, policy = self._stepup_row(connection, token, ip)
        if (row['state'] != 'verified' or self.clock() >= row['grant_expires'] or row['request_hash'] != request_hash
                or not hmac.compare_digest(row['grant_hash'], digest(grant))):
            raise MfaError(428, 'stepup_required', '操作授权已失效或内容已变化，请再次验证')
        connection.execute("UPDATE stepup_challenges SET state='consumed',grant_hash='' WHERE id=? AND state='verified'", (row['id'],))
        return session, policy

    def consume_stepup(self, token, ip, method, path, body, grant):
        with self.transaction() as connection:
            self._consume_stepup(connection, token, ip, method, path, body, grant)

    def sessions_list(self, token):
        with self.transaction() as connection:
            current, _ = self._secure_session(connection, token, require_email=False)
            rows = connection.execute('SELECT token_hash FROM sessions WHERE username=? ORDER BY created DESC LIMIT 100', (current['username'],)).fetchall()
            items = []
            for item in rows:
                row, _ = self._session_row(connection, None, hashed=item['token_hash'])
                if row is not None:
                    items.append({'id': row['session_id'], 'ip': row['source_ip'], 'device': row['device'],
                                  'created_at': utc(row['created']), 'last_seen': utc(row['last_seen']),
                                  'current': row['token_hash'] == digest(token)})
            return {'items': items}

    def revoke_sessions(self, token, ip, method, path, body, grant):
        with self.transaction() as connection:
            current, policy = self._consume_stepup(connection, token, ip, method, path, body, grant)
            if path.endswith('revoke-others'):
                rows = connection.execute('SELECT token_hash FROM sessions WHERE username=? AND token_hash<>?', (current['username'], digest(token))).fetchall()
            else:
                rows = connection.execute('SELECT token_hash FROM sessions WHERE username=? AND session_id=?', (current['username'], body['id'])).fetchall()
            hashes = [row[0] for row in rows]
            for value in hashes:
                connection.execute('DELETE FROM sessions WHERE token_hash=?', (value,))
                connection.execute('DELETE FROM stepup_challenges WHERE session_hash=?', (value,))
            self._audit(connection, 'sessions.revoke', True, '所选登录会话已撤销')
            self._queue_alert(connection, current['username'], policy, 'security_change', address(ip), current['device'])
            return {'ok': True, 'current_revoked': digest(token) in hashes}

    def _queue_alert(self, connection, username, policy, event_type, ip, device):
        if not policy or not policy['verified']:
            return
        now = self.clock()
        key = digest(policy['policy_version'] + ':' + username + ':' + event_type + ':' + ip)
        if connection.execute('SELECT 1 FROM security_alerts WHERE dedupe_key=? AND at>? LIMIT 1', (key, now - 900)).fetchone():
            return
        connection.execute('INSERT INTO security_alerts(id,username,event_type,dedupe_key,policy_version,at,source_ip,device,status,next_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (secrets.token_hex(16), username, event_type, key, policy['policy_version'], now, ip, device, 'pending', now))
        connection.execute('DELETE FROM security_alerts WHERE at<? OR id NOT IN (SELECT id FROM security_alerts ORDER BY at DESC LIMIT 200)', (now - 30 * 86400,))

    def record_login(self, token, ip, agent, notify=True):
        ip, device = address(ip), device_kind(agent)
        with self.transaction() as connection:
            session, policy = self._secure_session(connection, token, require_email=False, allow_change=True)
            connection.execute('UPDATE sessions SET source_ip=?,device=? WHERE token_hash=?', (ip, device, digest(token)))
            if not notify or not policy or not policy['verified']:
                return
            now = self.clock()
            key = digest(policy['policy_version'] + ':' + ip + ':' + device)
            existing = connection.execute('SELECT at FROM known_login_sources WHERE username=? AND source_hash=?', (session['username'], key)).fetchone()
            if not existing or now - existing[0] >= 30 * 86400 or now < existing[0]:
                self._queue_alert(connection, session['username'], policy, 'new_login', ip, device)
            connection.execute('INSERT INTO known_login_sources VALUES(?,?,?) ON CONFLICT(username,source_hash) DO UPDATE SET at=excluded.at', (session['username'], key, now))
            connection.execute('DELETE FROM known_login_sources WHERE at<? OR rowid NOT IN (SELECT rowid FROM known_login_sources ORDER BY at DESC LIMIT 200)', (now - 30 * 86400,))
            connection.execute('DELETE FROM security_failures WHERE username=? AND ip_hash=?', (session['username'], digest(ip)))

    def record_login_failure(self, username, ip, agent):
        with self.transaction() as connection:
            self._record_login_failure(connection, username, ip, agent)

    def _record_login_failure(self, connection, username, ip, agent):
        user = connection.execute('SELECT username FROM users WHERE username=?', (username,)).fetchone()
        if not user:
            return
        policy = self._email_policy(connection, username)
        if not policy or not policy['verified']:
            return
        ip, now = address(ip), self.clock()
        connection.execute('DELETE FROM security_failures WHERE at<?', (now - 900,))
        connection.execute('INSERT INTO security_failures VALUES(?,?,?)', (username, digest(ip), now))
        count = connection.execute('SELECT COUNT(*) FROM security_failures WHERE username=? AND ip_hash=?', (username, digest(ip))).fetchone()[0]
        if count >= 5:
            self._queue_alert(connection, username, policy, 'login_failures', ip, device_kind(agent))

    def record_security_change(self, token, ip, agent):
        with self.transaction() as connection:
            session, policy = self._secure_session(connection, token, require_email=False)
            self._queue_alert(connection, session['username'], policy, 'security_change', address(ip), device_kind(agent))

    def _prune_security(self, connection):
        now = self.clock()
        connection.execute('DELETE FROM security_alerts WHERE at<?', (now - 30 * 86400,))
        connection.execute('DELETE FROM stepup_challenges WHERE expires<=? OR session_hash NOT IN (SELECT token_hash FROM sessions)', (now,))
        connection.execute('DELETE FROM known_login_sources WHERE at<?', (now - 30 * 86400,))
        connection.execute('DELETE FROM security_failures WHERE at<?', (now - 900,))
        connection.execute('DELETE FROM stepup_attempts WHERE at<?', (now - 900,))

    def alerts_list(self, token):
        with self.transaction() as connection:
            session, _ = self._secure_session(connection, token, require_email=False)
            self._prune_security(connection)
            pending = connection.execute("SELECT COUNT(*) FROM security_alerts WHERE username=? AND status IN ('pending','sending')", (session['username'],)).fetchone()[0]
            rows = connection.execute('SELECT * FROM security_alerts WHERE username=? ORDER BY at DESC LIMIT 50', (session['username'],)).fetchall()
            return {'items': [{'id': row['id'], 'event_type': row['event_type'], 'at': utc(row['at']),
                               'source_ip': row['source_ip'], 'device': row['device'], 'status': row['status'], 'attempts': row['attempts']} for row in rows],
                    'pending_count': pending}

    def claim_alert(self):
        with self.transaction() as connection:
            self._prune_security(connection)
            now = self.clock()
            connection.execute("UPDATE security_alerts SET status='failed',lease='' WHERE (status='pending' OR (status='sending' AND lease_until<=?)) AND (at>? OR at<? OR attempts>=8)", (now, now + 5, now - 7 * 86400))
            # 同次扫描跳过旧策略，避免旧邮箱积压延迟新事件。
            while True:
                row = connection.execute("SELECT * FROM security_alerts WHERE (status='pending' AND next_at<=?) OR (status='sending' AND lease_until<=?) ORDER BY at LIMIT 1", (now, now)).fetchone()
                if not row:
                    return None
                policy = self._email_policy(connection, row['username'])
                if policy and policy['verified'] and policy['policy_version'] == row['policy_version']:
                    break
                connection.execute("UPDATE security_alerts SET status='failed',lease='' WHERE id=?", (row['id'],))
            lease = secrets.token_hex(16)
            connection.execute("UPDATE security_alerts SET status='sending',attempts=attempts+1,lease=?,lease_until=? WHERE id=?", (lease, now + 120, row['id']))
            return {'id': row['id'], 'lease': lease, 'params': {key: row[key] for key in ('event_type', 'policy_version', 'source_ip', 'device')} | {'event_id': row['id'], 'at': utc(row['at'])}}

    def finish_alert(self, identifier, lease, success):
        with self.transaction() as connection:
            row = connection.execute('SELECT attempts FROM security_alerts WHERE id=? AND lease=? AND status=?', (identifier, lease, 'sending')).fetchone()
            if not row:
                return
            status = 'sent' if success else 'failed' if row['attempts'] >= 8 else 'pending'
            connection.execute('UPDATE security_alerts SET status=?,next_at=?,lease=?,lease_until=0 WHERE id=? AND lease=?',
                               (status, self.clock() + min(3600, 30 * 2 ** min(row['attempts'], 7)), '', identifier, lease))


async def dispatch_security_alert(store, bridge):
    claim = await asyncio.to_thread(store.claim_alert)
    if claim is None:
        return False
    success = False
    try:
        result = await asyncio.wait_for(bridge.call('auth.security.send', claim['params']), 50)
        success = isinstance(result, dict) and result.get('accepted') is True
    except asyncio.CancelledError:
        # 保留租约，重启后使用同一事件ID重试；不把结果不明当作未发送。
        raise
    except Exception:
        pass
    await asyncio.to_thread(store.finish_alert, claim['id'], claim['lease'], success)
    return True


async def security_alert_worker(store, bridge):
    while True:
        try:
            delivered = await dispatch_security_alert(store, bridge)
        except asyncio.CancelledError:
            raise
        except Exception:
            delivered = False
        await asyncio.sleep(2 if delivered else 30)
