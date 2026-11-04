"""有界的 API 令牌桶与临时 IP 封禁；不修改宿主网络规则。"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import secrets
from dataclasses import dataclass

from .mfa import MfaError
from .security import utc

DEFAULT_LIMITS = {
    'ip_requests_per_minute': 600,
    'session_requests_per_minute': 180,
    'block_after_violations': 20,
    'block_seconds': 300,
}
LIMIT_RANGES = {
    'ip_requests_per_minute': (120, 6000),
    'session_requests_per_minute': (60, 1200),
    'block_after_violations': (5, 100),
    'block_seconds': (60, 1800),
}
MAX_BUCKETS = 4096
RECOVERY_BUCKETS = 1024
MAX_BLOCKS = 1024
BUCKET_TTL = 120
RECOVERY_RATE = 60
RECOVERY_ROUTES = frozenset({
    ('POST', '/api/login'), ('GET', '/api/login/challenge'),
    ('POST', '/api/login/verify'), ('POST', '/api/login/resend'), ('POST', '/api/login/cancel'),
    ('GET', '/api/session'), ('POST', '/api/logout'), ('POST', '/api/password'),
    ('POST', '/api/stepup/start'), ('GET', '/api/stepup/challenge'),
    ('POST', '/api/stepup/resend'), ('POST', '/api/stepup/verify'), ('POST', '/api/stepup/cancel'),
    ('GET', '/api/abuse'), ('PUT', '/api/abuse'),
    ('GET', '/api/abuse/blocks'), ('POST', '/api/abuse/unblock'),
})


@dataclass(frozen=True)
class AbuseRejection:
    code: str
    retry_after: int


def ipv4(value):
    try:
        result = ipaddress.ip_address(value) if isinstance(value, str) else None
        if result is None or result.version != 4 or str(result) != value:
            raise ValueError()
        return str(result)
    except ValueError:
        raise MfaError(400, 'validation', '请提供有效的 IPv4 地址') from None


def validate_limits(body):
    if (not isinstance(body, dict) or set(body) != {'revision', 'limits'}
            or not isinstance(body['revision'], str) or not re.fullmatch(r'[0-9a-f]{32}', body['revision'])
            or not isinstance(body['limits'], dict) or set(body['limits']) != set(DEFAULT_LIMITS)):
        raise MfaError(400, 'validation', '接口防护配置不符合要求')
    for name, (minimum, maximum) in LIMIT_RANGES.items():
        value = body['limits'][name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise MfaError(400, 'validation', '接口防护额度超出允许范围')
    if body['limits']['session_requests_per_minute'] > body['limits']['ip_requests_per_minute']:
        raise MfaError(400, 'validation', '单会话额度不能超过 IP 总额度')


class AbuseMixin:
    def _abuse_schema(self, connection):
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS abuse_policy (
                id INTEGER PRIMARY KEY CHECK(id=1), revision TEXT NOT NULL,
                limits TEXT NOT NULL, last_clock REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS abuse_buckets (
                bucket TEXT PRIMARY KEY, ip TEXT NOT NULL, recovery INTEGER NOT NULL,
                tokens REAL NOT NULL, updated REAL NOT NULL,
                violations INTEGER NOT NULL DEFAULT 0, violation_start REAL NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS abuse_buckets_updated ON abuse_buckets(updated);
            CREATE TABLE IF NOT EXISTS abuse_blocks (
                ip TEXT PRIMARY KEY, blocked_at REAL NOT NULL, expires REAL NOT NULL);
        ''')
        connection.execute('INSERT OR IGNORE INTO abuse_policy VALUES(1,?,?,?)',
                           (secrets.token_hex(16), json.dumps(DEFAULT_LIMITS), self.clock()))

    def _abuse_cleanup(self, connection):
        now = self.clock()
        previous = connection.execute('SELECT last_clock FROM abuse_policy WHERE id=1').fetchone()[0]
        # 时钟回拨时丢弃短期状态，不能把临时限制延长为无期限锁定。
        if now < previous:
            connection.execute('DELETE FROM abuse_buckets')
            connection.execute('DELETE FROM abuse_blocks')
        connection.execute('UPDATE abuse_policy SET last_clock=? WHERE id=1', (now,))
        connection.execute('DELETE FROM abuse_buckets WHERE updated<=?', (now - BUCKET_TTL,))
        connection.execute('DELETE FROM abuse_blocks WHERE expires<=? OR blocked_at>? OR expires>?',
                           (now, now, now + LIMIT_RANGES['block_seconds'][1]))
        return now

    def _abuse_policy(self, connection):
        row = connection.execute('SELECT revision,limits FROM abuse_policy WHERE id=1').fetchone()
        return {'revision': row['revision'], 'limits': json.loads(row['limits'])}

    def abuse_settings(self):
        with self.transaction() as connection:
            self._abuse_cleanup(connection)
            return self._abuse_policy(connection)

    def _abuse_take(self, connection, bucket, ip, rate, now, recovery=False):
        row = connection.execute('SELECT * FROM abuse_buckets WHERE bucket=?', (bucket,)).fetchone()
        if row is None:
            maximum = RECOVERY_BUCKETS if recovery else MAX_BUCKETS - RECOVERY_BUCKETS
            count = connection.execute('SELECT COUNT(*) FROM abuse_buckets WHERE recovery=?', (int(recovery),)).fetchone()[0]
            if count >= maximum:
                return AbuseRejection('rate_limited', BUCKET_TTL)
            connection.execute('INSERT INTO abuse_buckets(bucket,ip,recovery,tokens,updated) VALUES(?,?,?,?,?)',
                               (bucket, ip, int(recovery), rate - 1, now))
            return None
        tokens = min(rate, row['tokens'] + max(0, now - row['updated']) * rate / 60)
        accepted = tokens >= 1
        connection.execute('UPDATE abuse_buckets SET tokens=?,updated=? WHERE bucket=?',
                           (tokens - 1 if accepted else tokens, now, bucket))
        return None if accepted else AbuseRejection('rate_limited', max(1, math.ceil((1 - tokens) * 60 / rate)))

    def check_abuse(self, ip, token, method, path):
        ip = ipv4(ip)
        with self.transaction() as connection:
            now = self._abuse_cleanup(connection)
            current, _ = self._session_row(connection, token)
            recovery = (method, path) in RECOVERY_ROUTES
            if recovery:
                # 有效会话拥有独立救援额度，避免同 NAT 的匿名请求耗尽解封入口。
                key = 'recovery:session:' + current['token_hash'] if current else 'recovery:ip:' + ip
                return self._abuse_take(connection, key, ip, RECOVERY_RATE, now, True)
            blocked = connection.execute('SELECT expires FROM abuse_blocks WHERE ip=?', (ip,)).fetchone()
            if blocked:
                return AbuseRejection('ip_temporarily_blocked', max(1, math.ceil(blocked['expires'] - now)))
            limits = self._abuse_policy(connection)['limits']
            if current:
                limited = self._abuse_take(connection, 'session:' + current['token_hash'], ip,
                                           limits['session_requests_per_minute'], now)
                if limited:
                    return limited
            bucket = 'ip:' + ip
            limited = self._abuse_take(connection, bucket, ip, limits['ip_requests_per_minute'], now)
            if not limited:
                return None
            row = connection.execute('SELECT violations,violation_start FROM abuse_buckets WHERE bucket=?', (bucket,)).fetchone()
            if row is None:
                return limited
            start = row['violation_start'] if now - row['violation_start'] < 60 else now
            violations = min(limits['block_after_violations'], row['violations'] + 1) if start == row['violation_start'] else 1
            connection.execute('UPDATE abuse_buckets SET violations=?,violation_start=? WHERE bucket=?', (violations, start, bucket))
            if (violations >= limits['block_after_violations']
                    and connection.execute('SELECT COUNT(*) FROM abuse_blocks').fetchone()[0] < MAX_BLOCKS):
                connection.execute('INSERT INTO abuse_blocks VALUES(?,?,?)', (ip, now, now + limits['block_seconds']))
                connection.execute('DELETE FROM abuse_buckets WHERE bucket=?', (bucket,))
                self._audit(connection, 'abuse.block', True, '来源 IP ' + ip + ' 请求持续超限，已临时封禁')
                return AbuseRejection('ip_temporarily_blocked', limits['block_seconds'])
            return limited

    def abuse_blocks(self, current_ip):
        with self.transaction() as connection:
            now = self._abuse_cleanup(connection)
            rows = connection.execute('SELECT * FROM abuse_blocks ORDER BY expires DESC,ip LIMIT ?', (MAX_BLOCKS,)).fetchall()
            return {'items': [{'ip': row['ip'], 'blocked_at': utc(row['blocked_at']), 'expires_at': utc(row['expires']),
                               'retry_after': max(1, math.ceil(row['expires'] - now)),
                               'reason': 'ip_rate_exceeded', 'current': row['ip'] == current_ip} for row in rows]}

    def update_abuse(self, token, ip, body, grant):
        validate_limits(body)
        with self.transaction() as connection:
            self._consume_stepup(connection, token, ip, 'PUT', '/api/abuse', body, grant)
            if self._abuse_policy(connection)['revision'] != body['revision']:
                raise MfaError(409, 'stale_revision', '接口防护配置已更新，请刷新后重试')
            connection.execute('UPDATE abuse_policy SET revision=?,limits=? WHERE id=1',
                               (secrets.token_hex(16), json.dumps(body['limits'])))
            # 新额度从完整令牌桶开始；救援额度与已有临时封禁继续保留。
            connection.execute('DELETE FROM abuse_buckets WHERE recovery=0')
            self._audit(connection, 'abuse.update', True, '接口防护额度已更新')
            return self._abuse_policy(connection)

    def unblock_abuse(self, token, ip, body, grant):
        if not isinstance(body, dict) or set(body) != {'ip'}:
            raise MfaError(400, 'validation', '请提供需要解除封禁的 IP 地址')
        target = ipv4(body['ip'])
        with self.transaction() as connection:
            self._consume_stepup(connection, token, ip, 'POST', '/api/abuse/unblock', body, grant)
            self._abuse_cleanup(connection)
            removed = connection.execute('DELETE FROM abuse_blocks WHERE ip=?', (target,)).rowcount > 0
            connection.execute('DELETE FROM abuse_buckets WHERE ip=? AND recovery=0', (target,))
            self._audit(connection, 'abuse.unblock', True, '来源 IP ' + target + ' 的临时封禁已解除')
            return {'ok': True, 'removed': removed}

    def clear_abuse_blocks(self, ip=None):
        target = ipv4(ip) if ip is not None else None
        with self.transaction() as connection:
            self._abuse_cleanup(connection)
            removed = connection.execute('DELETE FROM abuse_blocks' + (' WHERE ip=?' if target else ''),
                                         (target,) if target else ()).rowcount
            connection.execute('DELETE FROM abuse_buckets' + (' WHERE ip=?' if target else ''),
                               (target,) if target else ())
            self._audit(connection, 'abuse.rescue', True, '已通过私有终端清除接口临时限制')
            return removed
