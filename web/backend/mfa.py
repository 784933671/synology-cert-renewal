from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
from dataclasses import dataclass

CODE_SECONDS = 300
CHALLENGE_SECONDS = 600
RESEND_SECONDS = 60
MAX_CODE_ATTEMPTS = 5


class MfaError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


@dataclass(frozen=True, repr=False)
class EmailDelivery:
    token: str
    code: str
    generation: str
    policy_version: str


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_email(value):
    return (isinstance(value, str) and len(value) <= 254 and not value.startswith("-")
            and re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value) is not None)


def masked_email(email):
    local, domain = email.split("@")
    return local[:1] + "***@" + domain


class EmailLoginMixin:
    def _email_schema(self, connection):
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS login_security (
                username TEXT PRIMARY KEY, email TEXT NOT NULL, policy_version TEXT NOT NULL,
                enabled INTEGER NOT NULL, verified INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS login_challenges (
                token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, ip_hash TEXT NOT NULL,
                auth_version INTEGER NOT NULL, password_snapshot TEXT NOT NULL,
                policy_version TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                code_mac TEXT NOT NULL, code_expires REAL NOT NULL, send_state TEXT NOT NULL,
                generation TEXT NOT NULL, last_sent REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS email_sends (bucket TEXT NOT NULL, at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS email_sends_bucket_at ON email_sends(bucket, at);
        """)
        for table, columns in {
            "users": {"auth_version": "INTEGER NOT NULL DEFAULT 1", "email_login_required": "INTEGER NOT NULL DEFAULT 0"},
            "sessions": {"auth_version": "INTEGER NOT NULL DEFAULT 1", "auth_level": "INTEGER NOT NULL DEFAULT 1", "policy_version": "TEXT NOT NULL DEFAULT ''"},
        }.items():
            existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            for name, declaration in columns.items():
                if name not in existing:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def _email_policy(self, connection, username):
        user = connection.execute("SELECT email_login_required FROM users WHERE username=?", (username,)).fetchone()
        policy = connection.execute("SELECT * FROM login_security WHERE username=?", (username,)).fetchone()
        if not user or user[0] not in (0, 1):
            raise MfaError(503, "mail_unavailable", "登录验证配置不可用，请联系管理员")
        if not policy and not user[0]:
            return None
        if (not policy or policy["enabled"] not in (0, 1) or policy["verified"] not in (0, 1)
                or policy["enabled"] != user[0] or not valid_email(policy["email"])
                or not isinstance(policy["policy_version"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", policy["policy_version"])):
            raise MfaError(503, "mail_unavailable", "登录验证配置不可用，请联系管理员")
        return policy if policy["enabled"] else None

    def configure_email_login(self, username, email=None, policy_version=None, enabled=True):
        if enabled and (not valid_email(email) or not isinstance(policy_version, str)
                        or not re.fullmatch(r"[0-9a-f]{32}", policy_version)):
            raise ValueError("登录邮箱或策略版本不正确")
        with self.transaction() as connection:
            if not connection.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise ValueError("管理员账号不存在")
            if enabled:
                connection.execute("INSERT INTO login_security(username,email,policy_version,enabled,verified) VALUES(?,?,?,1,0) "
                                   "ON CONFLICT(username) DO UPDATE SET email=excluded.email,policy_version=excluded.policy_version,enabled=1,verified=0",
                                   (username, email, policy_version))
            else:
                connection.execute("DELETE FROM login_security WHERE username=?", (username,))
            connection.execute("UPDATE users SET auth_version=auth_version+1,email_login_required=? WHERE username=?", (int(enabled), username))
            connection.execute("DELETE FROM sessions")
            connection.execute("DELETE FROM login_challenges")
            self._audit(connection, "email_login_enable" if enabled else "email_login_disable", True,
                        "邮箱登录验证已启用，原有会话已撤销" if enabled else "邮箱登录验证已通过私有终端停用，原有会话已撤销")

    def _reserve_email(self, connection, username, ip, now):
        buckets = (("all", 900, 40), ("all", 86400, 200),
                   ("user:" + digest(username), 900, 5), ("user:" + digest(username), 3600, 10),
                   ("user:" + digest(username), 86400, 20),
                   ("ip:" + digest(ip), 900, 10), ("ip:" + digest(ip), 86400, 40))
        connection.execute("DELETE FROM email_sends WHERE at<?", (now - 86400,))
        recent = connection.execute("SELECT MAX(at) FROM email_sends WHERE bucket=?", ("user:" + digest(username),)).fetchone()[0]
        if recent is not None and now < recent + RESEND_SECONDS:
            raise MfaError(429, "rate_limited", "验证码已发送，请稍后再试")
        for bucket, window, limit in buckets:
            count = connection.execute("SELECT COUNT(*) FROM email_sends WHERE bucket=? AND at>?", (bucket, now - window)).fetchone()[0]
            if count >= limit:
                raise MfaError(429, "rate_limited", "验证码发送过于频繁，请稍后重试")
        connection.executemany("INSERT INTO email_sends(bucket,at) VALUES(?,?)", [(bucket, now) for bucket in dict.fromkeys(item[0] for item in buckets)])

    def _code_mac(self, token, generation, code):
        return hmac.new(token.encode("ascii"), (generation + ":" + code).encode("ascii"), hashlib.sha256).hexdigest()

    def _start_challenge(self, connection, username, ip, user, policy):
        now = self.clock()
        self._reserve_email(connection, username, ip, now)
        token, generation = secrets.token_urlsafe(32), secrets.token_hex(16)
        code = f"{secrets.randbelow(1000000):06d}"
        connection.execute("DELETE FROM login_challenges WHERE username=? OR expires<=?", (username, now))
        connection.execute("INSERT INTO login_challenges(token_hash,username,ip_hash,auth_version,password_snapshot,policy_version,created,expires,code_mac,code_expires,send_state,generation,last_sent,attempts) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,'sending',?,?,0)",
                           (digest(token), username, digest(ip), user["auth_version"], digest(user["password_hash"]), policy["policy_version"],
                            now, now + CHALLENGE_SECONDS, self._code_mac(token, generation, code), now + CODE_SECONDS, generation, now))
        return EmailDelivery(token, code, generation, policy["policy_version"])

    def _challenge(self, connection, token, ip):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise MfaError(410, "challenge_expired", "登录验证已失效，请重新输入账号密码")
        row = connection.execute("SELECT * FROM login_challenges WHERE token_hash=?", (digest(token),)).fetchone()
        now = self.clock()
        if not row or not hmac.compare_digest(row["ip_hash"], digest(ip)) or not row["created"] <= now < row["expires"]:
            raise MfaError(410, "challenge_expired", "登录验证已失效，请重新输入账号密码")
        user = connection.execute("SELECT * FROM users WHERE username=?", (row["username"],)).fetchone()
        policy = self._email_policy(connection, row["username"])
        if (not user or not policy or user["auth_version"] != row["auth_version"]
                or not hmac.compare_digest(digest(user["password_hash"]), row["password_snapshot"])
                or not hmac.compare_digest(policy["policy_version"], row["policy_version"])):
            raise MfaError(410, "challenge_expired", "登录验证已失效，请重新输入账号密码")
        return row, policy

    def _challenge_meta(self, row, policy):
        now = self.clock()
        return {"verification_required": True, "email_masked": masked_email(policy["email"]),
                "expires_in": max(0, math.ceil(min(row["expires"], row["code_expires"]) - now)) if row["send_state"] == "ready" else 0,
                "resend_after": max(0, math.ceil(row["last_sent"] + RESEND_SECONDS - now))}

    def challenge(self, token, ip):
        with self.transaction() as connection:
            try:
                row, policy = self._challenge(connection, token, ip)
            except MfaError as error:
                if error.code == "challenge_expired":
                    return {"verification_required": False}
                raise
            return self._challenge_meta(row, policy)

    def resend_challenge(self, token, ip):
        with self.transaction() as connection:
            row, policy = self._challenge(connection, token, ip)
            now = self.clock()
            if row["attempts"] >= MAX_CODE_ATTEMPTS:
                raise MfaError(410, "challenge_expired", "验证码错误次数过多，请重新登录")
            if now < row["last_sent"] + RESEND_SECONDS:
                raise MfaError(429, "rate_limited", "验证码已发送，请稍后再试")
            self._reserve_email(connection, row["username"], ip, now)
            code, generation = f"{secrets.randbelow(1000000):06d}", secrets.token_hex(16)
            connection.execute("UPDATE login_challenges SET code_mac=?,code_expires=?,send_state='sending',generation=?,last_sent=? WHERE token_hash=?",
                               (self._code_mac(token, generation, code), min(now + CODE_SECONDS, row["expires"]), generation, now, digest(token)))
            return EmailDelivery(token, code, generation, policy["policy_version"])

    def finish_delivery(self, delivery, ip, success):
        with self.transaction() as connection:
            # 同一轮发送只允许完成一次；取消、重发或策略变更后不能重新激活旧码。
            connection.execute("UPDATE login_challenges SET send_state=?,code_mac=CASE WHEN ? THEN code_mac ELSE '' END "
                               "WHERE token_hash=? AND generation=? AND send_state='sending'",
                               ("ready" if success else "failed", int(success), digest(delivery.token), delivery.generation))
            self._audit(connection, "email_code_send", success, "登录验证码已发送" if success else "登录验证码发送未完成")
        return self.challenge(delivery.token, ip)

    def invalidate_delivery(self, delivery):
        with self.transaction() as connection:
            result = connection.execute("UPDATE login_challenges SET send_state='failed',code_mac='' "
                                        "WHERE token_hash=? AND generation=? AND send_state IN ('sending','ready')",
                                        (digest(delivery.token), delivery.generation))
            if result.rowcount:
                self._audit(connection, "email_code_send", False, "验证码发送请求已取消，本轮验证码已失效")

    def cancel_challenge(self, token, ip):
        if isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            with self.transaction() as connection:
                connection.execute("DELETE FROM login_challenges WHERE token_hash=? AND ip_hash=?", (digest(token), digest(ip)))

    def verify_challenge(self, token, ip, code):
        error, result = None, None
        with self.transaction() as connection:
            row, policy = self._challenge(connection, token, ip)
            if row["attempts"] >= MAX_CODE_ATTEMPTS:
                error = MfaError(410, "challenge_expired", "验证码错误次数过多，请重新登录")
            elif row["send_state"] != "ready" or self.clock() >= row["code_expires"]:
                error = MfaError(400, "code_expired", "验证码已失效，请重新发送")
            elif (not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code)
                  or not hmac.compare_digest(row["code_mac"], self._code_mac(token, row["generation"], code))):
                connection.execute("UPDATE login_challenges SET attempts=attempts+1 WHERE token_hash=?", (digest(token),))
                if row["attempts"] + 1 >= MAX_CODE_ATTEMPTS:
                    connection.execute("DELETE FROM login_challenges WHERE token_hash=?", (digest(token),))
                    error = MfaError(410, "challenge_expired", "验证码错误次数过多，请重新登录")
                else:
                    error = MfaError(400, "invalid_code", "验证码不正确，请重新输入")
            else:
                connection.execute("DELETE FROM login_challenges WHERE token_hash=?", (digest(token),))
                connection.execute("UPDATE login_security SET verified=1 WHERE username=? AND policy_version=?", (row["username"], policy["policy_version"]))
                result = self._new_session(connection, row["username"], auth_level=2, policy_version=policy["policy_version"])
            self._audit(connection, "email_login_verify", result is not None, "管理员邮箱验证登录成功" if result else "邮箱验证码校验未通过")
        if error:
            raise error
        return result
