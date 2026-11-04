from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .mfa import EmailLoginMixin, MfaError, masked_email
from .security import SecurityMixin

IDLE_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 8 * 60 * 60
PASSWORD_MIN = 12
PASSWORD_MAX = 128


def valid_password(value):
    if not isinstance(value, str) or not PASSWORD_MIN <= len(value) <= PASSWORD_MAX or "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=32768, r=8, p=3, maxmem=67108864)
    return "scrypt$32768$8$3$" + salt.hex() + "$" + digest.hex()


def verify_password(password, encoded):
    try:
        method, n, r, p, salt, expected = encoded.split("$")
        if (method, n, r, p) != ("scrypt", "32768", "8", "3"):
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=32768, r=8, p=3, maxmem=67108864)
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError, AttributeError):
        return False


def token_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AuthStore(SecurityMixin, EmailLoginMixin):
    def __init__(self, directory: Path, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("认证数据目录必须是权限 0700 的独立目录")
        self.path = directory / "auth.sqlite3"
        if self.path.is_symlink():
            raise ValueError("认证数据库不得为符号链接")
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        if not stat.S_ISREG(self.path.stat().st_mode) or self.path.stat().st_mode & 0o077:
            raise ValueError("认证数据库权限必须为 0600")
        with self.transaction() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                    must_change INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
                    csrf TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (
                    bucket TEXT NOT NULL, at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS attempts_bucket_at ON attempts(bucket, at);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                    action TEXT NOT NULL, success INTEGER NOT NULL, message TEXT NOT NULL);
            """)
            self._email_schema(connection)
            self._security_schema(connection)
        self.dummy_hash = password_hash(secrets.token_urlsafe(32))

    @contextmanager
    def transaction(self):
        with self.lock:
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def initialize(self, username, password, reset=False):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username) or not valid_password(password):
            raise ValueError("账号须为 3 至 64 位字母、数字或 ._-，密码须为 12 至 128 个字符")
        hashed = password_hash(password)
        with self.transaction() as connection:
            exists = connection.execute("SELECT username FROM users").fetchone()
            if not reset and exists:
                raise ValueError("管理员已经初始化；如需恢复，请使用 reset-password")
            if reset and (not exists or exists["username"] != username):
                raise ValueError("管理员账号不存在")
            if reset:
                connection.execute("UPDATE users SET password_hash=?,must_change=1,auth_version=auth_version+1 WHERE username=?", (hashed, username))
            else:
                connection.execute("INSERT INTO users(username,password_hash,must_change) VALUES (?, ?, 1)", (username, hashed))
            connection.execute("DELETE FROM sessions")
            connection.execute("DELETE FROM login_challenges")
            connection.execute("DELETE FROM attempts")
        self.audit("password_reset" if reset else "initialize", True, "管理员密码已重置" if reset else "管理员已初始化")

    def allow_attempt(self, ip, username, purpose="login"):
        now = self.clock()
        buckets = ((purpose + ":all", 40), (purpose + ":ip:" + token_hash(ip), 15),
                   (purpose + ":pair:" + token_hash(ip + "\x00" + username), 5))
        with self.transaction() as connection:
            connection.execute("DELETE FROM attempts WHERE at < ?", (now - 900,))
            for bucket, limit in buckets:
                count = connection.execute("SELECT COUNT(*) FROM attempts WHERE bucket=?", (bucket,)).fetchone()[0]
                if count >= limit:
                    return False
            connection.executemany("INSERT INTO attempts VALUES (?, ?)", [(bucket, now) for bucket, _ in buckets])
        return True

    def credentials_valid(self, username, password):
        with self.transaction() as connection:
            user = connection.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        valid = verify_password(password, user[0] if user else self.dummy_hash)
        return bool(user and valid)

    def login(self, username, password, ip=None):
        with self.transaction() as connection:
            user = connection.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        valid = verify_password(password, user[0] if user else self.dummy_hash)
        if not user or not valid:
            return None
        with self.transaction() as connection:
            current = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not current or not hmac.compare_digest(current["password_hash"], user[0]):
                return None
            policy = self._email_policy(connection, username)
            if policy:
                if not ip:
                    raise MfaError(403, "verification_required", "请完成邮箱验证码验证")
                return self._start_challenge(connection, username, ip, current, policy)
            return self._new_session(connection, username)

    def _new_session(self, connection, username, auth_level=1, policy_version=""):
        policy = self._email_policy(connection, username)
        if policy and (auth_level != 2 or policy_version != policy["policy_version"]):
            raise MfaError(403, "verification_required", "请完成邮箱验证码验证")
        user = connection.execute("SELECT must_change,auth_version FROM users WHERE username=?", (username,)).fetchone()
        now = self.clock()
        connection.execute("DELETE FROM sessions WHERE created<=? OR last_seen<=?", (now - ABSOLUTE_SECONDS, now - IDLE_SECONDS))
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        connection.execute("INSERT INTO sessions(token_hash,username,csrf,created,last_seen,auth_version,auth_level,policy_version,session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (token_hash(token), username, csrf, now, now, user["auth_version"], auth_level, policy_version, secrets.token_hex(16)))
        connection.execute("DELETE FROM sessions WHERE username=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE username=? ORDER BY created DESC,rowid DESC LIMIT 20)", (username, username))
        connection.execute("DELETE FROM stepup_challenges WHERE session_hash NOT IN (SELECT token_hash FROM sessions)")
        return token, self._session_data(username, csrf, user["must_change"], policy)

    def _session_data(self, username, csrf, must_change, policy):
        result = {"username": username, "csrf_token": csrf, "must_change_password": bool(must_change), "email_verification_enabled": bool(policy)}
        if policy:
            result["login_email_masked"] = masked_email(policy["email"])
        return result

    def create_session(self, username):
        with self.transaction() as connection:
            return self._new_session(connection, username)

    def _session_row(self, connection, token, hashed=None):
        if hashed is None:
            if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
                return None, None
            hashed = token_hash(token)
        row = connection.execute("SELECT sessions.*, users.must_change,users.auth_version AS current_version FROM sessions JOIN users USING(username) WHERE token_hash=?", (hashed,)).fetchone()
        if not row:
            return None, None
        now = self.clock()
        policy = self._email_policy(connection, row["username"])
        if (now - row["created"] >= ABSOLUTE_SECONDS or now - row["last_seen"] >= IDLE_SECONDS or now < row["created"]
                or row["auth_version"] != row["current_version"]
                or (policy and (row["auth_level"] != 2 or row["policy_version"] != policy["policy_version"]))):
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (hashed,))
            connection.execute("DELETE FROM stepup_challenges WHERE session_hash=?", (hashed,))
            return None, None
        return row, policy

    def session(self, token, touch=True):
        with self.transaction() as connection:
            row, policy = self._session_row(connection, token)
            if row is None:
                return None
            if touch:
                connection.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (self.clock(), token_hash(token)))
        return self._session_data(row["username"], row["csrf"], row["must_change"], policy)

    def logout(self, token):
        with self.transaction() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))
            connection.execute("DELETE FROM stepup_challenges WHERE session_hash=?", (token_hash(token),))

    def change_password(self, username, old_password, new_password, session_token=None):
        if not valid_password(new_password) or hmac.compare_digest(old_password.encode(), new_password.encode()):
            return None
        with self.transaction() as connection:
            row = connection.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        if not row or not verify_password(old_password, row[0]):
            return None
        hashed = password_hash(new_password)
        with self.transaction() as connection:
            policy = self._email_policy(connection, username)
            auth_level, policy_version = 1, ""
            if policy:
                current = connection.execute("SELECT sessions.*,users.auth_version AS current_version FROM sessions JOIN users USING(username) WHERE token_hash=? AND username=?",
                                             (token_hash(session_token or ""), username)).fetchone()
                now = self.clock()
                if (not current or current["auth_level"] != 2 or current["policy_version"] != policy["policy_version"]
                        or current["auth_version"] != current["current_version"] or not current["created"] <= now < current["created"] + ABSOLUTE_SECONDS
                        or now - current["last_seen"] >= IDLE_SECONDS):
                    raise MfaError(401, "unauthorized", "登录已失效，请重新登录")
                auth_level, policy_version = 2, policy["policy_version"]
            result = connection.execute("UPDATE users SET password_hash=?,must_change=0,auth_version=auth_version+1 WHERE username=? AND password_hash=?", (hashed, username, row[0]))
            if result.rowcount != 1:
                return None
            connection.execute("DELETE FROM sessions WHERE username=?", (username,))
            connection.execute("DELETE FROM login_challenges WHERE username=?", (username,))
            return self._new_session(connection, username, auth_level, policy_version)

    def audit(self, action, success, message):
        with self.transaction() as connection:
            self._audit(connection, action, success, message)

    def _audit(self, connection, action, success, message):
        connection.execute("INSERT INTO audit(at,action,success,message) VALUES (?,?,?,?)", (self.clock(), action, int(success), message))
        connection.execute("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 2000)")

    def audit_list(self):
        with self.transaction() as connection:
            rows = connection.execute("SELECT at,action,success,message FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        return {"items": [{"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["at"])), "action": row["action"], "success": bool(row["success"]), "message": row["message"]} for row in rows]}
