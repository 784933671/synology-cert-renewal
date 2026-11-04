"""邮箱二次验证、持久限流及原子消费回归。所有邮件均使用内存执行器。"""
import asyncio
import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import httpx

from web.backend.__main__ import main
from web.backend.app import CHALLENGE_COOKIE, COOKIE, SECURITY_HEADERS, create_app
from web.backend.auth import AuthStore, token_hash
from web.backend.bridge import BridgeError
from web.backend.config import Config
from web.backend.mfa import CODE_SECONDS, MfaError, valid_email

ORIGIN = "https://ttxli.cn:18443"
LAN_ORIGIN = "https://10.10.10.37:18443"
PASSWORD = "fixture-initial-password-42"
NEW_PASSWORD = "fixture-new-password-99"
EMAIL = "owner@example.com"
VERSION = "a" * 32
IP = "10.10.10.24"


class MailBridge:
    def __init__(self):
        self.calls = []
        self.error = None
        self.wait = None
        self.entered = asyncio.Event()
        self.accepted = True

    async def call(self, method, params=None):
        self.calls.append((method, dict(params or {})))
        if method == "auth.code.send":
            self.entered.set()
            if self.wait:
                await self.wait.wait()
            if self.error:
                raise self.error
            return {"accepted": self.accepted}
        return {"accepted": True}

    @property
    def code(self):
        return [params["code"] for method, params in self.calls if method == "auth.code.send"][-1]


class EmailLoginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="certweb-mfa-")
        self.root = Path(self.tmp.name)
        self.now = [1700000000.0]
        self.store = AuthStore(self.root / "data", clock=lambda: self.now[0])
        self.store.initialize("admin", PASSWORD)
        self.store.configure_email_login("admin", EMAIL, VERSION)
        self.config = Config(data_dir=self.root / "data", allowed_networks=("10.10.10.0/24",),
                             allowed_hosts=("ttxli.cn:18443",), origin=ORIGIN)
        self.bridge = MailBridge()
        self.app = create_app(self.config, self.store, self.bridge)
        self.client = self.make_client()

    def make_client(self, ip=IP, app=None):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app or self.app, client=(ip, 43210)), base_url=ORIGIN)

    async def asyncTearDown(self):
        await self.client.aclose()
        self.tmp.cleanup()

    async def post(self, path, data=None, client=None):
        return await (client or self.client).post("/api/" + path, json={} if data is None else data, headers={"Origin": ORIGIN})

    async def login(self, client=None):
        return await self.post("login", {"username": "admin", "password": PASSWORD}, client)

    async def verify(self, code=None, client=None):
        return await self.post("login/verify", {"code": self.bridge.code if code is None else code}, client)

    def count(self, table):
        with self.store.transaction() as connection:
            return connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]

    async def test_two_steps_and_cookie_security(self):
        response = await self.login()
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json(), {"verification_required": True, "email_masked": "o***@example.com", "expires_in": 300, "resend_after": 60})
        self.assertEqual(self.count("sessions"), 0)
        self.assertIsNone(self.client.cookies.get(COOKIE))
        token = self.client.cookies.get(CHALLENGE_COOKIE)
        self.assertEqual(len(token), 43)
        cookie = next(value for value in response.headers.get_list("set-cookie") if value.startswith(CHALLENGE_COOKIE + "="))
        for value in ("Secure", "HttpOnly", "SameSite=strict", "Path=/", "Max-Age=600"):
            self.assertIn(value, cookie)
        self.assertEqual((await self.client.get("/api/session")).status_code, 401)
        self.assertEqual((await self.client.get("/api/status")).status_code, 401)
        self.assertEqual(self.bridge.calls, [("auth.code.send", {"code": self.bridge.code, "policy_version": VERSION})])
        result = await self.verify()
        self.assertEqual(result.status_code, 200, result.text)
        self.assertTrue(result.json()["email_verification_enabled"])
        self.assertEqual(result.json()["login_email_masked"], "o***@example.com")
        self.assertIsNone(self.client.cookies.get(CHALLENGE_COOKIE))
        self.assertEqual(self.count("sessions"), 1)
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute("SELECT verified FROM login_security").fetchone()[0], 1)
        self.assertEqual((await self.client.get("/api/status")).json()["error"]["code"], "password_change_required")

    async def test_invalid_credentials_never_send(self):
        response = await self.post("login", {"username": "admin", "password": "wrong"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.bridge.calls, [])
        self.assertEqual(self.count("login_challenges"), 0)

    async def test_email_login_completes_on_each_exact_host(self):
        app = create_app(replace(self.config, allowed_hosts=("ttxli.cn:18443", "10.10.10.37:18443")),
                         self.store, self.bridge)
        for origin in (ORIGIN, LAN_ORIGIN):
            with self.subTest(origin=origin):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(IP, 43210)),
                                             base_url=origin) as client:
                    login = await client.post("/api/login", json={"username": "admin", "password": PASSWORD},
                                              headers={"Origin": origin})
                    self.assertEqual(login.status_code, 202, login.text)
                    self.assertIsNotNone(client.cookies.get(CHALLENGE_COOKIE))
                    self.assertIsNone(client.cookies.get(COOKIE))
                    verified = await client.post("/api/login/verify", json={"code": self.bridge.code},
                                                 headers={"Origin": origin})
                    self.assertEqual(verified.status_code, 200, verified.text)
                    self.assertTrue(verified.json()["email_verification_enabled"])
                    self.assertIsNone(client.cookies.get(CHALLENGE_COOKIE))
                    self.assertIsNotNone(client.cookies.get(COOKIE))
                    self.assertEqual((await client.get("/api/session")).status_code, 200)
                    cookie = next(value for value in verified.headers.get_list("set-cookie")
                                  if value.startswith(COOKIE + "="))
                    for attribute in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
                        self.assertIn(attribute, cookie)
                    self.assertNotIn("Domain=", cookie)
            self.now[0] += 61

    async def test_get_challenge_recovers_without_send_and_cancel_revokes(self):
        self.assertEqual((await self.client.get("/api/login/challenge")).json(), {"verification_required": False})
        await self.login()
        old = self.client.cookies.get(CHALLENGE_COOKIE)
        for _ in range(3):
            self.assertTrue((await self.client.get("/api/login/challenge")).json()["verification_required"])
        self.assertEqual(len(self.bridge.calls), 1)
        self.assertEqual((await self.post("login/cancel")).status_code, 200)
        self.client.cookies.set(CHALLENGE_COOKIE, old)
        self.assertEqual((await self.verify()).status_code, 410)
        self.assertEqual(self.count("sessions"), 0)

    async def test_same_origin_and_extra_keys_for_all_mutations(self):
        await self.login()
        for endpoint, data in (("verify", {"code": self.bridge.code}), ("resend", {}), ("cancel", {})):
            response = await self.client.post("/api/login/" + endpoint, json=data)
            self.assertEqual(response.status_code, 403)
            response = await self.post("login/" + endpoint, {**data, "email": "attacker@example.com"})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.bridge.calls), 1)

    async def test_code_expiration_allows_resend_without_extending_challenge(self):
        await self.login()
        old = self.bridge.code
        self.now[0] += CODE_SECONDS
        self.assertEqual((await self.verify(old)).json()["error"]["code"], "code_expired")
        self.assertEqual((await self.post("login/resend")).status_code, 200)
        self.now[0] += CODE_SECONDS
        self.assertEqual((await self.verify()).status_code, 410)
        self.assertEqual((await self.client.get("/api/login/challenge")).json(), {"verification_required": False})

    async def test_resend_cooldown_replaces_code_without_resetting_attempts(self):
        with patch("web.backend.mfa.secrets.randbelow", side_effect=[123456, 654321]):
            await self.login()
            self.assertEqual((await self.verify("999999")).status_code, 400)
            self.assertEqual((await self.post("login/resend")).status_code, 429)
            self.now[0] += 60
            response = await self.post("login/resend")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["resend_after"], 60)
            self.assertEqual((await self.verify("123456")).status_code, 400)
            with self.store.transaction() as connection:
                self.assertEqual(connection.execute("SELECT attempts FROM login_challenges").fetchone()[0], 2)
            self.assertEqual((await self.verify("654321")).status_code, 200)

    async def test_five_wrong_attempts_lock_challenge_including_non_ascii(self):
        await self.login()
        for code in ("x", "１２３４５６", "", None):
            response = await self.verify(code if code is not None else "wrong")
            self.assertEqual(response.json()["error"]["code"], "invalid_code")
        response = await self.verify("wrong")
        self.assertEqual(response.status_code, 410)
        self.assertEqual(self.count("sessions"), 0)
        self.assertEqual((await self.post("login/resend")).status_code, 410)

    async def test_cross_ip_cannot_read_resend_cancel_or_verify_challenge(self):
        await self.login()
        async with self.make_client("10.10.10.25") as other:
            other.cookies.set(CHALLENGE_COOKIE, self.client.cookies.get(CHALLENGE_COOKIE))
            self.assertEqual((await other.get("/api/login/challenge")).json(), {"verification_required": False})
            other.cookies.set(CHALLENGE_COOKIE, self.client.cookies.get(CHALLENGE_COOKIE))
            self.assertEqual((await self.post("login/cancel", client=other)).status_code, 200)
            other.cookies.set(CHALLENGE_COOKIE, self.client.cookies.get(CHALLENGE_COOKIE))
            self.assertEqual((await self.post("login/resend", client=other)).status_code, 410)
            other.cookies.set(CHALLENGE_COOKIE, self.client.cookies.get(CHALLENGE_COOKIE))
            self.assertEqual((await self.verify(client=other)).status_code, 410)
        self.assertEqual((await self.verify()).status_code, 200)

    async def test_concurrent_verify_consumes_once_across_store_instances(self):
        await self.login()
        token, code = self.client.cookies.get(CHALLENGE_COOKIE), self.bridge.code
        second = AuthStore(self.root / "data", clock=lambda: self.now[0])
        def verify(store):
            try:
                return store.verify_challenge(token, IP, code)
            except MfaError as error:
                return error.code
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = await asyncio.gather(loop.run_in_executor(executor, verify, self.store), loop.run_in_executor(executor, verify, second))
        self.assertEqual(sum(isinstance(result, tuple) for result in results), 1)
        self.assertIn("challenge_expired", results)
        self.assertEqual(self.count("sessions"), 1)

    async def test_smtp_failure_invalidates_code_preserves_challenge_and_limit(self):
        self.bridge.error = BridgeError("unavailable")
        response = await self.login()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "mail_unavailable")
        self.assertIsNotNone(self.client.cookies.get(CHALLENGE_COOKIE))
        self.assertEqual((await self.verify()).json()["error"]["code"], "code_expired")
        self.assertEqual((await self.post("login/resend")).status_code, 429)
        self.assertEqual(self.count("email_sends"), 3)
        self.now[0] += 60
        self.bridge.error = None
        self.assertEqual((await self.post("login/resend")).status_code, 200)
        self.assertEqual((await self.verify()).status_code, 200)

    async def test_smtp_timeout_invalidates_code(self):
        self.bridge.wait = asyncio.Event()
        app = create_app(replace(self.config, bridge_timeout=0.01), self.store, self.bridge)
        async with self.make_client(app=app) as client:
            result = await self.login(client)
            self.assertEqual(result.json()["error"]["code"], "mail_unavailable")
            self.assertEqual((await self.verify(client=client)).json()["error"]["code"], "code_expired")
        self.assertEqual(self.count("sessions"), 0)

    async def test_cancel_inflight_send_cannot_reactivate_challenge(self):
        await self.login()
        self.now[0] += 60
        self.bridge.wait = asyncio.Event()
        self.bridge.entered.clear()
        task = asyncio.create_task(self.post("login/resend"))
        await self.bridge.entered.wait()
        self.assertEqual((await self.verify()).json()["error"]["code"], "code_expired")
        await self.post("login/cancel")
        self.bridge.wait.set()
        response = await task
        self.assertEqual(response.status_code, 410)
        self.assertEqual(self.count("sessions"), 0)

    async def test_policy_change_during_delivery_invalidates_late_success(self):
        self.bridge.wait = asyncio.Event()
        task = asyncio.create_task(self.login())
        await self.bridge.entered.wait()
        self.store.configure_email_login("admin", EMAIL, "b" * 32)
        self.bridge.wait.set()
        self.assertEqual((await task).status_code, 410)
        self.assertEqual(self.count("sessions"), 0)
        self.assertEqual(self.count("login_challenges"), 0)

    async def test_request_cancellation_invalidates_pending_code(self):
        await self.login()
        self.now[0] += 60
        self.bridge.wait = asyncio.Event()
        self.bridge.entered.clear()
        task = asyncio.create_task(self.post("login/resend"))
        await self.bridge.entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual((await self.verify()).json()["error"]["code"], "code_expired")
        self.assertEqual((await self.post("login/resend")).status_code, 429)

    async def assert_cancel_during_finish(self, commit_before_cancel):
        await self.login()
        self.now[0] += 60
        original = self.store.finish_delivery
        loop = asyncio.get_running_loop()
        entered, completed, release = asyncio.Event(), asyncio.Event(), threading.Event()

        def delayed_finish(delivery, ip, success):
            if not success:
                return original(delivery, ip, success)
            result = original(delivery, ip, success) if commit_before_cancel else None
            loop.call_soon_threadsafe(entered.set)
            try:
                if not release.wait(5):
                    raise AssertionError("未释放发送完成线程")
                return result if commit_before_cancel else original(delivery, ip, success)
            finally:
                loop.call_soon_threadsafe(completed.set)

        with patch.object(self.store, "finish_delivery", delayed_finish):
            task = asyncio.create_task(self.post("login/resend"))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                release.set()
                await asyncio.wait_for(completed.wait(), 2)
        with self.store.transaction() as connection:
            row = connection.execute("SELECT send_state,code_mac FROM login_challenges").fetchone()
            self.assertEqual(tuple(row), ("failed", ""))
        self.assertEqual((await self.verify()).json()["error"]["code"], "code_expired")
        self.assertEqual((await self.post("login/resend")).status_code, 429)
        self.assertEqual(self.count("sessions"), 0)

    async def test_request_cancellation_before_success_commit_prevents_late_activation(self):
        await self.assert_cancel_during_finish(False)

    async def test_request_cancellation_after_success_commit_invalidates_ready_code(self):
        await self.assert_cancel_during_finish(True)

    async def test_old_delivery_cancellation_cannot_invalidate_new_generation(self):
        await self.login()
        token = self.client.cookies.get(CHALLENGE_COOKIE)
        self.now[0] += 60
        previous = self.store.resend_challenge(token, IP)
        self.store.finish_delivery(previous, IP, True)
        self.now[0] += 60
        current = self.store.resend_challenge(token, IP)
        self.store.invalidate_delivery(previous)
        self.store.finish_delivery(previous, IP, True)
        with self.store.transaction() as connection:
            row = connection.execute("SELECT generation,send_state FROM login_challenges").fetchone()
            self.assertEqual(tuple(row), (current.generation, "sending"))
        self.store.finish_delivery(current, IP, True)
        self.store.invalidate_delivery(previous)
        self.assertIsNotNone(self.store.verify_challenge(token, IP, current.code))

    async def test_send_rate_limit_survives_restart_and_reset(self):
        await self.login()
        for _ in range(4):
            self.now[0] += 60
            self.assertEqual((await self.post("login/resend")).status_code, 200)
        self.now[0] += 60
        restarted = AuthStore(self.root / "data", clock=lambda: self.now[0])
        app = create_app(self.config, restarted, self.bridge)
        async with self.make_client(app=app) as client:
            client.cookies.set(CHALLENGE_COOKIE, self.client.cookies.get(CHALLENGE_COOKIE))
            self.assertEqual((await self.post("login/resend", client=client)).status_code, 429)
        self.store.initialize("admin", NEW_PASSWORD, reset=True)
        response = await self.post("login", {"username": "admin", "password": NEW_PASSWORD})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(len(self.bridge.calls), 5)

    async def test_policy_change_and_password_reset_revoke_challenges_and_sessions(self):
        await self.login()
        await self.verify()
        session = self.client.cookies.get(COOKIE)
        self.now[0] += 60
        await self.login()
        challenge = self.client.cookies.get(CHALLENGE_COOKIE)
        self.store.configure_email_login("admin", EMAIL, "b" * 32)
        self.assertIsNone(self.store.session(session))
        self.assertEqual(self.store.challenge(challenge, IP), {"verification_required": False})
        self.now[0] += 60
        await self.login()
        self.store.initialize("admin", NEW_PASSWORD, reset=True)
        self.assertEqual((await self.verify()).status_code, 410)
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute("SELECT enabled,policy_version FROM login_security").fetchone()[:], (1, "b" * 32))

    async def test_change_password_preserves_mfa_and_rejects_helper_bypass(self):
        await self.login()
        first = await self.verify()
        with self.assertRaises(MfaError):
            self.store.change_password("admin", PASSWORD, NEW_PASSWORD)
        with self.assertRaises(MfaError):
            self.store.create_session("admin")
        with self.assertRaises(MfaError):
            self.store.login("admin", PASSWORD)
        async with self.make_client() as other:
            self.now[0] += 60
            await self.login(other)
            response = await self.client.post("/api/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
                                              headers={"Origin": ORIGIN, "X-CSRF-Token": first.json()["csrf_token"]})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["email_verification_enabled"])
            self.assertEqual((await self.verify(client=other)).status_code, 410)
        self.assertEqual((await self.client.get("/api/status")).status_code, 200)

    async def test_corrupt_policy_fails_closed(self):
        for mutate in ("UPDATE login_security SET email='invalid'", "DELETE FROM login_security"):
            with self.store.transaction() as connection:
                connection.execute(mutate)
            response = await self.login()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(self.count("sessions"), 0)
        self.assertEqual(self.bridge.calls, [])

    async def test_weaker_or_old_version_session_is_rejected(self):
        await self.login()
        await self.verify()
        token = self.client.cookies.get(COOKIE)
        with self.store.transaction() as connection:
            connection.execute("UPDATE sessions SET auth_level=1")
        self.assertIsNone(self.store.session(token))
        self.now[0] += 60
        await self.login()
        await self.verify()
        with self.store.transaction() as connection:
            connection.execute("UPDATE users SET auth_version=auth_version+1")
        self.assertEqual((await self.client.get("/api/session")).status_code, 401)

    async def test_secrets_absent_from_response_audit_database_and_error_logs(self):
        with patch("web.backend.mfa.secrets.randbelow", return_value=981527):
            response = await self.login()
        token, code = self.client.cookies.get(CHALLENGE_COOKIE), self.bridge.code
        self.assertNotIn(token, response.text)
        self.assertNotIn(code, response.text)
        self.assertNotIn(EMAIL, response.text)
        for secret in (token, code, PASSWORD):
            self.assertNotIn(secret.encode(), self.store.path.read_bytes())
            self.assertNotIn(secret, json.dumps(self.store.audit_list()))
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(response.headers[name], value)
        await self.verify()
        self.assertNotIn(code, json.dumps(self.store.audit_list()))

    async def test_completed_session_survives_restart(self):
        await self.login()
        await self.verify()
        restarted = AuthStore(self.root / "data", clock=lambda: self.now[0])
        self.assertTrue(restarted.session(self.client.cookies.get(COOKIE))["email_verification_enabled"])

    async def test_legacy_schema_migration_preserves_sessions_until_policy_enabled(self):
        directory = self.root / "legacy"
        directory.mkdir(mode=0o700)
        database = directory / "auth.sqlite3"
        with self.store.transaction() as connection:
            hashed = connection.execute("SELECT password_hash FROM users").fetchone()[0]
        with sqlite3.connect(database) as connection:
            connection.executescript("CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,must_change INTEGER NOT NULL DEFAULT 1);"
                                     "CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,created REAL NOT NULL,last_seen REAL NOT NULL);")
            connection.execute("INSERT INTO users VALUES(?,?,0)", ("admin", hashed))
            connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (token_hash("A" * 43), "admin", "old-csrf", self.now[0], self.now[0]))
        database.chmod(0o600)
        migrated = AuthStore(directory, clock=lambda: self.now[0])
        self.assertFalse(migrated.session("A" * 43)["email_verification_enabled"])
        self.assertIsNotNone(migrated.login("admin", PASSWORD))
        migrated.configure_email_login("admin", EMAIL, VERSION)
        self.assertIsNone(migrated.session("A" * 43))
        with self.assertRaises(MfaError):
            migrated.create_session("admin")

    async def test_account_ip_global_and_daily_limits_reserve_atomically(self):
        now = self.now[0]
        for bucket, count, age in (("user:" + token_hash("admin"), 5, 120),
                                    ("user:" + token_hash("admin"), 10, 1000),
                                    ("user:" + token_hash("admin"), 20, 7200),
                                    ("ip:" + token_hash(IP), 10, 120),
                                    ("ip:" + token_hash(IP), 40, 7200),
                                    ("all", 40, 120), ("all", 200, 7200)):
            with self.subTest(bucket=bucket, count=count, age=age):
                with self.store.transaction() as connection:
                    connection.execute("DELETE FROM email_sends")
                    connection.executemany("INSERT INTO email_sends(bucket,at) VALUES(?,?)", [(bucket, now - age)] * count)
                with self.assertRaises(MfaError) as error:
                    self.store.login("admin", PASSWORD, IP)
                self.assertEqual(error.exception.code, "rate_limited")
                self.assertEqual(self.count("email_sends"), count)
                self.assertEqual(self.count("login_challenges"), 0)

    async def test_cli_enable_disable_audits_and_revokes_without_email_output(self):
        await self.login()
        output = io.StringIO()
        with patch.dict(os.environ, {"CERTWEB_DATA_DIR": str(self.root / "data")}), patch("sys.stdout", output):
            self.assertEqual(main(["disable-email-login", "--username", "admin"]), 0)
            self.assertEqual(self.count("login_challenges"), 0)
            self.assertEqual((await self.login()).status_code, 200)
            self.assertEqual(main(["enable-email-login", "--username", "admin", "--email", EMAIL, "--policy-version", VERSION]), 0)
            self.assertEqual(self.count("sessions"), 0)
        self.assertNotIn(EMAIL, output.getvalue())
        self.assertNotIn(VERSION, output.getvalue())

    async def test_email_validation_matches_host_policy(self):
        from web.login_mail import email_valid
        for value in (EMAIL, "a+b@example.com", "-option@example.com", "a!b@example.com", "邮件@example.com", "x@y.example\n", "x" * 255, None):
            self.assertEqual(valid_email(value), email_valid(value))
        for email in ("-option@example.com", "a!b@example.com"):
            with self.assertRaises(ValueError):
                self.store.configure_email_login("admin", email, VERSION)

    async def test_new_password_login_cannot_bypass_send_cooldown(self):
        await self.login()
        token = self.client.cookies.get(CHALLENGE_COOKIE)
        response = await self.login()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(len(self.bridge.calls), 1)
        self.assertEqual(self.client.cookies.get(CHALLENGE_COOKIE), token)
        self.assertEqual((await self.verify()).status_code, 200)

    async def test_authenticated_renew_reuses_action_guards(self):
        self.assertEqual((await self.post("actions/renew")).status_code, 401)
        await self.login()
        result = await self.verify()
        headers = {"Origin": ORIGIN, "X-CSRF-Token": result.json()["csrf_token"]}
        self.assertEqual((await self.client.post("/api/actions/renew", json={}, headers=headers)).status_code, 403)
        with self.store.transaction() as connection:
            connection.execute("UPDATE users SET must_change=0")
        self.assertEqual((await self.client.post("/api/actions/renew", json={"force": True}, headers=headers)).status_code, 400)
        self.assertEqual((await self.client.post("/api/actions/renew", json={}, headers=headers)).status_code, 428)
        token = self.client.cookies.get(COOKIE)
        delivery = self.store.start_stepup(token, IP, 'POST', '/api/actions/renew', {})
        self.store.finish_stepup(token, IP, delivery, True)
        grant = self.store.verify_stepup(token, IP, delivery.challenge_id, delivery.code)
        headers['X-Step-Up-Token'] = grant['token']
        self.assertEqual((await self.client.post("/api/actions/renew", json={}, headers=headers)).status_code, 200)
        self.assertEqual(self.bridge.calls[-1], ("renew", {}))


if __name__ == "__main__":
    unittest.main()
