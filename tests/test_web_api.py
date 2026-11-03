"""局域网管理 API 的认证边界与真实 Unix socket 回归测试。"""
import asyncio
import copy
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import httpx

from web import access_policy
from web.backend.__main__ import main
from web.backend.app import BODY_LIMIT, COOKIE, SECURITY_HEADERS, create_app
from web.backend.auth import ABSOLUTE_SECONDS, IDLE_SECONDS, AuthStore, password_hash, verify_password
from web.backend.bridge import BridgeClient, BridgeError, safe_data
from web.backend.config import Config

ORIGIN = "https://ttxli.cn:18443"
INITIAL_PASSWORD = "fixture-initial-password-42"
NEW_PASSWORD = "fixture-changed-password-51"


def settings_payload():
    return {"revision": "a" * 64, "certificate_id": "AbCd01", "email": "owner@example.com", "renew_before_days": 2,
            "probes": [{"host": "127.0.0.1", "port": 5001, "server_name": "example.com"}],
            "schedule": {"enabled": True, "mode": "hourly", "interval_hours": 1, "hour": 0, "minute": 17},
            "notifications": {"success_enabled": True, "success_email": "owner@example.com", "failure_enabled": True, "failure_email": "owner@example.com"}}


class FixtureBridge:
    def __init__(self):
        self.calls = []
        self.error = None

    async def call(self, method, params=None):
        self.calls.append((method, copy.deepcopy(params)))
        if self.error:
            raise self.error
        if method == "security.update":
            try:
                return access_policy.write_policy(self.policy_path, params["access_mode"], params["revision"],
                                                  owner_uid=os.getuid(), gid=os.getgid())
            except access_policy.PolicyConflict:
                raise BridgeError("stale_revision") from None
        if method.startswith("settings."):
            return safe_data({**settings_payload(), "secret_id_configured": True, "secret_key_configured": True})
        if method in ("run", "check"):
            return {"accepted": True, "message": "请求已提交"}
        if method == "failures.list":
            return {"items": []}
        if method == "failures.get":
            return {"id": params["id"], "report": {"summary": "权限不足"}, "logs": []}
        return {"certificate": {"description": "测试证书"}, "pending": {}, "task": {"running": False}}


class WebApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="certweb-api-")
        self.root = Path(self.tmp.name)
        self.static = self.root / "static"
        (self.static / "assets").mkdir(parents=True)
        (self.static / "index.html").write_text("<!doctype html><title>证书管家</title>", encoding="utf-8")
        (self.static / "assets" / "app.js").write_text("console.log('fixture')", encoding="utf-8")
        self.now = [1700000000.0]
        self.store = AuthStore(self.root / "data", clock=lambda: self.now[0])
        self.store.initialize("admin", INITIAL_PASSWORD)
        self.config = Config(data_dir=self.root / "data", static_dir=self.static,
                             allowed_networks=("10.10.10.0/24",), denied_addresses=("10.10.10.1",),
                             allowed_hosts=("ttxli.cn:18443",), origin=ORIGIN)
        self.bridge = FixtureBridge()
        self.app = create_app(self.config, self.store, self.bridge)
        self.client = self.make_client()

    def make_client(self, peer="10.10.10.24", app=None, base=ORIGIN):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app or self.app, client=(peer, 43210)), base_url=base)

    async def asyncTearDown(self):
        await self.client.aclose()
        self.tmp.cleanup()

    async def login(self, client=None, password=INITIAL_PASSWORD):
        return await (client or self.client).post("/api/login", json={"username": "admin", "password": password}, headers={"Origin": ORIGIN})

    async def ready(self):
        with self.store.transaction() as connection:
            connection.execute("UPDATE users SET must_change=0")
        response = await self.login()
        self.assertEqual(response.status_code, 200, response.text)
        self.csrf = response.json()["csrf_token"]
        return {"Origin": ORIGIN, "X-CSRF-Token": self.csrf}

    async def test_business_requires_authentication(self):
        for route in ("status", "settings", "failures", "failures/id", "security", "audit", "session"):
            with self.subTest(route=route):
                response = await self.client.get("/api/" + route)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["error"]["code"], "unauthorized")
        self.assertEqual(self.bridge.calls, [])

    async def test_health_has_no_business_information(self):
        response = await self.client.get("/healthz")
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual(self.bridge.calls, [])

    async def test_login_cookie_and_first_password_gate(self):
        response = await self.login()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"username", "csrf_token", "must_change_password"})
        self.assertTrue(response.json()["must_change_password"])
        cookie = response.headers["set-cookie"]
        for part in (COOKIE + "=", "HttpOnly", "Secure", "SameSite=strict", "Path=/", "Max-Age=28800"):
            self.assertIn(part, cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertEqual((await self.client.get("/api/session")).status_code, 200)
        for route in ("status", "settings", "audit", "security"):
            denied = await self.client.get("/api/" + route)
            self.assertEqual(denied.json()["error"]["code"], "password_change_required")

    async def test_login_requires_same_origin_json(self):
        payload = {"username": "admin", "password": INITIAL_PASSWORD}
        for headers in ({}, {"Origin": "https://evil.example"}, {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"}):
            self.assertEqual((await self.client.post("/api/login", json=payload, headers=headers)).status_code, 403)
        response = await self.client.post("/api/login", content=json.dumps(payload), headers={"Origin": ORIGIN, "Content-Type": "text/plain"})
        self.assertEqual(response.status_code, 415)
        self.assertIsNone(self.client.cookies.get(COOKIE))

    async def test_all_mutations_require_csrf(self):
        await self.ready()
        for method, path, body in (("POST", "/api/logout", {}), ("POST", "/api/password", {}),
                                   ("POST", "/api/actions/run", {}), ("POST", "/api/actions/check", {}),
                                   ("PUT", "/api/settings", settings_payload())):
            with self.subTest(path=path):
                response = await self.client.request(method, path, json=body, headers={"Origin": ORIGIN})
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json()["error"]["code"], "csrf_failed")
        self.assertEqual(self.bridge.calls, [])

    async def test_password_change_checks_old_password_and_rotates_all_sessions(self):
        first = await self.login()
        old_token = self.client.cookies.get(COOKIE)
        async with self.make_client() as second:
            second_login = await self.login(second)
            self.assertEqual(second_login.status_code, 200)
            headers = {"Origin": ORIGIN, "X-CSRF-Token": first.json()["csrf_token"]}
            for old, new in (("wrong-password", NEW_PASSWORD), (INITIAL_PASSWORD, "short"), (INITIAL_PASSWORD, INITIAL_PASSWORD)):
                response = await self.client.post("/api/password", json={"current_password": old, "new_password": new}, headers=headers)
                self.assertEqual(response.status_code, 400)
            changed = await self.client.post("/api/password", json={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD}, headers=headers)
            self.assertEqual(changed.status_code, 200, changed.text)
            self.assertFalse(changed.json()["must_change_password"])
            self.assertNotEqual(changed.json()["csrf_token"], first.json()["csrf_token"])
            self.assertNotEqual(self.client.cookies.get(COOKIE), old_token)
            self.assertIsNone(self.store.session(old_token))
            self.assertEqual((await second.get("/api/session")).status_code, 401)
            self.assertEqual((await self.client.get("/api/status")).status_code, 200)

    async def test_logout_invalidates_server_session(self):
        headers = await self.ready()
        token = self.client.cookies.get(COOKIE)
        response = await self.client.post("/api/logout", json={}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Max-Age=0", response.headers["set-cookie"])
        self.assertIsNone(self.store.session(token))
        self.assertEqual((await self.client.get("/api/session")).status_code, 401)

    async def test_idle_timeout_survives_process_recreation(self):
        await self.ready()
        self.now[0] += IDLE_SECONDS
        store = AuthStore(self.root / "data", clock=lambda: self.now[0])
        self.assertIsNone(store.session(self.client.cookies.get(COOKIE)))

    async def test_absolute_timeout_cannot_be_extended_by_activity(self):
        await self.ready()
        token = self.client.cookies.get(COOKIE)
        for _ in range(16):
            self.now[0] += 1700
            self.assertIsNotNone(self.store.session(token))
        self.now[0] = 1700000000 + ABSOLUTE_SECONDS
        self.assertIsNone(self.store.session(token))

    async def test_background_status_polling_does_not_extend_idle_timeout(self):
        await self.ready()
        for _ in range(5):
            self.now[0] += 300
            self.assertEqual((await self.client.get("/api/status")).status_code, 200)
        self.now[0] += 300
        self.assertEqual((await self.client.get("/api/status")).status_code, 401)

    async def test_security_application_polling_does_not_extend_idle_timeout(self):
        await self.ready()
        for _ in range(5):
            self.now[0] += 300
            self.assertEqual((await self.client.get("/api/security")).status_code, 200)
        self.now[0] += 300
        self.assertEqual((await self.client.get("/api/security")).status_code, 401)

    async def test_user_navigation_extends_idle_but_not_absolute_expiry(self):
        await self.ready()
        self.now[0] += 1500
        self.assertEqual((await self.client.get("/api/settings")).status_code, 200)
        self.now[0] += 1500
        self.assertEqual((await self.client.get("/api/status")).status_code, 200)
        self.now[0] += 300
        self.assertEqual((await self.client.get("/api/session")).status_code, 401)

    async def test_rate_limit_persists_and_expires(self):
        for _ in range(5):
            self.assertEqual((await self.login(password="wrong-password")).status_code, 401)
        response = await self.login()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["retry-after"], "900")
        store = AuthStore(self.root / "data", clock=lambda: self.now[0])
        self.assertFalse(store.allow_attempt("10.10.10.24", "admin"))
        self.now[0] += 901
        self.assertEqual((await self.login()).status_code, 200)

    async def test_per_ip_and_global_limits_prevent_account_ip_rotation(self):
        for i in range(15):
            self.assertTrue(self.store.allow_attempt("10.10.10.25", "account" + str(i)))
        self.assertFalse(self.store.allow_attempt("10.10.10.25", "another"))
        for i in range(25):
            self.assertTrue(self.store.allow_attempt("10.10.10." + str(50 + i), "account"))
        self.assertFalse(self.store.allow_attempt("10.10.10.100", "account"))
        self.now[0] += 901
        self.assertTrue(self.store.allow_attempt("10.10.10.100", "account"))

    async def test_private_network_whitelist_public_ipv6_and_gateway_denied(self):
        for peer in ("8.8.8.8", "192.168.1.20", "10.10.11.20", "::1", "::ffff:10.10.10.24", "fd00::1", "10.10.10.1", "invalid"):
            async with self.make_client(peer) as client:
                response = await client.get("/healthz")
                self.assertEqual(response.status_code, 403, peer)
        async with self.make_client("10.10.10.37") as client:
            self.assertEqual((await client.get("/healthz")).status_code, 200)

    async def test_default_network_config_denies_lan(self):
        app = create_app(replace(self.config, allowed_networks=()), self.store, self.bridge)
        async with self.make_client(app=app) as client:
            self.assertEqual((await client.get("/healthz")).status_code, 403)

    async def test_loopback_only_allows_health_and_checks_host(self):
        async with self.make_client("127.0.0.1") as client:
            self.assertEqual((await client.get("/healthz")).json(), {"ok": True})
            self.assertEqual((await client.get("/api/session")).status_code, 403)
            self.assertEqual((await client.get("/")).status_code, 403)
            self.assertEqual((await client.get("/healthz", headers={"Host": "localhost"})).status_code, 400)

    async def test_proxy_headers_rejected_even_from_lan(self):
        for header in ("Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Forwarded-Whatever"):
            response = await self.client.get("/healthz", headers={header: "10.10.10.24"})
            self.assertEqual(response.status_code, 403, header)
            self.assertEqual(response.json()["error"]["code"], "proxy_forbidden")
        async with self.make_client("8.8.8.8") as client:
            self.assertEqual((await client.get("/healthz", headers={"X-Forwarded-For": "10.10.10.24"})).status_code, 403)

    async def test_host_allowlist_is_exact_and_http_denied(self):
        for host in ("evil.example", "ttxli.cn", "ttxli.cn:443", "ttxli.cn.evil:18443", "ttxli.cn:18443@evil.example"):
            self.assertEqual((await self.client.get("/healthz", headers={"Host": host})).status_code, 400)
        async with self.make_client(base="http://ttxli.cn:18443") as client:
            self.assertEqual((await client.get("/healthz")).json()["error"]["code"], "https_required")

    async def test_security_headers_on_success_and_error_no_cors(self):
        for path in ("/healthz", "/api/status", "/missing"):
            response = await self.client.get(path)
            for name, value in SECURITY_HEADERS.items():
                self.assertEqual(response.headers[name], value)
            self.assertNotIn("access-control-allow-origin", response.headers)
            self.assertNotIn("server", response.headers)
            self.assertNotIn("strict-transport-security", response.headers)
        response = await self.client.options("/api/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn("access-control-allow-origin", response.headers)

    async def test_management_does_not_set_or_clear_shared_hostname_hsts(self):
        for path in ("/", "/assets/app.js", "/healthz", "/api/session", "/missing"):
            response = await self.client.get(path)
            self.assertNotIn("strict-transport-security", response.headers)
        response = await self.login()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("strict-transport-security", response.headers)
        self.assertIn("Secure", response.headers["set-cookie"])
        denied = await self.client.get("/healthz", headers={"Host": "evil.example"})
        self.assertEqual(denied.status_code, 400)
        self.assertNotIn("strict-transport-security", denied.headers)

    async def test_body_limit_json_shape_and_duplicate_keys(self):
        headers = {"Origin": ORIGIN, "Content-Type": "application/json"}
        too_large = await self.client.post("/api/login", content=b"x" * (BODY_LIMIT + 1), headers=headers)
        self.assertEqual(too_large.status_code, 413)
        for content in ('[]', '{"username":"admin","username":"other","password":"secret"}', '{"password":NaN}', "{bad"):
            response = await self.client.post("/api/login", content=content, headers=headers)
            self.assertEqual(response.status_code, 400)
            self.assertNotIn(content, response.text)

    async def test_surrogate_password_is_rejected_without_internal_error(self):
        response = await self.client.post("/api/login", content=b'{"username":"admin","password":"\\ud800"}',
                                          headers={"Origin": ORIGIN, "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 400)

    async def test_duplicate_security_headers_and_query_parameters_are_rejected(self):
        for headers in ([("Host", "ttxli.cn:18443"), ("Host", "evil.example")],
                        [("Origin", ORIGIN), ("Origin", "https://evil.example")]):
            response = await self.client.post("/api/login", json={"username": "admin", "password": INITIAL_PASSWORD}, headers=headers)
            self.assertEqual(response.status_code, 400)
        self.assertEqual((await self.client.get("/api/status?path=/root/private")).status_code, 400)

    async def test_chunked_oversized_body_is_rejected(self):
        async def chunks():
            yield b"x" * BODY_LIMIT
            yield b"x"
        response = await self.client.post("/api/login", content=chunks(), headers={"Origin": ORIGIN, "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)

    async def test_body_read_timeout(self):
        app = create_app(replace(self.config, body_timeout=0.01), self.store, self.bridge)
        async with self.make_client(app=app) as client:
            async def delayed():
                await asyncio.sleep(0.05)
                yield b"{}"
            response = await client.post("/api/login", content=delayed(), headers={"Origin": ORIGIN, "Content-Type": "application/json"})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"]["code"], "timeout")

    async def test_static_spa_fallback_and_path_traversal(self):
        for path in ("/", "/login", "/overview", "/renewal"):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn("证书管家", response.text)
        self.assertEqual((await self.client.get("/assets/app.js")).status_code, 200)
        for path in ("/%2e%2e/auth.sqlite3", "/%252e%252e/auth.sqlite3", "/assets/%2e%2e/index.html", "/.env", "/%5cetc/passwd", "/%00"):
            self.assertEqual((await self.client.get(path)).status_code, 400, path)
        for path in ("/assets/missing.js", "/assets/app.js.map", "/auth.sqlite3", "/api/anything", "/docs", "/openapi.json"):
            self.assertEqual((await self.client.get(path)).status_code, 404, path)

    async def test_static_symlink_escape_is_blocked(self):
        private = self.root / "private.js"
        private.write_text("private-fixture-content")
        (self.static / "assets" / "escape.js").symlink_to(private)
        response = await self.client.get("/assets/escape.js")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("private-fixture-content", response.text)

    async def test_unknown_endpoints_cannot_map_to_arbitrary_bridge_actions(self):
        headers = await self.ready()
        response = await self.client.post("/api/actions/shell", json={"command": "example"}, headers=headers)
        self.assertEqual(response.status_code, 405)
        for path in ("/api/failures/%2Fetc%2Fpasswd", "/api/failures/abc.txt"):
            self.assertIn((await self.client.get(path)).status_code, (400, 404))
        self.assertEqual(self.bridge.calls, [])

    async def test_fixed_bridge_mapping_and_audit(self):
        headers = await self.ready()
        for path, method in (("status", "status"), ("settings", "settings.get"), ("failures", "failures.list"), ("failures/abc-001", "failures.get")):
            self.assertEqual((await self.client.get("/api/" + path)).status_code, 200)
            self.assertEqual(self.bridge.calls[-1][0], method)
        for action in ("run", "check"):
            self.assertEqual((await self.client.post("/api/actions/" + action, json={}, headers=headers)).status_code, 200)
            self.assertEqual(self.bridge.calls[-1], (action, None))
        response = await self.client.put("/api/settings", json=settings_payload(), headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.bridge.calls[-1], ("settings.update", settings_payload()))
        audit = (await self.client.get("/api/audit")).json()
        self.assertIn("settings.update", [item["action"] for item in audit["items"]])
        self.assertNotIn(INITIAL_PASSWORD, json.dumps(audit))

    async def test_action_rejects_force_and_extra_parameters(self):
        headers = await self.ready()
        for action in ("run", "check"):
            response = await self.client.post("/api/actions/" + action, json={"force": True}, headers=headers)
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.bridge.calls, [])

    async def test_settings_validation_and_secrets_not_in_output_or_audit(self):
        headers = await self.ready()
        data = settings_payload()
        data.update(secret_id="fixtureSecretId", secret_key="fixtureSecretKey")
        response = await self.client.put("/api/settings", json=data, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.bridge.calls[-1][1]["secret_key"], "fixtureSecretKey")
        self.assertNotIn("fixtureSecret", response.text)
        self.assertNotIn("fixtureSecret", (await self.client.get("/api/audit")).text)
        invalid = [dict(data, renew_before_days=True), dict(data, renew_before_days=0), dict(data, renew_before_days=31),
                   dict(data, description="not-writable"), dict(data, revision="invalid"), dict(data, email="owner@example.com\nBcc:x"),
                   dict(data, secret_id="", secret_key="only-one")]
        for value in invalid:
            self.assertEqual((await self.client.put("/api/settings", json=value, headers=headers)).status_code, 400)
        self.assertEqual(len(self.bridge.calls), 1)

    async def test_settings_nested_fields_validated(self):
        headers = await self.ready()
        for key, values in (("schedule", {"minute": 60, "hour": 24, "interval_hours": 5, "mode": "unsupported", "enabled": "yes"}),
                            ("notifications", {"failure_email": "invalid", "success_enabled": "false"})):
            for field, value in values.items():
                data = settings_payload()
                data[key][field] = value
                self.assertEqual((await self.client.put("/api/settings", json=data, headers=headers)).status_code, 400)
        for field, value in (("port", 0), ("port", 65536), ("host", "x; command"), ("server_name", "https://example.com")):
            data = settings_payload()
            data["probes"][0][field] = value
            self.assertEqual((await self.client.put("/api/settings", json=data, headers=headers)).status_code, 400)
        self.assertEqual(self.bridge.calls, [])

    async def test_disabled_email_and_probe_limits_match_executor(self):
        headers = await self.ready()
        data = settings_payload()
        data["notifications"].update(success_enabled=False, success_email="", failure_enabled=False, failure_email="")
        self.assertEqual((await self.client.put("/api/settings", json=data, headers=headers)).status_code, 200)
        data["notifications"]["success_email"] = "invalid"
        self.assertEqual((await self.client.put("/api/settings", json=data, headers=headers)).status_code, 400)
        data["notifications"]["success_email"] = "-owner@example.com"
        self.assertEqual((await self.client.put("/api/settings", json=data, headers=headers)).status_code, 400)
        data["notifications"]["success_email"] = ""
        data["probes"] *= 9
        self.assertEqual((await self.client.put("/api/settings", json=data, headers=headers)).status_code, 400)

    async def test_bridge_errors_have_fixed_safe_mapping(self):
        headers = await self.ready()
        for code, status in (("validation", 400), ("busy", 409), ("stale_revision", 409), ("unavailable", 503), ("internal", 502)):
            self.bridge.error = BridgeError(code)
            response = await self.client.post("/api/actions/check", json={}, headers=headers)
            self.assertEqual(response.status_code, status)
            self.assertEqual(response.json()["error"]["code"], code)
        self.bridge.error = RuntimeError("fixtureSecretKey=do-not-echo /root/private.json")
        response = await self.client.get("/api/status")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("fixtureSecretKey", response.text)
        self.assertNotIn("private.json", response.text)

    async def test_security_response_reports_enforced_policy(self):
        await self.ready()
        self.assertEqual((await self.client.get("/api/security")).json(), {
            "lan_only": True, "allowed_networks": ["10.10.10.0/24"], "https": True,
            "session_idle_minutes": 30, "session_absolute_hours": 8,
            "access_mode": "lan", "applied_mode": "lan", "revision": "0" * 32, "pending": False})

    async def configure_access_policy(self, mode="lan", peer="10.10.10.24"):
        self.policy_path = self.root / "access/access.json"
        value = access_policy.initialize_policy(self.policy_path, mode, os.getuid(), os.getgid())
        self.bridge.policy_path = self.policy_path
        reader = patch("web.backend.config.read_policy", side_effect=lambda path: access_policy.read_policy(path, os.getuid()))
        reader.start()
        self.addCleanup(reader.stop)
        self.config = replace(self.config, access_policy_file=self.policy_path)
        self.app = create_app(self.config, self.store, self.bridge)
        await self.client.aclose()
        self.client = self.make_client(peer=peer)
        return value

    async def test_public_mode_accepts_public_and_gateway_sources_but_still_requires_login(self):
        await self.configure_access_policy("public", peer="203.0.113.8")
        for peer in ("203.0.113.8", "10.10.10.1"):
            async with self.make_client(peer) as client:
                self.assertEqual((await client.get("/api/status")).status_code, 401)
                self.assertEqual((await self.login(client)).status_code, 200)
                self.assertEqual((await client.get("/api/status")).json()["error"]["code"], "password_change_required")
        async with self.make_client("2001:db8::1") as client:
            self.assertEqual((await self.login(client)).status_code, 403)

    async def test_public_mode_preserves_host_origin_proxy_csrf_and_https_guards(self):
        await self.configure_access_policy("public", peer="203.0.113.8")
        headers = await self.ready()
        self.assertEqual((await self.client.get("/api/status", headers={"Host": "evil.example"})).status_code, 400)
        self.assertEqual((await self.client.get("/api/status", headers={"X-Forwarded-For": "10.10.10.24"})).status_code, 403)
        self.assertEqual((await self.client.post("/api/actions/check", json={}, headers={"Origin": "https://evil.example"})).status_code, 403)
        self.assertEqual((await self.client.post("/api/actions/check", json={}, headers={"Origin": ORIGIN})).json()["error"]["code"], "csrf_failed")
        async with self.make_client("203.0.113.8", base="http://ttxli.cn:18443") as client:
            self.assertEqual((await client.get("/api/status")).status_code, 403)
        self.assertEqual((await self.client.post("/api/actions/check", json={}, headers=headers)).status_code, 200)

    async def test_policy_changes_are_hot_loaded_without_restarting_application(self):
        current = await self.configure_access_policy()
        async with self.make_client("203.0.113.8") as client:
            self.assertEqual((await client.get("/api/status")).status_code, 403)
            changed = access_policy.write_policy(self.policy_path, "public", current["revision"], os.getuid(), os.getgid())
            self.assertEqual((await client.get("/api/status")).status_code, 401)
            access_policy.write_policy(self.policy_path, "lan", changed["revision"], os.getuid(), os.getgid())
            self.assertEqual((await client.get("/api/status")).status_code, 403)

    async def test_configured_missing_or_corrupt_policy_denies_all_requests(self):
        await self.configure_access_policy("public")
        self.policy_path.unlink()
        self.assertEqual((await self.client.get("/healthz")).status_code, 503)
        self.policy_path.write_text('{"mode":"public","revision":"bad"}')
        self.policy_path.chmod(0o640)
        self.assertEqual((await self.client.get("/api/session")).status_code, 503)
        self.assertEqual(self.bridge.calls, [])

    async def test_security_update_requires_authentication_csrf_and_first_password_change(self):
        value = await self.configure_access_policy()
        body = {"access_mode": "public", "revision": value["revision"]}
        self.assertEqual((await self.client.put("/api/security", json=body, headers={"Origin": ORIGIN})).status_code, 401)
        login = await self.login()
        headers = {"Origin": ORIGIN, "X-CSRF-Token": login.json()["csrf_token"]}
        self.assertEqual((await self.client.put("/api/security", json=body, headers=headers)).json()["error"]["code"], "password_change_required")
        await self.ready()
        self.assertEqual((await self.client.put("/api/security", json=body, headers={"Origin": ORIGIN})).json()["error"]["code"], "csrf_failed")
        self.assertEqual(self.bridge.calls, [])

    async def test_security_update_reports_pending_application_and_rejects_stale_revision(self):
        value = await self.configure_access_policy()
        access_policy.write_applied(self.policy_path, value, os.getuid(), os.getgid())
        headers = await self.ready()
        body = {"access_mode": "public", "revision": value["revision"]}
        response = await self.client.put("/api/security", json=body, headers=headers)
        self.assertEqual(response.status_code, 200)
        saved = response.json()
        self.assertEqual(saved["access_mode"], "public")
        self.assertEqual(saved["applied_mode"], "lan")
        self.assertTrue(saved["pending"])
        self.assertFalse(saved["lan_only"])
        self.assertEqual(saved["allowed_networks"], ["0.0.0.0/0"])
        self.assertEqual(self.bridge.calls[-1], ("security.update", body))
        current = access_policy.read_policy(self.policy_path, os.getuid())
        access_policy.write_applied(self.policy_path, current, os.getuid(), os.getgid())
        applied = (await self.client.get("/api/security")).json()
        self.assertEqual(applied["applied_mode"], "public")
        self.assertFalse(applied["pending"])
        stale = await self.client.put("/api/security", json=body, headers=headers)
        self.assertEqual(stale.status_code, 409)
        audit = (await self.client.get("/api/audit")).json()["items"]
        updates = [entry for entry in audit if entry["action"] == "security.update"]
        self.assertEqual({entry["success"] for entry in updates}, {True, False})

    async def test_security_can_close_public_access_without_skipping_save_response(self):
        value = await self.configure_access_policy("public", peer="203.0.113.8")
        headers = await self.ready()
        response = await self.client.put("/api/security", json={"access_mode": "lan", "revision": value["revision"]}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["access_mode"], "lan")
        self.assertEqual((await self.client.get("/api/security")).status_code, 403)

    async def test_security_update_rejects_extra_fields_and_invalid_values(self):
        value = await self.configure_access_policy()
        headers = await self.ready()
        valid = {"access_mode": "public", "revision": value["revision"]}
        for body in ({**valid, "path": "/etc/anything"}, {**valid, "access_mode": "all"},
                     {**valid, "revision": "bad"}, {"access_mode": "public"}):
            with self.subTest(body=body):
                self.assertEqual((await self.client.put("/api/security", json=body, headers=headers)).status_code, 400)
        self.assertEqual(self.bridge.calls, [])

    async def test_security_missing_applied_record_is_pending_and_unconfigured_update_is_unavailable(self):
        headers = await self.ready()
        self.assertEqual((await self.client.put("/api/security", json={"access_mode": "public", "revision": "0" * 32}, headers=headers)).status_code, 503)
        await self.configure_access_policy()
        await self.ready()
        data = (await self.client.get("/api/security")).json()
        self.assertTrue(data["pending"])
        self.assertIsNone(data["applied_mode"])

    async def test_database_contains_hashes_not_password_or_session_token(self):
        await self.ready()
        data = self.store.path.read_bytes()
        self.assertNotIn(INITIAL_PASSWORD.encode(), data)
        self.assertNotIn(self.client.cookies.get(COOKIE).encode(), data)
        self.assertIn(b"scrypt$32768$8$3$", data)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)


class BridgeProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cw-", dir="/tmp")
        self.socket = str(Path(self.tmp.name) / "bridge.sock")
        self.requests = []
        self.response = b'{"ok":true,"data":{"accepted":true}}\n'
        self.delay = 0

        async def handle(reader, writer):
            try:
                self.requests.append(json.loads(await reader.readline()))
                await asyncio.sleep(self.delay)
                writer.write(self.response)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = await asyncio.start_unix_server(handle, path=self.socket)
        self.bridge = BridgeClient(self.socket, timeout=0.5)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.tmp.cleanup()

    async def test_wire_protocol_and_fixed_method(self):
        self.assertEqual(await self.bridge.call("run"), {"accepted": True})
        self.assertEqual(self.requests, [{"method": "run", "params": {}}])
        with self.assertRaises(BridgeError):
            await self.bridge.call("shell", {"command": "example"})
        self.assertEqual(len(self.requests), 1)

    async def test_authenticated_api_reaches_real_socket_and_redacts_response(self):
        data_dir = Path(self.tmp.name) / "data"
        store = AuthStore(data_dir)
        store.initialize("admin", INITIAL_PASSWORD)
        with store.transaction() as connection:
            connection.execute("UPDATE users SET must_change=0")
        app = create_app(Config(data_dir=data_dir, bridge_socket=self.socket, allowed_networks=("10.10.10.0/24",),
                                allowed_hosts=("ttxli.cn:18443",), origin=ORIGIN), store, self.bridge)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.10.10.24", 43210)), base_url=ORIGIN) as client:
            response = await client.post("/api/login", json={"username": "admin", "password": INITIAL_PASSWORD}, headers={"Origin": ORIGIN})
            headers = {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}
            self.assertEqual((await client.post("/api/actions/run", json={}, headers=headers)).status_code, 200)
            self.assertEqual(self.requests[-1], {"method": "run", "params": {}})
            payload = settings_payload()
            payload.update(secret_id="fixture-secret-id", secret_key="fixture-secret-key")
            self.response = json.dumps({"ok": True, "data": payload}).encode() + b"\n"
            updated = await client.put("/api/settings", json=payload, headers=headers)
            self.assertEqual(updated.status_code, 200)
            self.assertEqual(self.requests[-1], {"method": "settings.update", "params": payload})
            self.assertNotIn("fixture-secret", updated.text)
            self.assertNotIn("fixture-secret", (await client.get("/api/audit")).text)

    async def test_response_sanitizes_secret_fields_and_labeled_text(self):
        self.response = json.dumps({"ok": True, "data": {"secret_id": "fixture-secret-id", "secret_key": "fixture-secret-key",
            "secret_id_configured": True, "secret_key_configured": True, "nested": {"password": "do-not-echo", "title": "SecretKey=labelled-secret"}}}).encode() + b"\n"
        result = await self.bridge.call("settings.get")
        self.assertEqual(result, {"secret_id_configured": True, "secret_key_configured": True, "nested": {"title": "SecretKey=[已隐藏]"}})

    async def test_error_does_not_forward_backend_message(self):
        self.response = b'{"ok":false,"error":{"code":"stale_revision","message":"SecretKey=do-not-echo"}}\n'
        with self.assertRaises(BridgeError) as context:
            await self.bridge.call("settings.update", {})
        self.assertEqual(context.exception.code, "stale_revision")
        self.assertNotIn("SecretKey", str(context.exception))

    async def test_malformed_oversized_and_incomplete_response(self):
        for response in (b"not-json\n", b'{}\n', b'{"ok":true,"data":[]}\n', b'{"ok":true,"data":{}}', b"x" * (2 * 1024 * 1024 + 2) + b"\n"):
            self.response = response
            with self.subTest(size=len(response)), self.assertRaises(BridgeError) as context:
                await self.bridge.call("status")
            self.assertEqual(context.exception.code, "internal")

    async def test_request_size_and_timeout(self):
        with self.assertRaises(BridgeError) as context:
            await self.bridge.call("settings.update", {"value": "x" * 65536})
        self.assertEqual(context.exception.code, "validation")
        self.delay = 0.05
        self.bridge.timeout = 0.01
        with self.assertRaises(BridgeError) as context:
            await self.bridge.call("status")
        self.assertEqual(context.exception.code, "unavailable")
        await asyncio.sleep(0.06)

    async def test_unavailable_socket(self):
        with self.assertRaises(BridgeError) as context:
            await BridgeClient(self.socket + "missing").call("status")
        self.assertEqual(context.exception.code, "unavailable")


class AuthenticationStorageTests(unittest.TestCase):
    def test_hash_has_random_salt_and_verifies_unicode_password(self):
        password = "这是用于测试的管理员密码123"
        first, second = password_hash(password), password_hash(password)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password(password, first))
        self.assertFalse(verify_password("wrong", first))
        self.assertFalse(verify_password(password, "corrupted"))

    def test_config_rejects_wildcard_public_or_ipv6_networks_and_origins(self):
        for network in ("0.0.0.0/0", "8.8.8.0/24", "127.0.0.0/8", "::/0", "169.254.0.0/16", "10.10.10.1/24"):
            with self.subTest(network=network), self.assertRaises(ValueError):
                Config(allowed_networks=(network,))
        for kwargs in ({"allowed_hosts": ("*.example.com",)}, {"origin": "http://localhost:18443"},
                       {"allowed_hosts": ("evil@example.com",)}, {"denied_addresses": ("8.8.8.8",)}):
            with self.assertRaises(ValueError):
                Config(**kwargs)

    def test_private_storage_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            unsafe.chmod(0o755)
            with self.assertRaises(ValueError):
                AuthStore(unsafe)
            target = root / "target"
            target.mkdir(mode=0o700)
            (root / "linked").symlink_to(target)
            with self.assertRaises(ValueError):
                AuthStore(root / "linked")

    def test_cli_initialization_and_reset_revoke_sessions_without_secret_output(self):
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {"CERTWEB_DATA_DIR": name}):
            output, error = io.StringIO(), io.StringIO()
            with patch("sys.stdin", io.StringIO(INITIAL_PASSWORD + "\n")), patch("sys.stdout", output), patch("sys.stderr", error):
                self.assertEqual(main(["init", "--password-stdin"]), 0)
            store = AuthStore(Path(name))
            session = store.login("admin", INITIAL_PASSWORD)
            self.assertIsNotNone(session)
            with patch("sys.stdin", io.StringIO(NEW_PASSWORD + "\n")), patch("sys.stdout", output), patch("sys.stderr", error):
                self.assertEqual(main(["init", "--password-stdin"]), 1)
            with patch("sys.stdin", io.StringIO(NEW_PASSWORD + "\n")), patch("sys.stdout", output), patch("sys.stderr", error):
                self.assertEqual(main(["reset-password", "--password-stdin"]), 0)
            self.assertIsNone(store.session(session[0]))
            self.assertFalse(store.credentials_valid("admin", INITIAL_PASSWORD))
            self.assertTrue(store.credentials_valid("admin", NEW_PASSWORD))
            self.assertNotIn(INITIAL_PASSWORD, output.getvalue() + error.getvalue())
            self.assertNotIn(NEW_PASSWORD, output.getvalue() + error.getvalue())

    def test_server_binds_private_address_and_disables_proxy_trust(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "cert").write_text("test certificate file")
            (root / "key").write_text("test key file")
            variables = {"CERTWEB_DATA_DIR": str(root / "data"), "CERTWEB_BIND": "10.10.10.37", "CERTWEB_PORT": "18443",
                         "CERTWEB_ALLOWED_NETWORKS": "10.10.10.0/24", "CERTWEB_DENIED_ADDRESSES": "10.10.10.1",
                         "CERTWEB_ALLOWED_HOSTS": "ttxli.cn:18443", "CERTWEB_ORIGIN": ORIGIN,
                         "CERTWEB_TLS_CERT": str(root / "cert"), "CERTWEB_TLS_KEY": str(root / "key")}
            with patch.dict(os.environ, variables), patch("uvicorn.run") as run:
                self.assertEqual(main(["serve"]), 0)
                kwargs = run.call_args.kwargs
                self.assertEqual(kwargs["host"], "10.10.10.37")
                self.assertEqual(kwargs["workers"], 1)
                self.assertFalse(kwargs["proxy_headers"])
                self.assertEqual(kwargs["forwarded_allow_ips"], "")
                self.assertFalse(kwargs["access_log"])
                self.assertFalse(kwargs["server_header"])
                self.assertEqual(kwargs["ssl_keyfile"], str(root / "key"))
            for invalid in ("0.0.0.0", "127.0.0.1", "::", "8.8.8.8", "10.10.10.1"):
                with patch.dict(os.environ, {**variables, "CERTWEB_BIND": invalid}), patch("uvicorn.run") as run, patch("sys.stderr", io.StringIO()):
                    self.assertEqual(main(["serve"]), 1)
                    run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
