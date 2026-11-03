from __future__ import annotations

import asyncio
import hmac
import json
import re
import secrets
from pathlib import Path
from urllib.parse import unquote

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, HTMLResponse, JSONResponse

from . import validation
from .auth import ABSOLUTE_SECONDS, AuthStore, valid_password
from .bridge import BridgeClient, BridgeError
from .config import Config
from .mfa import CHALLENGE_SECONDS, EmailDelivery, MfaError

COOKIE = "__Host-certweb_session"
CHALLENGE_COOKIE = "__Host-certweb_challenge"
BODY_LIMIT = 128 * 1024
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store",
}
SAFE_ROUTES = frozenset({"", "login", "overview", "certificate", "renewal", "notifications", "logs", "security", "audit", "health", "runs"})
ALLOWED_ASSETS = frozenset({".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".woff", ".woff2"})


class ApiError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


def error_response(status, code, message):
    response = JSONResponse({"error": {"code": code, "message": message}}, status_code=status)
    if status == 429:
        response.headers["Retry-After"] = "900"
    return response


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


async def json_body(request):
    try:
        data = json.loads(await request.body(), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (ValueError, UnicodeError, RecursionError):
        raise ApiError(400, "invalid_request", "请求必须是有效的 JSON 对象") from None


class SecurityBoundary:
    def __init__(self, app, config):
        self.app, self.config = app, config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.app(scope, receive, send)
            return
        started = False

        async def secure_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = [(key, value) for key, value in message.get("headers", [])
                           if key.lower() not in {name.lower().encode() for name in SECURITY_HEADERS}]
                security_headers = SECURITY_HEADERS.copy()
                nonce = scope.get("state", {}).get("csp_nonce")
                if nonce and any(key.lower() == b"content-type" and value.split(b";", 1)[0] == b"text/html" for key, value in headers):
                    security_headers["Content-Security-Policy"] = security_headers["Content-Security-Policy"].replace(
                        "style-src 'self';", f"style-src 'self' 'nonce-{nonce}';")
                headers.extend((key.lower().encode(), value.encode()) for key, value in security_headers.items())
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.handle(scope, receive, secure_send)
        except ApiError as error:
            if not started:
                await error_response(error.status, error.code, error.message)(scope, receive, secure_send)
        except asyncio.TimeoutError:
            if not started:
                await error_response(503, "timeout", "操作超时，请稍后重试")(scope, receive, secure_send)
        except Exception:
            # 不把异常、请求正文、路径或凭据写入响应与服务器日志。
            if not started:
                await error_response(503, "unavailable", "管理服务暂不可用，请稍后重试")(scope, receive, secure_send)

    async def handle(self, scope, receive, send):
        headers = scope.get("headers", [])
        hosts = [value.decode("latin1").lower() for key, value in headers if key.lower() == b"host"]
        if len(hosts) != 1 or hosts[0] not in self.config.allowed_hosts:
            raise ApiError(400, "invalid_host", "访问地址不在允许的主机列表中")
        if any(key.lower() == b"forwarded" or key.lower().startswith(b"x-forwarded") or key.lower() == b"x-real-ip" for key, _ in headers):
            raise ApiError(403, "proxy_forbidden", "此管理页面不允许通过代理转发访问")
        path = scope.get("path", "")
        peer = scope.get("client") or ("", 0)
        if not self.config.allows_peer(peer[0], path):
            raise ApiError(403, "network_forbidden", "仅允许指定局域网中的设备访问")
        if scope.get("scheme") != "https":
            raise ApiError(403, "https_required", "管理页面仅接受 HTTPS 连接")
        raw_path = scope.get("raw_path", path.encode()).decode("latin1")
        for _ in range(4):
            if "\\" in raw_path or "\x00" in raw_path or any(part.startswith(".") for part in raw_path.split("/")):
                raise ApiError(400, "invalid_path", "请求路径不正确")
            decoded = unquote(raw_path)
            if decoded == raw_path:
                break
            raw_path = decoded
        if "%" in raw_path:
            raise ApiError(400, "invalid_path", "请求路径不正确")
        query = scope.get("query_string", b"")
        if query and (path != "/api/runs" or scope.get("method") != "GET" or len(query) > 64):
            raise ApiError(400, "invalid_request", "此接口不接受查询参数")
        request_headers = {}
        for key, value in headers:
            key = key.lower()
            if key in (b"origin", b"content-type", b"content-length", b"x-csrf-token", b"cookie") and key in request_headers:
                raise ApiError(400, "invalid_request", "请求头不正确")
            request_headers[key] = value.decode("latin1")
        method = scope.get("method", "GET")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            if request_headers.get(b"origin") != self.config.origin or request_headers.get(b"sec-fetch-site") == "cross-site":
                raise ApiError(403, "origin_forbidden", "请求来源校验失败，请从管理页面重新操作")
            content_type = request_headers.get(b"content-type", "").lower().replace(" ", "")
            if content_type not in ("application/json", "application/json;charset=utf-8"):
                raise ApiError(415, "invalid_content_type", "请求须使用 UTF-8 JSON 格式")
        length = request_headers.get(b"content-length")
        if length is not None and (not length.isdecimal() or int(length) > BODY_LIMIT):
            raise ApiError(413, "body_too_large", "请求内容过大")

        async def read_body():
            chunks, size = [], 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    raise ApiError(400, "disconnected", "连接已中断")
                if message["type"] != "http.request":
                    raise ApiError(400, "invalid_request", "请求格式不正确")
                piece = message.get("body", b"")
                size += len(piece)
                if size > BODY_LIMIT:
                    raise ApiError(413, "body_too_large", "请求内容过大")
                chunks.append(piece)
                if not message.get("more_body", False):
                    return b"".join(chunks)

        body = await asyncio.wait_for(read_body(), self.config.body_timeout)
        supplied = False

        async def replay():
            nonlocal supplied
            if not supplied:
                supplied = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await asyncio.wait_for(self.app(scope, replay, send), self.config.request_timeout)


def create_app(config=None, store=None, bridge=None):
    config = config or Config.from_env()
    store = store or AuthStore(config.data_dir)
    bridge = bridge or BridgeClient(config.bridge_socket, config.bridge_timeout)
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None, redirect_slashes=False)
    app.state.store, app.state.bridge, app.state.config = store, bridge, config
    password_slot = asyncio.Semaphore(1)

    async def password_work(function, *args):
        # DS218+ 内存有限，昂贵密码运算串行执行，避免并发登录放大内存占用。
        async with password_slot:
            return await run_in_threadpool(function, *args)

    @app.exception_handler(ApiError)
    async def api_error(_request, error):
        return error_response(error.status, error.code, error.message)

    @app.exception_handler(MfaError)
    async def mfa_error(_request, error):
        response = error_response(error.status, error.code, error.message)
        if error.code == "challenge_expired":
            clear_challenge_cookie(response)
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_request, error):
        return error_response(error.status_code, "not_found" if error.status_code == 404 else "invalid_request", "请求的页面或接口不存在" if error.status_code == 404 else "请求方法或内容不正确")

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request, _error):
        return error_response(400, "invalid_request", "请求内容不符合要求")

    @app.exception_handler(Exception)
    async def unexpected_error(_request, _error):
        return error_response(503, "unavailable", "管理服务暂不可用，请稍后重试")

    async def session(request, write=False, allow_change=False):
        token = request.cookies.get(COOKIE, "")
        polling = request.method == "GET" and (request.url.path in ("/api/status", "/api/security", "/api/health", "/api/monitor", "/api/runs")
                                                or request.url.path.startswith("/api/runs/"))
        current = await run_in_threadpool(store.session, token, not polling)
        if not current:
            raise ApiError(401, "unauthorized", "登录已失效，请重新登录")
        if write:
            csrf = request.headers.get("x-csrf-token", "")
            if not csrf or not hmac.compare_digest(csrf.encode(), current["csrf_token"].encode()):
                raise ApiError(403, "csrf_failed", "安全校验失败，请刷新页面后重试")
        if current["must_change_password"] and not allow_change:
            raise ApiError(403, "password_change_required", "首次登录请先修改管理员密码")
        return current

    def authenticated_response(result):
        token, current = result
        response = JSONResponse(current)
        response.set_cookie(COOKIE, token, max_age=ABSOLUTE_SECONDS, secure=True, httponly=True, samesite="strict", path="/")
        clear_challenge_cookie(response)
        return response

    def clear_challenge_cookie(response):
        response.delete_cookie(CHALLENGE_COOKIE, secure=True, httponly=True, samesite="strict", path="/")

    async def deliver_code(delivery, request, initial=False):
        try:
            try:
                result = await asyncio.wait_for(bridge.call("auth.code.send", {"code": delivery.code, "policy_version": delivery.policy_version}),
                                                min(config.bridge_timeout, max(0.01, config.request_timeout - 1), 50))
                if not isinstance(result, dict) or result.get("accepted") is not True:
                    raise ValueError("delivery unavailable")
            except Exception:
                await run_in_threadpool(store.finish_delivery, delivery, request.client.host, False)
                response = error_response(503, "mail_unavailable", "验证码发送未完成，请稍后重试或联系管理员")
            else:
                meta = await run_in_threadpool(store.finish_delivery, delivery, request.client.host, True)
                if not meta["verification_required"]:
                    raise MfaError(410, "challenge_expired", "登录验证已失效，请重新输入账号密码")
                response = JSONResponse(meta, status_code=202 if initial else 200)
            if initial:
                response.set_cookie(CHALLENGE_COOKIE, delivery.token, max_age=CHALLENGE_SECONDS, secure=True, httponly=True, samesite="strict", path="/")
                response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict", path="/")
            return response
        except asyncio.CancelledError:
            # 工作线程不会随请求取消；按轮次撤销已完成或尚未完成的验证码。
            store.invalidate_delivery(delivery)
            raise

    async def call_bridge(method, params=None, audit=None):
        try:
            result = await bridge.call(method, params)
        except BridgeError as error:
            if audit:
                await run_in_threadpool(store.audit, audit, False, error.message)
            raise ApiError(error.status, error.code, error.message) from None
        except Exception:
            if audit:
                await run_in_threadpool(store.audit, audit, False, "执行器连接异常，操作未确认完成")
            raise ApiError(503, "unavailable", "群晖执行器暂不可用，请稍后重试") from None
        if audit:
            await run_in_threadpool(store.audit, audit, True, "访问范围已保存，等待应用" if audit == "security.update" else "配置已更新" if audit == "settings.update" else "执行请求已提交")
        return result

    @app.get("/healthz")
    async def health():
        return {"ok": True}

    @app.post("/api/login")
    async def login(request: Request):
        data = await json_body(request)
        try:
            validation.exact_keys(data, {"username", "password"})
            if not isinstance(data["username"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", data["username"]) or not isinstance(data["password"], str) or not 1 <= len(data["password"]) <= 128:
                raise ValueError()
            data["password"].encode("utf-8")
        except ValueError:
            raise ApiError(400, "invalid_request", "账号或密码格式不正确") from None
        allowed = await run_in_threadpool(store.allow_attempt, request.client.host, data["username"])
        if not allowed:
            raise ApiError(429, "rate_limited", "登录尝试过于频繁，请在 15 分钟后重试")
        result = await password_work(store.login, data["username"], data["password"], request.client.host)
        await run_in_threadpool(store.audit, "login", bool(result), "密码校验通过，等待邮箱验证" if isinstance(result, EmailDelivery) else "管理员登录成功" if result else "账号或密码不正确")
        if not result:
            raise ApiError(401, "invalid_credentials", "账号或密码不正确")
        if isinstance(result, EmailDelivery):
            await run_in_threadpool(store.logout, request.cookies.get(COOKIE, ""))
            return await deliver_code(result, request, initial=True)
        return authenticated_response(result)

    @app.get("/api/login/challenge")
    async def login_challenge(request: Request):
        meta = await run_in_threadpool(store.challenge, request.cookies.get(CHALLENGE_COOKIE, ""), request.client.host)
        response = JSONResponse(meta)
        if not meta["verification_required"]:
            clear_challenge_cookie(response)
        return response

    @app.post("/api/login/verify")
    async def login_verify(request: Request):
        data = await json_body(request)
        if set(data) != {"code"}:
            raise ApiError(400, "invalid_request", "请仅提交邮箱验证码")
        result = await run_in_threadpool(store.verify_challenge, request.cookies.get(CHALLENGE_COOKIE, ""), request.client.host, data["code"])
        return authenticated_response(result)

    @app.post("/api/login/resend")
    async def login_resend(request: Request):
        if await json_body(request) != {}:
            raise ApiError(400, "invalid_request", "此操作不接受额外参数")
        delivery = await run_in_threadpool(store.resend_challenge, request.cookies.get(CHALLENGE_COOKIE, ""), request.client.host)
        return await deliver_code(delivery, request)

    @app.post("/api/login/cancel")
    async def login_cancel(request: Request):
        if await json_body(request) != {}:
            raise ApiError(400, "invalid_request", "此操作不接受额外参数")
        await run_in_threadpool(store.cancel_challenge, request.cookies.get(CHALLENGE_COOKIE, ""), request.client.host)
        response = JSONResponse({"ok": True})
        clear_challenge_cookie(response)
        return response

    @app.get("/api/session")
    async def get_session(request: Request):
        return await session(request, allow_change=True)

    @app.post("/api/logout")
    async def logout(request: Request):
        await session(request, write=True, allow_change=True)
        if await json_body(request) != {}:
            raise ApiError(400, "invalid_request", "此操作不接受额外参数")
        await run_in_threadpool(store.logout, request.cookies.get(COOKIE, ""))
        await run_in_threadpool(store.audit, "logout", True, "管理员已退出登录")
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict", path="/")
        return response

    @app.post("/api/password")
    async def password(request: Request):
        current = await session(request, write=True, allow_change=True)
        data = await json_body(request)
        try:
            validation.exact_keys(data, {"current_password", "new_password"})
            if not valid_password(data["new_password"]) or not isinstance(data["current_password"], str) or not 1 <= len(data["current_password"]) <= 128:
                raise ValueError()
            data["current_password"].encode("utf-8")
        except ValueError:
            raise ApiError(400, "invalid_password", "新密码须为 12 至 128 个字符，并且不同于旧密码") from None
        if not await run_in_threadpool(store.allow_attempt, request.client.host, current["username"], "password"):
            raise ApiError(429, "rate_limited", "密码校验过于频繁，请在 15 分钟后重试")
        result = await password_work(store.change_password, current["username"], data["current_password"], data["new_password"], request.cookies.get(COOKIE, ""))
        await run_in_threadpool(store.audit, "password", bool(result), "管理员密码已更新，旧会话已撤销" if result else "密码校验失败")
        if not result:
            raise ApiError(400, "invalid_password", "旧密码不正确，或新密码与旧密码相同")
        return authenticated_response(result)

    @app.get("/api/status")
    async def status(request: Request):
        await session(request)
        return await call_bridge("status")

    @app.get("/api/settings")
    async def get_settings(request: Request):
        await session(request)
        return await call_bridge("settings.get")

    @app.get("/api/health")
    async def runtime_health(request: Request):
        await session(request)
        return await call_bridge("health")

    @app.get("/api/monitor")
    async def monitor_settings(request: Request):
        await session(request)
        return await call_bridge("monitor.get")

    @app.put("/api/monitor")
    async def save_monitor(request: Request):
        await session(request, write=True)
        data = await json_body(request)
        try:
            validation.monitor(data)
        except ValueError:
            raise ApiError(400, "validation", "预警设置不符合要求，请检查填写项") from None
        return await call_bridge("monitor.update", data, "monitor.update")

    @app.get("/api/runs")
    async def runs(request: Request):
        await session(request)
        pairs = request.query_params.multi_items()
        if len(pairs) != len(dict(pairs)) or set(request.query_params) - {"offset", "limit"}:
            raise ApiError(400, "invalid_request", "执行记录分页参数无效")
        values = {}
        for key, default, minimum, maximum in (("offset", "0", 0, 500), ("limit", "20", 1, 50)):
            value = request.query_params.get(key, default)
            if not re.fullmatch(r"[0-9]{1,3}", value) or not minimum <= int(value) <= maximum:
                raise ApiError(400, "invalid_request", "执行记录分页参数无效")
            values[key] = int(value)
        return await call_bridge("runs.list", values)

    @app.get("/api/runs/{run_id}")
    async def run_detail(request: Request, run_id: str):
        await session(request)
        if not re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}", run_id):
            raise ApiError(400, "invalid_request", "执行记录编号无效")
        return await call_bridge("runs.get", {"id": run_id})

    @app.put("/api/settings")
    async def put_settings(request: Request):
        await session(request, write=True)
        data = await json_body(request)
        try:
            validation.settings(data)
        except ValueError:
            raise ApiError(400, "validation", "配置内容不符合要求，请检查填写项") from None
        return await call_bridge("settings.update", data, "settings.update")

    async def action(request, method):
        await session(request, write=True)
        if await json_body(request) != {}:
            raise ApiError(400, "invalid_request", "此操作不接受额外参数")
        return await call_bridge(method, audit=method)

    @app.post("/api/actions/run")
    async def run(request: Request):
        return await action(request, "run")

    @app.post("/api/actions/renew")
    async def renew(request: Request):
        return await action(request, "renew")

    @app.post("/api/actions/check")
    async def check(request: Request):
        return await action(request, "check")

    @app.get("/api/failures")
    async def failures(request: Request):
        await session(request)
        return await call_bridge("failures.list")

    @app.get("/api/failures/{failure_id}")
    async def failure(request: Request, failure_id: str):
        await session(request)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", failure_id):
            raise ApiError(400, "invalid_request", "失败记录编号不正确")
        return await call_bridge("failures.get", {"id": failure_id})

    @app.get("/api/audit")
    async def audit(request: Request):
        await session(request)
        return await run_in_threadpool(store.audit_list)

    @app.get("/api/security")
    async def security(request: Request):
        await session(request)
        return await run_in_threadpool(config.security_snapshot)

    @app.put("/api/security")
    async def update_security(request: Request):
        await session(request, write=True)
        data = await json_body(request)
        try:
            validation.exact_keys(data, {"access_mode", "revision"})
            if data["access_mode"] not in ("lan", "public") or not isinstance(data["revision"], str) or not re.fullmatch(r"[0-9a-f]{32}", data["revision"]):
                raise ValueError()
        except ValueError:
            raise ApiError(400, "validation", "访问范围配置不符合要求") from None
        if config.access_policy_file is None:
            raise ApiError(503, "unavailable", "访问范围配置尚未启用")
        await call_bridge("security.update", data, "security.update")
        return await run_in_threadpool(config.security_snapshot)

    @app.api_route("/{path:path}", methods=["GET", "HEAD"])
    async def static(request: Request, path: str):
        if path in SAFE_ROUTES:
            target = config.static_dir / "index.html"
        elif path.startswith("assets/") and Path(path).suffix.lower() in ALLOWED_ASSETS:
            target = config.static_dir / path
        elif path == "favicon.ico":
            target = config.static_dir / path
        else:
            raise ApiError(404, "not_found", "请求的页面或资源不存在")
        root = config.static_dir.resolve()
        try:
            target.resolve().relative_to(root)
        except ValueError:
            raise ApiError(404, "not_found", "请求的资源不存在") from None
        if not target.is_file():
            raise ApiError(404, "not_found", "请求的页面或资源不存在")
        if path in SAFE_ROUTES:
            document = await run_in_threadpool(target.read_text, encoding="utf-8")
            nonce = secrets.token_urlsafe(32)
            request.state.csp_nonce = nonce
            response = HTMLResponse(document.replace("__CERTWEB_CSP_NONCE__", nonce))
            if request.method == "HEAD":
                # 保留 GET 对应的内容长度，但 HEAD 不发送实体正文。
                response.body = b""
            return response
        return FileResponse(target)

    secured = SecurityBoundary(app, config)
    secured.state = app.state
    return secured
