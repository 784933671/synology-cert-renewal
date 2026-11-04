"""以镜像自带依赖验证真实 HTTPS、认证数据库及接口防护，无外部网络。"""
from __future__ import annotations

import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import tempfile
import threading
import time

import uvicorn

from web.backend.app import COOKIE, create_app
from web.backend.auth import AuthStore
from web.backend.config import Config

INITIAL_PASSWORD = 'runtime-smoke-initial-password-42'
CHANGED_PASSWORD = 'runtime-smoke-changed-password-51'
IP = '127.0.0.1'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class TestClock:
    def __init__(self):
        self.value = time.time()
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            return self.value

    def advance(self, seconds):
        with self.lock:
            self.value += seconds


class MockBridge:
    def __init__(self):
        self.deliveries = []
        self.lock = threading.Lock()

    async def call(self, method, params=None):
        if method in ('auth.code.send', 'auth.stepup.send'):
            with self.lock:
                self.deliveries.append((method, dict(params)))
            return {'accepted': True}
        if method == 'auth.security.send':
            return {'accepted': True}
        if method == 'status':
            return {'task': {'running': False}}
        raise RuntimeError('冒烟测试禁止调用其他宿主操作')

    def code(self, method, operation=None):
        with self.lock:
            values = [body for name, body in self.deliveries if name == method]
            require(bool(values), '未收到测试邮箱验证码')
            value = values[-1]
            if operation:
                require(value.get('operation') == operation, '邮箱验证码操作绑定错误')
            return value['code']


class HTTPSClient:
    def __init__(self, port, certificate):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(certificate))
        require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, 'TLS 必须校验证书和主机名')
        self.connection = http.client.HTTPSConnection('localhost', port, context=context, timeout=5)
        self.origin = f'https://localhost:{port}'
        self.cookies = SimpleCookie()
        self.csrf = ''

    def close(self):
        self.connection.close()

    def request(self, method, path, body=None, expected=200, grant=None):
        headers = {'Accept': 'application/json'}
        if self.cookies:
            headers['Cookie'] = '; '.join(f'{name}={cookie.value}' for name, cookie in self.cookies.items())
        encoded = None
        if method != 'GET':
            encoded = json.dumps({} if body is None else body).encode('utf-8')
            headers.update({'Content-Type': 'application/json', 'Origin': self.origin})
            if self.csrf:
                headers['X-CSRF-Token'] = self.csrf
            if grant:
                headers['X-Step-Up-Token'] = grant
        self.connection.request(method, path, body=encoded, headers=headers)
        response = self.connection.getresponse()
        payload = json.loads(response.read())
        for name, value in response.getheaders():
            if name.lower() != 'set-cookie':
                continue
            received = SimpleCookie(value)
            for key, cookie in received.items():
                if cookie['max-age'] == '0':
                    self.cookies.pop(key, None)
                else:
                    require(bool(cookie['secure']) and bool(cookie['httponly']) and cookie['samesite'].lower() == 'strict',
                            '认证 Cookie 安全属性缺失')
                    self.cookies[key] = cookie.value
        code = payload.get('error', {}).get('code', '')
        require(response.status == expected,
                f'{method} {path} 状态错误：期望 {expected}，实际 {response.status} ({code})')
        require(response.getheader('X-Content-Type-Options') == 'nosniff', '安全响应头缺失')
        if response.status == 429:
            require(int(response.getheader('Retry-After', '0')) == payload['error']['retry_after'] > 0,
                    '限流重试时间不一致')
        if 'csrf_token' in payload:
            self.csrf = payload['csrf_token']
        return payload


def authorize(client, bridge, method, path, body, operation):
    denied = client.request(method, path, body, expected=428)
    require(denied['error']['code'] == 'stepup_required', '敏感操作没有要求邮箱验证')
    challenge = client.request('POST', '/api/stepup/start', {'method': method, 'path': path, 'body': body})
    require(challenge['operation'] == operation, '二次验证挑战未绑定目标操作')
    verified = client.request('POST', '/api/stepup/verify', {
        'challenge_id': challenge['challenge_id'], 'code': bridge.code('auth.stepup.send', operation),
    })
    return client.request(method, path, body, grant=verified['token'])


def exercise(port, certificate, store, clock, bridge):
    client, anonymous = HTTPSClient(port, certificate), HTTPSClient(port, certificate)
    try:
        require(client.request('GET', '/healthz') == {'ok': True}, '健康检查失败')
        require(client.connection.sock.version() in ('TLSv1.2', 'TLSv1.3'), '未建立有效 TLS 连接')
        client.request('GET', '/api/session', expected=401)
        challenge = client.request('POST', '/api/login', {'username': 'admin', 'password': INITIAL_PASSWORD}, expected=202)
        require(challenge['verification_required'], '登录未进入邮箱验证')
        current = client.request('POST', '/api/login/verify', {'code': bridge.code('auth.code.send')})
        require(current['must_change_password'] and current['email_verification_enabled'], '首次登录状态错误')
        current = client.request('POST', '/api/password', {
            'current_password': INITIAL_PASSWORD, 'new_password': CHANGED_PASSWORD,
        })
        require(not current['must_change_password'], '首次密码修改未完成')
        require(store.credentials_valid('admin', CHANGED_PASSWORD), 'scrypt 密码验证失败')
        print('通过：真实 TLS、Cookie、CSRF、SQLite、scrypt 与邮箱登录', flush=True)

        policy = client.request('GET', '/api/abuse')
        revision = policy['revision']
        policy['limits'] = {'ip_requests_per_minute': 120, 'session_requests_per_minute': 60,
                            'block_after_violations': 5, 'block_seconds': 120}
        saved = authorize(client, bridge, 'PUT', '/api/abuse', policy, 'abuse.update')
        require(saved['revision'] != revision and saved['limits'] == policy['limits'], '防护设置未持久保存')
        for _ in range(60):
            require(client.request('GET', '/api/status') == {'task': {'running': False}}, '状态接口结果错误')
        limited = client.request('GET', '/api/status', expected=429)
        require(limited['error']['code'] == 'rate_limited', '会话额度未生效')
        require(client.request('GET', '/api/session')['username'] == 'admin', '429 错误撤销了登录会话')

        # 不携带会话的实际 HTTPS 请求突破 IP 聚合额度，避免直接写数据库制造封禁。
        for number in range(65):
            expected = 401 if number < 60 else 429
            limited = anonymous.request('GET', '/api/status', expected=expected)
        require(limited['error']['code'] == 'ip_temporarily_blocked', 'IP 持续超限未触发临时封禁')
        require(client.request('GET', '/api/status', expected=429)['error']['code'] == 'ip_temporarily_blocked',
                'IP 封禁未应用到普通接口')
        require(client.request('GET', '/healthz') == {'ok': True}, 'IP 封禁影响了健康检查')
        items = client.request('GET', '/api/abuse/blocks')['items']
        require(len(items) == 1 and items[0]['ip'] == IP and items[0]['current'], '被封来源无法读取恢复页面')
        reopened = AuthStore(store.path.parent, clock=clock)
        require(len(reopened.abuse_blocks(IP)['items']) == 1 and reopened.abuse_settings() == saved,
                '重新打开数据库丢失了封禁或设置')

        # 只推进测试时钟，实际运行仍使用生产的发信冷却与限额校验。
        clock.advance(61)
        unlocked = authorize(client, bridge, 'POST', '/api/abuse/unblock', {'ip': IP}, 'abuse.unblock')
        require(unlocked == {'ok': True, 'removed': True}, '邮箱验证解封失败')
        require(client.request('GET', '/api/abuse/blocks') == {'items': []}, '解封后仍有封禁记录')
        client.request('GET', '/api/status')
        require(reopened.session(client.cookies[COOKIE].value, False) is not None, '防护操作影响了登录状态')
        client.request('POST', '/api/logout')
        client.request('GET', '/api/session', expected=401)
        print('通过：防护设置授权、会话 429、持久 IP 封禁、邮箱自助解封与退出', flush=True)
    finally:
        client.close()
        anonymous.close()


def main():
    require(os.getuid() != 0, '冒烟测试必须以非 root 身份运行')
    certificate, key, policy = (Path(os.environ[name]) for name in (
        'CERTWEB_SMOKE_CERT', 'CERTWEB_SMOKE_KEY', 'CERTWEB_SMOKE_POLICY'))
    require(all(path.is_absolute() and path.is_file() for path in (certificate, key, policy)), '缺少只读 TLS 或访问策略 fixture')
    with tempfile.TemporaryDirectory(prefix='certweb-runtime-', dir='/tmp') as directory:
        root, clock, bridge = Path(directory), TestClock(), MockBridge()
        store = AuthStore(root / 'data', clock=clock)
        store.initialize('admin', INITIAL_PASSWORD)
        store.configure_email_login('admin', 'smoke@example.invalid', 'a' * 32)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((IP, 0))
            port = listener.getsockname()[1]
            configuration = Config(data_dir=root / 'data', static_dir=root / 'static',
                                   allowed_hosts=(f'localhost:{port}',), origin=f'https://localhost:{port}',
                                   access_policy_file=policy)
            require(configuration.access_policy()['mode'] == 'public', '测试策略必须是 root 所有的 public fixture')
            server = uvicorn.Server(uvicorn.Config(
                create_app(configuration, store, bridge), host=IP, port=port,
                ssl_certfile=str(certificate), ssl_keyfile=str(key),
                log_config=None, log_level='error', access_log=False, server_header=False,
                proxy_headers=False, forwarded_allow_ips='', ws='none', http='h11', loop='asyncio',
                limit_concurrency=32, timeout_keep_alive=5, timeout_graceful_shutdown=10,
            ))
            failures = []

            def serve():
                try:
                    server.run(sockets=[listener])
                except BaseException as error:
                    failures.append(type(error).__name__)

            thread = threading.Thread(target=serve, name='runtime-smoke-https', daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 10
                while not server.started and thread.is_alive() and time.monotonic() < deadline:
                    time.sleep(0.025)
                require(server.started and not failures, 'HTTPS 服务未在 10 秒内启动')
                exercise(port, certificate, store, clock, bridge)
            finally:
                server.should_exit = True
                thread.join(timeout=20)
                require(not thread.is_alive(), 'HTTPS 服务未在 20 秒内停止')
            require(not failures, 'HTTPS 服务线程异常退出')
    print('运行镜像冒烟验证通过。', flush=True)


if __name__ == '__main__':
    require(sqlite3.sqlite_version_info >= (3, 54, 0), '运行镜像 SQLite 尚未包含 FTS5 安全修复')
    with sqlite3.connect(':memory:') as database:
        database.execute('CREATE VIRTUAL TABLE smoke_fts USING fts5(content)')
        database.execute('INSERT INTO smoke_fts VALUES (?)', ('certificate renewal',))
        require(database.execute("SELECT COUNT(*) FROM smoke_fts WHERE smoke_fts MATCH 'renewal'").fetchone()[0] == 1,
                'SQLite FTS5 功能验证失败')
    print('运行镜像 SQLite ' + sqlite3.sqlite_version, flush=True)
    main()
