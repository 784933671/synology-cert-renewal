"""监督就绪后运行 HTTPS，证书副本切换时重启单 worker。"""
import json
import math
import os
from pathlib import Path
import signal
import ssl
import stat
import subprocess
import sys
import time


def project_ready(path=None, now=None):
    path = Path('/bridge/project-ready.json') if path is None else Path(path)
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'r') as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or info.st_mode & 0o022 or info.st_size > 1024):
                return False
            value = json.loads(handle.read(1025))
        if (not isinstance(value, dict) or set(value) != {'version', 'ready', 'expires_at'}
                or type(value['version']) is not int or value['version'] != 1
                or value['ready'] is not True
                or type(value['expires_at']) not in (int, float)):
            return False
        current = time.time() if now is None else now
        expiry = value['expires_at']
        return math.isfinite(current) and math.isfinite(expiry) and current <= expiry <= current + 30
    except (OSError, ValueError, TypeError, OverflowError):
        return False


def material():
    cert = Path(os.getenv('CERTWEB_TLS_CERT', '/tls/current.cert')).resolve(strict=True)
    key = Path(os.getenv('CERTWEB_TLS_KEY', '/tls/current.key')).resolve(strict=True)
    if cert.parent != key.parent:
        raise ValueError('TLS generation mismatch')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    return cert, key


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    project_mode = os.getenv('CERTWEB_PROJECT_MODE') == '1'
    shutdown = [False]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: shutdown.__setitem__(0, True))
    child = None
    loaded = None
    waiting = None
    try:
        while not shutdown[0]:
            if project_mode and not project_ready():
                if child is not None:
                    stop(child)
                    child = loaded = None
                if waiting != 'project':
                    print('等待宿主监督就绪，HTTPS 服务保持关闭。', file=sys.stderr, flush=True)
                    waiting = 'project'
                time.sleep(1)
                continue
            try:
                candidate = material()
            except (OSError, ValueError, ssl.SSLError):
                if child is None:
                    if waiting != 'tls':
                        print('HTTPS 材料未就绪，服务保持关闭。', file=sys.stderr, flush=True)
                        waiting = 'tls'
                    if project_mode:
                        time.sleep(1)
                        continue
                    return 1
                candidate = loaded
            waiting = None
            if candidate != loaded:
                if child is not None:
                    stop(child)
                    child = loaded = None
                if shutdown[0]:
                    break
                # TLS 读取和旧 worker 退出可能跨过租约期限，监听前重新确认。
                if project_mode and not project_ready():
                    time.sleep(1)
                    continue
                env = dict(os.environ, CERTWEB_TLS_CERT=str(candidate[0]), CERTWEB_TLS_KEY=str(candidate[1]))
                child = subprocess.Popen([sys.executable, '-m', 'web.backend', 'serve'], env=env)
                loaded = candidate
            if child.poll() is not None:
                return child.returncode or 1
            for _ in range(1 if project_mode else 5):
                if shutdown[0]:
                    break
                time.sleep(1)
        return 0
    finally:
        if child is not None:
            stop(child)


if __name__ == '__main__':
    raise SystemExit(main())
