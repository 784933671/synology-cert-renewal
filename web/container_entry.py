"""证书副本切换后重启单 worker，TLS 材料无效时保留已运行进程。"""
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import time


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
    shutdown = [False]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: shutdown.__setitem__(0, True))
    child = None
    loaded = None
    try:
        while not shutdown[0]:
            try:
                candidate = material()
            except (OSError, ValueError, ssl.SSLError):
                if child is None:
                    print('HTTPS 材料未就绪，服务保持关闭。', file=sys.stderr, flush=True)
                    return 1
                candidate = loaded
            if candidate != loaded:
                if child is not None:
                    stop(child)
                env = dict(os.environ, CERTWEB_TLS_CERT=str(candidate[0]), CERTWEB_TLS_KEY=str(candidate[1]))
                child = subprocess.Popen([sys.executable, '-m', 'web.backend', 'serve'], env=env)
                loaded = candidate
            if child.poll() is not None:
                return child.returncode or 1
            for _ in range(5):
                if shutdown[0]:
                    break
                time.sleep(1)
        return 0
    finally:
        if child is not None:
            stop(child)


if __name__ == '__main__':
    raise SystemExit(main())
