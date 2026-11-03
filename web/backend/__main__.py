from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .auth import AuthStore
from .config import Config, private_ipv4


def main(argv=None):
    parser = argparse.ArgumentParser(description="证书管家局域网管理服务")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve")
    for command in ("init", "reset-password"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--username", default="admin")
        command_parser.add_argument("--password-stdin", action="store_true")
    enable_parser = subparsers.add_parser("enable-email-login")
    enable_parser.add_argument("--username", default="admin")
    enable_parser.add_argument("--email", required=True)
    enable_parser.add_argument("--policy-version", required=True)
    disable_parser = subparsers.add_parser("disable-email-login")
    disable_parser.add_argument("--username", default="admin")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command in ("enable-email-login", "disable-email-login"):
            store = AuthStore(Path(os.getenv("CERTWEB_DATA_DIR", "/data")))
            enabled = args.command == "enable-email-login"
            store.configure_email_login(args.username, getattr(args, "email", None), getattr(args, "policy_version", None), enabled)
            print("邮箱登录验证已启用；原有会话与挑战已撤销。" if enabled else "邮箱登录验证已停用；原有会话与挑战已撤销。")
            return 0
        if args.command != "serve":
            if args.password_stdin:
                password = sys.stdin.readline(1024).removesuffix("\n").removesuffix("\r")
            else:
                if not sys.stdin.isatty():
                    raise ValueError("请在私有交互终端输入密码，或使用 --password-stdin")
                password = getpass.getpass("请输入管理员密码（至少 12 个字符）：")
                if password != getpass.getpass("请再次输入密码："):
                    raise ValueError("两次密码输入不一致")
            store = AuthStore(Path(os.getenv("CERTWEB_DATA_DIR", "/data")))
            store.initialize(args.username, password, reset=args.command == "reset-password")
            print("管理员凭据已保存。下一次登录必须修改密码；原有会话已撤销。")
            return 0
        import uvicorn
        from .app import create_app
        config = Config.from_env()
        bind = os.getenv("CERTWEB_BIND", "")
        port = int(os.getenv("CERTWEB_PORT", "18443"))
        if not private_ipv4(bind) or not config.allows_peer(bind, "/api/session") or not 1024 <= port <= 65535:
            raise ValueError("服务必须绑定白名单内的明确局域网 IPv4 地址与非特权端口")
        cert = os.getenv("CERTWEB_TLS_CERT", "/tls/current.cert")
        key = os.getenv("CERTWEB_TLS_KEY", "/tls/current.key")
        if not Path(cert).is_file() or not Path(key).is_file():
            raise ValueError("HTTPS 证书或私钥未就绪")
        uvicorn.run(create_app(config), host=bind, port=port, workers=1, proxy_headers=False,
                    forwarded_allow_ips="", access_log=False, server_header=False,
                    log_level="warning", ws="none", http="h11", loop="asyncio",
                    limit_concurrency=32, backlog=64, timeout_keep_alive=5,
                    timeout_graceful_shutdown=15, h11_max_incomplete_event_size=16384,
                    ssl_certfile=cert, ssl_keyfile=key)
        return 0
    except (ValueError, OSError):
        print("操作未完成：请检查私有目录权限、管理员输入及局域网/HTTPS 配置。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
