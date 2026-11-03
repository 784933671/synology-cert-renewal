#!/usr/bin/env python3
"""安装管理层，不重装、不重新初始化既有证书执行器。"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_guard import validate_network
from deployment import load_config, private_json
from access_policy import initialize_policy

DEFAULT_HOME = Path('/usr/local/share/synology-cert-web')
RC = Path('/usr/local/etc/rc.d/S99synology-cert-web.sh')


def prepare(args):
    source = Path(__file__).resolve().parent
    home = args.home
    native = args.native_home
    validate_network(args.bind, args.network, args.deny, args.port)
    if home.exists() or home.is_symlink():
        raise ValueError('管理目录已存在；不覆盖已有安装或登录数据')
    if str(home) != str(home.resolve()) or not home.is_absolute():
        raise ValueError('管理目录必须是无符号链接的绝对路径')
    if not (native / 'config.json').is_file() or not (native / 'certctl.py').is_file():
        raise ValueError('必须先存在已配置的原证书执行器')
    if (native / 'web/host_bridge.py').exists():
        raise ValueError('原执行器中已有桥接，需按升级流程处理')
    home.mkdir(mode=0o700)
    os.chmod(str(home), 0o700)
    config = {'home': str(home), 'native_home': str(native), 'bind': args.bind, 'networks': args.network,
              'denied': args.deny, 'port': args.port, 'origin': args.origin}
    private_json(home / 'deployment.json', config)
    checked = load_config(home / 'deployment.json')
    # 构建上下文仅包含代码；禁止复制本地凭据、链接和构建缓存。
    for current, directories, files in os.walk(str(source), followlinks=False):
        relative = Path(current).relative_to(source)
        directories[:] = [name for name in directories if name not in ('node_modules', 'dist', '__pycache__', 'coverage', 'data', 'tls', 'bridge', 'access', '.git')]
        destination = home / 'code' / relative
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in directories + files:
            if (Path(current) / name).is_symlink():
                raise ValueError('构建源不能包含符号链接')
        for name in files:
            if name.startswith('.env') or name.endswith(('.pyc', '.log', '.db', '.sqlite3', '.pem', '.key')):
                continue
            if name in ('deployment.json', 'deployment.env'):
                continue
            shutil.copyfile(str(Path(current) / name), str(destination / name))
            os.chmod(str(destination / name), 0o600)
    for directory in ('data', 'bridge', 'tls', 'access'):
        path = home / directory
        path.mkdir(mode=0o700)
        os.chown(str(path), 10100 if directory == 'data' else 0, 10100)
        os.chmod(str(path), 0o700 if directory == 'data' else 0o750)
    initialize_policy(home / 'access/access.json', mode=args.access_mode)
    target = native / 'web'
    target.mkdir(mode=0o700, exist_ok=True)
    if target.is_symlink() or target.stat().st_uid != 0 or target.stat().st_mode & 0o077:
        raise ValueError('既有桥接目录权限不安全')
    for name in ('host_bridge.py', 'access_policy.py', 'login_mail.py'):
        shutil.copyfile(str(source / name), str(target / name))
        os.chmod(str(target / name), 0o600)
    env = {'CERTWEB_HOME': str(home), 'CERTWEB_BIND': args.bind, 'CERTWEB_PORT': str(args.port),
           'CERTWEB_ALLOWED_NETWORKS': ','.join(args.network), 'CERTWEB_DENIED_ADDRESSES': ','.join(args.deny),
           'CERTWEB_ALLOWED_HOSTS': checked['authority'], 'CERTWEB_ORIGIN': args.origin}
    if any(any(char in value for char in '\n\r\x00\"\'#$`\\') for value in env.values()):
        raise ValueError('部署环境值包含非法字符')
    with (home / 'deployment.env').open('x') as handle:
        handle.write(''.join(key + '=' + value + '\n' for key, value in env.items()))
    print('管理代码和私有目录已准备完成；原续期配置与计划未修改。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=DEFAULT_HOME)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('prepare')
    command.add_argument('--native-home', type=Path, default=Path('/usr/local/share/synology-cert-renewal'))
    command.add_argument('--bind', required=True)
    command.add_argument('--network', action='append', required=True)
    command.add_argument('--deny', action='append', required=True)
    command.add_argument('--port', type=int, default=18443)
    command.add_argument('--origin', required=True)
    command.add_argument('--access-mode', choices=['lan', 'public'], default='lan')
    commands.add_parser('build')
    commands.add_parser('activate')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('必须在 NAS root 终端运行')
    os.umask(0o077)
    try:
        if args.command == 'prepare':
            prepare(args)
            return 0
        config = load_config(args.home / 'deployment.json')
        code = args.home / 'code'
        if args.command == 'build':
            return subprocess.call(['/usr/local/bin/docker', 'compose', '--project-name', 'synology-cert-web', '--env-file', str(args.home / 'deployment.env'), '-f', str(code / 'compose.yaml'), 'build'])
        if not (args.home / 'data/auth.sqlite3').is_file():
            raise ValueError('请先在私有终端初始化管理员账号')
        if RC.exists() or RC.is_symlink():
            raise ValueError('开机脚本已存在，停止以避免覆盖')
        command = shlex.join(['/usr/bin/python3', '-I', str(code / 'deployment.py'), '--config', str(args.home / 'deployment.json')])
        RC.write_text('#!/bin/sh\n# Synology certificate web management\ncase "$1" in\n  start|stop|status) exec ' + command + ' "$1" ;;\n  *) exit 2 ;;\nesac\n')
        os.chmod(str(RC), 0o755)
        return subprocess.call(['/bin/sh', str(RC), 'start'])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # 安装参数不含凭据，仍只输出安全的固定提示。
        print('安装未完成，请检查目录是否已存在、配置格式及 Docker 状态；原证书执行器未被重装。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
