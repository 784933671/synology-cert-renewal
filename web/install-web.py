#!/usr/bin/env python3
"""安装管理层，不重装、不重新初始化既有证书执行器。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import stat
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_guard import validate_network
from deployment import load_config, private_json, validate_origin, validate_task_id
from access_policy import initialize_policy

DEFAULT_HOME = Path('/usr/local/share/synology-cert-web')
RC = Path('/usr/local/etc/rc.d/S99synology-cert-web.sh')


def source_files(source):
    top = {'.dockerignore', 'Dockerfile', 'compose.yaml', '__init__.py', 'README.md', 'CONTRACT.md',
           'DEPLOYMENT.md', 'requirements.txt', 'requirements.in', 'requirements-test.txt',
           'requirements-test.in', 'deployment.env.example', 'access_policy.py', 'container_entry.py',
           'deployment.py', 'healthcheck.py', 'host_bridge.py', 'install-web.py', 'login_mail.py', 'monitor.py', 'observability.py', 'startup_check.py', 'adaptive_schedule.py',
           'network_guard.py', 'tls_sync.py', 'setup.py', 'setup_tasks.py', 'setup_upgrade.py', 'container_project.py'}
    frontend = {'package.json', 'package-lock.json', 'tsconfig.json', 'vite.config.ts', 'vitest.config.ts',
                'index.html', '.gitignore'}
    result = {}
    paths = []
    for current, directories, names in os.walk(str(source), followlinks=False):
        directories[:] = [name for name in directories if name not in
                          ('node_modules', 'dist', '__pycache__', 'coverage', 'data', 'tls', 'bridge', 'access', '.git')]
        for name in directories:
            if (Path(current) / name).is_symlink():
                raise ValueError('构建源不能包含符号链接目录')
        paths.extend(Path(current) / name for name in names)
    for path in paths:
        relative = path.relative_to(source)
        parts = relative.parts
        allowed = ((len(parts) == 1 and path.name in top)
                   or (parts[0] == 'backend' and len(parts) == 2 and (path.suffix == '.py' or path.name == 'README.md'))
                   or (parts[0] == 'frontend' and len(parts) == 2 and path.name in frontend)
                   or (parts[0] == 'frontend' and len(parts) >= 3 and parts[1] in ('src', 'build', 'tests')
                       and path.suffix in ('.vue', '.ts', '.css', '.svg', '.json')))
        if not allowed:
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != source.parent):
            raise ValueError('构建源不能包含符号链接')
        if path.is_file():
            result[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    for required in ('Dockerfile', 'compose.yaml', 'deployment.py', 'container_project.py', 'host_bridge.py', 'login_mail.py', 'monitor.py', 'observability.py', 'startup_check.py', 'adaptive_schedule.py',
                     'access_policy.py', 'backend/app.py', 'frontend/package.json'):
        if required not in result:
            raise ValueError('管理源码缺少必要文件')
    return result


def private_root(path, directory=False):
    info = path.lstat()
    if (path.is_symlink() or str(path) != str(path.resolve()) or info.st_uid != 0 or info.st_mode & 0o077
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError('安装私有目录或文件权限不安全')


def prepare(args):
    source = Path(__file__).resolve().parent
    home, native = args.home, args.native_home
    task_id = validate_task_id(getattr(args, 'task_id', 7))
    validate_network(args.bind, args.network, args.deny, args.port)
    authority, _ = validate_origin(args.origin, args.port)
    if args.access_mode not in ('lan', 'public'):
        raise ValueError('访问模式无效')
    for path in (home, native):
        if str(path) != str(path.resolve()) or not path.is_absolute():
            raise ValueError('安装目录必须是无符号链接的绝对路径')
    private_root(native, directory=True)
    for name in ('config.json', 'certctl.py'):
        private_root(native / name)
    config = {'home': str(home), 'native_home': str(native), 'bind': args.bind, 'networks': args.network,
              'denied': args.deny, 'port': args.port, 'origin': args.origin, 'task_id': task_id}
    env = {'CERTWEB_HOME': str(home), 'CERTWEB_BIND': args.bind, 'CERTWEB_PORT': str(args.port),
           'CERTWEB_ALLOWED_NETWORKS': ','.join(args.network), 'CERTWEB_DENIED_ADDRESSES': ','.join(args.deny),
           'CERTWEB_ALLOWED_HOSTS': authority, 'CERTWEB_ORIGIN': args.origin}
    if any(any(char in value for char in '\n\r\x00"\'#$`\\') for value in env.values()):
        raise ValueError('部署环境值包含非法字符')
    files = source_files(source)
    marker = {'version': 1, 'config': config, 'files': files, 'access_mode': args.access_mode}
    new_home, staging, created = False, None, []
    target = native / 'web'
    try:
        if home.exists() or home.is_symlink():
            private_root(home, directory=True)
            private_root(home / 'setup-preparation.json')
            if json.loads((home / 'setup-preparation.json').read_text()) != marker:
                raise ValueError('既有目录不属于此次准备流程；请使用原安装包继续或执行升级')
            if json.loads((home / 'deployment.json').read_text()) != config:
                raise ValueError('恢复安装配置已发生变化')
            for name, digest in files.items():
                path = home / 'code' / name
                private_root(path)
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError('恢复安装源码不完整或已变化')
        else:
            if target.exists():
                private_root(target, directory=True)
                if any(os.path.lexists(target / name) for name in ('host_bridge.py', 'access_policy.py', 'login_mail.py', 'monitor.py', 'observability.py', 'adaptive_schedule.py')):
                    raise ValueError('原执行器中已有桥接，需按升级流程处理')
            staging = Path(tempfile.mkdtemp(prefix='.' + home.name + '-prepare-', dir=str(home.parent)))
            for name in files:
                path = staging / 'code' / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(str(source / name), str(path));os.chmod(str(path), 0o600)
            private_json(staging / 'deployment.json', config)
            private_json(staging / 'setup-preparation.json', marker)
            for directory in ('data', 'bridge', 'tls', 'access'):
                path = staging / directory;path.mkdir(mode=0o700)
                os.chown(str(path), 10100 if directory == 'data' else 0, 10100)
                os.chmod(str(path), 0o700 if directory == 'data' else 0o750)
            initialize_policy(staging / 'access/access.json', mode=args.access_mode)
            (staging / 'deployment.env').write_text(''.join(key + '=' + value + '\n' for key, value in env.items()))
            os.chmod(str(staging / 'deployment.env'), 0o600)
            os.rename(str(staging), str(home));staging = None;new_home = True
        target.mkdir(mode=0o700, exist_ok=True)
        private_root(target, directory=True)
        for name in ('host_bridge.py', 'access_policy.py', 'login_mail.py', 'monitor.py', 'observability.py', 'adaptive_schedule.py'):
            path = target / name
            content = (home / 'code' / name).read_bytes()
            if os.path.lexists(path):
                private_root(path)
                if path.read_bytes() != content:
                    raise ValueError('原生桥接内容不同，不能覆盖')
                continue
            descriptor, temporary = tempfile.mkstemp(prefix='.bridge-install-', dir=str(target))
            try:
                with os.fdopen(descriptor, 'wb') as handle:
                    handle.write(content);handle.flush();os.fsync(handle.fileno())
                os.link(temporary, str(path));created.append(path)
            finally:
                os.unlink(temporary)
        load_config(home / 'deployment.json')
        print('管理代码和私有目录已准备完成；原续期配置与计划未修改。')
    except BaseException:
        if new_home:
            for path in created:
                path.unlink()
            shutil.rmtree(str(home))
        raise
    finally:
        if staging is not None:
            shutil.rmtree(str(staging))


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
    command.add_argument('--task-id', type=int, default=7)
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
