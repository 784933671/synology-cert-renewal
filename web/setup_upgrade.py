"""已有管理层的事务升级；运行数据只备份，不作为升级源码复制。"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time

DOCKER = '/usr/local/bin/docker'
CONTAINER = 'synology-cert-web'
LABEL = 'io.github.784933671.certweb.managed'
DEFAULT_HOME = Path('/usr/local/share/synology-cert-web')
ACME_STAMP = '3.1.6\n807da6498377ee5e0cf43a78091f46f12dc59a89\nddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220\n'
WEB_FILES = (
    '.dockerignore', '__init__.py', 'Dockerfile', 'compose.yaml', 'requirements.txt',
    'access_policy.py', 'container_entry.py', 'deployment.py', 'healthcheck.py',
    'host_bridge.py', 'install-web.py', 'login_mail.py', 'monitor.py', 'observability.py', 'startup_check.py', 'network_guard.py', 'tls_sync.py',
    'frontend/index.html', 'frontend/package.json', 'frontend/package-lock.json',
    'frontend/tsconfig.json', 'frontend/vite.config.ts', 'frontend/vitest.config.ts',
)
OPTIONAL_WEB_FILES = ('README.md', 'CONTRACT.md', 'DEPLOYMENT.md', 'deployment.env.example',
                      'setup.py', 'setup_tasks.py', 'setup_upgrade.py', 'setup_settings.py')
CODE_TREES = {'backend': {'.py'}, 'frontend/src': {'.vue', '.ts', '.css', '.svg'},
              'frontend/build': {'.ts'}, 'frontend/tests': {'.ts'}}
NATIVE_FILES = {'certctl.py': 'certctl.py', 'run_history.py': 'run_history.py', 'failure_diagnostics.py': 'failure_diagnostics.py',
                'dns_cleanup.py': 'dns_cleanup.py', 'dns_cleanup_retry.sh': 'dns_cleanup_retry.sh',
                'web/host_bridge.py': 'web/host_bridge.py', 'web/access_policy.py': 'web/access_policy.py',
                'web/login_mail.py': 'web/login_mail.py', 'web/monitor.py': 'web/monitor.py',
                'web/observability.py': 'web/observability.py',
                'acme/dnsapi/dns_tencent.sh': 'dns_tencent_tracked.sh'}


class UpgradeError(RuntimeError):
    pass


def safe_errors(method):
    def invoke(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except UpgradeError:
            raise
        except (Exception, KeyboardInterrupt):
            raise UpgradeError('升级未完成，请检查私有部署配置、文件权限和恢复记录') from None
    return invoke


def run_command(args, timeout=60):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=timeout,
                                env=dict(os.environ, PATH='/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'))
        if result.returncode:
            raise UpgradeError('升级命令执行失败，请检查 Docker 与管理服务状态')
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise UpgradeError('升级命令执行失败，请检查 Docker 与管理服务状态') from None


def fsync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path, content, mode=0o600, owner=None):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    try:
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            if owner is not None:
                os.fchown(handle.fileno(), *owner)
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def regular(path, uid=None, private=False):
    info = Path(path).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            (uid is not None and info.st_uid != uid) or
            (private and info.st_mode & 0o077)):
        raise UpgradeError('安装文件类型、属主或权限不安全')
    return info


def directory(path, uid=None, private=False):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path != path.resolve() or
            (uid is not None and info.st_uid != uid) or info.st_mode & (0o077 if private else 0o022)):
        raise UpgradeError('安装目录类型、属主或权限不安全')


def copy_payload(source_root, destination):
    """只复制编译与运行所需代码；凭据目录、配置和缓存不进入镜像。"""
    source = Path(source_root) / 'web'
    directory(source)
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    names = list(WEB_FILES)
    names.extend(name for name in OPTIONAL_WEB_FILES if (source / name).exists())
    for tree, suffixes in CODE_TREES.items():
        root = source / tree
        directory(root)
        for current, dirs, files in os.walk(str(root), followlinks=False):
            for name in list(dirs):
                path = Path(current) / name
                if path.is_symlink():
                    raise UpgradeError('升级源码不能包含符号链接')
                if name in ('__pycache__', 'node_modules', 'dist', 'coverage') or name.startswith('.'):
                    dirs.remove(name)
                else:
                    directory(path)
            for name in files:
                path = Path(current) / name
                if path.is_symlink():
                    raise UpgradeError('升级源码不能包含符号链接')
                if path.suffix in suffixes and not name.startswith('.'):
                    names.append(str(path.relative_to(source)))
    total = 0
    for name in sorted(set(names)):
        path = source / name
        info = regular(path)
        if info.st_mode & 0o022 or info.st_size > 4 * 1024 * 1024:
            raise UpgradeError('升级源码权限或大小不符合要求')
        total += info.st_size
        if total > 32 * 1024 * 1024:
            raise UpgradeError('升级源码体积异常')
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_bytes(target, path.read_bytes())
    for name in ('backend/__main__.py', 'backend/app.py', 'backend/auth.py', 'frontend/src/main.ts'):
        regular(destination / name)
    return sorted(set(names))


class Upgrade:
    def __init__(self, source_root, home=DEFAULT_HOME, runner=None, uid=0,
                 clock=time.time, sleeper=time.sleep):
        self.source = Path(source_root).resolve()
        self.home = Path(home)
        self.runner = runner or run_command
        self.uid, self.clock, self.sleep = uid, clock, sleeper
        self.journal = self.home / 'upgrade-state.json'
        self.config_path = self.home / 'deployment.json'
        self.config = None
        self.native = None

    def command(self, args, timeout=60):
        try:
            return self.runner(args, timeout=timeout)
        except (Exception, KeyboardInterrupt):
            raise UpgradeError('升级操作未完成，请检查安装状态后重新运行') from None

    def validate(self):
        if os.geteuid() != self.uid:
            raise UpgradeError('请在 NAS root 终端执行升级')
        directory(self.home, self.uid, True)
        regular(self.config_path, self.uid, True)
        config = json.loads(self.config_path.read_text())
        if config.get('home') != str(self.home):
            raise UpgradeError('管理目录与已有部署配置不一致')
        self.native = Path(config['native_home'])
        directory(self.native, self.uid, True)
        directory(self.native / 'state', self.uid, True)
        if (self.home / 'code').exists():
            directory(self.home / 'code', self.uid, True)
        elif not self.journal.exists():
            raise UpgradeError('管理代码缺失且没有可用升级恢复记录')
        directory(self.home / 'data', private=True)
        regular(self.home / 'data/auth.sqlite3', private=True)
        regular(self.native / 'config.json', self.uid, True)
        regular(self.native / 'ACME-VERSION', self.uid, True)
        if (self.native / 'ACME-VERSION').read_text() != ACME_STAMP:
            raise UpgradeError('ACME 版本不同，请使用对应版本的迁移流程')
        self.config = config

    @contextlib.contextmanager
    def locked(self, path):
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077 or info.st_nlink != 1):
                raise UpgradeError('安装锁权限不安全')
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UpgradeError('其他安装或证书任务正在运行，请稍后重试') from None
            yield

    def save_journal(self, state):
        atomic_bytes(self.journal, json.dumps(state, ensure_ascii=False).encode())

    def read_journal(self):
        regular(self.journal, self.uid, True)
        state = json.loads(self.journal.read_text())
        if (state.get('version') != 1 or not re.fullmatch(r'upgrade-[0-9a-f]{32}', state.get('work', ''))
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', state.get('old_image', ''))
                or not re.fullmatch(r'synology-cert-web:upgrade-[0-9a-f]{32}', state.get('tag', ''))
                or type(state.get('snapshot')) is not bool
                or state.get('phase') not in ('prepared', 'switching', 'starting', 'complete', 'rolled_back', 'rollback_failed')):
            raise UpgradeError('升级恢复记录异常，请检查私有备份')
        directory(self.home / 'upgrades' / state['work'], self.uid, True)
        return state

    def lifecycle(self, action, backup=None):
        script = self.home / 'code/deployment.py'
        if backup is None:
            args = [sys.executable, '-I', str(script), '--config', str(self.config_path), action]
        else:
            # 加载完整备份，但保留原监督进程启动路径用于 PID 身份核对。
            launcher = "import runpy,sys;n=runpy.run_path(sys.argv[1],run_name='certweb_recovery');n['main'].__globals__['__file__']=sys.argv[2];sys.exit(n['main'](['--config',sys.argv[3],sys.argv[4]]))"
            args = [sys.executable, '-I', '-c', launcher, str(backup / 'deployment.py'), str(script), str(self.config_path), action]
        self.command(args, timeout=370)

    def inspect_container(self):
        names = self.command([DOCKER, 'ps', '-a', '--filter', 'name=^/' + CONTAINER + '$', '--format', '{{.Names}}']).splitlines()
        if CONTAINER not in names:
            return None
        item = json.loads(self.command([DOCKER, 'inspect', CONTAINER]))[0]
        if item.get('Config', {}).get('Labels', {}).get(LABEL) != 'true':
            raise UpgradeError('同名容器不属于证书管家')
        return item

    def ensure_writers_stopped(self):
        item = self.inspect_container()
        if item and (item.get('State', {}).get('Running') or item.get('State', {}).get('Restarting')):
            raise UpgradeError('管理容器尚未停止，保留认证数据库')
        identifiers = self.command([DOCKER, 'ps', '-q']).splitlines()
        if identifiers:
            mounts = self.command([DOCKER, 'inspect', '--format', '{{json .Mounts}}'] + identifiers)
            for line in mounts.splitlines():
                for mount in json.loads(line):
                    source = Path(mount.get('Source', '/')).resolve()
                    data = (self.home / 'data').resolve()
                    if mount.get('RW') and (source == data or source in data.parents or data in source.parents):
                        raise UpgradeError('仍有容器可写入认证数据，保留现有数据库')

    def native_changes(self):
        changes = {}
        for target, source in NATIVE_FILES.items():
            path = self.source / source
            regular(path)
            if path.stat().st_mode & 0o022 or path.stat().st_size > 4 * 1024 * 1024:
                raise UpgradeError('原生执行器源码权限或大小异常')
            destination = self.native / target
            directory(destination.parent, self.uid, True)
            if os.path.lexists(destination):
                regular(destination, self.uid, True)
            changes[target] = path.read_bytes()
        return changes

    def snapshot(self, work, changes):
        backup = work / 'native'
        backup.mkdir(mode=0o700)
        entries = {}
        for name in changes:
            path = self.native / name
            info = regular(path, self.uid, True) if path.exists() else None
            entries[name] = {'exists': info is not None, 'mode': stat.S_IMODE(info.st_mode) if info else 0o600}
            if info:
                target = backup / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                atomic_bytes(target, path.read_bytes())
        database = self.home / 'data/auth.sqlite3'
        info = regular(database, private=True)
        with sqlite3.connect(str(database)) as source:
            with sqlite3.connect(str(work / 'auth.sqlite3')) as target:
                source.backup(target)
        os.chmod(str(work / 'auth.sqlite3'), 0o600)
        with (work / 'auth.sqlite3').open('rb') as handle:
            os.fsync(handle.fileno())
        manifest = {'native': entries, 'database_owner': [info.st_uid, info.st_gid]}
        atomic_bytes(work / 'manifest.json', json.dumps(manifest).encode())

    def healthy(self, image):
        item = self.inspect_container()
        return bool(item and item.get('Image') == image and item.get('State', {}).get('Running')
                    and item['State'].get('Health', {}).get('Status') == 'healthy')

    def wait_healthy(self, image):
        # 为主机启动稳定窗口和后续 Docker 健康探测留出余量。
        for _ in range(180):
            if self.healthy(image):
                return
            self.sleep(1)
        raise UpgradeError('新版本健康检查失败')

    def restore(self, state):
        work = self.home / 'upgrades' / state['work']
        previous = work / 'previous-code'
        backup_code = previous if previous.exists() else self.home / 'code'
        errors = []
        try:
            self.lifecycle('stop', backup=backup_code)
        except UpgradeError:
            # 停止结果不明确时，后续仍必须独立确认监督锁和所有数据库写入者。
            pass
        try:
            with self.locked(self.home / 'supervisor.lock'), self.locked(self.native / 'state/run.lock'):
                self.ensure_writers_stopped()
                if state['snapshot']:
                    regular(work / 'manifest.json', self.uid, True)
                    manifest = json.loads((work / 'manifest.json').read_text())
                    if (set(manifest.get('native', {})) != set(NATIVE_FILES) or
                            not isinstance(manifest.get('database_owner'), list) or
                            len(manifest['database_owner']) != 2 or
                            any(type(value) is not int or value < 0 for value in manifest['database_owner'])):
                        raise UpgradeError('升级备份清单异常')
                    for entry in manifest['native'].values():
                        if (not isinstance(entry, dict) or set(entry) != {'exists', 'mode'} or
                                type(entry['exists']) is not bool or type(entry['mode']) is not int or
                                not 0 <= entry['mode'] <= 0o700 or entry['mode'] & 0o077):
                            raise UpgradeError('升级文件备份权限异常')
                    if previous.exists():
                        directory(previous, self.uid, True)
                        if (self.home / 'code').exists():
                            os.rename(str(self.home / 'code'), str(work / ('failed-code-' + secrets.token_hex(8))))
                        os.rename(str(previous), str(self.home / 'code'))
                        fsync_directory(self.home)
                    for name, entry in manifest['native'].items():
                        target = self.native / name
                        directory(target.parent, self.uid, True)
                        if entry['exists']:
                            regular(work / 'native' / name, self.uid, True)
                            atomic_bytes(target, (work / 'native' / name).read_bytes(), entry['mode'])
                        elif os.path.lexists(target):
                            regular(target, self.uid, True)
                            target.unlink()
                    regular(work / 'auth.sqlite3', self.uid, True)
                    for suffix in ('-wal', '-shm', '-journal'):
                        side = self.home / 'data' / ('auth.sqlite3' + suffix)
                        if os.path.lexists(side):
                            regular(side, private=True)
                            side.unlink()
                    atomic_bytes(self.home / 'data/auth.sqlite3', (work / 'auth.sqlite3').read_bytes(), owner=manifest['database_owner'])
                self.command([DOCKER, 'tag', state['old_image'], 'synology-cert-web:local'])
        except (Exception, KeyboardInterrupt):
            errors.append('restore')
        if not errors:
            try:
                self.lifecycle('start')
                self.wait_healthy(state['old_image'])
            except (Exception, KeyboardInterrupt):
                errors.append('restart')
        state['phase'] = 'rollback_failed' if errors else 'rolled_back'
        self.save_journal(state)
        if errors:
            raise UpgradeError('自动恢复未完成；备份已保留，请重新运行升级恢复，不要删除认证数据')
        return {'recovered': True, 'backup': str(work)}

    @safe_errors
    def recover(self):
        self.validate()
        with self.locked(self.home / 'upgrade.lock'):
            if not self.journal.exists():
                return {'recovered': False}
            state = self.read_journal()
            if state['phase'] in ('complete', 'rolled_back'):
                return {'recovered': False}
            return self.restore(state)

    @safe_errors
    def run(self):
        self.validate()
        with self.locked(self.home / 'upgrade.lock'):
            if self.journal.exists():
                state = self.read_journal()
                if state['phase'] not in ('complete', 'rolled_back'):
                    return self.restore(state)
            changes = self.native_changes()
            item = self.inspect_container()
            old_image = item.get('Image') if item else self.command([DOCKER, 'image', 'inspect', 'synology-cert-web:local', '--format', '{{.Id}}']).strip()
            if not isinstance(old_image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', old_image):
                raise UpgradeError('无法确认已有管理镜像')
            upgrades = self.home / 'upgrades'
            upgrades.mkdir(mode=0o700, exist_ok=True)
            directory(upgrades, self.uid, True)
            identifier = secrets.token_hex(16)
            work = upgrades / ('upgrade-' + identifier)
            work.mkdir(mode=0o700)
            copy_payload(self.source, work / 'new-code')
            tag = 'synology-cert-web:upgrade-' + identifier
            self.command([DOCKER, 'build', '--tag', tag, str(work / 'new-code')], timeout=1200)
            image = self.command([DOCKER, 'image', 'inspect', tag, '--format', '{{.Id}}']).strip()
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
                raise UpgradeError('新镜像构建结果无法确认')
            state = {'version': 1, 'work': work.name, 'old_image': old_image, 'tag': tag, 'phase': 'prepared', 'snapshot': False}
            self.save_journal(state)
            stop_attempted = False
            try:
                # 原任务正在运行时不停止管理服务；锁也保护原生文件替换。
                with self.locked(self.native / 'state/run.lock'):
                    stop_attempted = True
                    self.lifecycle('stop')
                    with self.locked(self.home / 'supervisor.lock'):
                        self.ensure_writers_stopped()
                        self.snapshot(work, changes)
                        state['snapshot'] = True
                        state['phase'] = 'switching'
                        self.save_journal(state)
                        for name, content in changes.items():
                            target = self.native / name
                            mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o600
                            atomic_bytes(target, content, mode)
                        os.rename(str(self.home / 'code'), str(work / 'previous-code'))
                        os.rename(str(work / 'new-code'), str(self.home / 'code'))
                        fsync_directory(self.home)
                        fsync_directory(work)
                        self.command([DOCKER, 'tag', tag, 'synology-cert-web:local'])
                        state['phase'] = 'starting'
                        self.save_journal(state)
                self.lifecycle('start')
                self.wait_healthy(image)
                state['phase'] = 'complete'
                self.save_journal(state)
                return {'upgraded': True, 'image_tag': tag, 'backup': str(work)}
            except (Exception, KeyboardInterrupt):
                if not stop_attempted:
                    state['phase'] = 'rolled_back'
                    self.save_journal(state)
                    raise UpgradeError('原任务正在运行，升级尚未切换，请稍后重试') from None
                self.restore(state)
                raise UpgradeError('升级失败，已恢复原版本；请检查环境后重试') from None
