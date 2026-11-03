#!/bin/sh
# 私有仓库安装入口；源码目录和凭据分离，继续复用 setup.sh。
set -eu
set +x
umask 077
PATH=/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
case "${1:-}" in
  --help) printf '%s\n' '在 DSM 私有终端执行 sudo sh bootstrap-private.sh；隐藏输入 GitHub 只读令牌，自动准备依赖并进入原安装向导。'; exit 0 ;;
  ''|--token-stdin) ;;
  *) printf '%s\n' '不支持的安装参数。' >&2; exit 1 ;;
esac
[ "$#" -le 1 ] || exit 1
[ "$(id -u)" = 0 ] || { printf '%s\n' '请使用 sudo 在 NAS 上运行。' >&2; exit 1; }
[ -f /etc.defaults/VERSION ] && [ "$(uname -m)" = x86_64 ] || { printf '%s\n' '仅支持 DSM 7 的 x86_64 群晖。' >&2; exit 1; }
case "$(sed -n 's/^productversion="\([^"]*\)"/\1/p' /etc.defaults/VERSION)" in
  7.*) ;;
  *) printf '%s\n' '当前只支持 DSM 7。' >&2; exit 1 ;;
esac
if [ "${1:-}" = --token-stdin ]; then exec 3<&0; fi
exec </dev/tty
find_python() {
  for bootstrap_python in /usr/bin/python3 /usr/local/bin/python3 /var/packages/Python3/target/usr/local/bin/python3 /var/packages/Python3.9/target/usr/local/bin/python3.9; do
    if [ -x "$bootstrap_python" ] && "$bootstrap_python" -I -c 'import sys,ssl,sqlite3,fcntl;sys.exit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$bootstrap_python"; return 0
    fi
  done
  return 1
}
BOOTSTRAP_PYTHON=$(find_python || true)
if [ -z "$BOOTSTRAP_PYTHON" ]; then
  BOOTSTRAP_PKG=$(command -v synopkg || true)
  [ -n "$BOOTSTRAP_PKG" ] && "$BOOTSTRAP_PKG" --help 2>&1 | grep -q install_from_server || { printf '%s\n' '请先在套件中心安装 Python 3.8 或以上，再重新执行本命令。' >&2; exit 1; }
  printf '%s\n' '正在通过群晖套件中心安装 Python3……'
  "$BOOTSTRAP_PKG" install_from_server Python3 >/dev/null 2>&1 || true
  BOOTSTRAP_PYTHON=$(find_python || true)
  [ -n "$BOOTSTRAP_PYTHON" ] || { printf '%s\n' '套件中心未提供可用 Python，请先安装 Python 3.8 或以上后重试。' >&2; exit 1; }
fi
exec "$BOOTSTRAP_PYTHON" -I - "$@" <<'CERT_BOOTSTRAP_PY'
import contextlib
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

REPO = '784933671/synology-cert-renewal'
API = 'https://api.github.com/repos/' + REPO
BASE = Path('/usr/local/share/synology-cert-bootstrap')
INSTALL_STATE = Path('/usr/local/share/synology-cert-setup/install.json')
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}')


class BootstrapError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BootstrapError('安装数据字段重复。')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def private(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise BootstrapError('安装缓存不是当前管理员的私有文件或目录。')
    if not directory and info.st_nlink != 1:
        raise BootstrapError('安装缓存不能是硬链接。')


def read_private(path):
    private(path)
    if path.stat().st_size > 1024 * 1024:
        raise BootstrapError('安装状态过大。')
    return strict_json(path.read_bytes())


def write_private(path, value):
    private(path.parent, True)
    if os.path.lexists(path):
        private(path)
    fd, temporary = tempfile.mkstemp(prefix='.state-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, sort_keys=True)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, str(path))
        fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def safe_path(name):
    if (not isinstance(name, str) or not name or '\\' in name or '\x00' in name
            or any(ord(c) < 32 for c in name) or len(name) > 512):
        raise BootstrapError('源码路径无效。')
    path = PurePosixPath(name)
    if path.is_absolute() or any(x in ('', '.', '..') for x in name.split('/')):
        raise BootstrapError('源码路径越界。')
    return path


def blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


class GitHub:
    def __init__(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_]{20,255}', token):
            raise BootstrapError('GitHub 令牌格式无效。')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def open(self, url, authenticated=True):
        parts = urllib.parse.urlsplit(url)
        allowed = 'api.github.com' if authenticated else 'codeload.github.com'
        if (parts.scheme != 'https' or parts.hostname != allowed or parts.port not in (None, 443)
                or parts.username or parts.password or parts.fragment):
            raise BootstrapError('拒绝向非 GitHub 下载地址发送请求。')
        headers = {'User-Agent': 'synology-cert-bootstrap', 'Accept': 'application/vnd.github+json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.token
        return self.opener.open(urllib.request.Request(url, headers=headers), timeout=120)

    def json(self, suffix):
        with self.open(API + suffix) as response:
            data = response.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise BootstrapError('GitHub 返回数据过大。')
        return strict_json(data)

    def revision(self):
        data = self.json('/commits/main')
        sha = data.get('sha') if isinstance(data, dict) else None
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise BootstrapError('无法确认 main 分支版本。')
        return sha

    def manifest(self, revision):
        data = self.json('/git/trees/' + revision + '?recursive=1')
        if not isinstance(data, dict) or data.get('truncated') is not False or not isinstance(data.get('tree'), list):
            raise BootstrapError('源码清单不完整。')
        result = {}
        for entry in data['tree']:
            name = str(safe_path(entry.get('path')))
            if entry.get('type') == 'tree':
                continue
            if (entry.get('type') != 'blob' or entry.get('mode') not in ('100644', '100755')
                    or not isinstance(entry.get('sha'), str) or not SHA.fullmatch(entry['sha'])
                    or type(entry.get('size')) is not int or not 0 <= entry['size'] <= MAX_FILE
                    or name in result):
                raise BootstrapError('源码清单含不支持的文件或链接。')
            result[name] = {'sha': entry['sha'], 'size': entry['size']}
        if not result or len(result) > 2000 or sum(x['size'] for x in result.values()) > MAX_TOTAL:
            raise BootstrapError('源码清单大小不符合要求。')
        if not {'setup.sh', 'web/setup.py', 'install.sh'} <= set(result):
            raise BootstrapError('源码缺少安装入口。')
        return result

    def archive(self, revision, target):
        try:
            response = self.open(API + '/tarball/' + revision)
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise
            location = error.headers.get('Location', '')
            error.close()
            # 私有归档用短期签名 URL 下载，绝不转发 Authorization。
            response = self.open(location, authenticated=False)
        total = 0
        with response, target.open('xb') as output:
            while True:
                data = response.read(128 * 1024)
                if not data:
                    break
                total += len(data)
                if total > MAX_TOTAL:
                    raise BootstrapError('源码归档过大。')
                output.write(data)
        target.chmod(0o600)


def extract_verified(archive, target, manifest):
    seen, prefix, total = set(), None, 0
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream:
            raw = member.name.rstrip('/') if member.isdir() else member.name
            parts = safe_path(raw).parts
            if prefix is None:
                prefix = parts[0]
            if parts[0] != prefix:
                raise BootstrapError('归档包含多个根目录。')
            if len(parts) == 1:
                if not member.isdir():
                    raise BootstrapError('归档根目录无效。')
                continue
            name = '/'.join(parts[1:])
            if member.isdir():
                continue
            if not member.isfile() or name not in manifest or name in seen:
                raise BootstrapError('归档包含额外文件、链接或重复路径。')
            expected = manifest[name]
            if member.size != expected['size'] or member.size > MAX_FILE:
                raise BootstrapError('源码文件大小不匹配。')
            total += member.size
            if total > MAX_TOTAL:
                raise BootstrapError('解压大小超出限制。')
            with stream.extractfile(member) as handle:
                data = handle.read(MAX_FILE + 1)
            if len(data) != member.size or blob_sha(data) != expected['sha']:
                raise BootstrapError('源码完整性校验失败，尚未执行安装。')
            path = target / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as handle:
                handle.write(data)
            path.chmod(0o600)
            seen.add(name)
    if seen != set(manifest):
        raise BootstrapError('归档源码不完整。')


class Installer:
    def __init__(self, github, base=BASE, install_state=INSTALL_STATE, runner=subprocess.run):
        self.github, self.base, self.install_state, self.runner = github, Path(base), Path(install_state), runner
        self.receipt = self.base / 'pending.json'

    @contextlib.contextmanager
    def locked(self):
        if str(self.base.resolve()) != str(self.base):
            raise BootstrapError('安装缓存不能经过符号链接。')
        self.base.mkdir(mode=0o700, parents=False, exist_ok=True)
        private(self.base, True)
        fd = os.open(str(self.base / 'bootstrap.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as handle:
            private(self.base / 'bootstrap.lock')
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def cached(self, revision):
        if not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise BootstrapError('缓存版本无效。')
        root = self.base / revision
        private(root, True)
        manifest = read_private(root / 'files.json')
        source = root / 'source'
        private(source, True)
        if not isinstance(manifest, dict) or not manifest or len(manifest) > 2000:
            raise BootstrapError('缓存清单无效。')
        actual = set()
        for path in source.rglob('*'):
            if path.is_dir() and not path.is_symlink():
                private(path, True)
                continue
            private(path)
            name = path.relative_to(source).as_posix()
            expected = manifest.get(name)
            if (not isinstance(expected, dict) or set(expected) != {'sha', 'size'}
                    or type(expected['size']) is not int or not 0 <= expected['size'] <= MAX_FILE
                    or not isinstance(expected['sha'], str) or not SHA.fullmatch(expected['sha'])
                    or path.stat().st_size != expected['size'] or blob_sha(path.read_bytes()) != expected['sha']):
                raise BootstrapError('缓存源码已变化，停止执行。')
            actual.add(name)
        if actual != set(manifest) or not {'setup.sh', 'web/setup.py', 'install.sh'} <= actual:
            raise BootstrapError('缓存源码不完整。')
        return source

    def source(self):
        if os.path.lexists(self.receipt):
            receipt = read_private(self.receipt)
            if (not isinstance(receipt, dict) or set(receipt) != {'version', 'revision'}
                    or type(receipt['version']) is not int or receipt['version'] != 1):
                raise BootstrapError('未完成安装记录异常。')
            print('继续上次安装，使用同一份已校验源码。', flush=True)
            return self.cached(receipt['revision'])
        if os.path.lexists(self.install_state):
            state = read_private(self.install_state)
            if not isinstance(state, dict) or state.get('complete') is not True:
                raise BootstrapError('发现其他入口的未完成安装，请先用原源码包恢复。')
        revision = self.github.revision()
        final = self.base / revision
        if not os.path.lexists(final):
            manifest = self.github.manifest(revision)
            with tempfile.TemporaryDirectory(prefix='.download-', dir=str(self.base)) as temporary:
                work = Path(temporary)
                archive = work / 'source.tar.gz'
                self.github.archive(revision, archive)
                (work / 'source').mkdir(mode=0o700)
                extract_verified(archive, work / 'source', manifest)
                archive.unlink()
                write_private(work / 'files.json', manifest)
                os.rename(str(work), str(final))
        source = self.cached(revision)
        write_private(self.receipt, {'version': 1, 'revision': revision})
        print('已校验安装源码版本：' + revision[:12], flush=True)
        return source

    def dependencies(self):
        docker = '/usr/local/bin/docker'
        def works():
            return all(self.runner(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30).returncode == 0
                       for args in ([docker, 'info'], [docker, 'compose', 'version']))
        try:
            if works():
                return
        except (OSError, subprocess.SubprocessError):
            pass
        package_tool = shutil.which('synopkg')
        if not package_tool:
            raise BootstrapError('缺少群晖套件管理器，请先安装并启动 Container Manager。')
        existing = next((p for p in ('ContainerManager', 'Docker') if (Path('/var/packages') / p).is_dir()), None)
        if existing is None:
            version = Path('/etc.defaults/VERSION').read_text()
            match = re.search(r'^productversion="7\.(\d+)', version, re.M)
            package = 'ContainerManager' if match and int(match.group(1)) >= 2 else 'Docker'
            help_result = self.runner([package_tool, '--help'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=30)
            if 'install_from_server' not in (help_result.stdout or ''):
                raise BootstrapError('当前 DSM 不支持命令安装套件，请先在套件中心安装 Container Manager。')
            print('正在从群晖套件中心安装 ' + package + '……', flush=True)
            result = self.runner([package_tool, 'install_from_server', package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
            if result.returncode:
                raise BootstrapError('套件安装未完成，请在套件中心检查后重试；不会卸载现有套件。')
            existing = package
        result = self.runner([package_tool, 'start', existing], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
        if result.returncode or not works():
            raise BootstrapError('Docker 或 Compose 尚不可用，请查看套件中心状态后重新执行安装命令。')

    def run(self):
        with self.locked():
            source = self.source()
            self.github.token = None
            self.dependencies()
            print('进入安装向导：首次填写域名、DNSPod 密钥、邮箱与密码；已有安装保留配置升级。', flush=True)
            # 执行副本隔离安装器生成的 __pycache__，保留可再次核验的原始源码。
            with tempfile.TemporaryDirectory(prefix='.execute-', dir=str(self.base)) as temporary:
                execution = Path(temporary) / 'source'
                shutil.copytree(str(source), str(execution))
                with open('/dev/tty', 'r') as tty:
                    result = self.runner(['/bin/sh', str(execution / 'setup.sh')], stdin=tty)
            if result.returncode == 0:
                self.receipt.unlink()
            else:
                print('安装进度已保留；再次执行同一命令会复用本次源码。', file=sys.stderr)
            return result.returncode


def main():
    os.umask(0o077)
    try:
        if '--token-stdin' in sys.argv:
            with os.fdopen(3, 'r') as handle:
                token = handle.read(257).strip()
        else:
            token = getpass.getpass('GitHub 只读令牌（隐藏输入）: ')
        client = GitHub(token)
        token = None
        return Installer(client).run()
    except urllib.error.HTTPError as error:
        print('GitHub 下载未完成（HTTP {}），请检查令牌有效期、目标仓库 Contents 只读权限及网络。'.format(error.code), file=sys.stderr)
    except BootstrapError as error:
        print(str(error), file=sys.stderr)
    except BlockingIOError:
        print('已有一键安装正在运行，请等待结束。', file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print('已中断，安装进度保留。', file=sys.stderr)
    except Exception:
        print('安装未完成，请检查网络、磁盘空间、套件中心及私有缓存权限后重试；未输出凭据或下载地址。', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
CERT_BOOTSTRAP_PY
