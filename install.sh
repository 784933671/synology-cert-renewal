#!/bin/sh
set -eu
umask 077
PATH=/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH

BASE=/usr/local/share/synology-cert-renewal
PARENT=/usr/local/share
COMMIT=807da6498377ee5e0cf43a78091f46f12dc59a89
SHA256=ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220
SOURCE_DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd)

fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail '请在 NAS 上先执行 sudo -i，再运行安装脚本。'
[ -f /etc.defaults/VERSION ] || fail '当前设备不是可识别的 DSM；请在群晖 NAS 本机安装。'
[ ! -e "$BASE" ] && [ ! -L "$BASE" ] || fail "安装目录已存在，保留原配置并停止：$BASE"
for source_file in certctl.py dns_cleanup.py dns_cleanup_retry.sh dns_tencent_tracked.sh; do
    [ -f "$SOURCE_DIR/$source_file" ] && [ ! -L "$SOURCE_DIR/$source_file" ] || fail "安装包缺少 $source_file，或该文件是符号链接。"
done

PYTHON=
PATH_PYTHON=$(command -v python3 2>/dev/null || true)
for candidate in "$PATH_PYTHON" /var/packages/Python3/target/usr/local/bin/python3 /var/packages/Python3.9/target/usr/local/bin/python3.9 /usr/local/bin/python3 /usr/bin/python3 /bin/python3; do
    [ -n "$candidate" ] && [ -x "$candidate" ] || continue
    if "$candidate" -I -c 'import sys, ssl, hashlib, tarfile, fcntl; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
        PYTHON=$candidate
        break
    fi
done
[ -n "$PYTHON" ] || fail '需要 Python 3.8 或以上及标准库。请先在套件中心安装/更新 Python3，再重试。'
for dependency in curl openssl; do
    command -v "$dependency" >/dev/null 2>&1 || fail "缺少群晖本机依赖：$dependency"
done
if ! command -v synowebapi >/dev/null 2>&1; then
    for dependency in synouser synogroup synosetkeyvalue synogetkeyvalue; do
        command -v "$dependency" >/dev/null 2>&1 || fail "缺少群晖本机依赖：$dependency"
    done
fi
"$PYTHON" -I - <<'PY'
import pathlib, re, sys
text = pathlib.Path('/etc.defaults/VERSION').read_text()
match = re.search(r'^productversion="([0-9.]+)"', text, re.MULTILINE)
version = tuple(int(part) for part in match.group(1).split('.')) if match else ()
if not version or version[0] not in (6, 7) or (version[0] == 6 and version < (6, 2, 4)):
    sys.exit('当前 DSM 版本不在支持范围内；需要 DSM 6.2.4 或 DSM 7.x。')
print('检测到 DSM ' + match.group(1))
PY

mkdir -p "$PARENT"
INSTALL_TMP=$(mktemp -d "$PARENT/.synology-cert-install.XXXXXX")
cleanup() { rm -rf "$INSTALL_TMP"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s\n' '正在下载固定版本 acme.sh 3.1.6，并验证完整性……'
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 180 --retry 2 \
    "https://codeload.github.com/acmesh-official/acme.sh/tar.gz/$COMMIT" \
    -o "$INSTALL_TMP/acme.tar.gz"

"$PYTHON" -I - "$INSTALL_TMP" "$SOURCE_DIR" "$BASE" "$PYTHON" "$COMMIT" "$SHA256" <<'PY'
import hashlib, os, pathlib, shlex, shutil, sys, tarfile

tmp, source, base = map(pathlib.Path, sys.argv[1:4])
python_path, commit, expected = sys.argv[4:7]
archive = tmp / 'acme.tar.gz'
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    sys.exit('acme.sh 下载文件校验失败，未安装任何组件。')
if os.path.lexists(base):
    sys.exit('安装目录已存在，保留原配置并停止。')
package = tmp / 'package'
acme = package / 'acme'
acme.mkdir(parents=True, mode=0o700)
expected_root = 'acme.sh-' + commit
with tarfile.open(archive, 'r:gz') as tar:
    entries = tar.getmembers()
    if len(entries) > 20000 or sum(item.size for item in entries) > 64 * 1024 * 1024:
        sys.exit('压缩包体积异常，停止安装。')
    # 只复制普通文件和目录；不接受符号链接、硬链接、设备或路径逃逸。
    for item in entries:
        parts = pathlib.PurePosixPath(item.name).parts
        if not parts or parts[0] != expected_root or '..' in parts or pathlib.PurePosixPath(item.name).is_absolute():
            sys.exit('压缩包路径校验失败。')
        if not item.isdir() and not item.isfile():
            sys.exit('压缩包包含不允许的文件类型。')
    for item in entries:
        relative = pathlib.PurePosixPath(item.name).parts[1:]
        if not relative:
            continue
        target = acme.joinpath(*relative)
        if item.isdir():
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tar.extractfile(item) as incoming, target.open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            target.chmod(0o600)
required = ('acme.sh', 'dnsapi/dns_tencent.sh', 'deploy/synology_dsm.sh')
if not all((acme / name).is_file() for name in required):
    sys.exit('下载包缺少所需组件，停止安装。')
for name in ('certctl.py', 'dns_cleanup.py', 'dns_cleanup_retry.sh'):
    shutil.copyfile(source / name, package / name)
# 保留固定上游文件；项目钩子只增加持久清理和精确删除，不改变 DNS 提供商配置。
upstream = acme / 'dnsapi' / 'dns_tencent.sh'
upstream.rename(acme / 'dnsapi' / 'dns_tencent_upstream.sh')
shutil.copyfile(source / 'dns_tencent_tracked.sh', upstream)
(package / 'state').mkdir(mode=0o700)
(package / 'python-path').write_text(python_path + '\n')
(package / 'ACME-VERSION').write_text('3.1.6\n' + commit + '\n' + expected + '\n')
command = [python_path, '-I', str(base / 'certctl.py'), '--home', str(base), 'run']
(package / 'run-task.sh').write_text('#!/bin/sh\nexec ' + ' '.join(shlex.quote(arg) for arg in command) + '\n')
for path in [package] + list(package.rglob('*')):
    path.chmod(0o700 if path.is_dir() else 0o600)
(package / 'run-task.sh').chmod(0o700)
(acme / 'acme.sh').chmod(0o700)
os.rename(package, base)
print('安装完成：' + str(base))
print('下一步执行交互配置：')
print(' '.join(shlex.quote(arg) for arg in [python_path, '-I', str(base / 'certctl.py'), '--home', str(base), 'configure']))
PY
