"""在原续期互斥锁内复制已部署证书，使用目录指针原子切换。"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import tempfile


class TLSBusy(Exception):
    pass


def validate_material(directory, hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory / 'fullchain.pem'), str(directory / 'privkey.pem'))
    for option, value in [('-checkend', '0'), ('-checkhost', hostname)]:
        result = subprocess.run(['openssl', 'x509', '-in', str(directory / 'fullchain.pem'), '-noout', option, value],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode:
            raise ValueError('TLS certificate invalid for management host')
    chain = str(directory / 'fullchain.pem')
    result = subprocess.run(['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', hostname,
                             '-untrusted', chain, chain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode:
        raise ValueError('TLS certificate chain is not trusted')


def read_regular(path, limit):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError('invalid TLS source')
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError('TLS source too large')
        return data


@contextlib.contextmanager
def native_lock(home):
    fd = os.open(str(home / 'state/run.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TLSBusy()
        yield


def sync_tls(native_home, tls_home, hostname, uid=10100, gid=10100, archive=Path('/usr/syno/etc/certificate/_archive')):
    native_home, tls_home, archive = Path(native_home), Path(tls_home), Path(archive)
    with native_lock(native_home):
        config = json.loads(read_regular(native_home / 'config.json', 65536))
        cert_id = config.get('certificate_id', '')
        if not isinstance(cert_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', cert_id):
            raise ValueError('invalid certificate id')
        source = archive / cert_id
        if source.is_symlink() or source.resolve().parent != archive.resolve():
            raise ValueError('invalid archive directory')
        cert = read_regular(source / 'fullchain.pem', 262144)
        key = read_regular(source / 'privkey.pem', 32768)
        generation = hashlib.sha256(cert + key).hexdigest()
        versions = tls_home / 'versions'
        versions.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chown(str(tls_home), 0, gid)
        os.chmod(str(tls_home), 0o750)
        os.chown(str(versions), 0, gid)
        os.chmod(str(versions), 0o750)
        target = versions / generation
        if target.is_symlink():
            raise ValueError('unexpected TLS generation link')
        if not target.exists():
            temporary = Path(tempfile.mkdtemp(prefix='.tls-', dir=str(versions)))
            try:
                os.chown(str(temporary), 0, gid)
                os.chmod(str(temporary), 0o750)
                for name, data in [('fullchain.pem', cert), ('privkey.pem', key)]:
                    path = temporary / name
                    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
                    with os.fdopen(fd, 'wb') as handle:
                        handle.write(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chown(str(path), 0, gid)
                    os.chmod(str(path), 0o640)
                validate_material(temporary, hostname)
                os.rename(str(temporary), str(target))
            finally:
                if temporary.exists():
                    shutil.rmtree(str(temporary))
        else:
            if read_regular(target / 'fullchain.pem', 262144) != cert or read_regular(target / 'privkey.pem', 32768) != key:
                raise ValueError('TLS cached material mismatch')
            validate_material(target, hostname)
        current = tls_home / 'current'
        if current.exists() and not current.is_symlink():
            raise ValueError('unexpected current TLS path')
        changed = not (current.is_symlink() and current.resolve() == target.resolve())
        if changed:
            pointer = tls_home / '.next-current'
            if pointer.is_symlink():
                pointer.unlink()
            os.symlink('versions/' + generation, str(pointer))
            os.replace(str(pointer), str(current))
        for name, source_name in [('current.cert', 'fullchain.pem'), ('current.key', 'privkey.pem')]:
            link = tls_home / name
            if link.is_symlink() and os.readlink(str(link)) == 'current/' + source_name:
                continue
            if link.exists() or link.is_symlink():
                raise ValueError('unexpected TLS link')
            os.symlink('current/' + source_name, str(link))
        # 当前及最近两代保留，私钥只出现在私有只读挂载中。
        history = sorted((p for p in versions.iterdir() if p.is_dir() and re.fullmatch(r'[a-f0-9]{64}', p.name)), key=lambda p:p.stat().st_mtime, reverse=True)
        for old in history[3:]:
            if old != target and not old.is_symlink():
                shutil.rmtree(str(old))
        return changed
