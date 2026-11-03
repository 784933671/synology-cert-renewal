#!/usr/bin/env python3
"""生成只含安装源码的 ZIP 与 SHA-256；不打包 NAS 数据。"""
import argparse
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from web.setup_upgrade import copy_payload, regular

ROOT_FILES = ('setup.sh', 'install.sh', 'certctl.py', 'run_history.py', 'failure_diagnostics.py', 'dns_cleanup.py',
              'dns_cleanup_retry.sh', 'dns_tencent_tracked.sh', 'dns-policy.example.json',
              'README.md', 'DEPLOYMENT.md', 'INSTALL.md', 'PUBLIC-INSTALL.md', 'PRIVATE-INSTALL.md',
              'bootstrap.sh', 'bootstrap-private.sh')


def package(source, destination):
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cert-manager-package-') as temporary:
        payload = Path(temporary) / 'synology-cert-manager'
        payload.mkdir()
        copy_payload(source, payload / 'web')
        for name in ROOT_FILES:
            regular(source / name)
            shutil.copyfile(str(source / name), str(payload / name))
        files = sorted(p for p in payload.rglob('*') if p.is_file())
        manifest = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(payload).as_posix() + '\n' for p in files)
        (payload / 'SHA256SUMS').write_text(manifest)
        files.append(payload / 'SHA256SUMS')
        with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                archive.write(path, path.relative_to(payload.parent).as_posix())
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix + '.sha256').write_text(digest + '  ' + destination.name + '\n')
    return len(files), digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'output/releases/synology-cert-manager.zip')
    args = parser.parse_args()
    count, checksum = package(ROOT, args.output)
    print('安装包：{}\n文件数：{}\nSHA-256：{}'.format(args.output, count, checksum))
