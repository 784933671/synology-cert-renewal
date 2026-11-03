#!/bin/sh
set -eu
umask 077
PATH=/usr/syno/sbin:/usr/syno/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
SETUP_SOURCE=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
SETUP_PYTHON=$(command -v python3 2>/dev/null || true)
for candidate in "$SETUP_PYTHON" /var/packages/Python3/target/usr/local/bin/python3 /var/packages/Python3.9/target/usr/local/bin/python3.9 /usr/bin/python3; do
    [ -n "$candidate" ] && [ -x "$candidate" ] || continue
    if "$candidate" -I -c 'import sys,ssl,sqlite3,fcntl;sys.exit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1; then
        exec "$candidate" -I "$SETUP_SOURCE/web/setup.py" "$@"
    fi
done
printf '%s\n' '需要 Python 3.8 或以上。请先在群晖套件中心安装 Python3。' >&2
exit 1
