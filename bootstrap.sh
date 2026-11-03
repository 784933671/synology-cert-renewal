#!/bin/sh
# 完整读取函数后再执行，管道下载截断时不会提前开始安装。
cert_bootstrap() {
    set -eu
    set +x
    umask 077
    case "${1:-}" in
        --help) printf '%s\n' '在群晖 SSH 终端使用 sudo sh bootstrap.sh；公开下载无需 GitHub 令牌。'; return 0 ;;
        '') ;;
        *) printf '%s\n' '不支持的安装参数。' >&2; return 1 ;;
    esac
    [ "$#" -le 1 ] || return 1
    [ "$(id -u)" = 0 ] || { printf '%s\n' '请使用 sudo 在 NAS 上运行。' >&2; return 1; }
    [ -f /etc.defaults/VERSION ] || { printf '%s\n' '请在群晖 NAS 的 SSH 终端执行。' >&2; return 1; }
    cert_bootstrap_dir=$(mktemp -d /tmp/synology-cert-bootstrap.XXXXXX)
    trap 'rm -rf "$cert_bootstrap_dir"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    curl -qfsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 20 --max-time 120 --max-filesize 1048576 \
        https://raw.githubusercontent.com/784933671/synology-cert-renewal/main/bootstrap-private.sh \
        -o "$cert_bootstrap_dir/installer.sh"
    sh -n "$cert_bootstrap_dir/installer.sh"
    sh "$cert_bootstrap_dir/installer.sh" --public
}

cert_bootstrap "$@"
