#!/bin/sh
umask 077
[ -n "${CERTCTL_HOME:-}" ] && [ -n "${CERTCTL_PYTHON:-}" ] || exit 1
entries=$("$CERTCTL_PYTHON" -I "$CERTCTL_HOME/dns_cleanup.py" "$CERTCTL_HOME" list) || exit 1
[ -n "$entries" ] || exit 0
set -- :
. "$CERTCTL_HOME/acme/acme.sh" || exit 1
LE_WORKING_DIR="$CERTCTL_HOME/acme"
LE_CONFIG_HOME="$CERTCTL_HOME/acme"
_initpath || exit 1
. "$CERTCTL_HOME/acme/dnsapi/dns_tencent.sh" || exit 1
result=0
while IFS=' ' read -r name value; do
  [ -n "$name" ] || continue
  dns_tencent_rm "$name" "$value" || result=1
done <<EOF
$entries
EOF
exit "$result"
