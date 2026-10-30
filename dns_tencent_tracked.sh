#!/bin/sh
# 固定版本原始钩子保留不变；只替换入口并记录每次 TXT 创建意图。
[ -n "$CERTCTL_HOME" ] && [ -n "$CERTCTL_PYTHON" ] || return 1
. "$CERTCTL_HOME/acme/dnsapi/dns_tencent_upstream.sh" || return 1

_certctl_dns_state() {
  "$CERTCTL_PYTHON" -I "$CERTCTL_HOME/dns_cleanup.py" "$CERTCTL_HOME" "$@"
}

_certctl_dns_credentials() {
  Tencent_SecretId="${Tencent_SecretId:-$(_readaccountconf_mutable Tencent_SecretId)}"
  Tencent_SecretKey="${Tencent_SecretKey:-$(_readaccountconf_mutable Tencent_SecretKey)}"
  [ -n "$Tencent_SecretId" ] && [ -n "$Tencent_SecretKey" ]
}

dns_tencent_add() (
  _certctl_dns_credentials || return 1
  _certctl_dns_state track "$1" "$2" || return 1
  _saveaccountconf_mutable Tencent_SecretId "$Tencent_SecretId"
  _saveaccountconf_mutable Tencent_SecretKey "$Tencent_SecretKey"
  _get_root "$1" || return 1
  _add_record_query "$_domain" "$_sub_domain" "$2" || return 1
  _tencent_rest CreateRecord || return 1
  printf '%s' "$response" | _certctl_dns_state created
)

_certctl_dns_ids() (
  _certctl_offset=0
  _certctl_filter_value=$1
  _certctl_ids=
  while [ "$_certctl_offset" -lt 3000 ]; do
    query="{\"Domain\":\"$_domain\",\"SubDomain\":\"$_sub_domain\",\"RecordValue\":\"$_certctl_filter_value\",\"RecordType\":[\"TXT\"],\"IsExactSubDomain\":true,\"Offset\":$_certctl_offset,\"Limit\":100}"
    _tencent_rest DescribeRecordFilterList ignore || return 1
    _certctl_page=$(printf '%s' "$response" | _certctl_dns_state records "$_sub_domain" "$_certctl_filter_value") || return 1
    # 输出经过 Python 严格校验，只含十进制数量与记录 ID。
    set -- $_certctl_page
    _certctl_count=$1
    shift
    _certctl_ids="$_certctl_ids $*"
    if [ "$_certctl_count" -lt 100 ]; then
      printf '%s\n' "$_certctl_ids"
      return 0
    fi
    _certctl_offset=$((_certctl_offset + 100))
  done
  return 1
)

dns_tencent_rm() (
  _certctl_dns_credentials || return 1
  _certctl_dns_name=$1
  _certctl_dns_value=$2
  _certctl_dns_state track "$_certctl_dns_name" "$_certctl_dns_value" || return 1
  _get_root "$_certctl_dns_name" || return 1
  _certctl_records=$(_certctl_dns_ids "$_certctl_dns_value") || return 1
  _certctl_deleted=
  for _certctl_record in $_certctl_records; do
    _delete_record_query "$_certctl_record" || return 1
    _tencent_rest DeleteRecord || return 1
    printf '%s' "$response" | _certctl_dns_state response || return 1
    _certctl_deleted=deleted
  done
  _certctl_remaining=$(_certctl_dns_ids "$_certctl_dns_value") || return 1
  # 列表函数只输出空格和数字；空格表示空列表。
  [ -z "$(printf '%s' "$_certctl_remaining" | tr -d ' ')" ] || return 1
  _certctl_dns_state done "$_certctl_dns_name" "$_certctl_dns_value" "$_certctl_deleted"
)
