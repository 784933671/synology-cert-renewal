#!/bin/sh
# 固定上游文件只提供签名与请求方法；入口保留清理状态并校验每次 API 响应。
[ -n "$CERTCTL_HOME" ] && [ -n "$CERTCTL_PYTHON" ] || return 1
. "$CERTCTL_HOME/acme/dnsapi/dns_tencent_upstream.sh" || return 1

_certctl_dns_state() {
  "$CERTCTL_PYTHON" -I "$CERTCTL_HOME/dns_cleanup.py" "$CERTCTL_HOME" "$@"
}

_certctl_dns_fail() {
  _certctl_dns_state diagnostic "$@" || return 1
  return 1
}

_certctl_dns_credentials() {
  Tencent_SecretId="${Tencent_SecretId:-$(_readaccountconf_mutable Tencent_SecretId)}"
  Tencent_SecretKey="${Tencent_SecretKey:-$(_readaccountconf_mutable Tencent_SecretKey)}"
  if [ -z "$Tencent_SecretId" ] || [ -z "$Tencent_SecretKey" ]; then
    _certctl_dns_fail "$1" Credentials credentials MissingCredentials
    return 1
  fi
}

_certctl_dns_request() {
  _certctl_stage=$1
  _certctl_action=$2
  _certctl_mode=${3:-normal}
  _certctl_transport=0
  response=$(tencent_api_request dnspod 2021-03-23 "$_certctl_action" "$query" "$(date -u +%s)") || _certctl_transport=$?
  _certctl_api_detail=$(printf '%s' "$response" | _certctl_dns_state api "$_certctl_stage" "$_certctl_action" "$_certctl_mode" "$_certctl_transport")
}

_certctl_dns_root() {
  _certctl_root_name=$1
  _certctl_root_stage=$2
  _certctl_root_candidate=$1
  _certctl_root_error=ResourceNotFound.NoDataOfDomain
  while [ "${_certctl_root_candidate#*.}" != "$_certctl_root_candidate" ]; do
    _describe_records_query "$_certctl_root_candidate" "@" || return 1
    _certctl_root_status=0
    _certctl_dns_request "$_certctl_root_stage" DescribeRecordList root || _certctl_root_status=$?
    if [ "$_certctl_root_status" = 0 ]; then
      _domain=$_certctl_root_candidate
      _sub_domain=${_certctl_root_name%."$_domain"}
      return 0
    fi
    [ "$_certctl_root_status" = 2 ] || return 1
    case "$_certctl_api_detail" in
      ResourceNotFound.NoDataOfDomain|InvalidParameter.DomainInvalid|InvalidParameterValue.DomainInvalid) ;;
      *) _certctl_root_error=$_certctl_api_detail ;;
    esac
    _certctl_root_candidate=${_certctl_root_candidate#*.}
  done
  _certctl_dns_fail "$_certctl_root_stage" DescribeRecordList api "$_certctl_root_error"
}

dns_tencent_add() (
  _certctl_dns_credentials dns_create || return 1
  _certctl_dns_state track "$1" "$2" || { _certctl_dns_fail dns_create Journal local_state StateError; return 1; }
  _saveaccountconf_mutable Tencent_SecretId "$Tencent_SecretId" || { _certctl_dns_fail dns_create Journal local_state StateError; return 1; }
  _saveaccountconf_mutable Tencent_SecretKey "$Tencent_SecretKey" || { _certctl_dns_fail dns_create Journal local_state StateError; return 1; }
  _certctl_dns_root "$1" dns_query || return 1
  _add_record_query "$_domain" "$_sub_domain" "$2" || return 1
  _certctl_dns_request dns_create CreateRecord
)

_certctl_dns_ids() (
  _certctl_offset=0
  _certctl_filter_value=$1
  _certctl_ids=
  while [ "$_certctl_offset" -lt 3000 ]; do
    query="{\"Domain\":\"$_domain\",\"SubDomain\":\"$_sub_domain\",\"RecordValue\":\"$_certctl_filter_value\",\"RecordType\":[\"TXT\"],\"IsExactSubDomain\":true,\"Offset\":$_certctl_offset,\"Limit\":100}"
    _certctl_dns_request dns_cleanup DescribeRecordFilterList || return 1
    _certctl_page=$(printf '%s' "$response" | _certctl_dns_state records "$_sub_domain" "$_certctl_filter_value") || {
      _certctl_dns_fail dns_cleanup DescribeRecordFilterList invalid_response InvalidResponse; return 1;
    }
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
  _certctl_dns_fail dns_cleanup DescribeRecordFilterList local_state StateError
)

dns_tencent_rm() (
  _certctl_dns_credentials dns_cleanup || return 1
  _certctl_dns_name=$1
  _certctl_dns_value=$2
  _certctl_dns_state track "$_certctl_dns_name" "$_certctl_dns_value" || {
    _certctl_dns_fail dns_cleanup Journal local_state StateError; return 1;
  }
  _certctl_dns_root "$_certctl_dns_name" dns_cleanup || return 1
  _certctl_records=$(_certctl_dns_ids "$_certctl_dns_value") || return 1
  _certctl_deleted=
  for _certctl_record in $_certctl_records; do
    _delete_record_query "$_certctl_record" || return 1
    _certctl_dns_request dns_cleanup DeleteRecord || return 1
    _certctl_deleted=deleted
  done
  _certctl_remaining=$(_certctl_dns_ids "$_certctl_dns_value") || return 1
  if [ -n "$(printf '%s' "$_certctl_remaining" | tr -d ' ')" ]; then
    _certctl_dns_fail dns_cleanup DescribeRecordFilterList api RecordStillPresent
    return 1
  fi
  _certctl_dns_state done "$_certctl_dns_name" "$_certctl_dns_value" "$_certctl_deleted" || {
    _certctl_dns_fail dns_cleanup Journal local_state StateError; return 1;
  }
)
