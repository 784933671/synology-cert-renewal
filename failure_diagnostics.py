"""基于本轮证据分类错误，并保存有界、脱敏的失败记录。"""
import base64
import datetime
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time
from urllib.parse import quote, quote_plus
import uuid

REDACTED = '[REDACTED]'
MAX_LOG_BYTES = 256 * 1024
MAX_READ_BYTES = 1024 * 1024
STAGES = {
    'preflight': ('运行前检查', '系统、配置或既有运行状态检查未通过。', '检查 DSM 环境、配置权限和未完成操作标记。'),
    'backup': ('部署前备份', '证书或绑定备份未完成。', '检查安装目录的空间与读写权限，确认备份可用。'),
    'dns_query': ('DNSPod 查询域名或记录', 'DNSPod 查询未完成。', '检查域名托管、查询权限及 NAS 到 DNSPod 的网络。'),
    'dns_create': ('DNSPod 创建验证记录', 'DNSPod 验证 TXT 记录创建未完成。', '检查目标域名的创建权限、API 密钥及 DNSPod 返回的错误码。'),
    'dns_propagation': ('DNS 验证记录生效检查', '公共 DNS 检查未通过，尚不能确认验证记录已生效。', '检查权威 DNS、TXT 解析结果和 NAS 的 DNS 查询网络。'),
    'acme_challenge': ('证书机构验证域名', '证书机构的域名挑战验证未完成。', '结合错误码检查权威 TXT 记录、域名委派及验证服务状态。'),
    'ca_request': ('证书机构账户或订单请求', '证书机构账户或订单请求未完成。', '检查 NAS 到证书机构的网络及订单错误码；限流时等待后续任务。'),
    'ca_finalize': ('证书机构签发新证书', '域名验证后的证书签发或订单轮询未完成。', '检查签发错误码、系统时间和证书机构网络；保留原证书等待重试。'),
    'ca_download': ('下载新证书', '证书下载或返回内容检查未完成。', '检查证书机构网络和返回状态，等待后续任务重试。'),
    'acme_unknown': ('证书申请流程（未定位子阶段）', '证书申请流程失败，现有证据不足以确定具体子阶段或根因。', '查看本次归档日志；不要仅凭通用失败信息判断是 DNSPod 或证书机构故障。'),
    'certificate_validation': ('新证书材料校验', '证书域名、有效期、私钥或证书链校验未通过。', '检查候选证书及恢复状态；未通过校验的材料不会导入。'),
    'dsm_deploy': ('群晖证书导入及绑定检查', '群晖证书导入或服务绑定检查未通过。', '核查目标证书 ID、描述和服务绑定，必要时按备份恢复。'),
    'tls_verify': ('实际 HTTPS 服务验证', '实际 HTTPS 服务的连接、信任链、域名或指纹校验未通过。', '检查服务端口、SNI、完整证书链及服务是否加载新证书。'),
    'dns_cleanup': ('DNS 验证记录清理', 'DNS 验证 TXT 记录尚未确认清理完成。', '保留待清理记录，检查查询及删除权限；后续任务会独立重试。'),
    'success_notification': ('发送证书更新成功邮件', '成功通知未能完成提交。', '检查 DSM 邮件配置；待通知事件保留，后续任务仅重试通知。'),
    'result_recording': ('记录执行结果', '执行结果或事件日志未能保存。', '检查状态目录的空间、权限和文件类型；结合服务验证结果确认当前证书。'),
    'recovery': ('损坏证书材料恢复', '损坏材料恢复未完成或触及恢复保护限制。', '检查恢复记录、失败原因及重试间隔；不要反复清除计数。'),
    'unknown': ('未定位阶段', '任务失败，但缺少足够的阶段证据。', '查看本次失败记录与原始运行状态，核查后再继续。'),
}
DNS_CODES = {
    'AuthFailure.SecretIdNotFound': ('authentication', '腾讯云未识别所配置的 SecretId。'),
    'AuthFailure.InvalidSecretId': ('authentication', '腾讯云未接受所配置的 SecretId。'),
    'AuthFailure.SignatureFailure': ('authentication', '腾讯云请求签名校验失败。'),
    'AuthFailure.SignatureExpire': ('authentication', '腾讯云请求签名已过期，请核查系统时间。'),
    'AuthFailure.TokenFailure': ('authentication', '腾讯云临时凭据校验失败。'),
    'AuthFailure.InvalidAuthorization': ('authentication', '腾讯云未接受请求认证信息。'),
    'AuthFailure': ('authentication', '腾讯云请求认证未通过。'),
    'AuthFailure.UnauthorizedOperation': ('permission', '腾讯云拒绝了当前账号的操作权限。'),
    'UnauthorizedOperation': ('permission', '腾讯云拒绝了当前账号的操作权限。'),
    'UnauthorizedOperation.NoPermission': ('permission', '腾讯云账号缺少本次操作所需权限。'),
    'UnauthorizedOperation.CamNoPermission': ('permission', '腾讯云子账号缺少本次操作所需 CAM 权限。'),
    'UnauthorizedOperation.PermissionDenied': ('permission', '腾讯云拒绝了当前账号的操作权限。'),
    'UnauthorizedOperation.DomainNotAllowOperate': ('permission', '当前账号无权操作目标域名。'),
    'UnauthorizedOperation.OperationDenied': ('permission', '腾讯云拒绝执行本次操作。'),
    'ResourceNotFound.DomainNotExists': ('resource', 'DNSPod 未找到请求的域名资源。'),
    'ResourceNotFound.NoDataOfDomain': ('resource', 'DNSPod 未找到请求的域名资源。'),
    'ResourceNotFound.NoDataOfRecord': ('resource', 'DNSPod 未找到请求的解析记录。'),
    'InvalidParameter.DomainInvalid': ('request', 'DNSPod 拒绝了域名参数。'),
    'InvalidParameterValue.DomainInvalid': ('request', 'DNSPod 拒绝了域名参数。'),
    'InvalidParameterValue.DomainNotExists': ('resource', 'DNSPod 未找到请求的域名资源。'),
    'RequestLimitExceeded': ('rate_limit', '腾讯云接口请求频率受限。'),
    'RequestLimitExceeded.RequestLimitExceeded': ('rate_limit', '腾讯云接口请求频率受限。'),
    'LimitExceeded': ('quota', '腾讯云接口返回资源配额限制。'),
    'LimitExceeded.RecordLimitExceeded': ('quota', 'DNSPod 解析记录数量达到限制。'),
    'InternalError': ('provider', '腾讯云接口返回内部错误。'),
    'InternalError.RequestError': ('provider', '腾讯云接口返回请求处理错误。'),
    'FailedOperation': ('provider', '腾讯云未完成本次操作。'),
    'FailedOperation.DomainNotAllowedModify': ('permission', 'DNSPod 当前不允许修改该域名。'),
    'FailedOperation.DomainIsLocked': ('permission', 'DNSPod 返回域名已锁定，暂不能修改解析。'),
    'OperationDenied': ('permission', '腾讯云拒绝执行本次操作。'),
    'NetworkError': ('network', 'DNSPod 请求的网络传输未完成。'),
    'InvalidResponse': ('response', 'DNSPod 返回内容无法确认成功。'),
    'DiagnosticWriteFailed': ('local_io', '本轮诊断记录写入未完成。'),
    'MissingCredentials': ('configuration', '未找到可用的腾讯云 API 凭据。'),
    'StateError': ('local_io', 'DNS 操作的本机状态记录未能安全读写。'),
    'UnknownError': ('provider', 'DNSPod 返回未识别错误码，具体原因尚未定位。'),
    'RecordStillPresent': ('cleanup', '查询发现本次验证 TXT 记录仍存在，尚未确认清理完成。'),
    'IndexNotReady': ('cleanup', 'DNSPod 查询索引尚未确认本次记录状态，需要后续重试。'),
}
for _code, _category, _summary in (
        ('InvalidAction', 'request', '腾讯云未接受请求的 API 操作。'),
        ('InvalidParameter', 'request', '腾讯云未接受请求参数。'),
        ('InvalidParameterValue', 'request', '腾讯云未接受请求参数值。'),
        ('MissingParameter', 'request', '腾讯云报告缺少请求参数。'),
        ('UnknownParameter', 'request', '腾讯云报告存在未知请求参数。'),
        ('UnsupportedOperation', 'request', '腾讯云不支持本次操作。'),
        ('ResourceInUse', 'resource', '腾讯云报告目标资源正在使用。'),
        ('ResourceInsufficient', 'quota', '腾讯云报告可用资源不足。'),
        ('ResourceNotFound', 'resource', '腾讯云未找到目标资源。'),
        ('ResourceUnavailable', 'resource', '腾讯云报告目标资源暂不可用。')):
    DNS_CODES[_code] = (_category, _summary)
ACME_CODES = {
    'rateLimited': ('rate_limit', '证书机构返回签发频率限制。'),
    'unauthorized': ('authorization', '证书机构未认可本次域名授权。'),
    'dns': ('dns', '证书机构报告 DNS 验证查询错误。'),
    'connection': ('network', '证书机构报告验证连接错误。'),
    'tls': ('tls', '证书机构报告 TLS 验证错误。'),
    'caa': ('dns_policy', '证书机构报告 CAA 授权检查失败。'),
    'rejectedIdentifier': ('request', '证书机构拒绝了申请的域名标识。'),
    'malformed': ('request', '证书机构未接受请求格式。'),
    'serverInternal': ('provider', '证书机构返回内部错误。'),
    'badNonce': ('protocol', '证书机构未接受本次请求的 nonce。'),
    'orderNotReady': ('order', '证书机构表示订单尚未满足签发条件。'),
    'accountDoesNotExist': ('account', '证书机构未找到对应账户。'),
}
TRANSPORT_CODES = {
    '6': ('network', '网络客户端无法解析远端主机名。'),
    '7': ('network', '网络客户端无法建立远端连接。'),
    '28': ('timeout', '网络客户端报告请求超时。'),
    '35': ('tls', '网络客户端报告 TLS 握手失败。'),
    '60': ('tls', '网络客户端未通过远端证书信任校验。'),
}
_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_PUBLIC_CODES = set(DNS_CODES) | {'UNKNOWN', 'UNKNOWN_PROVIDER_ERROR', 'OPERATION_TIMEOUT_OR_INTERRUPTED'}
_PUBLIC_CODES.update(stage.upper() + '_FAILED' for stage in STAGES)


def sanitize(text, secrets=(), limit=None, public_paths=()):
    text = text.decode('utf-8', errors='replace') if isinstance(text, bytes) else str(text)
    # 先处理完整内容，再截断，避免密钥在截断点只剩不可识别的前半段。
    variants = set()
    for secret in secrets:
        if not isinstance(secret, str) or not secret:
            continue
        variants.update((secret, quote(secret, safe=''), quote_plus(secret, safe=''),
                         json.dumps(secret, ensure_ascii=True)[1:-1]))
        encoded = secret.encode('utf-8')
        for value in (base64.b64encode(encoded).decode(), base64.urlsafe_b64encode(encoded).decode()):
            variants.update((value, value.rstrip('=')))
    for value in sorted(variants, key=len, reverse=True):
        text = text.replace(value, REDACTED)
        if '%' in value:
            text = re.sub(re.escape(value), REDACTED, text, flags=re.I)
    text = _ANSI.sub('', text)
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)',
                  REDACTED, text, flags=re.S)
    text = re.sub(r'(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie|x-tc-token)["\']?\s*[:=][^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*',
                  'Sensitive-Header: ' + REDACTED, text)
    text = re.sub(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+', REDACTED, text)
    text = re.sub(r'(?i)\b(?:Credential|Signature)\s*=\s*[^\s,;]+', REDACTED, text)
    text = re.sub(r'\bAKID[A-Za-z0-9]{10,}\b', REDACTED, text)
    names = r'(?:Tencent_SecretId|Tencent_SecretKey|SecretId|SecretKey|secret|password|passwd|authpass|token|access_token|refresh_token|session_id|sid|_sid|keyauthorization|txt|txtvalue|txt_value|RecordValue|Value)'
    text = re.sub(r'(?i)([\"\']?' + names + r'[\"\']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,;&}\]]+)',
                  lambda m: m.group(1) + REDACTED, text)
    text = re.sub(r'(?im)(' + names + r'[\\"\']*\s*[:=][\\"\']*\s*)[^\r\n]*',
                  lambda m: m.group(1) + REDACTED, text)
    text = re.sub(r'(?i)(' + names + r'%3[dDaA])[^\s]*', lambda m: m.group(1) + REDACTED, text)
    text = re.sub(r'(?im)((?:Adding|Removing)?\s*TXT value:\s*)\S+', lambda m: m.group(1) + REDACTED, text)
    text = re.sub(r'(?i)(https?://)[^/\s@]+@', r'\1' + REDACTED + '@', text)
    public = {}
    for path in public_paths:
        if (not isinstance(path, str) or '..' in Path(path).parts or
                not re.fullmatch(r'/[^\r\n\x00]*/failures/failure-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}', path)):
            continue
        if path in text:
            marker = '\x00PUBLICPATH' + str(len(public)) + '\x00'
            public[marker] = path
            text = text.replace(path, marker)
    # 未知的验证值和编码凭据也不能进入归档；错误码由白名单单独保留。
    text = re.sub(r'(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9])',
                  lambda m: m.group(0) if m.group(0) in _PUBLIC_CODES else REDACTED, text)
    for marker, path in public.items():
        text = text.replace(marker, path)
    text = ''.join(char for char in text if char in '\n\t' or ord(char) >= 32 and ord(char) != 127)
    if limit is not None and len(text.encode('utf-8')) > limit:
        marker = '\n[日志已截断]\n'
        budget = max(0, limit - len(marker.encode('utf-8')))
        text = (text.encode('utf-8')[:budget].decode('utf-8', errors='ignore') + marker).encode('utf-8')[:max(0, limit)].decode('utf-8', errors='ignore')
    return text


def _acme_stage(log):
    current = 'acme_unknown'
    for line in _ANSI.sub('', log).splitlines():
        line = re.sub(r'^\[[^\]\n]{1,100}\]\s*', '', line).strip()
        if re.match(r'(?:Error creating new order\.|Create new order with invalid status\.|Registering account:|Using CA:)', line):
            current = 'ca_request'
        elif re.match(r'(?:Adding TXT value:|Error adding TXT record to domain:)', line):
            current = 'dns_create'
        elif re.match(r"(?:Let's check each DNS record|Not valid yet,|Timed out waiting for DNS\.|Error checking DNS\.|Sleeping for \d+ seconds to wait for the the TXT)", line):
            current = 'dns_propagation'
        elif re.match(r'(?:Verifying:|[a-zA-Z0-9*_.-]+: (?:Challenge error:|Cannot get challenge:|Invalid status[.,]|Invalid code\. Verification error:|Unknown status:))', line):
            current = 'acme_challenge'
        elif re.match(r"(?:Verification finished, beginning signing\.|Let's finalize the order\.|Polling order status:|The order is not ready)", line):
            current = 'ca_finalize'
        elif re.match(r'(?:Downloading cert\.|Signing failed[.,] [Cc]ould not download cert:)', line):
            current = 'ca_download'
        elif re.match(r'(?:Signing failed[.:]|Signing error:|A signing error occurred:)', line) and current != 'ca_download':
            current = 'ca_finalize'
        elif line in ('All checks succeeded', 'Cert success.'):
            current = 'acme_unknown'
        # Removing DNS records 是善后动作，不覆盖此前失败的主阶段。
    return current


def _dns_error(events, stage):
    if isinstance(events, dict):
        events = events.get('events', [events])
    if not isinstance(events, list):
        return None
    failures = []
    for event in events:
        if not isinstance(event, dict) or event.get('stage') not in ('dns_query', 'dns_create', 'dns_cleanup'):
            continue
        if event.get('status') in ('ok', 'success', 'started', 'start'):
            continue
        if not event.get('code') and event.get('status') not in ('failed', 'failure', 'error'):
            continue
        if stage == 'dns_cleanup' and event['stage'] != 'dns_cleanup':
            continue
        failures.append(event)
    return next((item for item in failures if item['stage'] != 'dns_cleanup'), failures[0] if failures else None)


def classify(stage, message='', acme_log='', dns_events=None):
    stage = stage if isinstance(stage, str) and (stage in STAGES or stage == 'acme') else 'unknown'
    log = acme_log.decode('utf-8', errors='replace') if isinstance(acme_log, bytes) else str(acme_log or '')
    event = _dns_error(dns_events, stage) if stage in ('acme', 'acme_unknown', 'dns_query', 'dns_create', 'dns_cleanup') else None
    evidence = 'controller'
    if stage in ('acme', 'acme_unknown'):
        stage = _acme_stage(log)
        evidence = 'acme_log' if stage != 'acme_unknown' else 'insufficient'
        if event and (event['stage'] != 'dns_cleanup' or stage == 'acme_unknown'):
            stage, evidence = event['stage'], 'dns_event'
        else:
            event = None
    elif event:
        evidence = 'dns_event'
    label, summary, hint = STAGES[stage]
    code, category = 'UNKNOWN', 'unclassified'
    if event:
        code = event.get('code')
        if isinstance(code, str) and code in DNS_CODES:
            category, summary = DNS_CODES[code]
        else:
            code, category = 'UNKNOWN_PROVIDER_ERROR', 'provider'
    elif evidence == 'acme_log' or stage == 'acme_unknown':
        codes = re.findall(r'urn:ietf:params:acme:error:([A-Za-z]+)', log)
        known = codes[-1] if codes and codes[-1] in ACME_CODES else None
        transport = re.findall(r'curl:\s*\(([0-9]+)\)', log)
        if known:
            category, summary = ACME_CODES[known]
            code = 'urn:ietf:params:acme:error:' + known
        elif not codes and transport and transport[-1] in TRANSPORT_CODES:
            category, summary = TRANSPORT_CODES[transport[-1]]
            code = 'CURL_' + transport[-1]
    if code == 'UNKNOWN' and ('超时' in str(message) or re.search(r'Timed out waiting for DNS\.|: Timeout\s*$', log, re.M)):
        code, category = 'OPERATION_TIMEOUT_OR_INTERRUPTED', 'timeout_or_interrupted'
    if code == 'UNKNOWN' and stage != 'acme_unknown':
        code = stage.upper() + '_FAILED'
        category = 'stage_failure'
    return {'stage': stage, 'stage_label': label, 'category': category, 'code': code,
            'summary': summary, 'hint': hint, 'evidence': evidence}


def _private(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('unsafe path')


def _json_safe(value, secrets, depth=0):
    if depth > 8:
        return '[超出结构深度]'
    if isinstance(value, str):
        return sanitize(value, secrets, limit=32768)
    if isinstance(value, dict):
        return {sanitize(str(k), secrets, limit=128): _json_safe(v, secrets, depth + 1)
                for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, secrets, depth + 1) for item in value[:100]]
    if value is None or type(value) in (int, bool):
        return value
    return sanitize(str(value), secrets, limit=1024)


def _write(path, text):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def _log_text(value, state):
    if isinstance(value, Path):
        relative = value.relative_to(state)
        if '..' in relative.parts:
            raise ValueError('unsafe path')
        current = state
        for part in relative.parts:
            current = current / part
            _private(current, directory=current != value)
        fd = os.open(str(value), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('unsafe log')
            data = b'' if info.st_size > MAX_READ_BYTES else handle.read(MAX_READ_BYTES + 1)
            if info.st_size > MAX_READ_BYTES or len(data) > MAX_READ_BYTES:
                return '[日志超过安全读取上限，未复制；请在 NAS 本机核查原运行日志。]\n'
            return data
    if not isinstance(value, (str, bytes)):
        raise ValueError('invalid log')
    return value


def _prune(root, timestamp, max_failures, retention_days, newest):
    entries = []
    for path in root.iterdir():
        if not re.fullmatch(r'failure-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}', path.name):
            continue
        try:
            _private(path, directory=True)
            complete = path / 'complete.json'
            _private(complete)
            data = json.loads(complete.read_text())
            completed = data['completed_at']
            if data.get('version') != 1 or type(completed) not in (int, float) or not math.isfinite(completed):
                continue
            entries.append((completed, path))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    # 系统时间回拨时，本轮刚生成且邮件即将引用的记录也必须保留。
    entries.sort(key=lambda item: (item[1] == newest, item[0], item[1].name), reverse=True)
    for index, (completed, path) in enumerate(entries):
        if index >= max_failures or completed < timestamp - retention_days * 86400:
            shutil.rmtree(path)


def archive_failure(state, report, logs, secrets=(), now=None, max_failures=30, retention_days=30,
                    max_log_bytes=MAX_LOG_BYTES):
    temporary = None
    archived = None
    try:
        state = Path(state)
        if not state.is_absolute() or '..' in state.parts:
            raise ValueError('unsafe state path')
        _private(state, directory=True)
        timestamp = time.time() if now is None else now.timestamp() if isinstance(now, datetime.datetime) else float(now)
        if not math.isfinite(timestamp) or max_failures < 1 or retention_days < 1 or max_log_bytes < 64:
            raise ValueError('invalid retention')
        if not isinstance(logs, dict):
            raise ValueError('invalid logs')
        root = state / 'failures'
        if not os.path.lexists(root):
            root.mkdir(mode=0o700)
        _private(root, directory=True)
        temporary = Path(tempfile.mkdtemp(prefix='.partial-', dir=str(root)))
        warnings = []
        for name, value in list(logs.items())[:8]:
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}', name)
                    or name in ('report.json', 'complete.json')):
                warnings.append('不安全的日志名称已跳过。')
                continue
            try:
                text = sanitize(_log_text(value, state), secrets, limit=max_log_bytes)
            except (OSError, ValueError, TypeError):
                text = '[日志读取失败或路径不安全，未复制。]\n'
                warnings.append('部分日志未能安全读取。')
            _write(temporary / name, text)
        safe_report = _json_safe(report, secrets)
        if not isinstance(safe_report, dict):
            safe_report = {'message': safe_report}
        if warnings:
            safe_report['archive_warnings'] = sorted(set(warnings))
        _write(temporary / 'report.json', json.dumps(safe_report, ensure_ascii=False, indent=2) + '\n')
        _write(temporary / 'complete.json', json.dumps({'version': 1, 'completed_at': timestamp}) + '\n')
        fd = os.open(str(temporary), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        stamp = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        archived = root / ('failure-' + stamp + '-' + uuid.uuid4().hex)
        os.rename(str(temporary), str(archived))
        temporary = None
        fd = os.open(str(root), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _prune(root, timestamp, max_failures, retention_days, archived)
        return {'archive_path': str(archived), 'archive_error': '；'.join(sorted(set(warnings))) or None}
    except (OSError, ValueError, TypeError, OverflowError):
        return {'archive_path': str(archived) if archived is not None and archived.exists() else None,
                'archive_error': '失败日志归档未完整完成，请检查 NAS 日志目录权限和磁盘空间。'}
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
