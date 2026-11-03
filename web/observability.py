"""把主机私有快照投影成固定字段；不执行系统命令或返回原始日志。"""
import datetime
import math
import time

RUNTIME_TTL = 45
MONITOR_TTL = 180
COMPONENTS = {'container': '管理容器', 'bridge': '群晖桥接', 'tls': 'HTTPS 证书',
              'access': '访问规则', 'monitor': '独立预警检查'}
STATUSES = {'ok', 'warning', 'error', 'unknown'}
UPGRADE_PHASES = {'prepared': '已完成镜像准备', 'switching': '正在切换版本',
                  'starting': '等待新版本健康检查', 'complete': '升级完成',
                  'rollback_failed': '恢复原版本未完成，请检查升级记录', 'rolled_back': '已恢复原版本'}


def timestamp(value):
    try:
        if isinstance(value, str):
            date = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
            return date.timestamp() if date.tzinfo is not None else None
        if type(value) in (int, float) and math.isfinite(value) and value > 0:
            return value
    except (ValueError, OverflowError, OSError):
        pass
    return None


def iso(value):
    value = timestamp(value)
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat(timespec='seconds') if value is not None else None
    except (ValueError, OverflowError, OSError):
        return None


def stale(value, current, limit):
    value = timestamp(value)
    return value is None or value > current + 5 or current - value > limit


def number(value, integer=False, minimum=None):
    if type(value) not in ((int,) if integer else (int, float)):
        return None
    try:
        if not math.isfinite(value):
            return None
    except OverflowError:
        return None
    return value if minimum is None or value >= minimum else None


def boolean(value):
    return value if type(value) is bool else None


def choice(value, allowed, default='unknown'):
    return value if isinstance(value, str) and value in allowed else default


def snapshot(home, read, sanitize, settings, current=None):
    current = time.time() if current is None else current

    def load(name):
        if home is None:
            return {}
        try:
            value = read(home / name, {})
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, RuntimeError):
            return {}

    def text(value, limit=600):
        return sanitize(value, limit) if isinstance(value, str) else ''

    raw_runtime, raw_monitor = load('runtime-health.json'), load('monitor-status.json')
    runtime_stale = stale(raw_runtime.get('checked_at'), current, RUNTIME_TTL) or raw_runtime.get('version') != 1
    monitor_stale = (stale(raw_monitor.get('checked_at'), current, MONITOR_TTL)
                     or raw_monitor.get('version') != 1 or raw_monitor.get('settings') != settings)
    raw_components = raw_runtime.get('components', [])
    components = {item.get('key'): item for item in raw_components
                  if isinstance(item, dict) and isinstance(item.get('key'), str) and item['key'] in COMPONENTS} if isinstance(raw_components, list) else {}
    checks = []
    for key, label in COMPONENTS.items():
        item = components.get(key, {})
        status = choice(item.get('status'), STATUSES)
        message = text(item.get('message'))
        if runtime_stale or (key == 'monitor' and monitor_stale):
            status, message = 'unknown', '尚无有效快照或快照已过期，请刷新并检查主机服务。'
        checks.append({'key': key, 'label': label, 'status': status, 'message': message})
    raw_container = raw_runtime.get('container', {})
    if not isinstance(raw_container, dict):
        raw_container = {}
    container = {'running': boolean(raw_container.get('running')),
                 'health': choice(raw_container.get('health'), ('healthy', 'unhealthy', 'starting', 'none')),
                 'restart_count': number(raw_container.get('restart_count'), integer=True, minimum=0),
                 'oom_killed': boolean(raw_container.get('oom_killed')),
                 'started_at': iso(raw_container.get('started_at')),
                 'uptime_seconds': number(raw_container.get('uptime_seconds'), minimum=0)}
    raw_alerts = raw_monitor.get('alerts', [])
    alerts = []
    if isinstance(raw_alerts, list):
        for item in raw_alerts[:20]:
            if not isinstance(item, dict) or item.get('code') not in (
                    'task_missed', 'certificate_expiry', 'clock_anomaly', 'source_unavailable'):
                continue
            alerts.append({'code': item['code'], 'label': text(item.get('label'), 100),
                           'since': iso(item.get('since')), 'message': text(item.get('message')),
                           'notification_status': item.get('notification_status') if item.get('notification_status') in
                           ('pending', 'sent', 'failed', 'disabled') else 'unknown'})
    delivery = raw_monitor.get('delivery', {})
    if not isinstance(delivery, dict):
        delivery = {}
    monitor = {'checked_at': iso(raw_monitor.get('checked_at')), 'stale': monitor_stale,
               'stale_after_seconds': MONITOR_TTL,
               'status': 'unknown' if monitor_stale else choice(raw_monitor.get('status'), STATUSES | {'disabled'}),
               'task_enabled': boolean(raw_monitor.get('task_enabled')),
               'schedule_supported': boolean(raw_monitor.get('schedule_supported')),
               'last_completed_at': iso(raw_monitor.get('last_completed_at')),
               'next_expected_at': iso(raw_monitor.get('next_expected_at')),
               'missed_runs': number(raw_monitor.get('missed_runs'), integer=True, minimum=0),
               'certificate_remaining_seconds': number(raw_monitor.get('certificate_remaining_seconds')),
               'alerts': alerts,
               'delivery': {'enabled': delivery.get('enabled') is True, 'recipient': text(delivery.get('recipient'), 254),
                            'last_error': text(delivery.get('last_error'))},
               'settings': settings}
    state = load('deployment-state.json')
    supervisor = None
    if isinstance(state.get('status'), str):
        supervisor = {key: text(state.get(key), 600 if key == 'message' else 80) for key in ('status', 'stage', 'message')}
        supervisor['at'] = iso(state.get('at'))
    upgrade = load('upgrade-state.json')
    phase = choice(upgrade.get('phase'), UPGRADE_PHASES)
    upgrade = {'phase': phase, 'label': UPGRADE_PHASES[phase]} if phase in UPGRADE_PHASES else None
    event_data = load('deployment-events.json').get('items', [])
    events = []
    if isinstance(event_data, list):
        for item in event_data[:100]:
            if not isinstance(item, dict) or not iso(item.get('at')):
                continue
            events.append({'at': iso(item['at']),
                           'category': item.get('category') if item.get('category') in ('maintenance', 'fault', 'recovery', 'info') else 'info',
                           'status': text(item.get('status'), 80), 'stage': text(item.get('stage'), 80),
                           'message': text(item.get('message'))})
    return {'server_time': iso(current), 'timezone': 'Asia/Shanghai',
            'runtime': {'checked_at': iso(raw_runtime.get('checked_at')), 'stale': runtime_stale,
                        'stale_after_seconds': RUNTIME_TTL, 'components': checks, 'container': container},
            'supervisor': supervisor, 'upgrade': upgrade, 'events': events, 'monitor': monitor}
