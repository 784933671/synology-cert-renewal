import type { HealthSnapshot, MonitorSettings, RunPage, RunRecord } from '../src/types'
export function monitorSettings(): MonitorSettings {
  return { revision: 'a'.repeat(64), enabled: true, missed_runs: 2, grace_minutes: 15, expiry_hours: 24, notification_enabled: true, recipient: 'a***@example.com', interval_seconds: 60 }
}
export function health(): HealthSnapshot {
  return {
    server_time: '2026-11-03T04:00:00Z', timezone: 'Asia/Shanghai',
    runtime: {
      checked_at: '2026-11-03T04:00:00Z', stale: false, stale_after_seconds: 45,
      components: ['container', 'bridge', 'tls', 'access', 'monitor'].map((key, index) => ({ key, label: ['管理容器', '群晖桥接', 'HTTPS 证书', '访问规则', '监测进程'][index], status: 'ok', message: '检查通过' })),
      container: { running: true, health: 'healthy', restart_count: 0, oom_killed: false, started_at: '2026-11-03T03:00:00Z', uptime_seconds: 3600 },
    },
    supervisor: { status: 'running', stage: 'running', message: '服务运行中', at: '2026-11-03T04:00:00Z' },
    upgrade: { phase: 'complete', label: '升级完成' }, events: [],
    monitor: {
      checked_at: '2026-11-03T04:00:00Z', stale: false, stale_after_seconds: 180, status: 'ok', task_enabled: true, schedule_supported: true,
      last_completed_at: '2026-11-03T03:17:00Z', next_expected_at: '2026-11-03T04:17:00Z', missed_runs: 0, certificate_remaining_seconds: 200000,
      alerts: [], delivery: { enabled: true, recipient: 'a***@example.com', last_error: '' },
      settings: { version: 1, enabled: true, missed_runs: 2, grace_minutes: 15, expiry_hours: 24 },
    },
  }
}
export function run(index = 0): RunRecord {
  return {
    id: `run-20261103T040000Z-${index.toString(16).padStart(32, '0')}`, kind: 'routine', status: 'skipped', started_at: '2026-11-03T04:00:00Z', finished_at: '2026-11-03T04:00:04Z', duration_seconds: 4,
    domains: ['nas.example.com'], certificate_id: 'certificate-a', summary: `检查记录 ${index}：尚未进入续期时间`,
    stages: [{ stage: 'skip', label: '正常跳过', status: 'skipped', started_at: '2026-11-03T04:00:00Z', finished_at: '2026-11-03T04:00:04Z', duration_seconds: 4, message: '证书仍然有效' }],
  }
}
export function runPage(offset = 0, total = 41): RunPage {
  return { items: Array.from({ length: Math.min(20, Math.max(0, total - offset)) }, (_, index) => run(offset + index)), total, offset, limit: 20 }
}
export function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
