export function durationText(seconds: number | null) {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) return '—'
  const value = Math.floor(seconds)
  if (!value) return '不足 1 秒'
  if (value < 60) return `${value} 秒`
  if (value < 3600) return `${Math.floor(value / 60)} 分 ${value % 60} 秒`
  if (value < 86400) return `${Math.floor(value / 3600)} 小时 ${Math.floor(value % 3600 / 60)} 分`
  return `${Math.floor(value / 86400)} 天 ${Math.floor(value % 86400 / 3600)} 小时`
}

export function healthState(value: string) {
  return ({
    ok: { label: '正常', color: 'success' },
    warning: { label: '需要关注', color: 'warning' },
    error: { label: '异常', color: 'error' },
    disabled: { label: '监测已关闭', color: 'default' },
  } as Record<string, { label: string; color: string }>)[value] || { label: '状态未知', color: 'default' }
}

export function runState(value: string) {
  return ({
    running: { label: '运行中', color: 'processing' },
    succeeded: { label: '成功', color: 'success' },
    skipped: { label: '已跳过', color: 'default' },
    failed: { label: '失败', color: 'error' },
    interrupted: { label: '已中断', color: 'warning' },
  } as Record<string, { label: string; color: string }>)[value] || { label: '状态未知', color: 'default' }
}

export function runKind(value: string) {
  return ({ routine: '普通检查', forced: '立即换证', recovery: '恢复任务', check: '手动检查' } as Record<string, string>)[value] || '其他执行'
}

export function notificationState(value: string) {
  return ({
    sent: '已发送', pending: '等待发送', failed: '发送失败', disabled: '通知已关闭',
    suppressed: '已抑制重复通知', delivered: '已发送', error: '发送失败',
  } as Record<string, string>)[value] || '发送状态待确认'
}

export function snapshotExpired(serverTime: string, checkedAt: string | null, maxAge: number, elapsed: number) {
  const server = Date.parse(serverTime), checked = checkedAt ? Date.parse(checkedAt) : NaN
  if (!Number.isFinite(server) || !Number.isFinite(checked) || !Number.isFinite(maxAge) || maxAge <= 0) return true
  const age = (server - checked) / 1000
  return age < 0 || age + Math.max(0, elapsed) > maxAge
}
