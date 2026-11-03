export function dateText(value?: string | null, timezone = 'Asia/Shanghai') {
  if (!value) return '暂无记录'
  const parsed = new Date(
    /^\d{4}-\d{2}-\d{2} \d{2}:/.test(value)
      ? value.replace(' ', 'T') + '+08:00'
      : value,
  )
  if (Number.isNaN(parsed.getTime())) return '时间待确认'
  try {
    return new Intl.DateTimeFormat('zh-CN', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(parsed)
  } catch {
    return parsed.toISOString()
  }
}
export function remainingText(seconds: number) {
  if (!Number.isFinite(seconds)) return '待确认'
  if (seconds <= 0) return '已到期'
  if (seconds < 3600) return '不足 1 小时'
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时`
  return `${Math.floor(seconds / 86400)} 天 ${Math.floor((seconds % 86400) / 3600)} 小时`
}
