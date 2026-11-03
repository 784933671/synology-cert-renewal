import type { Draft, Settings } from '../types'
export function makeDraft(settings: Settings): Draft {
  return {
    certificate_id: settings.certificate_id,
    email: settings.email,
    renew_before_days: settings.renew_before_days,
    secret_id: '',
    secret_key: '',
    probes: settings.probes.map((item) => ({ ...item })),
    schedule: { ...settings.schedule },
    notifications: { ...settings.notifications },
  }
}
const isEmail = (value: string) =>
  /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(value)
const isNotificationEmail = (value: string) =>
  !value.startsWith('-') && isEmail(value)
const integer = (value: number, min: number, max: number) =>
  Number.isInteger(value) && value >= min && value <= max
export function validateDraft(draft: Draft, settings: Settings): string[] {
  const errors: string[] = []
  const certificate = settings.certificates.find(
    (item) => item.id === draft.certificate_id && item.available !== false,
  )
  if (!certificate) errors.push('请选择可用的群晖证书。')
  if (certificate?.selectable === false)
    errors.push(certificate.reason || '所选证书暂不可用，请选择其他证书。')
  if (!isEmail(draft.email.trim())) errors.push('请输入有效的证书注册邮箱。')
  if (!integer(draft.renew_before_days, 1, 30))
    errors.push('提前续期时间必须是 1～30 天的整数。')
  const plan = draft.schedule
  if (!['hourly', 'daily', 'adaptive'].includes(plan.mode) || plan.editable === false)
    errors.push('当前计划无法通过网页修改，请先检查群晖任务计划。')
  if (!integer(plan.minute, 0, 59)) errors.push('检查分钟必须是 0～59 的整数。')
  if (
    plan.mode === 'hourly' &&
    ![1, 2, 3, 4, 6, 8, 12].includes(plan.interval_hours)
  )
    errors.push('请选择支持的小时检查频率。')
  if (['daily', 'adaptive'].includes(plan.mode) && !integer(plan.hour, 0, 23))
    errors.push('检查小时必须是 0～23 的整数。')
  if (
    (draft.notifications.success_enabled ||
      draft.notifications.success_email.trim()) &&
    !isNotificationEmail(draft.notifications.success_email.trim())
  )
    errors.push('请输入有效的成功通知邮箱。')
  if (
    (draft.notifications.failure_enabled ||
      draft.notifications.failure_email.trim()) &&
    !isNotificationEmail(draft.notifications.failure_email.trim())
  )
    errors.push('请输入有效的失败通知邮箱。')
  if (Boolean(draft.secret_id.trim()) !== Boolean(draft.secret_key.trim()))
    errors.push('更换 DNSPod 凭据时，请同时填写 SecretId 和 SecretKey。')
  if (
    [draft.secret_id, draft.secret_key].some(
      (value) => value && !/^[A-Za-z0-9+/_=-]+$/.test(value.trim()),
    )
  )
    errors.push('DNSPod 凭据格式不正确，请检查是否完整复制。')
  if (!draft.probes.length || draft.probes.length > 8)
    errors.push('请配置 1～8 个 HTTPS 验证目标。')
  draft.probes.forEach((probe, index) => {
    if (!probe.host.trim() || /[\s/@?#]/.test(probe.host.trim()))
      errors.push(
        `验证目标 ${index + 1} 的连接地址应为域名或 IP，不含协议和路径。`,
      )
    if (!integer(probe.port, 1, 65535))
      errors.push(`验证目标 ${index + 1} 的端口必须是 1～65535 的整数。`)
    const domain = probe.server_name.trim().toLowerCase()
    const covered = certificate?.domains.some((item) => {
      const name = item.toLowerCase()
      return (
        name === domain ||
        (name.startsWith('*.') &&
          domain.endsWith(name.slice(1)) &&
          domain.split('.').length === name.split('.').length)
      )
    })
    if (!domain || !covered || domain.includes('*'))
      errors.push(`验证目标 ${index + 1} 的服务域名必须由所选证书覆盖。`)
  })
  return errors
}
export function buildPayload(draft: Draft, revision: string) {
  return {
    revision,
    certificate_id: draft.certificate_id,
    email: draft.email.trim(),
    renew_before_days: draft.renew_before_days,
    probes: draft.probes.map((probe) => ({
      host: probe.host.trim(),
      port: probe.port,
      server_name: probe.server_name.trim().toLowerCase(),
    })),
    schedule: {
      enabled: draft.schedule.enabled,
      mode: draft.schedule.mode,
      interval_hours:
        draft.schedule.mode === 'hourly' ? draft.schedule.interval_hours : 1,
      hour: draft.schedule.mode === 'hourly' ? 0 : draft.schedule.hour,
      minute: draft.schedule.minute,
    },
    notifications: {
      success_enabled: draft.notifications.success_enabled,
      success_email: draft.notifications.success_email.trim(),
      failure_enabled: draft.notifications.failure_enabled,
      failure_email: draft.notifications.failure_email.trim(),
    },
    ...(draft.secret_id.trim() && draft.secret_key.trim()
      ? {
          secret_id: draft.secret_id.trim(),
          secret_key: draft.secret_key.trim(),
        }
      : {}),
  }
}
