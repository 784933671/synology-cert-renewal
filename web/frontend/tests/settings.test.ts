import { describe, expect, it } from 'vitest'
import { buildPayload, makeDraft, validateDraft } from '../src/lib/settings'
import { settings } from './fixtures'
describe('配置校验与最小提交', () => {
  it('拒绝程序设置的禁选证书并保留服务器给出的原因', () => {
    const original = settings(),
      draft = makeDraft(original)
    original.certificates[0].selectable = false
    original.certificates[0].reason = '该证书已到期'
    expect(validateDraft(draft, original)).toContain('该证书已到期')
    expect(buildPayload(draft, original.revision)).not.toHaveProperty(
      'selectable',
    )
    expect(buildPayload(draft, original.revision)).not.toHaveProperty('reason')
  })
  it('首次读取不包含现有密钥，普通修改不提交秘密或服务器只读字段', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.notifications.success_email = ' new@example.com '
    const payload = buildPayload(draft, original.revision)
    expect(draft.secret_id).toBe('')
    expect(draft.secret_key).toBe('')
    expect(Object.keys(payload).sort()).toEqual(
      [
        'certificate_id',
        'email',
        'notifications',
        'probes',
        'renew_before_days',
        'revision',
        'schedule',
      ].sort(),
    )
    expect(payload.notifications.success_email).toBe('new@example.com')
    expect(original.notifications.success_email).toBe('ok@example.com')
    expect(payload.revision).toBe('revision-one')
  })
  it('一项密钥不能覆盖现有密钥，成对替换才可提交', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.secret_id = 'AKIDexample'
    expect(validateDraft(draft, original)).toContain(
      '更换 DNSPod 凭据时，请同时填写 SecretId 和 SecretKey。',
    )
    expect(buildPayload(draft, original.revision)).not.toHaveProperty(
      'secret_id',
    )
    draft.secret_key = 'example-secret'
    expect(validateDraft(draft, original)).toEqual([])
    expect(buildPayload(draft, original.revision)).toMatchObject({
      secret_id: 'AKIDexample',
      secret_key: 'example-secret',
    })
  })
  it('更换证书不能保留不受保护的 HTTPS 服务域名', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.certificate_id = 'b'
    expect(
      validateDraft(draft, original).some((item) => item.includes('服务域名')),
    ).toBe(true)
    draft.probes[0].server_name = 'second.test'
    expect(validateDraft(draft, original)).toEqual([])
  })
  it('通配证书只覆盖一级子域名，不允许字面通配 SNI', () => {
    const original = settings(),
      draft = makeDraft(original)
    for (const name of [
      'example.com',
      'nested.nas.example.com',
      '*.example.com',
    ]) {
      draft.probes[0].server_name = name
      expect(
        validateDraft(draft, original).some((item) =>
          item.includes('服务域名'),
        ),
      ).toBe(true)
    }
    draft.probes[0].server_name = 'new.example.com'
    expect(validateDraft(draft, original)).toEqual([])
  })
  it.each([0, 31, 1.5, Number.NaN])('拒绝不安全的续期窗口 %s', (value) => {
    const original = settings(),
      draft = makeDraft(original)
    draft.renew_before_days = value
    expect(
      validateDraft(draft, original).some((item) => item.includes('续期时间')),
    ).toBe(true)
  })
  it('空时间、未知计划与不合法端口不能保存', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.schedule.minute = Number.NaN
    draft.schedule.mode = 'unsupported'
    draft.probes[0].port = 0
    const errors = validateDraft(draft, original)
    expect(errors.some((item) => item.includes('分钟'))).toBe(true)
    expect(errors.some((item) => item.includes('当前计划'))).toBe(true)
    expect(errors.some((item) => item.includes('端口'))).toBe(true)
  })
  it('每天计划不会携带旧的小时频率，关闭成功通知不改变失败通知', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.schedule.mode = 'daily'
    draft.schedule.hour = 8
    draft.schedule.interval_hours = 12
    draft.notifications.success_enabled = false
    const payload = buildPayload(draft, original.revision)
    expect(payload.schedule).toMatchObject({
      mode: 'daily',
      hour: 8,
      interval_hours: 1,
      minute: 17,
    })
    expect(payload.notifications).toMatchObject({
      success_enabled: false,
      failure_enabled: true,
      failure_email: 'error@example.com',
    })
  })
  it('自适应保留每日基准时间，提交时去掉执行频率和提示等只读字段', () => {
    const original = settings()
    original.schedule = { ...original.schedule, mode: 'adaptive', hour: 3, minute: 18,
      interval_hours: 12, active_mode: 'hourly', editable: true, message: '正在处理待办' }
    const draft = makeDraft(original)
    expect(validateDraft(draft, original)).toEqual([])
    expect(buildPayload(draft, original.revision).schedule).toEqual({
      enabled: true, mode: 'adaptive', interval_hours: 1, hour: 3, minute: 18,
    })
    draft.schedule.hour = 6
    expect(original.schedule.hour).toBe(3)
  })
  it.each([-1, 24, 1.5, Number.NaN])('自适应每日基准小时无效时拒绝保存 %s', (hour) => {
    const original = settings(), draft = makeDraft(original)
    draft.schedule.mode = 'adaptive'
    draft.schedule.hour = hour
    expect(validateDraft(draft, original)).toContain('检查小时必须是 0～23 的整数。')
  })
  it('自适应只读计划仍禁止保存，改回固定计划不携带自适应展示字段', () => {
    const original = settings(), draft = makeDraft(original)
    draft.schedule = { ...draft.schedule, mode: 'adaptive', hour: 3, minute: 18,
      active_mode: 'daily', editable: false, message: '执行计划已变化' }
    expect(validateDraft(draft, original)).toContain('当前计划无法通过网页修改，请先检查群晖任务计划。')
    draft.schedule.editable = true
    draft.schedule.mode = 'hourly'
    draft.schedule.interval_hours = 6
    expect(validateDraft(draft, original)).toEqual([])
    expect(buildPayload(draft, original.revision).schedule).toEqual({
      enabled: true, mode: 'hourly', interval_hours: 6, hour: 0, minute: 18,
    })
  })
  it('关闭的通知可留空，但非空邮箱仍必须有效', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.notifications.success_enabled = false
    draft.notifications.success_email = ''
    expect(validateDraft(draft, original)).toEqual([])
    draft.notifications.success_email = 'invalid'
    expect(validateDraft(draft, original)).toContain(
      '请输入有效的成功通知邮箱。',
    )
  })
  it('拒绝超过执行器限制的探针数量和选项形式的通知邮箱', () => {
    const original = settings(),
      draft = makeDraft(original)
    draft.probes = Array.from({ length: 9 }, () => ({ ...draft.probes[0] }))
    draft.notifications.failure_email = '-option@example.com'
    expect(validateDraft(draft, original)).toContain(
      '请配置 1～8 个 HTTPS 验证目标。',
    )
    expect(validateDraft(draft, original)).toContain(
      '请输入有效的失败通知邮箱。',
    )
  })
})
