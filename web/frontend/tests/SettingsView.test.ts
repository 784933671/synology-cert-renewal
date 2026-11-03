import { afterEach, describe, expect, it, vi } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import SettingsView from '../src/views/SettingsView.vue'
import { settings } from './fixtures'
vi.mock('../src/lib/api', async (original) => ({
  ...(await original<typeof import('../src/lib/api')>()),
  api: vi.fn(),
}))
let wrapper: VueWrapper | undefined
afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  document.body.innerHTML = ''
  vi.mocked(api).mockReset()
  vi.unstubAllGlobals()
})
function input(label: string) {
  const field = wrapper!.findAll('label').find((node) => node.text().includes(label))!
  return wrapper!.get<HTMLInputElement>(`#${field.attributes('for')}`)
}
function button(label: string) {
  return wrapper!.findAll('button').find((item) => item.text().replace(/\s/g, '') === label)!
}
async function choose(id: string, label: string) {
  await wrapper!.get(`#${id}`).trigger('mousedown')
  await flushPromises()
  const option = [...document.querySelectorAll('.ant-select-item-option')].find((item) => item.textContent === label)!
  await new DOMWrapper(option).trigger('click')
  await flushPromises()
}
describe('配置编辑完整状态', () => {
  it('不兼容证书禁选并显示原因，旧数据省略字段仍可选择', async () => {
    const value = settings()
    value.certificates[1].selectable = false
    value.certificates[1].reason = '未覆盖管理域名 ttxli.cn'
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'certificate' } })
    await flushPromises()
    await wrapper.get('#certificate-id').trigger('mousedown')
    await flushPromises()
    const options = [...document.querySelectorAll('.ant-select-item-option')]
    const disabled = options.find((item) => item.textContent?.includes('Second'))!
    expect(disabled.classList.contains('ant-select-item-option-disabled')).toBe(true)
    expect(disabled.textContent).toContain('未覆盖管理域名 ttxli.cn')
    const available = options.find((item) => item.textContent?.includes('NAS'))!
    expect(available.classList.contains('ant-select-item-option-disabled')).toBe(false)
    await new DOMWrapper(disabled).trigger('click')
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
  })
  it('保存冲突保留邮箱和新密钥草稿，不尝试覆盖其他用户修改', async () => {
    vi.mocked(api)
      .mockResolvedValueOnce(settings())
      .mockRejectedValueOnce(
        new ApiError('服务器配置已经改变', 409, 'revision_conflict'),
      )
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'certificate' } })
    await flushPromises()
    expect(input('新 SecretId').element.value).toBe('')
    await input('证书注册邮箱').setValue('updated@example.com')
    await input('新 SecretId').setValue('AKIDnew')
    await input('新 SecretKey').setValue('new-secret')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('当前草稿已保留')
    expect(input('证书注册邮箱').element.value).toBe('updated@example.com')
    expect(input('新 SecretKey').element.value).toBe('new-secret')
    expect(
      wrapper
        .findAll('button')
        .find((button) => button.text().replace(/\s/g, '') === '保存配置')!
        .attributes('disabled'),
    ).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenCalledTimes(2)
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([true])
  })
  it('成功保存后清空新密钥，并恢复已保存状态', async () => {
    const latest = settings()
    latest.revision = 'revision-two'
    vi.mocked(api)
      .mockResolvedValueOnce(settings())
      .mockResolvedValueOnce(latest)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'certificate' } })
    await flushPromises()
    await input('新 SecretId').setValue('AKIDnew')
    await input('新 SecretKey').setValue('new-secret')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('配置已保存并生效')
    expect(input('新 SecretId').element.value).toBe('')
    expect(input('新 SecretKey').element.value).toBe('')
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
  })
  it('读取失败显示错误且允许重新读取，无假配置兜底', async () => {
    vi.mocked(api)
      .mockRejectedValueOnce(new ApiError('连接不可用'))
      .mockResolvedValueOnce(settings())
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    expect(wrapper.text()).toContain('连接不可用')
    expect(wrapper.find('form').exists()).toBe(false)
    await wrapper
      .findAll('button')
      .find((button) => button.text().replace(/\s/g, '') === '重试')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.find('form').exists()).toBe(true)
  })
  it('未知计划只读，不允许按默认时间覆盖', async () => {
    const value = settings()
    value.schedule.mode = 'unsupported'
    value.schedule.editable = false
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    expect(wrapper.text()).toContain('配置已设为只读')
    expect(
      wrapper.get('#renew-before-days').attributes('disabled'),
    ).toBeDefined()
    expect(wrapper.get('#schedule-enabled').attributes('disabled')).toBeDefined()
    expect(wrapper.get('#schedule-mode').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenCalledOnce()
  })
  it('切换每日检查后保存小时、分钟和提前续期天数', async () => {
    vi.mocked(api).mockResolvedValueOnce(settings()).mockResolvedValueOnce(settings())
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    await choose('schedule-mode', '每天固定时间')
    expect(wrapper.find('#schedule-interval').exists()).toBe(false)
    await input('检查小时').setValue('6')
    await input('检查分钟').setValue('30')
    await input('提前续期时间').setValue('3')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenLastCalledWith('/api/settings', expect.objectContaining({
      method: 'PUT',
      body: expect.objectContaining({ renew_before_days: 3, schedule: expect.objectContaining({ mode: 'daily', hour: 6, minute: 30 }) }),
    }))
  })
  it('切换自适应检查保留每日时分，保存期间禁用并以回读的实际频率为准', async () => {
    const saved = settings()
    saved.schedule = { ...saved.schedule, mode: 'adaptive', hour: 3, minute: 18,
      active_mode: 'hourly', editable: true, message: '当前存在待办，每小时检查。' }
    let finish!: (value: ReturnType<typeof settings>) => void
    vi.mocked(api).mockResolvedValueOnce(settings()).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    await choose('schedule-mode', '自适应检查')
    expect(wrapper.find('#schedule-interval').exists()).toBe(false)
    await input('平时检查小时').setValue('3')
    await input('检查分钟').setValue('18')
    expect(wrapper.text()).toContain('平时每天 03:18 检查')
    expect(wrapper.text()).toContain('到期前 48 小时或待办未完成时，每小时第 18 分钟检查')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(input('平时检查小时').attributes('disabled')).toBeDefined()
    expect(wrapper.get('#schedule-enabled').attributes('disabled')).toBeDefined()
    const options = vi.mocked(api).mock.calls.at(-1)![1]!
    expect((options.body as { schedule: unknown }).schedule).toEqual({
      enabled: true, mode: 'adaptive', interval_hours: 1, hour: 3, minute: 18,
    })
    finish(saved)
    await flushPromises()
    expect(wrapper.text()).toContain('配置已保存并生效')
    expect(wrapper.text()).toContain('最近读取的执行频率：每小时第 18 分钟')
    expect(wrapper.text()).toContain('当前存在待办，每小时检查')
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
  })
  it('编辑自适应草稿不冒充已经生效的执行时间，暂停状态也沿用已保存值', async () => {
    const saved = settings()
    saved.schedule = { ...saved.schedule, mode: 'adaptive', hour: 3, minute: 18, active_mode: 'daily' }
    vi.mocked(api).mockResolvedValueOnce(saved)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    await input('平时检查小时').setValue('6')
    await input('检查分钟').setValue('30')
    await wrapper.get('#schedule-enabled').trigger('click')
    expect(wrapper.text()).toContain('平时每天 06:30 检查')
    expect(wrapper.text()).toContain('最近读取的执行频率：每天 03:18')
    expect(wrapper.text()).not.toContain('最近读取的执行频率：每天 06:30')
    expect(wrapper.text()).not.toContain('已保存的自动检查已暂停')
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([true])
  })
  it('自适应切换导致保存版本冲突时保留草稿，重新读取才恢复保存', async () => {
    const initial = settings(), latest = settings()
    initial.schedule = { ...initial.schedule, mode: 'adaptive', hour: 3, minute: 18, active_mode: 'daily' }
    latest.schedule = { ...initial.schedule, active_mode: 'hourly' }
    latest.revision = 'after-cadence-switch'
    vi.mocked(api).mockResolvedValueOnce(initial)
      .mockRejectedValueOnce(new ApiError('执行计划已经更新', 409, 'stale_revision'))
      .mockResolvedValueOnce(latest)
    vi.stubGlobal('confirm', vi.fn(() => true))
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    await input('平时检查小时').setValue('6')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('当前草稿已保留')
    expect(input('平时检查小时').element.value).toBe('6')
    expect(button('保存配置').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    expect(api).toHaveBeenCalledTimes(2)
    await button('重新读取').trigger('click')
    await flushPromises()
    expect(input('平时检查小时').element.value).toBe('3')
    expect(wrapper.text()).toContain('最近读取的执行频率：每小时第 18 分钟')
    expect(wrapper.text()).not.toContain('当前草稿已保留')
    await input('平时检查小时').setValue('5')
    expect(button('保存配置').attributes('disabled')).toBeUndefined()
  })
  it('自适应保存失败保留草稿且允许重试，成功回读可确认暂停', async () => {
    const initial = settings(), saved = settings()
    initial.schedule = { ...initial.schedule, mode: 'adaptive', hour: 3, minute: 18, active_mode: 'daily' }
    saved.schedule = { ...initial.schedule, enabled: false }
    vi.mocked(api).mockResolvedValueOnce(initial)
      .mockRejectedValueOnce(new ApiError('保存暂不可用', 503, 'unavailable'))
      .mockResolvedValueOnce(saved)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    await wrapper.get('#schedule-enabled').trigger('click')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('保存暂不可用')
    expect(button('保存配置').attributes('disabled')).toBeUndefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('已保存的自动检查已暂停')
    expect(wrapper.text()).toContain('配置已保存并生效')
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
    expect(api).toHaveBeenCalledTimes(3)
  })
  it('自适应频率未知或计划冲突时不推测生效时间', async () => {
    const value = settings()
    value.schedule = { ...value.schedule, mode: 'adaptive', hour: 3, minute: 18 }
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    expect(wrapper.text()).toContain('执行频率暂未确认')
    expect(wrapper.text()).not.toContain('最近读取的执行频率')
    wrapper.unmount()
    value.schedule.editable = false
    value.schedule.active_mode = 'hourly'
    value.schedule.message = '原任务计划已被修改，请核对后再操作。'
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'renewal' } })
    await flushPromises()
    expect(wrapper.text()).toContain('原任务计划已被修改')
    expect(wrapper.text()).not.toContain('最近读取的执行频率')
    expect(wrapper.get('#schedule-mode').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenCalledTimes(2)
  })
  it('验证目标支持增删、限制八项且至少保留一项', async () => {
    vi.mocked(api).mockResolvedValueOnce(settings())
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'certificate' } })
    await flushPromises()
    expect(button('移除此目标').attributes('disabled')).toBeDefined()
    for (let index = 0; index < 7; index++) await button('添加目标').trigger('click')
    expect(wrapper.findAll('.settings-probe-row')).toHaveLength(8)
    expect(button('添加目标').attributes('disabled')).toBeDefined()
    expect(wrapper.get<HTMLInputElement>('#probe-server-name-7').element.value).toBe('nas.example.com')
    await button('移除此目标').trigger('click')
    expect(wrapper.findAll('.settings-probe-row')).toHaveLength(7)
    expect(button('添加目标').attributes('disabled')).toBeUndefined()
  })
  it('通知开关仅控制对应邮箱，保留草稿并分别保存通知选项', async () => {
    vi.mocked(api).mockResolvedValueOnce(settings()).mockResolvedValueOnce(settings())
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'notifications' } })
    await flushPromises()
    await input('成功通知邮箱').setValue('new-success@example.com')
    await wrapper.get('#notification-failure-enabled').trigger('click')
    expect(input('失败通知邮箱').attributes('disabled')).toBeDefined()
    expect(input('失败通知邮箱').element.value).toBe('error@example.com')
    expect(input('成功通知邮箱').attributes('disabled')).toBeUndefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenLastCalledWith('/api/settings', expect.objectContaining({
      body: expect.objectContaining({ notifications: {
        success_enabled: true, success_email: 'new-success@example.com',
        failure_enabled: false, failure_email: 'error@example.com',
      } }),
    }))
  })
  it('保存期间禁用全部输入、目标增删和放弃操作', async () => {
    vi.mocked(api).mockResolvedValueOnce(settings()).mockImplementationOnce(() => new Promise(() => {}))
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section: 'certificate' } })
    await flushPromises()
    await input('证书注册邮箱').setValue('changed@example.com')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(input('证书注册邮箱').attributes('disabled')).toBeDefined()
    expect(input('新 SecretId').attributes('disabled')).toBeDefined()
    expect(wrapper.get('#certificate-id').attributes('disabled')).toBeDefined()
    expect(button('添加目标').attributes('disabled')).toBeDefined()
    expect(button('放弃修改').attributes('disabled')).toBeDefined()
  })

  it.each([
    ['renewal', 'renew-before-days', '提前续期时间必须是 1～30 天的整数。'],
    ['renewal', 'schedule-hour', '检查小时必须是 0～23 的整数。'],
    ['renewal', 'schedule-minute', '检查分钟必须是 0～59 的整数。'],
    ['certificate', 'probe-port-0', '验证目标 1 的端口必须是 1～65535 的整数。'],
  ] as const)('清空 %s 页的 %s 后保持空值，校验失败不提交', async (section, id, message) => {
    const value = settings()
    value.schedule.mode = 'daily'
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { attachTo: document.body, props: { section } })
    await flushPromises()
    const field = wrapper.get<HTMLInputElement>(`#${id}`)
    await field.setValue('')
    await field.trigger('blur')
    await flushPromises()
    expect(field.element.value).toBe('')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(field.element.value).toBe('')
    expect(wrapper.text()).toContain(message)
    expect(api).toHaveBeenCalledOnce()
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([true])
  })

})
