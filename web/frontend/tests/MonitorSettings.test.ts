import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import MonitorSettingsPanel from '../src/components/MonitorSettingsPanel.vue'
import { deferred, monitorSettings } from './monitoring-fixtures'
vi.mock('../src/lib/api', async (original) => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); vi.unstubAllGlobals(); document.body.innerHTML = '' })
function button(label: string) { return wrapper!.findAll('button').find((node) => node.text().replace(/\s/g, '') === label)! }
async function edit(value: number | string) { await wrapper!.get('#monitor-expiry-hours').setValue(value); await flushPromises() }
async function submit() { await wrapper!.get('form').trigger('submit'); await flushPromises() }
describe('主动监测配置', () => {
  it('严格提交版本与四项配置，保存期间禁用重复操作并闭合dirty/busy事件', async () => {
    const pending = deferred<ReturnType<typeof monitorSettings>>()
    vi.mocked(api).mockResolvedValueOnce(monitorSettings()).mockImplementationOnce(() => pending.promise)
    wrapper = mount(MonitorSettingsPanel); await flushPromises()
    await edit(12); await wrapper.get('#monitor-enabled').trigger('click'); await submit()
    expect(api).toHaveBeenLastCalledWith('/api/monitor', expect.objectContaining({ method: 'PUT', body: { revision: 'a'.repeat(64), enabled: false, missed_runs: 2, grace_minutes: 15, expiry_hours: 12 } }))
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([true])
    expect(wrapper.emitted('busy')?.at(-1)).toEqual([true])
    await submit(); expect(api).toHaveBeenCalledTimes(2)
    expect(button('重新读取配置').attributes('disabled')).toBeDefined()
    pending.resolve({ ...monitorSettings(), revision: 'b'.repeat(64), enabled: false, expiry_hours: 12 }); await flushPromises()
    expect(wrapper.text()).toContain('监测配置已保存')
    expect(wrapper.emitted('saved')).toHaveLength(1)
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
    expect(wrapper.emitted('busy')?.at(-1)).toEqual([false])
    expect(button('保存监测配置').attributes('disabled')).toBeDefined()
  })
  it('清空数值不隐式保存零，展示校验并允许纠正', async () => {
    vi.mocked(api).mockResolvedValue(monitorSettings())
    wrapper = mount(MonitorSettingsPanel); await flushPromises()
    await edit(''); await submit()
    expect(wrapper.text()).toContain('临期提醒须为 1～168 小时的整数')
    expect(api).toHaveBeenCalledTimes(1)
    await edit(1); await submit()
    expect(api).toHaveBeenCalledTimes(2)
  })
  it('配置冲突保留草稿和锁定保存，取消重读不丢稿，确认后用新版本保存', async () => {
    vi.mocked(api).mockResolvedValueOnce(monitorSettings()).mockRejectedValueOnce(new ApiError('配置已改变', 409, 'revision_conflict')).mockResolvedValueOnce({ ...monitorSettings(), revision: 'b'.repeat(64), expiry_hours: 48 }).mockResolvedValueOnce(monitorSettings())
    wrapper = mount(MonitorSettingsPanel); await flushPromises()
    await edit(12); await submit()
    expect(wrapper.text()).toContain('草稿已保留')
    expect(wrapper.get<HTMLInputElement>('#monitor-expiry-hours').element.value).toBe('12')
    await submit(); expect(api).toHaveBeenCalledTimes(2)
    const confirm = vi.fn().mockReturnValue(false); vi.stubGlobal('confirm', confirm)
    await button('重新读取配置').trigger('click'); await flushPromises()
    expect(api).toHaveBeenCalledTimes(2)
    confirm.mockReturnValue(true)
    await button('重新读取配置').trigger('click'); await flushPromises()
    expect(wrapper.get<HTMLInputElement>('#monitor-expiry-hours').element.value).toBe('48')
    await edit(36); await submit()
    expect(api).toHaveBeenLastCalledWith('/api/monitor', expect.objectContaining({ body: expect.objectContaining({ revision: 'b'.repeat(64), expiry_hours: 36 }) }))
  })
  it.each([new ApiError('请求超时'), new ApiError('无法识别', 200, 'invalid_response'), new ApiError('服务失败', 503)])('结果不明阻止重复，放弃草稿也不假报同步，重新读取后恢复', async (failure) => {
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
    vi.mocked(api).mockResolvedValueOnce(monitorSettings()).mockRejectedValueOnce(failure).mockRejectedValueOnce(new ApiError('读取失败')).mockResolvedValueOnce({ ...monitorSettings(), expiry_hours: 12 })
    wrapper = mount(MonitorSettingsPanel); await flushPromises()
    await edit(12); await submit()
    expect(wrapper.text()).toContain('保存结果尚未确认')
    expect(wrapper.emitted('saved')).toBeUndefined()
    await button('放弃修改').trigger('click'); await flushPromises()
    expect(wrapper.text()).not.toContain('监测配置与服务器一致')
    await edit(36); await submit(); expect(api).toHaveBeenCalledTimes(2)
    await button('重新读取配置').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('保存结果尚未确认')
    await button('重新读取配置').trigger('click'); await flushPromises()
    expect(wrapper.text()).not.toContain('保存结果尚未确认')
    expect(wrapper.get<HTMLInputElement>('#monitor-expiry-hours').element.value).toBe('12')
    expect(wrapper.text()).toContain('监测配置与服务器一致')
  })
  it('明确拒绝可重试，失败通知关闭时说明沿用邮箱且不会发预警', async () => {
    vi.mocked(api).mockResolvedValueOnce({ ...monitorSettings(), notification_enabled: false, recipient: '' }).mockRejectedValueOnce(new ApiError('配置不合法', 400)).mockResolvedValueOnce(monitorSettings())
    wrapper = mount(MonitorSettingsPanel); await flushPromises()
    expect(wrapper.text()).toContain('当前不会发送预警邮件')
    await edit(12); await submit()
    expect(button('保存监测配置').attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).not.toContain('保存结果尚未确认')
    await submit(); expect(wrapper.emitted('saved')).toHaveLength(1)
  })
  it('初始读取失败可重试，卸载取消保存且迟到成功不会触发saved', async () => {
    const pending = deferred<ReturnType<typeof monitorSettings>>()
    vi.mocked(api).mockRejectedValueOnce(new ApiError('连接失败')).mockResolvedValueOnce(monitorSettings()).mockImplementationOnce(() => pending.promise)
    wrapper = mount(MonitorSettingsPanel); await flushPromises()
    expect(wrapper.text()).toContain('暂时无法读取监测配置')
    await button('重试').trigger('click'); await flushPromises(); await edit(12); await submit()
    const signal = vi.mocked(api).mock.calls.at(-1)![1]!.signal!
    const previous = wrapper; previous.unmount(); wrapper = undefined
    expect(signal.aborted).toBe(true)
    pending.resolve(monitorSettings()); await flushPromises()
    expect(previous.emitted('saved')).toBeUndefined()
  })
})
