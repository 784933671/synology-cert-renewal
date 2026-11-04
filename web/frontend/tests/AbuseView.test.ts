import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import AbuseView from '../src/views/AbuseView.vue'
import type { AbusePolicy } from '../src/types'
vi.mock('../src/lib/api', async original => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
const policy = (): AbusePolicy => ({ revision: 'a'.repeat(32), limits: { ip_requests_per_minute: 600, session_requests_per_minute: 180, block_after_violations: 20, block_seconds: 300 } })
const blocked = { ip: '10.10.10.2', current: true, reason: 'ip_rate_exceeded', blocked_at: '2026-11-04T01:00:00Z', expires_at: '2026-11-04T01:05:00Z', retry_after: 300 }
const button = (label: string) => wrapper!.findAll('button').find(node => node.text().replace(/\s+/g, '') === label)!
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
async function setup(blocks = false) {
  vi.mocked(api).mockImplementation(async path => path === '/api/abuse' ? policy() : { items: blocks ? [blocked] : [] })
  vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
  wrapper = mount(AbuseView); await flushPromises()
}
async function submit() { await wrapper!.get('form').trigger('submit'); await flushPromises() }
describe('接口防护管理', () => {
  it('展示实际额度和空封禁状态，真实AntForm绑定model后保存revision及完整limits', async () => {
    await setup()
    expect(wrapper!.text()).toContain('当前没有临时封禁的来源')
    expect(wrapper!.get<HTMLInputElement>('#abuse-ip_requests_per_minute').element.value).toBe('600')
    await wrapper!.get('#abuse-block_seconds').setValue(600)
    expect(wrapper!.emitted('dirty')?.at(-1)).toEqual([true])
    vi.mocked(api).mockResolvedValueOnce({ ...policy(), revision: 'b'.repeat(32), limits: { ...policy().limits, block_seconds: 600 } })
    await submit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('接口防护设置已保存'))
    expect(api).toHaveBeenLastCalledWith('/api/abuse', expect.objectContaining({ method: 'PUT', body: { revision: policy().revision, limits: { ...policy().limits, block_seconds: 600 } } }))
    expect(wrapper!.emitted('dirty')?.at(-1)).toEqual([false])
    expect(wrapper!.emitted('busy')).toEqual([[true], [false]])
  })
  it('会话额度大于IP额度和空输入均阻止提交', async () => {
    await setup()
    await wrapper!.get('#abuse-session_requests_per_minute').setValue(800)
    await submit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('会话补充额度不能超过 IP 补充额度'))
    expect(api).toHaveBeenCalledTimes(2)
    await wrapper!.get('#abuse-block_seconds').setValue('')
    await submit()
    expect(wrapper!.text()).toContain('临时封禁时长须为 60～1800 秒的整数')
    expect(api).toHaveBeenCalledTimes(2)
  })
  it.each([409, 0, 503])('保存%s保留草稿并阻止重放，确认重新读取后恢复', async status => {
    await setup()
    await wrapper!.get('#abuse-block_seconds').setValue(600)
    vi.mocked(api).mockRejectedValueOnce(new ApiError('写入失败', status))
    await submit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain(status === 409 ? '配置已在其他位置修改' : '保存结果尚未确认'))
    expect(wrapper!.get<HTMLInputElement>('#abuse-block_seconds').element.value).toBe('600')
    expect(button('保存防护设置').attributes('disabled')).toBeDefined()
    await submit()
    expect(api).toHaveBeenCalledTimes(3)
    vi.mocked(window.confirm).mockReturnValueOnce(false)
    await button('重新读取防护设置').trigger('click'); await flushPromises()
    expect(api).toHaveBeenCalledTimes(3)
    await button('重新读取防护设置').trigger('click'); await flushPromises()
    expect(wrapper!.get<HTMLInputElement>('#abuse-block_seconds').element.value).toBe('300')
  })
  it('取消或过期二次验证不误判保存未知，保留修改供再次操作', async () => {
    await setup()
    await wrapper!.get('#abuse-block_seconds').setValue(600)
    for (const [code, message] of [['stepup_cancelled', '已取消验证'], ['code_expired', '验证码已过期']]) {
      vi.mocked(api).mockRejectedValueOnce(new ApiError(message, 400, code))
      await submit()
      await vi.waitFor(() => expect(wrapper!.text()).toContain(message))
      expect(wrapper!.text()).not.toContain('保存结果尚未确认')
      expect(button('保存防护设置').attributes('disabled')).toBeUndefined()
    }
  })
  it('当前来源可邮箱解封，双击不重复提交并刷新列表', async () => {
    await setup(true)
    expect(wrapper!.text()).toContain('当前来源')
    expect(wrapper!.text()).toContain('IP 请求持续超限')
    let finish!: (value: unknown) => void
    vi.mocked(api).mockImplementationOnce(() => new Promise(resolve => { finish = resolve })).mockResolvedValueOnce({ items: [] })
    await button('解除封禁').trigger('click')
    await button('解除封禁').trigger('click')
    expect(api).toHaveBeenCalledTimes(3)
    expect(api).toHaveBeenLastCalledWith('/api/abuse/unblock', expect.objectContaining({ method: 'POST', body: { ip: blocked.ip } }))
    finish({ ok: true, removed: true }); await flushPromises()
    expect(wrapper!.text()).toContain('临时封禁已解除')
    expect(wrapper!.text()).toContain('当前没有临时封禁的来源')
  })
  it('解封确认取消不请求，结果未知仅刷新解锁', async () => {
    await setup(true)
    vi.mocked(window.confirm).mockReturnValueOnce(false)
    await button('解除封禁').trigger('click')
    expect(api).toHaveBeenCalledTimes(2)
    vi.mocked(api).mockRejectedValueOnce(new ApiError('网络中断'))
    await button('解除封禁').trigger('click'); await flushPromises()
    expect(wrapper!.text()).toContain('解封结果尚未确认')
    expect(button('解除封禁').attributes('disabled')).toBeDefined()
    await button('刷新封禁列表').trigger('click'); await flushPromises()
    expect(button('解除封禁').attributes('disabled')).toBeUndefined()
  })
  it('初始读取错误不显示假配置，重试和卸载取消完整', async () => {
    vi.mocked(api).mockRejectedValue(new ApiError('读取失败'))
    wrapper = mount(AbuseView); await flushPromises()
    expect(wrapper.text()).toContain('读取失败')
    expect(wrapper.find('form').exists()).toBe(false)
    vi.mocked(api).mockResolvedValueOnce(policy())
    await button('重试读取').trigger('click'); await flushPromises()
    expect(wrapper.find('form').exists()).toBe(true)
    const signals = vi.mocked(api).mock.calls.map(([, options]) => options!.signal!)
    wrapper.unmount(); wrapper = undefined
    expect(signals.every(signal => signal.aborted)).toBe(true)
  })
  it('封禁已到期时给出已解除状态，刷新移除过期记录', async () => {
    await setup(true)
    vi.mocked(api).mockResolvedValueOnce({ ok: true, removed: false }).mockResolvedValueOnce({ items: [] })
    await button('解除封禁').trigger('click'); await flushPromises()
    expect(wrapper!.text()).toContain('该来源已解除封禁或封禁已到期')
    expect(wrapper!.text()).toContain('当前没有临时封禁的来源')
  })

  it.each([409, 0])('保存%s后放弃修改仍明确状态未确认，不误报已同步', async status => {
    await setup()
    await wrapper!.get('#abuse-block_seconds').setValue(600)
    vi.mocked(api).mockRejectedValueOnce(new ApiError('写入失败', status))
    await submit()
    await vi.waitFor(() => expect(button('放弃修改').attributes('disabled')).toBeUndefined())
    await button('放弃修改').trigger('click')
    expect(wrapper!.get('.settings-save-note').text()).toContain('请重新读取')
    expect(wrapper!.get('.settings-save-note').text()).not.toContain('配置与服务器一致')
    expect(button('保存防护设置').attributes('disabled')).toBeDefined()
  })

})
