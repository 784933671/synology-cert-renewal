import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import type { AccessMode, Security } from '../src/types'
import SecurityView from '../src/views/SecurityView.vue'

vi.mock('../src/lib/api', async (original) => ({
  ...(await original<typeof import('../src/lib/api')>()),
  api: vi.fn(),
}))
let wrapper: VueWrapper | undefined
function security(mode: AccessMode = 'lan', pending = false): Security {
  return {
    access_mode: mode,
    applied_mode: pending ? 'lan' : mode,
    revision: mode === 'lan' ? 'a'.repeat(32) : 'b'.repeat(32),
    pending,
    lan_only: mode === 'lan',
    allowed_networks: mode === 'lan' ? ['10.10.10.0/24'] : ['0.0.0.0/0'],
    https: true,
    session_idle_minutes: 30,
    session_absolute_hours: 8,
  }
}
function button(label: string) {
  return wrapper!.findAll('button').find((item) => item.text().replace(/\s/g, '') === label)!
}
afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  vi.mocked(api).mockReset()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('访问模式配置', () => {
  it('展示服务器实际的外网模式、范围与会话策略', async () => {
    vi.mocked(api).mockResolvedValueOnce(security('public'))
    wrapper = mount(SecurityView)
    await flushPromises()
    expect(wrapper.get<HTMLInputElement>('input[name="access_mode"]:checked').element.value).toBe('public')
    expect(wrapper.get('.access-policy-status').text()).toContain('允许外网')
    expect(wrapper.get('.access-policy-status').text()).not.toContain('仅内网')
    expect(wrapper.text()).toContain('所有 IPv4 地址')
    expect(wrapper.text()).toContain('30 分钟')
    expect(wrapper.text()).toContain('外网连接可能立即断开')
    expect(button('保存访问模式').attributes('disabled')).toBeDefined()
  })

  it('保存模式和revision，区分已保存与已应用，并在确认后停止轮询', async () => {
    vi.useFakeTimers()
    vi.mocked(api)
      .mockResolvedValueOnce(security())
      .mockResolvedValueOnce(security('public', true))
      .mockResolvedValueOnce(security('public'))
    wrapper = mount(SecurityView)
    await flushPromises()
    await wrapper.get('input[name="access_mode"][value="public"]').setValue()
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([true])
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenNthCalledWith(2, '/api/security', {
      method: 'PUT', body: { access_mode: 'public', revision: 'a'.repeat(32) },
      signal: expect.any(AbortSignal),
    })
    expect(wrapper.text()).toContain('访问模式已保存，正在应用访问规则')
    expect(wrapper.text()).not.toContain('访问模式已保存并应用')
    expect(wrapper.get('input[name="access_mode"]').attributes('disabled')).toBeDefined()
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(wrapper.text()).toContain('访问模式已保存并应用')
    expect(wrapper.get('.access-policy-status').text()).toContain('允许外网')
    expect(wrapper.get('input[name="access_mode"]').attributes('disabled')).toBeUndefined()
    await vi.advanceTimersByTimeAsync(15000)
    expect(api).toHaveBeenCalledTimes(3)
  })

  it('409时保留草稿并禁止覆盖，重新读取前保留用户确认', async () => {
    vi.mocked(api)
      .mockResolvedValueOnce(security())
      .mockRejectedValueOnce(new ApiError('版本已改变', 409, 'stale_revision'))
      .mockResolvedValueOnce(security('public'))
    const confirm = vi.fn().mockReturnValue(false)
    vi.stubGlobal('confirm', confirm)
    wrapper = mount(SecurityView)
    await flushPromises()
    await wrapper.get('input[name="access_mode"][value="public"]').setValue()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get<HTMLInputElement>('input[name="access_mode"]:checked').element.value).toBe('public')
    expect(wrapper.text()).toContain('当前草稿已保留')
    expect(button('保存访问模式').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await button('重新读取').trigger('click')
    expect(api).toHaveBeenCalledTimes(2)
    expect(confirm).toHaveBeenCalled()
    confirm.mockReturnValue(true)
    await button('重新读取').trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('当前草稿已保留')
    expect(wrapper.get('.access-policy-status').text()).toContain('允许外网')
  })

  it.each([0, 503])('保存失败（%s）时不声称成功，保留草稿并要求确认结果', async (status) => {
    vi.mocked(api)
      .mockResolvedValueOnce(security('public'))
      .mockRejectedValueOnce(new ApiError('无法连接管理服务', status))
    wrapper = mount(SecurityView)
    await flushPromises()
    await wrapper.get('input[name="access_mode"][value="lan"]').setValue()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('保存结果尚未确认')
    expect(wrapper.text()).not.toContain('访问模式已保存')
    expect(wrapper.get<HTMLInputElement>('input[name="access_mode"]:checked').element.value).toBe('lan')
    expect(button('保存访问模式').attributes('disabled')).toBeDefined()
  })

  it('读取失败不提供假配置，可重试恢复', async () => {
    vi.mocked(api)
      .mockRejectedValueOnce(new ApiError('连接不可用'))
      .mockResolvedValueOnce(security('public'))
    wrapper = mount(SecurityView)
    await flushPromises()
    expect(wrapper.text()).toContain('连接不可用')
    expect(wrapper.find('form').exists()).toBe(false)
    await button('重试').trigger('click')
    await flushPromises()
    expect(wrapper.find('form').exists()).toBe(true)
    expect(wrapper.get<HTMLInputElement>('input[name="access_mode"]:checked').element.value).toBe('public')
  })

  it('应用中的连接错误保留最近状态，不误报已应用，恢复后继续确认', async () => {
    vi.useFakeTimers()
    vi.mocked(api)
      .mockResolvedValueOnce(security('public', true))
      .mockRejectedValueOnce(new ApiError('服务正在重启'))
      .mockResolvedValueOnce(security('public'))
    wrapper = mount(SecurityView)
    await flushPromises()
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(wrapper.text()).toContain('服务正在重启')
    expect(wrapper.text()).toContain('最近确认的模式')
    expect(wrapper.get('.access-policy-status').text()).toContain('仅内网')
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(wrapper.text()).not.toContain('服务正在重启')
    expect(wrapper.get('.access-policy-status').text()).toContain('允许外网')
  })

  it('长时间未应用时停止自动轮询并给出手动确认入口', async () => {
    vi.useFakeTimers()
    vi.mocked(api).mockResolvedValue(security('public', true))
    wrapper = mount(SecurityView)
    await flushPromises()
    await vi.advanceTimersByTimeAsync(60000)
    await flushPromises()
    expect(wrapper.text()).toContain('尚未确认访问规则的应用结果')
    expect(api).toHaveBeenCalledTimes(21)
    await vi.advanceTimersByTimeAsync(30000)
    expect(api).toHaveBeenCalledTimes(21)
  })

  it('离开页面停止轮询并取消正在等待的请求', async () => {
    vi.useFakeTimers()
    vi.mocked(api).mockResolvedValueOnce(security('public', true))
    wrapper = mount(SecurityView)
    await flushPromises()
    const signal = vi.mocked(api).mock.calls[0]![1]!.signal!
    wrapper.unmount()
    wrapper = undefined
    expect(signal.aborted).toBe(true)
    await vi.advanceTimersByTimeAsync(9000)
    expect(api).toHaveBeenCalledOnce()
  })
})
