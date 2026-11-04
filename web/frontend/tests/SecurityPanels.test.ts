import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import SessionsPanel from '../src/components/SessionsPanel.vue'
import SecurityAlertsPanel from '../src/components/SecurityAlertsPanel.vue'
import AccountView from '../src/views/AccountView.vue'
vi.mock('../src/lib/api', async (original) => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
const items = [
  { id: 'current-id', ip: '10.10.10.2', device: 'desktop', created_at: '2026-11-04T01:00:00Z', last_seen: '2026-11-04T02:00:00Z', current: true },
  { id: 'other-id', ip: '10.10.10.3', device: 'mobile', created_at: '2026-11-04T00:00:00Z', last_seen: '2026-11-04T01:00:00Z', current: false },
]
const button = (label: string) => wrapper!.findAll('button').find(node => node.text() === label)!
afterEach(() => { wrapper?.unmount(); vi.mocked(api).mockReset(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
async function sessions() {
  vi.mocked(api).mockResolvedValueOnce({ items })
  vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
  wrapper = mount(SessionsPanel)
  await flushPromises()
}
describe('账户安全面板', () => {
  it('会话来源、设备和当前标识可见，退出其他会话只提交一次并刷新', async () => {
    await sessions()
    expect(wrapper!.text()).toContain('当前会话')
    expect(wrapper!.text()).toContain('10.10.10.3')
    expect(wrapper!.text()).toContain('手机')
    let finish!: (value: unknown) => void
    vi.mocked(api).mockImplementationOnce(() => new Promise(resolve => { finish = resolve })).mockResolvedValueOnce({ items: [items[0]] })
    await button('退出其他会话').trigger('click')
    await button('退出其他会话').trigger('click')
    expect(vi.mocked(api).mock.calls.filter(([path]) => path === '/api/sessions/revoke-others')).toHaveLength(1)
    finish({ current_revoked: false })
    await flushPromises()
    expect(wrapper!.text()).toContain('其他登录会话已退出')
    expect(wrapper!.text()).not.toContain('10.10.10.3')
    expect(wrapper!.emitted('busy')).toEqual([[true], [false]])
  })
  it('撤销当前会话交给父组件立即清理登录状态，不误调用退出接口', async () => {
    await sessions()
    vi.mocked(api).mockResolvedValueOnce({ current_revoked: true })
    await button('退出当前').trigger('click')
    await flushPromises()
    expect(api).toHaveBeenLastCalledWith('/api/sessions/revoke', expect.objectContaining({ body: { id: 'current-id' } }))
    expect(wrapper!.emitted('revoked')).toHaveLength(1)
    expect(vi.mocked(api).mock.calls.map(([path]) => path)).not.toContain('/api/logout')
  })
  it('用户取消确认不提交；取消二次验证不误判操作结果未知', async () => {
    await sessions()
    vi.mocked(window.confirm).mockReturnValueOnce(false)
    await button('撤销会话').trigger('click')
    expect(api).toHaveBeenCalledTimes(1)
    vi.mocked(api).mockRejectedValueOnce(new ApiError('已取消二次验证，本次操作未执行。', 400, 'stepup_cancelled'))
    await button('撤销会话').trigger('click')
    await flushPromises()
    expect(wrapper!.text()).toContain('本次操作未执行')
    expect(button('撤销会话').attributes('disabled')).toBeUndefined()
  })
  it('撤销结果未知阻止重复提交，只在显式刷新后解锁', async () => {
    await sessions()
    vi.mocked(api).mockRejectedValueOnce(new ApiError('网络中断'))
    await button('撤销会话').trigger('click')
    await flushPromises()
    expect(wrapper!.text()).toContain('会话撤销结果尚未确认')
    expect(button('撤销会话').attributes('disabled')).toBeDefined()
    expect(api).toHaveBeenCalledTimes(2)
    vi.mocked(api).mockResolvedValueOnce({ items })
    await button('刷新会话').trigger('click')
    await flushPromises()
    expect(button('撤销会话').attributes('disabled')).toBeUndefined()
    expect(vi.mocked(api).mock.calls.filter(([path]) => path === '/api/sessions/revoke')).toHaveLength(1)
  })
  it('读取失败显示重试，空会话列表关闭撤销按钮', async () => {
    vi.mocked(api).mockRejectedValueOnce(new ApiError('读取失败'))
    wrapper = mount(SessionsPanel)
    await flushPromises()
    expect(wrapper.text()).toContain('读取失败')
    vi.mocked(api).mockResolvedValueOnce({ items: [] })
    await button('刷新会话').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('暂无有效会话')
    expect(button('退出其他会话').attributes('disabled')).toBeDefined()
  })
  it('首次改密不读取会话和提醒，避免未完成账户初始化时请求受限API', async () => {
    wrapper = mount(AccountView, { props: {
      session: { username: 'admin', csrf_token: 'csrf', must_change_password: true }, restoreSession: vi.fn(),
    } })
    await flushPromises()
    expect(api).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('暂无有效会话')
  })
  it('会话因普通改密或恢复轮换时重新读取列表，不保留已被撤销的旧会话', async () => {
    vi.mocked(api).mockImplementation(async path => path === '/api/sessions' ? { items } : { items: [], pending_count: 0 })
    const session = { username: 'admin', csrf_token: 'old-csrf-token-fixture', must_change_password: false }
    wrapper = mount(AccountView, { props: { session, restoreSession: vi.fn() } })
    await flushPromises()
    expect(wrapper.text()).toContain('10.10.10.3')
    vi.mocked(api).mockImplementation(async path => path === '/api/sessions' ? { items: [{ ...items[0], id: 'new-session-id' }] } : { items: [], pending_count: 0 })
    await wrapper.setProps({ session: { ...session, csrf_token: 'new-csrf-token-fixture' } })
    await flushPromises()
    expect(wrapper.text()).not.toContain('10.10.10.3')
    expect(vi.mocked(api).mock.calls.filter(([path]) => path === '/api/sessions')).toHaveLength(2)
    expect(vi.mocked(api).mock.calls.filter(([path]) => path === '/api/security-alerts')).toHaveLength(2)
    expect(wrapper.html()).not.toContain('old-csrf-token-fixture')
    expect(wrapper.html()).not.toContain('new-csrf-token-fixture')
  })
  it('取消普通改密二次验证不进入旧的网络结果不明恢复流程', async () => {
    const restore = vi.fn()
    vi.mocked(api).mockImplementation(async path => {
      if (path === '/api/password') throw new ApiError('已取消二次验证，本次操作未执行。', 400, 'stepup_cancelled')
      return { items: [], pending_count: 0 }
    })
    wrapper = mount(AccountView, { props: {
      session: { username: 'admin', csrf_token: 'csrf', must_change_password: false }, restoreSession: restore,
    } })
    await flushPromises()
    await wrapper.get('input[name="current_password"]').setValue('old-fixture-password')
    await wrapper.get('input[name="new_password"]').setValue('new-fixture-password')
    await wrapper.get('input[name="confirm_password"]').setValue('new-fixture-password')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('已取消二次验证'))
    expect(restore).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('密码更新结果尚未确认')
    expect(button('更新密码').attributes('disabled')).toBeUndefined()
  })
  it('提醒使用固定登录邮箱，显示事件、发送失败和待重试，不提供保护关闭开关', async () => {
    vi.mocked(api).mockResolvedValueOnce({ items: [
      { id: 'alert-1', event_type: 'new_login', at: '2026-11-04T01:00:00Z', source_ip: '10.10.10.3', device: 'mobile', status: 'failed', attempts: 8 },
      { id: 'alert-2', event_type: 'login_failures', at: '2026-11-04T02:00:00Z', source_ip: '10.10.10.4', device: 'desktop', status: 'pending', attempts: 1 },
    ], pending_count: 1 })
    wrapper = mount(SecurityAlertsPanel, { props: { enabled: true, email: 'a***@example.com' } })
    await flushPromises()
    expect(wrapper.text()).toContain('a***@example.com')
    expect(wrapper.text()).toContain('安全邮件提醒已启用')
    expect(wrapper.text()).toContain('新来源登录')
    expect(wrapper.text()).toContain('连续登录失败')
    expect(wrapper.text()).toContain('发送失败')
    expect(wrapper.text()).toContain('等待发送或重试')
    expect(wrapper.find('input').exists()).toBe(false)
    expect(wrapper.find('[role="switch"]').exists()).toBe(false)
  })
  it('刷新安全提醒失败保留最近记录，空记录有清晰提示', async () => {
    vi.mocked(api).mockResolvedValueOnce({ items: [], pending_count: 0 })
    wrapper = mount(SecurityAlertsPanel, { props: { enabled: true } })
    await flushPromises()
    expect(wrapper.text()).toContain('暂无安全提醒记录')
    vi.mocked(api).mockRejectedValueOnce(new ApiError('网络中断'))
    await button('刷新提醒').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('下方保留上次读取的记录')
  })
})
