import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import type { Session } from '../src/types'
import App from '../src/App.vue'
import AppShell from '../src/components/AppShell.vue'
import LoginView from '../src/views/LoginView.vue'
import AccountView from '../src/views/AccountView.vue'
vi.mock('../src/lib/api', async (original) => ({
  ...(await original<typeof import('../src/lib/api')>()),
  api: vi.fn(),
}))
let wrapper: VueWrapper | undefined
afterEach(() => {
  wrapper?.unmount()
  vi.mocked(api).mockReset()
  history.replaceState(null, '', '/')
})
const session: Session = {
  username: 'manager',
  csrf_token: 'memory-token',
  must_change_password: true,
}
async function fillPasswords(current = 'old-password', next = 'different-long-password', confirm = next) {
  await wrapper!.get('input[name="current_password"]').setValue(current)
  await wrapper!.get('input[name="new_password"]').setValue(next)
  await wrapper!.get('input[name="confirm_password"]').setValue(confirm)
}
describe('管理员会话与密码', () => {
  it('初次401显示登录，不展示不存在的状态；失败后清空密码', async () => {
    vi.mocked(api)
      .mockRejectedValueOnce(new ApiError('请登录', 401))
      .mockRejectedValueOnce(new ApiError('账号或密码不正确', 401))
    wrapper = mount(App)
    await flushPromises()
    expect(wrapper.text()).toContain('登录证书管家')
    expect(wrapper.text()).not.toContain('证书剩余')
    await wrapper.get('input[name="username"]').setValue('manager')
    await wrapper.get('input[name="password"]').setValue('wrong-password')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('账号或密码不正确'))
    expect((wrapper.get('input[name="password"]').element as HTMLInputElement).value).toBe('')
  })
  it('登录表单使用关联标签并阻止空账号或空密码提交', async () => {
    wrapper = mount(LoginView, { props: { busy: false, error: '' } })
    expect(wrapper.get('label[for="login-username"]').text()).toContain('管理员账号')
    expect(wrapper.get('label[for="login-password"]').text()).toContain('登录密码')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('请输入管理员账号'))
    expect(wrapper.emitted('login')).toBeUndefined()
    await wrapper.get('input[name="username"]').setValue(' manager ')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('请输入登录密码'))
    expect(wrapper.emitted('login')).toBeUndefined()
    await wrapper.get('input[name="password"]').setValue('long-password')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.emitted('login')).toEqual([['manager', 'long-password']]))
  })
  it('首次改密之前不读取业务API，菜单禁止进入业务页面', async () => {
    vi.mocked(api).mockResolvedValueOnce(session)
    history.replaceState(null, '', '#certificate')
    wrapper = mount(App)
    await flushPromises()
    expect(wrapper.text()).toContain('设置专用登录密码')
    const menuItems = wrapper.findAll('nav[aria-label="管理导航"] [role="menuitem"]')
    expect(menuItems).toHaveLength(8)
    expect(menuItems.filter((item) => item.attributes('aria-disabled') === 'true')).toHaveLength(7)
    await menuItems.find((item) => item.text() === '证书管理')!.trigger('click')
    expect(wrapper.text()).toContain('设置专用登录密码')
    expect(api).toHaveBeenCalledOnce()
    expect(api).toHaveBeenCalledWith('/api/session')
  })
  it('Ant菜单保留导航事件，锁定时账户和退出仍可用', async () => {
    wrapper = mount(AppShell, { props: { page: 'overview', username: 'manager', locked: false, busy: false } })
    const certificate = wrapper.findAll('[role="menuitem"]').find((item) => item.text() === '证书管理')!
    await certificate.trigger('click')
    expect(wrapper.emitted('navigate')).toEqual([['certificate']])
    await wrapper.setProps({ locked: true, page: 'account' })
    await certificate.trigger('click')
    expect(wrapper.emitted('navigate')).toHaveLength(1)
    await wrapper.findAll('[role="menuitem"]').find((item) => item.text() === '账户设置')!.trigger('click')
    expect(wrapper.emitted('navigate')?.[1]).toEqual(['account'])
    await wrapper.get('button[aria-label="退出登录"]').trigger('click')
    expect(wrapper.emitted('logout')).toHaveLength(1)
  })
  it('改密失败立即清空输入，成功后使用服务器返回的新会话', async () => {
    vi.mocked(api)
      .mockRejectedValueOnce(new ApiError('当前密码不正确', 400))
      .mockResolvedValueOnce({ ...session, csrf_token: 'rotated', must_change_password: false })
    wrapper = mount(AccountView, { props: { session } })
    await fillPasswords()
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('当前密码不正确'))
    expect(wrapper.findAll('input[type="password"]').every((node) => (node.element as HTMLInputElement).value === '')).toBe(true)
    await fillPasswords()
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.emitted('changed')?.[0]).toEqual([
      { ...session, csrf_token: 'rotated', must_change_password: false },
    ]))
  })
  it('保留当前密码必填、新密码长度和一致性校验', async () => {
    wrapper = mount(AccountView, { props: { session } })
    await fillPasswords('', 'different-long-password')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('请输入当前密码'))
    expect(api).not.toHaveBeenCalled()
    await fillPasswords('old-password', 'short')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('新密码须为 12～128 个字符'))
    await fillPasswords('old-password', 'different-long-password', 'another-long-password')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('两次输入的新密码不一致'))
    await fillPasswords('same-long-password', 'same-long-password')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('新密码不能与当前密码相同'))
    expect(api).not.toHaveBeenCalled()
  })
  it('改密请求期间禁用输入与提交，阻止重复请求', async () => {
    let resolveRequest!: (session: Session) => void
    vi.mocked(api).mockImplementation(() => new Promise<Session>((resolve) => { resolveRequest = resolve }))
    wrapper = mount(AccountView, { props: { session } })
    await fillPasswords()
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(api).toHaveBeenCalledOnce())
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    expect(wrapper.findAll('input[type="password"]').every((node) => node.attributes('disabled') !== undefined)).toBe(true)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenCalledOnce()
    resolveRequest({ ...session, must_change_password: false })
    await vi.waitFor(() => expect(wrapper!.emitted('busy')).toEqual([[true], [false]]))
  })
})
