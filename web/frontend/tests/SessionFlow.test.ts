import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import App from '../src/App.vue'
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
const session = {
  username: 'manager',
  csrf_token: 'memory-token',
  must_change_password: true,
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
    await flushPromises()
    expect(wrapper.text()).toContain('账号或密码不正确')
    expect(
      (wrapper.get('input[name="password"]').element as HTMLInputElement).value,
    ).toBe('')
  })
  it('首次改密之前不读取业务API，菜单禁止进入业务页面', async () => {
    vi.mocked(api).mockResolvedValueOnce(session)
    history.replaceState(null, '', '#certificate')
    wrapper = mount(App)
    await flushPromises()
    expect(wrapper.text()).toContain('设置专用登录密码')
    expect(
      wrapper
        .findAll('nav button')
        .every((button) => button.attributes('disabled') !== undefined),
    ).toBe(true)
    expect(api).toHaveBeenCalledOnce()
    expect(api).toHaveBeenCalledWith('/api/session')
  })
  it('改密失败立即清空输入，成功后使用服务器返回的新会话', async () => {
    vi.mocked(api)
      .mockRejectedValueOnce(new ApiError('当前密码不正确', 400))
      .mockResolvedValueOnce({
        ...session,
        csrf_token: 'rotated',
        must_change_password: false,
      })
    wrapper = mount(AccountView, { props: { session } })
    const fill = async () => {
      const fields = wrapper!.findAll('input[type="password"]')
      await fields[0].setValue('old-password')
      await fields[1].setValue('different-long-password')
      await fields[2].setValue('different-long-password')
    }
    await fill()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('当前密码不正确')
    expect(
      wrapper
        .findAll('input[type="password"]')
        .every((node) => (node.element as HTMLInputElement).value === ''),
    ).toBe(true)
    await fill()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.emitted('changed')?.[0]).toEqual([
      { ...session, csrf_token: 'rotated', must_change_password: false },
    ])
  })
})
