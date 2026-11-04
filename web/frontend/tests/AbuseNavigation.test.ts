import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api } from '../src/lib/api'
import { useSession } from '../src/composables/useSession'
import App from '../src/App.vue'
vi.mock('../src/lib/api', async original => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
vi.mock('../src/composables/useSession', async () => {
  const { shallowRef } = await import('vue')
  const state = {
    session: shallowRef({ username: 'fixture', csrf_token: 'first-session-fixture', must_change_password: false }),
    challenge: shallowRef(null), recoveryRequired: shallowRef(false), expiresIn: shallowRef(0), resendAfter: shallowRef(0),
    ready: shallowRef(true), busy: shallowRef(false), error: shallowRef(''),
    accept: vi.fn(), login: vi.fn(), verify: vi.fn(), resend: vi.fn(), cancel: vi.fn(), logout: vi.fn(), restore: vi.fn(),
  }
  return { useSession: () => state }
})
let wrapper: VueWrapper | undefined
const policy = { revision: 'a'.repeat(32), limits: { ip_requests_per_minute: 600, session_requests_per_minute: 180, block_after_violations: 20, block_seconds: 300 } }
function menu(label: string) { return wrapper!.findAll('nav[aria-label="管理导航"] [role="menuitem"]').find(node => node.text() === label)! }
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); vi.unstubAllGlobals(); history.replaceState(null, '', '/'); document.body.innerHTML = ''; useSession().session.value = { username: 'fixture', csrf_token: 'first-session-fixture', must_change_password: false } })
describe('接口防护导航与会话隔离', () => {
  it('hash直达、未保存和保存中保护导航，完成后可离开', async () => {
    history.replaceState(null, '', '#abuse')
    let finish!: (value: unknown) => void
    vi.mocked(api).mockImplementation(async (path, options) => path === '/api/abuse' ? options?.method === 'PUT' ? new Promise(resolve => { finish = resolve }) : policy : { items: [] })
    const confirm = vi.fn().mockReturnValue(false); vi.stubGlobal('confirm', confirm)
    wrapper = mount(App); await flushPromises()
    expect(wrapper.get('h1').text()).toBe('接口防护')
    expect(document.title).toBe('接口防护 · 证书管家')
    await wrapper.get('#abuse-block_seconds').setValue(600)
    await menu('操作审计').trigger('click'); await flushPromises()
    expect(confirm).toHaveBeenCalledOnce()
    expect(wrapper.get('h1').text()).toBe('接口防护')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    await vi.waitFor(() => expect(finish).toBeTypeOf('function'))
    await menu('操作审计').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('当前操作尚未完成')
    finish({ ...policy, limits: { ...policy.limits, block_seconds: 600 } }); await flushPromises()
    await menu('操作审计').trigger('click'); await flushPromises()
    expect(wrapper.get('h1').text()).toBe('操作审计')
    expect(location.hash).toBe('#audit')
  })
  it('会话轮换销毁旧请求和草稿，再次读取服务器状态，旧响应不回填', async () => {
    history.replaceState(null, '', '#abuse')
    let finish!: (value: unknown) => void
    vi.mocked(api).mockImplementation(async (path, options) => path === '/api/abuse' ? options?.method === 'PUT' ? new Promise(resolve => { finish = resolve }) : policy : { items: [] })
    wrapper = mount(App); await flushPromises()
    await wrapper.get('#abuse-block_seconds').setValue(600)
    await wrapper.get('form').trigger('submit'); await flushPromises()
    await vi.waitFor(() => expect(finish).toBeTypeOf('function'))
    const oldSignal = vi.mocked(api).mock.calls.find(([, options]) => options?.method === 'PUT')![1]!.signal!
    useSession().session.value = { username: 'fixture', csrf_token: 'rotated-session-fixture', must_change_password: false }
    await flushPromises()
    expect(oldSignal.aborted).toBe(true)
    expect(wrapper.get<HTMLInputElement>('#abuse-block_seconds').element.value).toBe('300')
    finish({ ...policy, limits: { ...policy.limits, block_seconds: 600 } }); await flushPromises()
    expect(wrapper.get<HTMLInputElement>('#abuse-block_seconds').element.value).toBe('300')
    expect(wrapper.text()).not.toContain('接口防护设置已保存')
    expect(vi.mocked(api).mock.calls.filter(([path, options]) => path === '/api/abuse' && options?.method !== 'PUT')).toHaveLength(2)
    expect(wrapper.html()).not.toContain('rotated-session-fixture')
  })
})
