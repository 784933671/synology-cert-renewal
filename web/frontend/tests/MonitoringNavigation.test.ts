import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../src/App.vue'
import { api } from '../src/lib/api'
import { health, monitorSettings, runPage, deferred } from './monitoring-fixtures'
vi.mock('../src/lib/api', async (original) => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); vi.unstubAllGlobals(); history.replaceState(null, '', '/'); document.body.innerHTML = '' })
function menu(label: string) { return wrapper!.findAll('nav[aria-label="管理导航"] [role="menuitem"]').find((node) => node.text() === label)! }
describe('运行页面导航', () => {
  it('hash直达健康页，未保存配置保护导航，保存中阻止离开，成功后进入历史', async () => {
    history.replaceState(null, '', '#health')
    const pending = deferred<ReturnType<typeof monitorSettings>>()
    const confirm = vi.fn().mockReturnValue(false); vi.stubGlobal('confirm', confirm)
    vi.mocked(api).mockImplementation(async (path, options) => {
      if (path === '/api/session') return { username: 'fixture', csrf_token: 'fixture-token', must_change_password: false }
      if (path === '/api/health') return health()
      if (path === '/api/monitor') return options?.method === 'PUT' ? pending.promise : monitorSettings()
      return runPage()
    })
    wrapper = mount(App); await flushPromises()
    expect(wrapper.get('h1').text()).toBe('运行健康')
    await wrapper.get('#monitor-expiry-hours').setValue(12)
    await menu('执行记录').trigger('click'); await flushPromises()
    expect(confirm).toHaveBeenCalledOnce()
    expect(wrapper.get('h1').text()).toBe('运行健康')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    await menu('执行记录').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('当前操作尚未完成')
    expect(confirm).toHaveBeenCalledOnce()
    pending.resolve({ ...monitorSettings(), expiry_hours: 12 }); await flushPromises()
    await menu('执行记录').trigger('click'); await flushPromises()
    expect(wrapper.get('h1').text()).toBe('执行记录')
    expect(location.hash).toBe('#runs')
    expect(document.title).toBe('执行记录 · 证书管家')
    expect(api).toHaveBeenCalledWith('/api/runs?offset=0&limit=20', expect.objectContaining({ signal: expect.any(AbortSignal) }))
  })
})
