import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../src/App.vue'
import { api, onAuthFailure, setCsrf } from '../src/lib/api'
import type { Session } from '../src/types'

let wrapper: VueWrapper | undefined
let current: Session, reads: number, writes: RequestInit[], calls: string[]
let readSession: () => Promise<Response>, writePassword: (options: RequestInit) => Promise<Response>
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
const unavailable = () => Promise.reject(new TypeError('fixture connection lost'))
function rotate() { current = { ...current, csrf_token: 'rotated-token', must_change_password: false } }
function button(label: string) { return wrapper!.findAll('button').find((item) => item.text() === label)! }
async function fillAndSubmit() {
  await wrapper!.get('input[name="current_password"]').setValue('old-valid-password')
  await wrapper!.get('input[name="new_password"]').setValue('new-valid-password')
  await wrapper!.get('input[name="confirm_password"]').setValue('new-valid-password')
  await wrapper!.get('form').trigger('submit')
}
async function open() { wrapper = mount(App); await flushPromises() }

beforeEach(() => {
  current = { username: 'admin', csrf_token: 'original-token', must_change_password: true, email_verification_enabled: true }
  reads = 0; writes = []; calls = []
  readSession = async () => json(current)
  writePassword = async () => { rotate(); return new Response('truncated body', { status: 200 }) }
  history.replaceState(null, '', '#account')
  vi.stubGlobal('fetch', vi.fn(async (path: string, options: RequestInit) => {
    calls.push(path)
    if (path === '/api/session') { reads++; return readSession() }
    if (path === '/api/password') { writes.push(options); return writePassword(options) }
    if (path === '/api/logout') return json({ ok: true })
    if (path === '/api/actions/check') return json({ accepted: true })
    throw new Error('Unexpected fixture request: ' + path)
  }))
})
afterEach(() => {
  wrapper?.unmount(); wrapper = undefined
  vi.useRealTimers(); vi.unstubAllGlobals()
  setCsrf(''); onAuthFailure(undefined)
  history.replaceState(null, '', '/')
})

describe('改密结果未知后的会话恢复（真实 App 与请求封装）', () => {
  it.each(['invalid_json', 'network', 'server_error'])('服务端已改密但%s时恢复新会话，不重放改密请求', async (failure) => {
    writePassword = async () => {
      rotate()
      if (failure === 'network') return unavailable()
      return failure === 'server_error'
        ? json({ error: { code: 'unavailable', message: '服务暂不可用' } }, 503)
        : new Response('truncated body', { status: 200 })
    }
    await open(); await fillAndSubmit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('登录状态已恢复，可以继续操作'))
    expect(wrapper!.text()).not.toContain('首次登录需要更换初始密码')
    expect(wrapper!.get('button[type="submit"]').attributes('disabled')).toBeUndefined()
    expect(wrapper!.findAll('input[type="password"]').every((item) => !(item.element as HTMLInputElement).value)).toBe(true)
    expect(writes).toHaveLength(1)
    expect(reads).toBe(2)
    await api('/api/actions/check', { method: 'POST' })
    const request = vi.mocked(fetch).mock.calls.find(([path]) => path === '/api/actions/check')!
    expect((request[1]!.headers as Record<string, string>)['X-CSRF-Token']).toBe('rotated-token')
  })

  it('恢复失败保留手动入口、禁用重复改密和离开；显式重试后解锁', async () => {
    await open()
    readSession = unavailable
    await fillAndSubmit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('暂时无法确认登录状态'))
    expect(button('重新确认登录状态').attributes('disabled')).toBeUndefined()
    expect(wrapper!.findAll('input[type="password"]').every((item) => item.attributes('disabled') !== undefined)).toBe(true)
    await wrapper!.get('form').trigger('submit')
    await wrapper!.findAll('[role="menuitem"]').find((item) => item.text() === '账户设置')!.trigger('click')
    expect(writes).toHaveLength(1)
    let complete!: (response: Response) => void
    readSession = () => new Promise((resolve) => { complete = resolve })
    await button('重新确认登录状态').trigger('click')
    await flushPromises()
    expect(button('正在确认登录状态…').attributes('disabled')).toBeDefined()
    complete(json(current))
    await vi.waitFor(() => expect(wrapper!.text()).toContain('登录状态已恢复，可以继续操作'))
    expect(reads).toBe(3)
    expect(writes).toHaveLength(1)
    expect(wrapper!.get('button[type="submit"]').attributes('disabled')).toBeUndefined()
  })

  it('恢复等待期间阻止导航丢失待确认状态', async () => {
    current.must_change_password = false
    await open()
    let complete!: (response: Response) => void
    readSession = () => new Promise((resolve) => { complete = resolve })
    await fillAndSubmit()
    await vi.waitFor(() => expect(reads).toBe(2))
    await wrapper!.findAll('[role="menuitem"]').find((item) => item.text() === '证书管理')!.trigger('click')
    expect(wrapper!.text()).toContain('当前操作尚未完成，请先确认操作结果')
    expect(location.hash).toBe('#account')
    expect(calls).not.toContain('/api/settings')
    complete(json(current))
    await vi.waitFor(() => expect(wrapper!.text()).toContain('登录状态已恢复，可以继续操作'))
  })

  it('会话仍为原状态时保持锁定，不误报成功，并允许退出后重新登录', async () => {
    writePassword = unavailable
    await open(); await fillAndSubmit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('密码更新仍未确认，请继续确认，或退出后重新登录'))
    expect(wrapper!.text()).not.toContain('密码已更新')
    expect(wrapper!.text()).toContain('首次登录需要更换初始密码')
    expect(wrapper!.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    await button('退出并重新登录').trigger('click')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('登录证书管家'))
    expect(writes).toHaveLength(1)
    expect(calls.filter((path) => path === '/api/logout')).toHaveLength(1)
  })

  it('旧会话先返回、后台改密稍后完成时继续等待，确认新会话后才解锁', async () => {
    writePassword = unavailable
    await open(); await fillAndSubmit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('密码更新仍未确认'))
    await wrapper!.get('form').trigger('submit')
    expect(writes).toHaveLength(1)
    rotate()
    await button('重新确认登录状态').trigger('click')
    await vi.waitFor(() => expect(wrapper!.text()).toContain('登录状态已恢复，可以继续操作'))
    expect(wrapper!.get('button[type="submit"]').attributes('disabled')).toBeUndefined()
    expect(writes).toHaveLength(1)
    expect(reads).toBe(3)
  })

  it('恢复返回401时回登录页并提示可能需要使用新密码', async () => {
    await open()
    readSession = async () => json({ error: { code: 'unauthorized', message: '请登录' } }, 401)
    await fillAndSubmit()
    await vi.waitFor(() => expect(wrapper!.text()).toContain('登录证书管家'))
    expect(wrapper!.text()).toContain('若密码已更新，请使用新密码')
    expect(wrapper!.find('input[name="current_password"]').exists()).toBe(false)
    expect(writes).toHaveLength(1)
    expect(calls).not.toContain('/api/login')
  })

  it('改密请求超时也先恢复会话，不再次发送密码', async () => {
    await open()
    vi.useFakeTimers()
    writePassword = (options) => {
      rotate()
      return new Promise((_resolve, reject) => options.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true }))
    }
    await fillAndSubmit()
    await vi.waitFor(() => expect(writes).toHaveLength(1))
    await vi.advanceTimersByTimeAsync(65000)
    await flushPromises()
    expect(wrapper!.text()).toContain('登录状态已恢复，可以继续操作')
    expect(reads).toBe(2)
    expect(writes).toHaveLength(1)
  })

  it('改密处理中卸载页面后取消请求，晚到响应不发起会话恢复', async () => {
    let complete!: (response: Response) => void
    writePassword = () => new Promise((resolve) => { complete = resolve })
    await open(); await fillAndSubmit()
    await vi.waitFor(() => expect(writes).toHaveLength(1))
    wrapper!.unmount(); wrapper = undefined
    expect(writes[0]!.signal!.aborted).toBe(true)
    complete(new Response('truncated body', { status: 200 }))
    await flushPromises()
    expect(reads).toBe(1)
  })

  it('会话恢复期间卸载后，晚到响应不覆盖新页面的CSRF', async () => {
    await open()
    let complete!: (response: Response) => void
    readSession = () => new Promise((resolve) => { complete = resolve })
    await fillAndSubmit()
    await vi.waitFor(() => expect(reads).toBe(2))
    wrapper!.unmount(); wrapper = undefined
    setCsrf('replacement-page-token')
    complete(json(current))
    await flushPromises()
    await api('/api/actions/check', { method: 'POST' })
    const request = vi.mocked(fetch).mock.calls.find(([path]) => path === '/api/actions/check')!
    expect((request[1]!.headers as Record<string, string>)['X-CSRF-Token']).toBe('replacement-page-token')
  })
})
