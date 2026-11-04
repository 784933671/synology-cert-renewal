import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, onAuthFailure, onStepUpRequired, setCsrf } from '../src/lib/api'
let unregister: (() => void) | undefined
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const required = () => response({ error: { code: 'stepup_required', message: '需要验证' } }, 428)
afterEach(() => { unregister?.(); onAuthFailure(undefined); setCsrf(''); vi.unstubAllGlobals(); vi.useRealTimers() })
describe('敏感请求只执行一次', () => {
  it('只在明确428后验证，并使用不变正文和单次授权发送一次', async () => {
    const source = { secret_key: 'fixture-key', nested: { enabled: true } }
    const handler = vi.fn(async (request) => {
      source.secret_key = 'changed'
      source.nested.enabled = false
      expect(request.body).toEqual({ secret_key: 'fixture-key', nested: { enabled: true } })
      return 'one-operation-grant'
    })
    unregister = onStepUpRequired(handler)
    setCsrf('session-a')
    const fetcher = vi.fn().mockResolvedValueOnce(required()).mockResolvedValueOnce(response({ ok: true }))
    vi.stubGlobal('fetch', fetcher)
    await expect(api('/api/settings', { method: 'PUT', body: source })).resolves.toEqual({ ok: true })
    expect(handler).toHaveBeenCalledOnce()
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(fetcher.mock.calls[1][1].body).toBe(fetcher.mock.calls[0][1].body)
    expect(fetcher.mock.calls[1][1].headers['X-Step-Up-Token']).toBe('one-operation-grant')
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it.each(['network', '428'])('授权后的%s错误不会再次验证或重放', async (failure) => {
    const handler = vi.fn().mockResolvedValue('grant')
    unregister = onStepUpRequired(handler)
    const fetcher = vi.fn().mockResolvedValueOnce(required())
    if (failure === 'network') fetcher.mockRejectedValueOnce(new Error('lost'))
    else fetcher.mockResolvedValueOnce(required())
    vi.stubGlobal('fetch', fetcher)
    await expect(api('/api/actions/renew', { method: 'POST' })).rejects.toBeInstanceOf(Error)
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(handler).toHaveBeenCalledOnce()
  })
  it('等待邮箱验证码不占用单次HTTP超时', async () => {
    vi.useFakeTimers()
    let grant!: (value: string) => void
    unregister = onStepUpRequired(() => new Promise((resolve) => { grant = resolve }))
    const fetcher = vi.fn().mockResolvedValueOnce(required()).mockResolvedValueOnce(response({ ok: true }))
    vi.stubGlobal('fetch', fetcher)
    const pending = api('/api/actions/renew', { method: 'POST' })
    await vi.advanceTimersByTimeAsync(90000)
    expect(fetcher.mock.calls[0][1].signal.aborted).toBe(false)
    grant('grant')
    await expect(pending).resolves.toEqual({ ok: true })
  })
  it.each(['session', 'abort'])('等待期间%s变化阻止旧授权执行', async (change) => {
    setCsrf('session-a')
    let grant!: (value: string) => void
    unregister = onStepUpRequired(() => new Promise((resolve) => { grant = resolve }))
    const controller = new AbortController(), fetcher = vi.fn().mockResolvedValueOnce(required())
    vi.stubGlobal('fetch', fetcher)
    const pending = api('/api/settings', { method: 'PUT', signal: controller.signal })
    const assertion = expect(pending).rejects.toMatchObject(change === 'session' ? { code: 'stepup_cancelled' } : { name: 'AbortError' })
    await vi.waitFor(() => expect(grant).toBeTypeOf('function'))
    if (change === 'session') setCsrf('session-b')
    else controller.abort()
    grant('stale-grant')
    await assertion
    expect(fetcher).toHaveBeenCalledOnce()
  })
  it('登录端点和最初网络失败不触发二次验证', async () => {
    const handler = vi.fn(), fetcher = vi.fn().mockResolvedValueOnce(required()).mockRejectedValueOnce(new Error('network'))
    unregister = onStepUpRequired(handler)
    vi.stubGlobal('fetch', fetcher)
    await expect(api('/api/login/verify', { method: 'POST' })).rejects.toMatchObject({ status: 428 })
    await expect(api('/api/actions/renew', { method: 'POST' })).rejects.toBeInstanceOf(Error)
    expect(handler).not.toHaveBeenCalled()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })
  it('旧会话迟到401不退出新会话', async () => {
    setCsrf('old')
    let finish!: (value: Response) => void
    const notify = vi.fn()
    onAuthFailure(notify)
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => { finish = resolve })))
    const pending = api('/api/settings')
    const assertion = expect(pending).rejects.toMatchObject({ status: 401 })
    setCsrf('new')
    finish(response({ error: { code: 'unauthorized' } }, 401))
    await assertion
    expect(notify).not.toHaveBeenCalled()
  })
})
