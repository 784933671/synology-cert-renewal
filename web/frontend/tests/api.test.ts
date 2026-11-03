import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, onAuthFailure, setCsrf } from '../src/lib/api'
afterEach(() => {
  setCsrf('')
  onAuthFailure(undefined)
  vi.unstubAllGlobals()
})
describe('同源会话请求', () => {
  it('写操作携带 CSRF 和 cookie，密钥只在请求正文', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ ok: true }), { status: 200 }),
      )
    vi.stubGlobal('fetch', fetcher)
    setCsrf('memory-only-token')
    await api('/api/settings', {
      method: 'PUT',
      body: { secret_key: 'fixture-key' },
    })
    expect(fetcher).toHaveBeenCalledOnce()
    const [url, options] = fetcher.mock.calls[0]
    expect(url).toBe('/api/settings')
    expect(options.credentials).toBe('same-origin')
    expect(options.headers['X-CSRF-Token']).toBe('memory-only-token')
    expect(options.body).toBe('{"secret_key":"fixture-key"}')
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })
  it('401 撤销本机会话；初始会话检查401不误报过期', async () => {
    const notify = vi.fn()
    onAuthFailure(notify)
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockImplementation(() =>
          Promise.resolve(
            new Response(
              '{"error":{"code":"unauthorized","message":"请登录"}}',
              { status: 401 },
            ),
          ),
        ),
    )
    await expect(api('/api/session')).rejects.toBeInstanceOf(ApiError)
    expect(notify).not.toHaveBeenCalled()
    await expect(api('/api/settings')).rejects.toBeInstanceOf(ApiError)
    expect(notify).toHaveBeenCalledWith('expired')
  })
  it('预登录验证端点401不触发退出且不携带旧CSRF', async () => {
    const notify = vi.fn()
    onAuthFailure(notify)
    setCsrf('previous-session-token')
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(new Response('{"error":{"code":"invalid_code","message":"验证码不正确"}}', { status: 401 })))
    vi.stubGlobal('fetch', fetcher)
    for (const path of ['/api/login', '/api/login/challenge', '/api/login/verify', '/api/login/resend', '/api/login/cancel']) {
      await expect(api(path, { method: 'POST' })).rejects.toBeInstanceOf(ApiError)
    }
    expect(notify).not.toHaveBeenCalled()
    expect(fetcher.mock.calls.every(([, options]) => !options.headers['X-CSRF-Token'])).toBe(true)
  })
  it('网络中断不自动重放写操作，不显示原始异常', async () => {
    const fetcher = vi
      .fn()
      .mockRejectedValue(new Error('raw credentials must never appear'))
    vi.stubGlobal('fetch', fetcher)
    await expect(
      api('/api/settings', { method: 'PUT', body: {} }),
    ).rejects.toMatchObject({ message: '无法连接管理服务，请检查网络后重试。' })
    expect(fetcher).toHaveBeenCalledOnce()
  })
  it('HTTP成功但JSON损坏标记为结果未知，不重放验证请求', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('broken response', { status: 200 }))
    vi.stubGlobal('fetch', fetcher)
    await expect(api('/api/login/verify', { method: 'POST', body: { code: '123456' } }))
      .rejects.toMatchObject({ status: 200, code: 'invalid_response' })
    expect(fetcher).toHaveBeenCalledOnce()
  })
  it('冲突状态保留为可识别的409', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response('{"error":{"code":"conflict","message":"配置已更新"}}', {
            status: 409,
          }),
        ),
    )
    await expect(api('/api/settings', { method: 'PUT' })).rejects.toMatchObject(
      { status: 409, code: 'conflict' },
    )
  })
})
