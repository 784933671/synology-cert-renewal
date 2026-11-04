export class ApiError extends Error {
  constructor(message: string, public status = 0, public code = '', public retryAfter = 0) {
    super(message)
    this.name = 'ApiError'
  }
}
export interface StepUpRequest {
  method: 'POST' | 'PUT'
  path: string
  body: unknown
  signal?: AbortSignal
}
type StepUpHandler = (request: StepUpRequest) => Promise<string>
let csrf = '', sessionVersion = 0
let authFailure: ((reason: 'expired' | 'password') => void) | undefined
let stepUpHandler: StepUpHandler | undefined
export function setCsrf(value: string) {
  if (csrf !== value) sessionVersion++
  csrf = value
}
export function onAuthFailure(callback: typeof authFailure) { authFailure = callback }
export function onStepUpRequired(callback: StepUpHandler) {
  stepUpHandler = callback
  return () => { if (stepUpHandler === callback) stepUpHandler = undefined }
}
export function errorText(error: unknown) {
  if (!(error instanceof ApiError)) return '操作未完成，请稍后重试。'
  return error.status === 429 && error.retryAfter > 0 ? `${error.message} 请在 ${error.retryAfter} 秒后重试。` : error.message
}
export function isUnknownResult(error: unknown) {
  return !(error instanceof ApiError) || !error.status || error.status >= 500 || error.code === 'invalid_response'
}
export function isAborted(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}
export async function api<T>(path: string, options: {
  method?: 'GET' | 'POST' | 'PUT'; body?: unknown; signal?: AbortSignal
} = {}): Promise<T> {
  const method = options.method || 'GET'
  const preLogin = path === '/api/login' || path.startsWith('/api/login/')
  const serialized = method === 'GET' ? undefined : JSON.stringify(options.body ?? {})
  const originalCsrf = csrf, originalVersion = sessionVersion
  async function attempt(token?: string): Promise<T> {
    const controller = new AbortController()
    const abort = () => controller.abort()
    options.signal?.addEventListener('abort', abort, { once: true })
    if (options.signal?.aborted) controller.abort()
    const timeout = setTimeout(abort, 65000)
    try {
      if (controller.signal.aborted) throw new DOMException('请求已取消', 'AbortError')
      const response = await fetch(path, {
        method, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: {
          Accept: 'application/json',
          ...(method !== 'GET' ? {
            'Content-Type': 'application/json',
            ...(originalCsrf && !preLogin ? { 'X-CSRF-Token': originalCsrf } : {}),
            ...(token ? { 'X-Step-Up-Token': token } : {}),
          } : {}),
        },
        ...(serialized !== undefined ? { body: serialized } : {}),
      })
      let data: any
      try { data = await response.json() }
      catch { throw new ApiError('服务器返回了无法识别的结果，请稍后重试。', response.status, 'invalid_response') }
      if (controller.signal.aborted) throw new DOMException('请求已取消', 'AbortError')
      if (!response.ok) {
        if (originalVersion === sessionVersion) {
          if (response.status === 401 && !preLogin && path !== '/api/session') authFailure?.('expired')
          if (data?.error?.code === 'password_change_required') authFailure?.('password')
        }
        const retryAfter = Number(data?.error?.retry_after ?? response.headers.get('Retry-After'))
        throw new ApiError(typeof data?.error?.message === 'string' ? data.error.message : '请求未完成，请稍后重试。', response.status, data?.error?.code || '', Number.isFinite(retryAfter) ? Math.max(0, Math.ceil(retryAfter)) : 0)
      }
      return data as T
    } catch (error) {
      if (options.signal?.aborted) throw new DOMException('请求已取消', 'AbortError')
      if (error instanceof ApiError) throw error
      throw new ApiError(controller.signal.aborted
        ? '请求超时，请刷新确认操作结果后再重试。'
        : '无法连接管理服务，请检查网络后重试。')
    } finally {
      clearTimeout(timeout)
      options.signal?.removeEventListener('abort', abort)
    }
  }
  try { return await attempt() }
  catch (cause) {
    // 只有服务器确认尚未执行的 428 才进入验证；网络异常绝不重放业务操作。
    if (!(cause instanceof ApiError) || cause.status !== 428 || cause.code !== 'stepup_required'
      || method === 'GET' || preLogin || path.startsWith('/api/stepup/') || !stepUpHandler) throw cause
    if (originalVersion !== sessionVersion) throw new ApiError('登录状态已变化，请重新发起操作。', 400, 'stepup_cancelled')
    const token = await stepUpHandler({ method, path, body: JSON.parse(serialized!), signal: options.signal })
    if (options.signal?.aborted) throw new DOMException('请求已取消', 'AbortError')
    if (originalVersion !== sessionVersion || !token) throw new ApiError('登录状态已变化，请重新发起操作。', 400, 'stepup_cancelled')
    return attempt(token)
  }
}
