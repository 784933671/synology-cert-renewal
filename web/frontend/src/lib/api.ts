export class ApiError extends Error {
  constructor(
    message: string,
    public status = 0,
    public code = '',
  ) {
    super(message)
    this.name = 'ApiError'
  }
}
let csrf = ''
let authFailure: ((reason: 'expired' | 'password') => void) | undefined
export function setCsrf(value: string) {
  csrf = value
}
export function onAuthFailure(callback: typeof authFailure) {
  authFailure = callback
}
export function errorText(error: unknown) {
  return error instanceof ApiError ? error.message : '操作未完成，请稍后重试。'
}
export function isAborted(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}
export async function api<T>(
  path: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT'
    body?: unknown
    signal?: AbortSignal
  } = {},
): Promise<T> {
  const controller = new AbortController()
  const abort = () => controller.abort()
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted) controller.abort()
  const timeout = setTimeout(abort, 65000)
  const method = options.method || 'GET'
  const preLogin = path === '/api/login' || path.startsWith('/api/login/')
  try {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(method !== 'GET'
          ? {
              'Content-Type': 'application/json',
              ...(csrf && !preLogin ? { 'X-CSRF-Token': csrf } : {}),
            }
          : {}),
      },
      ...(method !== 'GET' ? { body: JSON.stringify(options.body ?? {}) } : {}),
    })
    let data: any
    try {
      data = await response.json()
    } catch {
      throw new ApiError(
        '服务器返回了无法识别的结果，请稍后重试。',
        response.status,
        'invalid_response',
      )
    }
    if (controller.signal.aborted) throw new DOMException('请求已取消', 'AbortError')
    if (!response.ok) {
      if (
        response.status === 401 &&
        !preLogin && path !== '/api/session'
      )
        authFailure?.('expired')
      if (data?.error?.code === 'password_change_required')
        authFailure?.('password')
      throw new ApiError(
        typeof data?.error?.message === 'string'
          ? data.error.message
          : '请求未完成，请稍后重试。',
        response.status,
        data?.error?.code || '',
      )
    }
    return data as T
  } catch (error) {
    if (options.signal?.aborted)
      throw new DOMException('请求已取消', 'AbortError')
    if (error instanceof ApiError) throw error
    throw new ApiError(
      controller.signal.aborted
        ? '请求超时，请刷新确认操作结果后再重试。'
        : '无法连接管理服务，请检查网络后重试。',
    )
  } finally {
    clearTimeout(timeout)
    options.signal?.removeEventListener('abort', abort)
  }
}
