import { computed, onUnmounted, shallowRef } from 'vue'
import { api, ApiError, errorText, isAborted, onStepUpRequired, type StepUpRequest } from '../lib/api'
import type { StepUpChallenge } from '../types'

const operations: Record<string, string> = {
  '/api/settings': '保存证书、续期或通知配置', '/api/security': '修改访问安全设置',
  '/api/password': '修改管理员密码', '/api/monitor': '修改预警配置', '/api/actions/renew': '立即申请并替换证书',
  '/api/sessions/revoke': '撤销登录会话', '/api/sessions/revoke-others': '退出其他登录会话',
}
function unknownResult(cause: unknown) {
  return !(cause instanceof ApiError) || !cause.status || cause.status >= 500 || cause.code === 'invalid_response'
}
export function useStepUp() {
  const open = shallowRef(false), busy = shallowRef(false), error = shallowRef('')
  const challenge = shallowRef<StepUpChallenge | null>(null)
  const recoverSend = shallowRef(false), verifyUnknown = shallowRef(false)
  const operation = shallowRef('敏感操作'), now = shallowRef(0)
  const expiry = shallowRef(0), resendAt = shallowRef(0)
  let timer: ReturnType<typeof setInterval> | undefined
  let pending: { request: StepUpRequest; resolve: (token: string) => void; reject: (error: unknown) => void; abort: () => void } | undefined
  let active: AbortController | undefined, disposed = false
  const expiresIn = computed(() => Math.max(0, Math.ceil((expiry.value - now.value) / 1000)))
  const resendAfter = computed(() => Math.max(0, Math.ceil((resendAt.value - now.value) / 1000)))
  function setChallenge(value: StepUpChallenge) {
    if (!value || typeof value.challenge_id !== 'string' || !value.challenge_id
      || !Number.isFinite(value.expires_in) || !Number.isFinite(value.resend_after)) {
      throw new ApiError('无法确认验证状态，请重新确认。', 200, 'invalid_response')
    }
    challenge.value = value
    now.value = performance.now()
    expiry.value = now.value + Math.max(0, value.expires_in) * 1000
    resendAt.value = now.value + Math.max(0, value.resend_after) * 1000
  }
  function clear() {
    const previous = pending
    pending = undefined
    previous?.request.signal?.removeEventListener('abort', previous.abort)
    active?.abort()
    active = undefined
    if (timer) clearInterval(timer)
    timer = undefined
    open.value = busy.value = recoverSend.value = verifyUnknown.value = false
    error.value = ''
    challenge.value = null
    expiry.value = resendAt.value = 0
    return previous
  }
  function cancel(server = true) {
    const id = challenge.value?.challenge_id
    const previous = clear()
    previous?.reject(previous.request.signal?.aborted
      ? new DOMException('请求已取消', 'AbortError')
      : new ApiError('已取消二次验证，本次操作未执行。', 400, 'stepup_cancelled'))
    if (server && id) {
      // 本地立即取消业务请求；服务器挑战即使取消失败也会自动到期。
      void api('/api/stepup/cancel', { method: 'POST', body: { challenge_id: id } }).catch(() => {})
    }
  }
  const unregister = onStepUpRequired((request) => {
    if (disposed || request.signal?.aborted) return Promise.reject(new DOMException('请求已取消', 'AbortError'))
    if (pending) return Promise.reject(new ApiError('请先完成或取消当前二次验证。', 409, 'stepup_busy'))
    return new Promise<string>((resolve, reject) => {
      const abort = () => cancel()
      pending = { request, resolve, reject, abort }
      request.signal?.addEventListener('abort', abort, { once: true })
      operation.value = operations[request.path] || '敏感操作'
      open.value = true
      now.value = performance.now()
      timer = setInterval(() => { now.value = performance.now() }, 250)
    })
  })
  async function send(resend = false) {
    const current = pending
    if (!current || busy.value || verifyUnknown.value || disposed || (resend && resendAfter.value > 0)) return
    busy.value = true
    error.value = ''
    active = new AbortController()
    const path = resend && challenge.value ? '/api/stepup/resend' : '/api/stepup/start'
    const body = path.endsWith('/resend') ? { challenge_id: challenge.value!.challenge_id }
      : { method: current.request.method, path: current.request.path, body: current.request.body }
    try {
      const value = await api<StepUpChallenge>(path, { method: 'POST', body, signal: active.signal })
      if (pending !== current || disposed) return
      setChallenge(value)
      recoverSend.value = false
    } catch (cause) {
      if (pending !== current || disposed || isAborted(cause)) return
      error.value = errorText(cause)
      recoverSend.value = unknownResult(cause) || (cause instanceof ApiError && cause.status === 429)
      if (recoverSend.value) error.value += ' 请重新确认验证状态，业务操作尚未执行。'
      if (cause instanceof ApiError && cause.status === 410) { challenge.value = null; recoverSend.value = false }
    } finally { if (pending === current) busy.value = false }
  }
  async function verify(code: string) {
    const current = pending
    if (!current || !challenge.value || busy.value || verifyUnknown.value || recoverSend.value || expiresIn.value <= 0 || disposed) return
    error.value = ''
    if (!/^[0-9]{6}$/.test(code)) { error.value = '请输入 6 位数字验证码。'; return }
    busy.value = true
    active = new AbortController()
    const body = { challenge_id: challenge.value.challenge_id, code }
    try {
      const result = await api<{ token: string }>('/api/stepup/verify', { method: 'POST', body, signal: active.signal })
      if (pending !== current || disposed) return
      if (!result || typeof result.token !== 'string' || !result.token) throw new ApiError('无法确认验证结果。', 200, 'invalid_response')
      clear()?.resolve(result.token)
    } catch (cause) {
      if (pending !== current || disposed || isAborted(cause)) return
      verifyUnknown.value = unknownResult(cause)
      error.value = verifyUnknown.value
        ? '验证码验证结果尚未确认，本次业务操作未执行。请取消后重新发起操作，勿重复提交验证码。'
        : errorText(cause)
      if (cause instanceof ApiError && (cause.status === 410 || cause.code === 'code_expired')) expiry.value = now.value
    } finally {
      body.code = ''
      if (pending === current) busy.value = false
    }
  }
  onUnmounted(() => { disposed = true; cancel(); unregister() })
  return { open, busy, error, challenge, operation, expiresIn, resendAfter, recoverSend, verifyUnknown, send, verify, cancel }
}
