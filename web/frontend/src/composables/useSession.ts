import { computed, onMounted, onUnmounted, shallowRef } from 'vue'
import { api, ApiError, errorText, onAuthFailure, setCsrf } from '../lib/api'
import type { LoginChallenge, Session } from '../types'

type ChallengeResponse = LoginChallenge | { verification_required: false }
export function useSession() {
  const session = shallowRef<Session | null>(null),
    challenge = shallowRef<LoginChallenge | null>(null),
    recoveryRequired = shallowRef(false),
    ready = shallowRef(false),
    busy = shallowRef(false),
    error = shallowRef(''),
    now = shallowRef(Date.now()),
    expiresAt = shallowRef(0),
    resendAt = shallowRef(0)
  let timer: ReturnType<typeof setInterval> | undefined
  const expiresIn = computed(() => Math.max(0, Math.ceil((expiresAt.value - now.value) / 1000)))
  const resendAfter = computed(() => Math.max(0, Math.ceil((resendAt.value - now.value) / 1000)))
  function accept(value: Session | null) {
    session.value = value
    setCsrf(value?.csrf_token || '')
    if (value) {
      challenge.value = null
      recoveryRequired.value = false
    }
  }
  function setChallenge(value: ChallengeResponse) {
    accept(null)
    now.value = Date.now()
    challenge.value = value.verification_required ? value : null
    expiresAt.value = now.value + (value.verification_required ? value.expires_in : 0) * 1000
    resendAt.value = now.value + (value.verification_required ? value.resend_after : 0) * 1000
    recoveryRequired.value = false
  }
  async function recoverChallenge() {
    try {
      setChallenge(await api<ChallengeResponse>('/api/login/challenge'))
    } catch (cause) {
      recoveryRequired.value = true
      error.value = `${errorText(cause)} 请重新确认登录状态。`
    }
  }
  onAuthFailure((reason) => {
    if (reason === 'password' && session.value)
      accept({ ...session.value, must_change_password: true })
    else {
      accept(null)
      challenge.value = null
      recoveryRequired.value = false
      error.value = '登录已失效，请重新登录。'
    }
  })
  async function restore() {
    if (busy.value) return
    busy.value = true
    error.value = ''
    try {
      accept(await api<Session>('/api/session'))
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) await recoverChallenge()
      else {
        recoveryRequired.value = true
        error.value = errorText(cause)
      }
    } finally {
      ready.value = true
      busy.value = false
    }
  }
  async function handleChallengeFailure(cause: unknown, recover = false) {
    error.value = errorText(cause)
    if (cause instanceof ApiError && cause.code === 'invalid_response') {
      // Cookie 可能已经生效，先确认会话，不能再次消费验证码。
      recoveryRequired.value = true
    } else if (cause instanceof ApiError && (cause.status === 410 || cause.code === 'challenge_expired')) {
      setChallenge({ verification_required: false })
      error.value = '登录验证已失效，请重新输入账号和密码。'
    } else if (cause instanceof ApiError && cause.code === 'code_expired') {
      expiresAt.value = 0
      error.value = '验证码已过期，请重新发送验证码。'
    } else if (recover) await recoverChallenge()
  }
  async function login(username: string, password: string) {
    if (busy.value || recoveryRequired.value || challenge.value) return
    busy.value = true
    error.value = ''
    const body = { username, password }
    password = ''
    try {
      const result = await api<Session | LoginChallenge>('/api/login', { method: 'POST', body })
      if ('verification_required' in result) setChallenge(result)
      else accept(result)
    } catch (cause) {
      await handleChallengeFailure(cause, !(cause instanceof ApiError) || !cause.status || cause.status >= 500 || cause.status === 202)
    } finally {
      body.password = ''
      busy.value = false
    }
  }
  async function verify(code: string) {
    if (busy.value || recoveryRequired.value || !challenge.value || !expiresIn.value) return
    if (!/^[0-9]{6}$/.test(code)) {
      error.value = '请输入 6 位数字验证码。'
      return
    }
    busy.value = true
    error.value = ''
    const body = { code }
    code = ''
    try {
      accept(await api<Session>('/api/login/verify', { method: 'POST', body }))
    } catch (cause) {
      await handleChallengeFailure(cause)
      if (!(cause instanceof ApiError) || !cause.status || cause.status >= 500) recoveryRequired.value = true
    } finally {
      body.code = ''
      busy.value = false
    }
  }
  async function resend() {
    if (busy.value || recoveryRequired.value || !challenge.value || resendAfter.value) return
    busy.value = true
    error.value = ''
    try {
      setChallenge(await api<LoginChallenge>('/api/login/resend', { method: 'POST', body: {} }))
    } catch (cause) {
      await handleChallengeFailure(cause, true)
    } finally {
      busy.value = false
    }
  }
  async function cancel() {
    if (busy.value) return
    busy.value = true
    error.value = ''
    try {
      await api('/api/login/cancel', { method: 'POST', body: {} })
      setChallenge({ verification_required: false })
    } catch (cause) {
      await handleChallengeFailure(cause, true)
    } finally {
      busy.value = false
    }
  }
  async function logout() {
    if (busy.value) return
    busy.value = true
    error.value = ''
    try {
      await api('/api/logout', { method: 'POST' })
      setChallenge({ verification_required: false })
    } catch (cause) {
      error.value = errorText(cause)
    } finally {
      busy.value = false
    }
  }
  onMounted(() => {
    void restore()
    timer = setInterval(() => { now.value = Date.now() }, 1000)
  })
  onUnmounted(() => {
    clearInterval(timer)
    onAuthFailure(undefined)
  })
  return { session, challenge, recoveryRequired, expiresIn, resendAfter, ready, busy, error, accept, login, verify, resend, cancel, logout, restore }
}
