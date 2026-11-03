import { onMounted, onUnmounted, shallowRef } from 'vue'
import { api, ApiError, errorText, onAuthFailure, setCsrf } from '../lib/api'
import type { Session } from '../types'
export function useSession() {
  const session = shallowRef<Session | null>(null),
    ready = shallowRef(false),
    busy = shallowRef(false),
    error = shallowRef('')
  function accept(value: Session | null) {
    session.value = value
    setCsrf(value?.csrf_token || '')
  }
  onAuthFailure((reason) => {
    if (reason === 'password' && session.value)
      accept({ ...session.value, must_change_password: true })
    else {
      accept(null)
      error.value = '登录已失效，请重新登录。'
    }
  })
  async function restore() {
    busy.value = true
    error.value = ''
    try {
      accept(await api<Session>('/api/session'))
    } catch (cause) {
      if (!(cause instanceof ApiError && cause.status === 401))
        error.value = errorText(cause)
    } finally {
      ready.value = true
      busy.value = false
    }
  }
  async function login(username: string, password: string) {
    if (busy.value) return
    busy.value = true
    error.value = ''
    try {
      accept(
        await api<Session>('/api/login', {
          method: 'POST',
          body: { username, password },
        }),
      )
    } catch (cause) {
      error.value = errorText(cause)
    } finally {
      password = ''
      busy.value = false
    }
  }
  async function logout() {
    if (busy.value) return
    busy.value = true
    error.value = ''
    try {
      await api('/api/logout', { method: 'POST' })
      accept(null)
    } catch (cause) {
      error.value = errorText(cause)
    } finally {
      busy.value = false
    }
  }
  onMounted(restore)
  onUnmounted(() => onAuthFailure(undefined))
  return { session, ready, busy, error, accept, login, logout, restore }
}
