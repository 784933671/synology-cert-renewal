import { computed, onMounted, onUnmounted, shallowRef } from 'vue'
import { api, ApiError, errorText, isAborted } from '../lib/api'
import type { AccessMode, Security } from '../types'

export function useAccessPolicy() {
  const data = shallowRef<Security | null>(null)
  const mode = shallowRef<AccessMode>('lan')
  const loading = shallowRef(false), saving = shallowRef(false)
  const error = shallowRef(''), conflict = shallowRef(false)
  const uncertain = shallowRef(false), pollPaused = shallowRef(false)
  const savedRevision = shallowRef('')
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  let attempts = 0, disposed = false
  const dirty = computed(() => !!data.value && mode.value !== data.value.access_mode)
  const locked = computed(() => loading.value || saving.value || !!data.value?.pending)
  const saveMessage = computed(() => {
    if (!data.value || dirty.value || savedRevision.value !== data.value.revision) return ''
    return data.value.pending ? '访问模式已保存，正在应用访问规则。' : '访问模式已保存并应用。'
  })

  function stopPolling() {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
  }
  function schedulePoll() {
    stopPolling()
    if (disposed || !data.value?.pending || conflict.value || uncertain.value) return
    if (attempts >= 20) {
      pollPaused.value = true
      return
    }
    timer = setTimeout(() => {
      attempts++
      void read(true)
    }, 3000)
  }
  function accept(value: Security) {
    data.value = value
    mode.value = value.access_mode
  }
  async function read(poll = false) {
    if (loading.value || saving.value || disposed) return
    if (!poll && dirty.value && !window.confirm('重新读取会放弃尚未保存的修改，是否继续？')) return
    stopPolling()
    loading.value = true
    if (!poll) {
      error.value = ''
      savedRevision.value = ''
      attempts = 0
      pollPaused.value = false
    }
    try {
      const value = await api<Security>('/api/security', { signal: controller.signal })
      if (disposed) return
      accept(value)
      error.value = ''
      conflict.value = uncertain.value = false
    } catch (cause) {
      if (!disposed && !isAborted(cause)) error.value = errorText(cause)
    } finally {
      loading.value = false
      schedulePoll()
    }
  }
  async function save() {
    if (!data.value || !dirty.value || locked.value || conflict.value || uncertain.value || disposed) return
    stopPolling()
    saving.value = true
    error.value = ''
    savedRevision.value = ''
    try {
      const value = await api<Security>('/api/security', {
        method: 'PUT',
        body: { access_mode: mode.value, revision: data.value.revision },
        signal: controller.signal,
      })
      if (disposed) return
      accept(value)
      savedRevision.value = value.revision
      conflict.value = uncertain.value = false
      attempts = 0
      pollPaused.value = false
    } catch (cause) {
      if (!disposed && !isAborted(cause)) {
        error.value = errorText(cause)
        conflict.value = cause instanceof ApiError && cause.status === 409
        uncertain.value = cause instanceof ApiError && (cause.status === 0 || cause.status >= 500)
      }
    } finally {
      saving.value = false
      schedulePoll()
    }
  }
  function reset() {
    if (!data.value || locked.value) return
    mode.value = data.value.access_mode
    savedRevision.value = ''
  }
  onMounted(() => read())
  onUnmounted(() => {
    disposed = true
    stopPolling()
    controller.abort()
  })
  return {
    data, mode, loading, saving, error, conflict, uncertain, pollPaused,
    dirty, locked, saveMessage, reload: () => read(), save, reset,
  }
}
