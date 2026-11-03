import { computed, onMounted, onUnmounted, shallowRef } from 'vue'
import { api, errorText, isAborted } from '../lib/api'
import type { Status } from '../types'
export function useStatus() {
  const status = shallowRef<Status | null>(null),
    loading = shallowRef(false),
    error = shallowRef(''),
    actionError = shallowRef(''),
    message = shallowRef(''),
    action = shallowRef('')
  const waiting = shallowRef(false)
  let timer: ReturnType<typeof setTimeout> | undefined,
    alive = true,
    fetching = false
  const controller = new AbortController()
  let submittedAt = 0,
    beforeResult = ''
  const busy = computed(() =>
    Boolean(
      action.value ||
      waiting.value ||
      status.value?.task.running ||
      status.value?.check.running,
    ),
  )
  async function refresh() {
    if (fetching || !alive) return
    fetching = true
    loading.value = true
    try {
      status.value = await api<Status>('/api/status', {
        signal: controller.signal,
      })
      error.value = ''
      if (
        waiting.value &&
        (status.value.task.running ||
          status.value.check.running ||
          JSON.stringify([
            status.value.last_result,
            status.value.check.last_result,
            status.value.task.last_run,
          ]) !== beforeResult ||
          Date.now() - submittedAt > 30000)
      )
        waiting.value = false
    } catch (cause) {
      if (!isAborted(cause)) error.value = errorText(cause)
    } finally {
      fetching = false
      loading.value = false
    }
  }
  async function poll() {
    await refresh()
    if (alive) timer = setTimeout(poll, busy.value ? 3000 : 15000)
  }
  async function execute(kind: 'run' | 'check') {
    if (busy.value || !status.value || error.value) return
    action.value = kind
    actionError.value = ''
    message.value = ''
    beforeResult = JSON.stringify([
      status.value.last_result,
      status.value.check.last_result,
      status.value.task.last_run,
    ])
    try {
      const result = await api<{ accepted: boolean; message: string }>(
        `/api/actions/${kind}`,
        { method: 'POST', signal: controller.signal },
      )
      if (!result.accepted) throw new Error('unaccepted')
      message.value = result.message || '任务已提交，执行结果将自动更新。'
      waiting.value = true
      submittedAt = Date.now()
      await refresh()
    } catch (cause) {
      if (!isAborted(cause)) actionError.value = errorText(cause)
    } finally {
      action.value = ''
    }
  }
  onMounted(poll)
  onUnmounted(() => {
    alive = false
    clearTimeout(timer)
    controller.abort()
  })
  return {
    status,
    loading,
    error,
    actionError,
    message,
    action,
    waiting,
    busy,
    refresh,
    execute,
  }
}
