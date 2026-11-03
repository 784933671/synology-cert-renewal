import { computed, onMounted, onUnmounted, shallowRef } from 'vue'
import { api, errorText, isAborted } from '../lib/api'
import type { ManualRenewal, Status } from '../types'

type ActionKind = 'run' | 'check' | 'renew'
export function useStatus() {
  const status = shallowRef<Status | null>(null), loading = shallowRef(false), error = shallowRef(''),
    actionError = shallowRef(''), message = shallowRef(''), action = shallowRef<ActionKind | ''>(''),
    waiting = shallowRef(false), now = shallowRef(Date.now())
  let timer: ReturnType<typeof setTimeout> | undefined, clock: ReturnType<typeof setInterval> | undefined,
    alive = true, fetching: Promise<void> | undefined, receivedAt = Date.now(), submittedAt = 0,
    beforeResult = '', beforeRenewalId = '', expectedRenewalId = '', waitingKind: ActionKind | '' = ''
  const controller = new AbortController()
  const manualRunning = computed(() => ['queued', 'running'].includes(status.value?.manual_renewal?.state || ''))
  const busy = computed(() => Boolean(action.value || waiting.value || status.value?.task.running || status.value?.check.running || manualRunning.value))
  const pendingRecovery = computed(() => Boolean(status.value && Object.values(status.value.pending).some(Boolean)))
  const cooldownActive = computed(() => {
    const until = Date.parse(status.value?.manual_renewal?.cooldown_until || '')
    const serverAt = Date.parse(status.value?.server_time || '')
    const current = Number.isFinite(serverAt) ? serverAt + now.value - receivedAt : now.value
    return Number.isFinite(until) && until > current
  })
  const renewDisabled = computed(() => busy.value || !status.value || !!error.value || pendingRecovery.value || cooldownActive.value)
  function resultSignature(value: Status) {
    return JSON.stringify([value.last_result, value.check.last_result, value.task.last_run])
  }
  function trackResult(value: Status) {
    if (!waiting.value) return
    if (waitingKind === 'renew') {
      const renewal = value.manual_renewal
      // 只认本次申请记录，已有成功记录不能确认新请求完成。
      if (renewal && (expectedRenewalId ? renewal.request_id === expectedRenewalId : renewal.request_id !== beforeRenewalId)) {
        expectedRenewalId = renewal.request_id
        if (['succeeded', 'failed', 'expired'].includes(renewal.state)) {
          waiting.value = false
          message.value = ''
        }
      } else if (renewal && expectedRenewalId && renewal.request_id !== beforeRenewalId) {
        waiting.value = false
        message.value = '申请记录已更新，当前显示最新请求的状态。此前请求的结果未在本页确认。'
      }
    } else if (value.task.running || value.check.running || resultSignature(value) !== beforeResult || Date.now() - submittedAt > 30000) waiting.value = false
  }
  async function refresh() {
    if (!alive) return
    if (fetching) return fetching
    loading.value = true
    fetching = (async () => {
      try {
        const value = await api<Status>('/api/status', { signal: controller.signal })
        receivedAt = Date.now()
        now.value = receivedAt
        status.value = value
        error.value = ''
        trackResult(value)
      } catch (cause) {
        if (!isAborted(cause)) error.value = errorText(cause)
      } finally { loading.value = false }
    })()
    try { await fetching } finally { fetching = undefined }
  }
  async function poll() {
    await refresh()
    if (alive) timer = setTimeout(poll, busy.value ? 3000 : 15000)
  }
  async function execute(kind: ActionKind) {
    if (busy.value || !status.value || error.value || (kind === 'renew' && renewDisabled.value)) return
    action.value = kind
    actionError.value = ''
    message.value = ''
    beforeResult = resultSignature(status.value)
    beforeRenewalId = status.value.manual_renewal?.request_id || ''
    expectedRenewalId = ''
    try {
      const result = await api<{ accepted: boolean; message: string; request_id?: string; manual_renewal?: ManualRenewal }>(
        `/api/actions/${kind}`, { method: 'POST', body: {}, signal: controller.signal },
      )
      if (!result.accepted) throw new Error('unaccepted')
      message.value = result.message || '任务已提交，执行结果将自动更新。'
      waiting.value = true
      waitingKind = kind
      submittedAt = Date.now()
      expectedRenewalId = result.request_id || result.manual_renewal?.request_id || ''
      if (kind === 'renew' && result.manual_renewal) {
        status.value = { ...status.value, manual_renewal: result.manual_renewal }
        trackResult(status.value)
      }
      // 等已有刷新完成，再读取提交后的状态。
      if (fetching) await fetching
      await refresh()
    } catch (cause) {
      if (!isAborted(cause)) {
        actionError.value = errorText(cause)
        if (kind === 'renew') await refresh()
      }
    } finally {
      action.value = ''
      clearTimeout(timer)
      if (alive) timer = setTimeout(poll, busy.value ? 3000 : 15000)
    }
  }
  onMounted(() => {
    void poll()
    clock = setInterval(() => { now.value = Date.now() }, 1000)
  })
  onUnmounted(() => {
    alive = false
    clearTimeout(timer)
    clearInterval(clock)
    controller.abort()
  })
  return { status, loading, error, actionError, message, action, waiting, busy, manualRunning, pendingRecovery, cooldownActive, renewDisabled, refresh, execute }
}
