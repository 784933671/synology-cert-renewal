import { computed, onMounted, onUnmounted, ref, shallowRef } from 'vue'
import { api, ApiError, errorText, isAborted } from '../lib/api'
import type { MonitorDraft, MonitorSettings } from '../types'

export function useMonitorSettings() {
  const data = shallowRef<MonitorSettings | null>(null), draft = ref<MonitorDraft | null>(null)
  const loading = shallowRef(false), saving = shallowRef(false), conflict = shallowRef(false), uncertain = shallowRef(false)
  const error = shallowRef(''), success = shallowRef(''), validation = shallowRef<string[]>([])
  const initial = shallowRef(''), controller = new AbortController()
  let disposed = false
  const dirty = computed(() => !!draft.value && JSON.stringify(draft.value) !== initial.value)
  function accept(value: MonitorSettings) {
    data.value = value
    draft.value = { enabled: value.enabled, missed_runs: value.missed_runs, grace_minutes: value.grace_minutes, expiry_hours: value.expiry_hours }
    initial.value = JSON.stringify(draft.value)
    conflict.value = uncertain.value = false
  }
  async function reload() {
    if (disposed || loading.value || saving.value) return
    if (dirty.value && !window.confirm('重新读取会放弃尚未保存的监测配置，是否继续？')) return
    loading.value = true
    error.value = success.value = ''
    validation.value = []
    try {
      const value = await api<MonitorSettings>('/api/monitor', { signal: controller.signal })
      if (!disposed) accept(value)
    } catch (cause) {
      if (!disposed && !isAborted(cause)) error.value = errorText(cause)
    } finally { loading.value = false }
  }
  async function save() {
    if (disposed || !draft.value || !data.value || !dirty.value || loading.value || saving.value || conflict.value || uncertain.value) return false
    const fields: [keyof Pick<MonitorDraft, 'missed_runs' | 'grace_minutes' | 'expiry_hours'>, number, number, string][] = [
      ['missed_runs', 1, 6, '漏跑次数须为 1～6 的整数。'],
      ['grace_minutes', 5, 120, '宽限时间须为 5～120 分钟的整数。'],
      ['expiry_hours', 1, 168, '临期提醒须为 1～168 小时的整数。'],
    ]
    validation.value = fields.filter(([key, min, max]) => !Number.isInteger(draft.value![key]) || draft.value![key] < min || draft.value![key] > max).map((item) => item[3])
    error.value = success.value = ''
    if (validation.value.length) return false
    saving.value = true
    try {
      const value = await api<MonitorSettings>('/api/monitor', { method: 'PUT', body: { revision: data.value.revision, ...draft.value }, signal: controller.signal })
      if (disposed) return false
      accept(value)
      success.value = '监测配置已保存，将在下一次监测时应用。'
      return true
    } catch (cause) {
      if (!disposed && !isAborted(cause)) {
        error.value = errorText(cause)
        conflict.value = cause instanceof ApiError && cause.status === 409
        uncertain.value = !(cause instanceof ApiError) || cause.status === 0 || cause.status >= 500 || cause.code === 'invalid_response'
      }
      return false
    } finally { saving.value = false }
  }
  function reset() {
    if (loading.value || saving.value || !data.value || (dirty.value && !window.confirm('放弃尚未保存的监测配置？'))) return
    const pending = uncertain.value, changed = conflict.value
    accept(data.value)
    uncertain.value = pending; conflict.value = changed
    validation.value = []; success.value = ''
  }
  onMounted(reload)
  onUnmounted(() => { disposed = true; controller.abort() })
  return { data, draft, loading, saving, error, success, validation, conflict, uncertain, dirty, reload, save, reset }
}
