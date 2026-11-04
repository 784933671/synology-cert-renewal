import { computed, onMounted, onUnmounted, ref, shallowRef } from 'vue'
import { api, ApiError, errorText, isAborted, isUnknownResult } from '../lib/api'
import type { AbuseLimits, AbusePolicy } from '../types'

export const abuseFields: { key: keyof AbuseLimits; label: string; min: number; max: number; unit: string }[] = [
  { key: 'ip_requests_per_minute', label: '单个 IP 每分钟补充额度', min: 120, max: 6000, unit: '次' },
  { key: 'session_requests_per_minute', label: '单个会话每分钟补充额度', min: 60, max: 1200, unit: '次' },
  { key: 'block_after_violations', label: '触发临时封禁的 IP 超限次数', min: 5, max: 100, unit: '次' },
  { key: 'block_seconds', label: '临时封禁时长', min: 60, max: 1800, unit: '秒' },
]
function validate(value: AbuseLimits) {
  const errors = abuseFields.filter(({ key, min, max }) => !Number.isInteger(value[key]) || value[key] < min || value[key] > max)
    .map(({ label, min, max, unit }) => `${label}须为 ${min}～${max} ${unit}的整数。`)
  if (value.session_requests_per_minute > value.ip_requests_per_minute) errors.push('会话补充额度不能超过 IP 补充额度。')
  return errors
}
export function useAbusePolicy() {
  const data = shallowRef<AbusePolicy | null>(null), draft = ref<AbuseLimits | null>(null)
  const loading = shallowRef(false), saving = shallowRef(false), conflict = shallowRef(false), uncertain = shallowRef(false)
  const error = shallowRef(''), success = shallowRef(''), validation = shallowRef<string[]>([])
  const initial = shallowRef(''), controller = new AbortController()
  let disposed = false
  const dirty = computed(() => !!draft.value && JSON.stringify(draft.value) !== initial.value)
  function accept(value: AbusePolicy) {
    if (typeof value?.revision !== 'string' || !/^[a-f0-9]{32}$/.test(value.revision) || !value.limits || validate(value.limits).length) throw new ApiError('无法确认接口防护配置，请重新读取。', 200, 'invalid_response')
    data.value = value
    draft.value = { ...value.limits }
    initial.value = JSON.stringify(draft.value)
    conflict.value = uncertain.value = false
  }
  async function reload() {
    if (disposed || loading.value || saving.value) return
    if (dirty.value && !window.confirm('重新读取会放弃尚未保存的接口防护设置，是否继续？')) return
    loading.value = true
    error.value = success.value = ''
    validation.value = []
    try {
      const result = await api<AbusePolicy>('/api/abuse', { signal: controller.signal })
      if (!disposed) accept(result)
    } catch (cause) {
      if (!disposed && !isAborted(cause)) error.value = errorText(cause)
    } finally { if (!disposed) loading.value = false }
  }
  async function save() {
    if (disposed || !draft.value || !data.value || !dirty.value || loading.value || saving.value || conflict.value || uncertain.value) return
    error.value = success.value = ''
    validation.value = validate(draft.value)
    if (validation.value.length) return
    saving.value = true
    try {
      const result = await api<AbusePolicy>('/api/abuse', { method: 'PUT', body: { revision: data.value.revision, limits: { ...draft.value } }, signal: controller.signal })
      if (disposed) return
      accept(result)
      success.value = '接口防护设置已保存。'
    } catch (cause) {
      if (disposed || isAborted(cause)) return
      error.value = errorText(cause)
      conflict.value = cause instanceof ApiError && cause.status === 409
      uncertain.value = isUnknownResult(cause)
    } finally { if (!disposed) saving.value = false }
  }
  function reset() {
    if (disposed || loading.value || saving.value || !data.value) return
    draft.value = { ...data.value.limits }
    success.value = ''; validation.value = []
  }
  onMounted(reload)
  onUnmounted(() => { disposed = true; controller.abort() })
  return { data, draft, loading, saving, conflict, uncertain, error, success, validation, dirty, reload, save, reset }
}
