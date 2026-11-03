import { onMounted, onUnmounted, shallowRef } from 'vue'
import { api, errorText, isAborted } from '../lib/api'
export function useResource<T>(path: string) {
  const data = shallowRef<T | null>(null),
    dataRequestedAt = shallowRef<number | null>(null),
    loading = shallowRef(false),
    error = shallowRef('')
  let active: AbortController | undefined
  let disposed = false
  async function reload() {
    if (disposed || loading.value) return
    active = new AbortController()
    const requestedAt = performance.now()
    loading.value = true
    error.value = ''
    try {
      const value = await api<T>(path, { signal: active.signal })
      if (disposed) return
      dataRequestedAt.value = requestedAt
      data.value = value
    } catch (cause) {
      if (!disposed && !isAborted(cause)) error.value = errorText(cause)
    } finally {
      if (!disposed) loading.value = false
    }
  }
  onMounted(reload)
  onUnmounted(() => { disposed = true; active?.abort() })
  return { data, dataRequestedAt, loading, error, reload }
}
