import { onMounted, onUnmounted, shallowRef } from 'vue'
import { api, errorText, isAborted } from '../lib/api'
export function useResource<T>(path: string) {
  const data = shallowRef<T | null>(null),
    loading = shallowRef(false),
    error = shallowRef('')
  let active: AbortController | undefined
  async function reload() {
    if (loading.value) return
    active = new AbortController()
    loading.value = true
    error.value = ''
    try {
      data.value = await api<T>(path, { signal: active.signal })
    } catch (cause) {
      if (!isAborted(cause)) error.value = errorText(cause)
    } finally {
      loading.value = false
    }
  }
  onMounted(reload)
  onUnmounted(() => active?.abort())
  return { data, loading, error, reload }
}
