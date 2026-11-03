import { onMounted, onUnmounted, shallowRef } from 'vue'
import { api, errorText, isAborted } from '../lib/api'
import type { RunPage } from '../types'

export function useRuns() {
  const data = shallowRef<RunPage | null>(null), offset = shallowRef(0), total = shallowRef(0)
  const loading = shallowRef(false), error = shallowRef('')
  const limit = 20
  let controller: AbortController | undefined, request = 0, disposed = false
  async function load(nextOffset = offset.value): Promise<void> {
    if (disposed || !Number.isInteger(nextOffset) || nextOffset < 0) return
    controller?.abort()
    controller = new AbortController()
    const signal = controller.signal, current = ++request
    offset.value = nextOffset
    if (data.value?.offset !== nextOffset) data.value = null
    loading.value = true; error.value = ''
    try {
      const value = await api<RunPage>(`/api/runs?offset=${nextOffset}&limit=${limit}`, { signal })
      if (disposed || current !== request) return
      total.value = value.total
      const lastOffset = value.total ? Math.floor((value.total - 1) / limit) * limit : 0
      if (nextOffset > lastOffset) { await load(lastOffset); return }
      data.value = value
    } catch (cause) {
      if (!disposed && current === request && !isAborted(cause)) error.value = errorText(cause)
    } finally { if (current === request) loading.value = false }
  }
  onMounted(() => load())
  onUnmounted(() => { disposed = true; request++; controller?.abort() })
  return { data, offset, total, limit, loading, error, reload: () => load(), changePage: (page: number) => load((page - 1) * limit) }
}
