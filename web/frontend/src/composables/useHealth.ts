import { computed, onMounted, onUnmounted, shallowRef, watch } from 'vue'
import { useResource } from './useResource'
import { snapshotExpired } from '../lib/monitoring'
import type { HealthSnapshot } from '../types'

export function useHealth() {
  const resource = useResource<HealthSnapshot>('/api/health')
  const elapsed = shallowRef(0)
  let receivedAt = performance.now(), timer: ReturnType<typeof setInterval> | undefined
  watch(resource.data, () => { receivedAt = performance.now(); elapsed.value = 0 }, { flush: 'sync' })
  function stale(kind: 'runtime' | 'monitor') {
    const value = resource.data.value
    return !value || !!resource.error.value || value[kind].stale || snapshotExpired(
      value.server_time, value[kind].checked_at, value[kind].stale_after_seconds, elapsed.value,
    )
  }
  const runtimeStale = computed(() => stale('runtime')), monitorStale = computed(() => stale('monitor'))
  onMounted(() => { timer = setInterval(() => { elapsed.value = (performance.now() - receivedAt) / 1000 }, 1000) })
  onUnmounted(() => clearInterval(timer))
  return { ...resource, runtimeStale, monitorStale }
}
