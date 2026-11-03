import { computed, onMounted, onUnmounted, shallowRef, watch } from 'vue'
import { useResource } from './useResource'
import { snapshotExpired } from '../lib/monitoring'
import type { HealthSnapshot } from '../types'

export function useHealth() {
  const resource = useResource<HealthSnapshot>('/api/health')
  const elapsed = shallowRef(0)
  let sampledAt = 0, invalidClock = false, timer: ReturnType<typeof setInterval> | undefined
  function updateElapsed() {
    const current = performance.now(), started = resource.dataRequestedAt.value
    invalidClock ||= started === null || !Number.isFinite(started) || !Number.isFinite(current)
      || started < 0 || current < started || current < sampledAt
    // 包含响应等待时间；时钟异常后须取得新的有效快照才能恢复。
    elapsed.value = invalidClock || started === null ? Infinity : (current - started) / 1000
    sampledAt = current
  }
  watch(resource.data, () => {
    sampledAt = 0; invalidClock = false; updateElapsed()
  }, { flush: 'sync' })
  function stale(kind: 'runtime' | 'monitor') {
    const value = resource.data.value
    return !value || !!resource.error.value || value[kind].stale || snapshotExpired(
      value.server_time, value[kind].checked_at, value[kind].stale_after_seconds, elapsed.value,
    )
  }
  const runtimeStale = computed(() => stale('runtime')), monitorStale = computed(() => stale('monitor'))
  onMounted(() => { timer = setInterval(updateElapsed, 1000) })
  onUnmounted(() => clearInterval(timer))
  return { ...resource, runtimeStale, monitorStale }
}
