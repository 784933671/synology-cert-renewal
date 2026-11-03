import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import { useHealth } from '../src/composables/useHealth'
import { deferred, health } from './monitoring-fixtures'

vi.mock('../src/lib/api', async (original) => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); vi.useRealTimers() })

function mountHealth() {
  let state!: ReturnType<typeof useHealth>
  wrapper = mount(defineComponent({ setup() { state = useHealth(); return () => null } }))
  return state
}

describe('健康快照时效', () => {
  it('首次响应的网络等待计入两个快照的年龄', async () => {
    vi.useFakeTimers()
    let now = 1000
    vi.spyOn(performance, 'now').mockImplementation(() => now)
    const pending = deferred<ReturnType<typeof health>>()
    vi.mocked(api).mockReturnValue(pending.promise)
    const state = mountHealth(), value = health()
    value.monitor.checked_at = '2026-11-03T03:57:50Z'
    now += 60000; pending.resolve(value); await flushPromises()
    expect(state.runtimeStale.value).toBe(true)
    expect(state.monitorStale.value).toBe(true)
  })

  it('等待刷新时旧快照继续老化，迟到的新响应不重置年龄，及时响应可恢复', async () => {
    vi.useFakeTimers()
    let now = 1000
    vi.spyOn(performance, 'now').mockImplementation(() => now)
    const slow = deferred<ReturnType<typeof health>>(), fast = deferred<ReturnType<typeof health>>()
    vi.mocked(api).mockResolvedValueOnce(health()).mockReturnValueOnce(slow.promise).mockReturnValueOnce(fast.promise)
    const state = mountHealth(); await flushPromises()
    expect(state.runtimeStale.value).toBe(false)
    now = 20000; const refresh = state.reload()
    now = 47000; await vi.advanceTimersByTimeAsync(1000)
    expect(state.runtimeStale.value).toBe(true)
    now = 81000; slow.resolve(health()); await refresh
    expect(state.runtimeStale.value).toBe(true)
    expect(state.monitorStale.value).toBe(false)
    now = 82000; const retry = state.reload()
    now = 83000; fast.resolve(health()); await retry
    expect(state.runtimeStale.value).toBe(false)
  })

  it('刷新失败不替换快照，重试等待期间也不让已过期的数据恢复正常', async () => {
    vi.useFakeTimers()
    let now = 1000
    vi.spyOn(performance, 'now').mockImplementation(() => now)
    const failed = deferred<ReturnType<typeof health>>(), retry = deferred<ReturnType<typeof health>>()
    vi.mocked(api).mockResolvedValueOnce(health()).mockReturnValueOnce(failed.promise).mockReturnValueOnce(retry.promise)
    const state = mountHealth(); await flushPromises()
    const original = state.data.value
    now = 20000; const refresh = state.reload()
    now = 47000; await vi.advanceTimersByTimeAsync(1000)
    failed.reject(new ApiError('连接失败')); await refresh
    expect(state.data.value).toBe(original)
    expect(state.runtimeStale.value).toBe(true)
    const next = state.reload()
    expect(state.runtimeStale.value).toBe(true)
    now = 48000; retry.resolve(health()); await next
    expect(state.runtimeStale.value).toBe(false)
  })

  it.each(['success', 'failure'] as const)('卸载后忽略迟到%s，停止计时并取消请求', async (result) => {
    vi.useFakeTimers()
    const pending = deferred<ReturnType<typeof health>>()
    vi.mocked(api).mockReturnValue(pending.promise)
    const state = mountHealth(), signal = vi.mocked(api).mock.calls[0][1]!.signal!
    wrapper!.unmount(); wrapper = undefined
    if (result === 'success') pending.resolve(health())
    else pending.reject(new ApiError('迟到错误'))
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(state.data.value).toBeNull()
    expect(state.error.value).toBe('')
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['request', 'display'] as const)('%s期间单调时间回退后保持未知，新的有效响应才能恢复', async (phase) => {
    vi.useFakeTimers()
    let now = 1000
    vi.spyOn(performance, 'now').mockImplementation(() => now)
    const pending = deferred<ReturnType<typeof health>>()
    vi.mocked(api).mockReturnValueOnce(pending.promise).mockResolvedValueOnce(health())
    const state = mountHealth()
    now = phase === 'request' ? 500 : 2000
    pending.resolve(health()); await flushPromises()
    if (phase === 'display') { now = 1500; await vi.advanceTimersByTimeAsync(1000) }
    expect(state.runtimeStale.value).toBe(true)
    expect(state.monitorStale.value).toBe(true)
    now = 3000; await vi.advanceTimersByTimeAsync(1000)
    expect(state.runtimeStale.value).toBe(true)
    now = 4000; await state.reload()
    expect(state.runtimeStale.value).toBe(false)
  })
})
