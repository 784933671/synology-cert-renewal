import { afterEach, describe, expect, it, vi } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { api, ApiError } from '../src/lib/api'
import { useRuns } from '../src/composables/useRuns'
import RunsView from '../src/views/RunsView.vue'
import RunDetailPanel from '../src/components/RunDetailPanel.vue'
import { deferred, run, runPage } from './monitoring-fixtures'
vi.mock('../src/lib/api', async (original) => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); document.body.innerHTML = '' })
function button(label: string) { return new DOMWrapper(document.body).findAll('button').find((node) => node.text().replace(/\s/g, '') === label)! }
describe('执行历史', () => {
  it('真实表格分页只读取本页，详情单独请求，记录保存警告可见', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/runs?offset=0&limit=20') return { ...runPage(), warning: '记录保存异常，执行历史可能不完整。' }
      if (path === '/api/runs?offset=20&limit=20') return runPage(20)
      return { ...run(20), summary: '详情服务返回的摘要' }
    })
    wrapper = mount(RunsView, { attachTo: document.body }); await flushPromises()
    expect(wrapper.text()).toContain('执行历史可能不完整')
    expect(wrapper.text()).toContain('普通检查')
    expect(wrapper.text()).not.toContain('定时触发')
    expect(wrapper.text()).toContain('检查记录 0：')
    expect(wrapper.text()).not.toContain('检查记录 20：')
    await wrapper.get('.ant-pagination-next button').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('检查记录 20：')
    expect(wrapper.text()).not.toContain('检查记录 0：')
    await button('查看时间线').trigger('click'); await flushPromises()
    expect(api).toHaveBeenLastCalledWith(`/api/runs/${run(20).id}`, expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain('详情服务返回的摘要')
    await new DOMWrapper(document.body).get('.ant-modal-close').trigger('click'); await flushPromises()
    expect(wrapper.findComponent(RunDetailPanel).exists()).toBe(false)
  })
  it('刷新失败保留本页旧数据，换页失败清空旧页但保留翻页恢复入口', async () => {
    vi.mocked(api).mockResolvedValueOnce(runPage()).mockRejectedValueOnce(new ApiError('刷新失败')).mockRejectedValueOnce(new ApiError('第二页失败')).mockResolvedValueOnce(runPage(20))
    wrapper = mount(RunsView, { attachTo: document.body }); await flushPromises()
    await button('刷新执行记录').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('下方为本页上次读取的记录')
    expect(wrapper.text()).toContain('检查记录 0：')
    await wrapper.get('.ant-pagination-next button').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('第二页失败')
    expect(wrapper.text()).not.toContain('检查记录 0：')
    expect(wrapper.text()).toContain('共 41 条记录')
    expect(wrapper.text()).not.toContain('暂无执行记录')
    await button('刷新执行记录').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('检查记录 20：')
    expect(wrapper.text()).not.toContain('第二页失败')
  })
  it('空历史显示空态，初始读取期间显示加载并在卸载时取消', async () => {
    const pending = deferred<ReturnType<typeof runPage>>()
    vi.mocked(api).mockReturnValueOnce(pending.promise)
    wrapper = mount(RunsView, { attachTo: document.body }); await flushPromises()
    expect(wrapper.text()).toContain('正在读取执行记录')
    pending.resolve(runPage(0, 0)); await flushPromises()
    expect(wrapper.text()).toContain('暂无执行记录')
    const signal = vi.mocked(api).mock.calls[0][1]!.signal!
    wrapper.unmount(); wrapper = undefined
    expect(signal.aborted).toBe(true)
  })
  it('快速换页忽略迟到成功和失败，只显示最后请求结果', async () => {
    const first = deferred<ReturnType<typeof runPage>>(), second = deferred<ReturnType<typeof runPage>>(), third = deferred<ReturnType<typeof runPage>>()
    vi.mocked(api).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise).mockReturnValueOnce(third.promise)
    let state!: ReturnType<typeof useRuns>
    wrapper = mount(defineComponent({ setup() { state = useRuns(); return () => null } }))
    const goSecond = state.changePage(2), goThird = state.changePage(3)
    expect(vi.mocked(api).mock.calls[0][1]!.signal!.aborted).toBe(true)
    second.reject(new ApiError('旧页失败')); first.resolve(runPage()); await flushPromises()
    expect(state.data.value).toBeNull(); expect(state.error.value).toBe(''); expect(state.loading.value).toBe(true)
    third.resolve(runPage(40)); await Promise.all([goSecond, goThird]); await flushPromises()
    expect(state.data.value?.offset).toBe(40); expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })
  it('历史保留清理后跳回有效尾页，不留在不存在的页码', async () => {
    vi.mocked(api).mockResolvedValueOnce(runPage()).mockResolvedValueOnce(runPage(40, 21)).mockResolvedValueOnce(runPage(20, 21))
    let state!: ReturnType<typeof useRuns>
    wrapper = mount(defineComponent({ setup() { state = useRuns(); return () => null } })); await flushPromises()
    await state.changePage(3)
    expect(state.offset.value).toBe(20)
    expect(state.data.value?.items[0].id).toBe(run(20).id)
    expect(state.total.value).toBe(21); expect(state.loading.value).toBe(false)
  })
  it('详情保留重复阶段，不伪造未计时DNS和中断结束时间，内容转义', async () => {
    const value = run(); value.status = 'interrupted'; value.finished_at = null; value.duration_seconds = null
    value.stages = [
      { stage: 'validate', label: '证书校验', status: 'succeeded', started_at: value.started_at, finished_at: value.started_at, duration_seconds: 0, message: '首次检查' },
      { stage: 'dns', label: 'DNS 验证记录', status: 'unknown', started_at: null, finished_at: null, duration_seconds: null, message: '<img src=x onerror=alert(1)> 事后证据' },
      { stage: 'validate', label: '证书校验', status: 'interrupted', started_at: value.started_at, finished_at: null, duration_seconds: null, message: '恢复后再次检查' },
    ]
    vi.mocked(api).mockResolvedValue(value)
    wrapper = mount(RunDetailPanel, { attachTo: document.body, props: { id: value.id } }); await flushPromises()
    expect(wrapper.findAll('.run-timeline .ant-timeline-item')).toHaveLength(3)
    const dns = wrapper.findAll('.run-timeline .ant-timeline-item')[1]
    expect(dns.text()).toContain('暂无记录'); expect(dns.text()).not.toContain('0 秒'); expect(dns.find('img').exists()).toBe(false)
    expect(wrapper.get('.ant-descriptions').text()).toContain('结束时间未记录耗时—')
    expect(wrapper.text()).toContain('恢复后再次检查')
  })
  it('运行中详情可手动刷新到成功，失败保留旧详情并支持重试', async () => {
    const current = { ...run(), status: 'running', finished_at: null, duration_seconds: null }
    vi.mocked(api).mockResolvedValueOnce(current).mockRejectedValueOnce(new ApiError('详情刷新失败')).mockResolvedValueOnce({ ...run(), status: 'succeeded', summary: '续期替换完成' })
    wrapper = mount(RunDetailPanel, { attachTo: document.body, props: { id: run().id } }); await flushPromises()
    expect(wrapper.text()).toContain('尚未结束')
    await button('刷新详情').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('下方为上次读取的执行详情')
    await button('刷新详情').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('续期替换完成'); expect(wrapper.text()).not.toContain('详情刷新失败')
  })
})
