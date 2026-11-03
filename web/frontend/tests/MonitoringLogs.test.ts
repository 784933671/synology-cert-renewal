import { afterEach, describe, expect, it, vi } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import FailuresView from '../src/views/FailuresView.vue'
import AuditView from '../src/views/AuditView.vue'
import DialogPanel from '../src/components/DialogPanel.vue'
import type { AuditItem, FailureDetail, FailureItem } from '../src/types'

vi.mock('../src/lib/api', async (original) => ({
  ...(await original<typeof import('../src/lib/api')>()),
  api: vi.fn(),
}))
let wrapper: VueWrapper | undefined
const page = () => new DOMWrapper(document.body)
afterEach(() => {
  wrapper?.unmount()
  vi.mocked(api).mockReset()
  document.body.innerHTML = ''
})
const failure: FailureItem = {
  id: 'failure 1', at: '2026-11-03T00:00:00Z', stage_label: 'DNSPod 创建验证记录', summary: '域名权限不足', code: 'AccessDenied',
}
function button(label: string) {
  return page().findAll('button').find((node) => node.text() === label)!
}

describe('失败归档与审计组件', () => {
  it('失败详情通过真实弹窗加载，日志按文本转义，关闭后可重新打开', async () => {
    const detail: FailureDetail = {
      id: failure.id,
      report: { ...failure, archive_path: '/data/failures/report', hint: '检查域名授权' },
      logs: [{ name: 'acme.log', text: '<img src=x onerror="alert(1)"> SecretKey=[已脱敏]' }, { name: 'deploy.log', text: '' }],
    }
    vi.mocked(api).mockImplementation(async (path) => path === '/api/failures' ? { items: [failure] } : detail)
    wrapper = mount(FailuresView, { attachTo: document.body })
    await flushPromises()
    expect(wrapper.find('.ant-table').exists()).toBe(true)
    await button('查看详情').trigger('click')
    await flushPromises()
    expect(api).toHaveBeenCalledWith('/api/failures/failure%201', expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(page().get('[role="dialog"]').text()).toContain('DNSPod 创建验证记录')
    expect(page().get('.monitoring-event-log').text()).toContain('<img src=x onerror="alert(1)">')
    expect(page().find('.monitoring-event-log img').exists()).toBe(false)
    await page().findAll('.ant-tabs-tab')[1].trigger('click')
    await flushPromises()
    expect(page().text()).toContain('该日志没有内容。')
    await page().get('.ant-modal-close').trigger('click')
    await flushPromises()
    expect(wrapper.findComponent(DialogPanel).exists()).toBe(false)
    await button('查看详情').trigger('click')
    await flushPromises()
    expect(wrapper.findComponent(DialogPanel).exists()).toBe(true)
    await page().get('.ant-modal-wrap').trigger('keydown', { key: 'Escape', keyCode: 27 })
    await flushPromises()
    expect(wrapper.findComponent(DialogPanel).exists()).toBe(false)
  })

  it('失败详情请求失败可在弹窗内重试，缺少日志时显示中文空态', async () => {
    vi.mocked(api)
      .mockResolvedValueOnce({ items: [failure] })
      .mockRejectedValueOnce(new ApiError('详情读取失败'))
      .mockResolvedValueOnce({ id: failure.id, report: { summary: '记录已恢复' }, logs: [] })
    wrapper = mount(FailuresView, { attachTo: document.body })
    await flushPromises()
    await button('查看详情').trigger('click')
    await flushPromises()
    expect(page().get('[role="dialog"]').text()).toContain('详情读取失败')
    await button('重新读取').trigger('click')
    await flushPromises()
    expect(page().get('[role="dialog"]').text()).toContain('记录已恢复')
    expect(page().get('[role="dialog"]').text()).toContain('暂无可用的脱敏日志')
    expect(page().get('[role="dialog"]').text()).not.toContain('详情读取失败')
  })

  it('列表失败和空记录不混淆，刷新成功后清除错误', async () => {
    vi.mocked(api).mockRejectedValueOnce(new ApiError('连接失败')).mockResolvedValueOnce({ items: [] })
    wrapper = mount(FailuresView, { attachTo: document.body })
    await flushPromises()
    expect(wrapper.text()).toContain('暂时无法读取记录')
    expect(wrapper.text()).not.toContain('暂无失败记录')
    await button('刷新记录').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('暂无失败记录')
    expect(wrapper.text()).not.toContain('连接失败')
  })

  it('审计表格分页保留所有记录，操作名称与成功失败正确展示', async () => {
    const items: AuditItem[] = Array.from({ length: 11 }, (_, index) => ({
      at: `2026-11-03T00:00:${String(index).padStart(2, '0')}Z`,
      action: index ? 'settings.update' : 'login', success: index !== 0,
      message: `审计记录-${index}`,
    }))
    vi.mocked(api).mockResolvedValue({ items })
    wrapper = mount(AuditView, { attachTo: document.body })
    await flushPromises()
    expect(wrapper.find('.ant-table').exists()).toBe(true)
    expect(wrapper.text()).toContain('登录')
    expect(wrapper.text()).toContain('更新配置')
    expect(wrapper.text()).toContain('失败')
    expect(wrapper.text()).toContain('成功')
    expect(wrapper.text()).toContain('共 11 条记录')
    expect(wrapper.text()).not.toContain('审计记录-10')
    await wrapper.get('.ant-pagination-next button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('审计记录-10')
    expect(wrapper.text()).not.toContain('审计记录-0')
  })

  it('审计刷新失败保留上次记录并标明过期状态', async () => {
    vi.mocked(api).mockResolvedValueOnce({ items: [{ at: '', action: 'custom.action', success: true, message: '' }] }).mockRejectedValueOnce(new ApiError('刷新失败'))
    wrapper = mount(AuditView, { attachTo: document.body })
    await flushPromises()
    await button('刷新记录').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('下方为上次读取的记录')
    expect(wrapper.text()).toContain('custom.action')
    expect(wrapper.text()).toContain('刷新失败')
  })
})
