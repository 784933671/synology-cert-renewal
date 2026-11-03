import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import OverviewView from '../src/views/OverviewView.vue'
import type { Status } from '../src/types'
vi.mock('../src/lib/api', async (original) => ({
  ...(await original<typeof import('../src/lib/api')>()),
  api: vi.fn(),
}))
let wrapper: VueWrapper | undefined
afterEach(() => {
  wrapper?.unmount()
  vi.useRealTimers()
  vi.mocked(api).mockReset()
  document.body.innerHTML = ''
})
function status(): Status {
  return {
    certificate: {
      id: 'a',
      description: 'NAS',
      domains: ['nas.example.com'],
      not_after: '2027-01-01T00:00:00Z',
      fingerprint: 'ab',
      remaining_seconds: 864000,
      renew_at: '2026-12-30T00:00:00Z',
    },
    renew_before_days: 2,
    task: {
      enabled: true,
      running: false,
      schedule_text: '每小时第17分钟',
      last_run: null,
    },
    last_result: null,
    pending: {
      deployment: false,
      dns_cleanup: false,
      notification: false,
      interrupted: false,
    },
    check: { running: false, last_result: null },
    server_time: '2026-12-22T00:00:00Z',
    timezone: 'Asia/Shanghai',
  }
}
describe('运行操作反馈', () => {
  it('检查只触发检查端点，接受后等待结果，不允许连续提交', async () => {
    vi.mocked(api).mockImplementation(async (path) =>
      path === '/api/status'
        ? status()
        : { accepted: true, message: '检查已提交' },
    )
    wrapper = mount(OverviewView)
    await flushPromises()
    const button = wrapper
      .findAll('button')
      .find((node) => node.text() === '立即检查')!
    await button.trigger('click')
    await button.trigger('click')
    await flushPromises()
    expect(
      vi
        .mocked(api)
        .mock.calls.filter(([path]) => path === '/api/actions/check'),
    ).toHaveLength(1)
    expect(
      vi.mocked(api).mock.calls.some(([path]) => path === '/api/actions/run'),
    ).toBe(false)
    expect(wrapper.text()).toContain('检查已提交')
    expect(wrapper.text()).toContain('等待任务启动')
    expect(wrapper.text()).not.toContain('检查已通过')
  })
  it('无法读取状态时禁止运行，展示连接错误', async () => {
    vi.mocked(api).mockRejectedValueOnce(new ApiError('连接失败'))
    wrapper = mount(OverviewView)
    await flushPromises()
    expect(wrapper.text()).toContain('连接失败')
    expect(
      wrapper
        .findAll('button')
        .find((node) => node.text() === '立即检查')!
        .attributes('disabled'),
    ).toBeDefined()
    expect(wrapper.text()).not.toContain('状态已读取')
  })
  it('明确展示过期、暂停和待办状态，不将流程说明标记成已完成', async () => {
    const value = status()
    value.certificate.remaining_seconds = -1
    value.task.enabled = false
    value.pending.deployment = true
    value.pending.dns_cleanup = 2
    value.pending.notification = true
    value.pending.interrupted = true
    value.last_result = { success: false, message: '权限不足', failure: { stage_label: 'DNSPod 创建验证记录' } }
    vi.mocked(api).mockResolvedValue(value)
    wrapper = mount(OverviewView)
    await flushPromises()
    expect(wrapper.get('.certificate-countdown').text()).toContain('已到期')
    expect(wrapper.get('.certificate-countdown').classes()).toContain('is-expired')
    expect(wrapper.text()).toContain('自动检查已暂停')
    expect(wrapper.text()).toContain('证书部署、DNS 验证记录清理、邮件通知、中断恢复')
    expect(wrapper.text()).toContain('DNSPod 创建验证记录')
    expect(wrapper.findAll('.ant-steps-item-finish')).toHaveLength(0)
  })
  it('运行提交失败后恢复按钮，重试只调用续期任务端点', async () => {
    let attempts = 0
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/status') return status()
      if (++attempts === 1) throw new ApiError('任务启动失败')
      return { accepted: true, message: '续期任务已提交' }
    })
    wrapper = mount(OverviewView)
    await flushPromises()
    const button = wrapper.findAll('button').find((node) => node.text() === '运行一次续期任务')!
    await button.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('任务启动失败')
    expect(button.attributes('disabled')).toBeUndefined()
    await button.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('续期任务已提交')
    expect(wrapper.text()).not.toContain('任务启动失败')
    expect(button.attributes('disabled')).toBeDefined()
    expect(vi.mocked(api).mock.calls.filter(([path]) => path === '/api/actions/run')).toHaveLength(2)
    expect(vi.mocked(api).mock.calls.some(([path]) => path === '/api/actions/check')).toBe(false)
  })
  it('刷新失败保留上次数据并禁用操作，重新连接成功后恢复', async () => {
    vi.mocked(api).mockResolvedValueOnce(status()).mockRejectedValueOnce(new ApiError('连接中断')).mockResolvedValueOnce(status())
    wrapper = mount(OverviewView)
    await flushPromises()
    const refresh = wrapper.findAll('button').find((node) => node.text() === '刷新状态')!
    await refresh.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('下方为上次读取的状态')
    expect(wrapper.text()).toContain('nas.example.com')
    expect(wrapper.findAll('button').find((node) => node.text() === '立即检查')!.attributes('disabled')).toBeDefined()
    await refresh.trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('连接中断')
    expect(wrapper.findAll('button').find((node) => node.text() === '立即检查')!.attributes('disabled')).toBeUndefined()
  })
})

function pageButton(text: string) { return wrapper!.findAll('button').find((node) => node.text() === text)! }
async function dialogButton(text: string) {
  const target = Array.from(document.querySelectorAll<HTMLButtonElement>('.ant-modal button')).find((node) => node.textContent?.replace(/\s/g, '') === text)
  expect(target).toBeDefined()
  target!.click()
  await flushPromises()
}
async function confirmRenewal() {
  await pageButton('立即申请并替换证书').trigger('click')
  await flushPromises()
  await dialogButton('确认申请并替换')
}
function renewal(state: NonNullable<Status['manual_renewal']>['state'], requestId = 'request-new'): NonNullable<Status['manual_renewal']> {
  return { request_id: requestId, state, message: `服务器结果 ${state}`, requested_at: '2026-12-22T00:00:00Z' }
}
describe('立即申请并替换证书', () => {
  it('真实Ant确认弹窗明确影响，取消不发送请求且保留旧操作', async () => {
    vi.mocked(api).mockResolvedValue(status())
    wrapper = mount(OverviewView)
    await flushPromises()
    expect(pageButton('立即检查').exists()).toBe(true)
    expect(pageButton('运行一次续期任务').exists()).toBe(true)
    await pageButton('立即申请并替换证书').trigger('click')
    await flushPromises()
    expect(document.querySelector('.ant-modal')?.textContent).toContain('会立即申请、替换并验证证书，CA 有申请频率限制')
    await dialogButton('取消')
    expect(vi.mocked(api).mock.calls.every(([path]) => path === '/api/status')).toBe(true)
  })
  it('确认仅发送renew空对象，排队和运行均不可重复，只有服务器最终成功才显示成功', async () => {
    let current = status()
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/status') return current
      current = { ...status(), manual_renewal: renewal('queued') }
      return { accepted: true, message: '立即申请任务已提交', request_id: 'request-new', manual_renewal: current.manual_renewal }
    })
    wrapper = mount(OverviewView)
    await flushPromises()
    await confirmRenewal()
    expect(api).toHaveBeenCalledWith('/api/actions/renew', expect.objectContaining({ method: 'POST', body: {} }))
    expect(wrapper.text()).toContain('等待立即换证')
    expect(wrapper.text()).not.toContain('申请替换成功')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    await pageButton('立即申请并替换证书').trigger('click')
    await flushPromises()
    expect(vi.mocked(api).mock.calls.filter(([path]) => path === '/api/actions/renew')).toHaveLength(1)
    expect(vi.mocked(api).mock.calls.some(([path]) => ['/api/actions/run', '/api/actions/check'].includes(path))).toBe(false)
    current = { ...status(), manual_renewal: renewal('running') }
    await pageButton('刷新状态').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('正在申请并替换')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    current = { ...status(), manual_renewal: { ...renewal('succeeded'), completed_at: '2026-12-22T00:01:00Z', cooldown_until: '2026-12-22T01:00:00Z' } }
    await pageButton('刷新状态').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('申请替换成功')
    expect(wrapper.text()).toContain('服务器结果 succeeded')
    expect(wrapper.text()).not.toContain('立即申请任务已提交')
    expect(wrapper.text()).toContain('下次可申请时间：2026/12/22 09:00:00')
    expect(pageButton('运行一次续期任务').attributes('disabled')).toBeUndefined()
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
  })
  it('提交后不会被旧请求结果解除等待，超过普通任务30秒仍等待本次请求', async () => {
    vi.useFakeTimers()
    let current = { ...status(), manual_renewal: renewal('succeeded', 'request-old') }
    vi.mocked(api).mockImplementation(async (path) => path === '/api/status' ? current : { accepted: true, request_id: 'request-new', message: '任务已提交' })
    wrapper = mount(OverviewView)
    await flushPromises()
    await confirmRenewal()
    await vi.advanceTimersByTimeAsync(31000)
    expect(wrapper.text()).toContain('等待任务启动')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    current = { ...status(), manual_renewal: renewal('failed') }
    await pageButton('刷新状态').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('申请替换失败')
    expect(wrapper.text()).not.toContain('等待任务启动')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeUndefined()
  })
  it.each(['queued', 'running'] as const)('刷新恢复%s时阻止所有重复任务', async (state) => {
    vi.mocked(api).mockResolvedValue({ ...status(), manual_renewal: renewal(state) })
    wrapper = mount(OverviewView)
    await flushPromises()
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    expect(wrapper!.findAll('button').filter((node) => node.text().includes('任务处理中')).every((node) => node.attributes('disabled') !== undefined)).toBe(true)
  })
  it('其他会话的新申请覆盖记录后解除旧等待，但不确认旧请求成功', async () => {
    let current = status()
    vi.mocked(api).mockImplementation(async (path) => path === '/api/status' ? current : {
      accepted: true, request_id: 'request-A', message: '任务已提交',
    })
    wrapper = mount(OverviewView)
    await flushPromises()
    await confirmRenewal()
    current = { ...status(), manual_renewal: renewal('running', 'request-A') }
    await pageButton('刷新状态').trigger('click')
    await flushPromises()
    current = { ...status(), manual_renewal: renewal('failed', 'request-B') }
    await pageButton('刷新状态').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('此前请求的结果未在本页确认')
    expect(wrapper.text()).not.toContain('申请替换成功')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeUndefined()
    expect(pageButton('运行一次续期任务').attributes('disabled')).toBeUndefined()
  })
  it.each(['deployment', 'dns_cleanup', 'notification', 'interrupted'] as const)('存在%s待恢复时先运行恢复，禁止立即申请', async (key) => {
    const current = status()
    current.pending[key] = true
    vi.mocked(api).mockResolvedValue(current)
    wrapper = mount(OverviewView)
    await flushPromises()
    expect(wrapper.text()).toContain('请先运行一次续期任务完成恢复')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    expect(pageButton('运行一次续期任务').attributes('disabled')).toBeUndefined()
  })
  it('冷却依据服务器时间展示并在结束后解除，旧运行检查继续可用', async () => {
    vi.useFakeTimers()
    vi.mocked(api).mockResolvedValue({ ...status(), manual_renewal: { ...renewal('failed'), cooldown_until: '2026-12-22T00:00:02Z' } })
    wrapper = mount(OverviewView)
    await flushPromises()
    expect(wrapper.text()).toContain('立即申请间隔至少一小时')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    expect(pageButton('立即检查').attributes('disabled')).toBeUndefined()
    expect(pageButton('运行一次续期任务').attributes('disabled')).toBeUndefined()
    await vi.advanceTimersByTimeAsync(2000)
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeUndefined()
  })
  it('提交失败恢复可操作，提交后读取失败保留等待，恢复连接显示真实失败结果', async () => {
    let current = status()
    let rejected = true
    let statusUnavailable = false
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/status') {
        if (statusUnavailable) throw new ApiError('状态读取失败')
        return current
      }
      if (rejected) throw new ApiError('操作冲突', 409, 'conflict')
      statusUnavailable = true
      return { accepted: true, message: '已提交', request_id: 'request-new' }
    })
    wrapper = mount(OverviewView)
    await flushPromises()
    await confirmRenewal()
    expect(wrapper.text()).toContain('操作冲突')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeUndefined()
    rejected = false
    await confirmRenewal()
    expect(wrapper.text()).toContain('状态读取失败')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeDefined()
    statusUnavailable = false
    current = { ...status(), manual_renewal: renewal('expired') }
    await pageButton('刷新状态').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('申请请求已过期')
    expect(wrapper.text()).not.toContain('状态读取失败')
    expect(wrapper.text()).not.toContain('申请替换成功')
    expect(pageButton('立即申请并替换证书').attributes('disabled')).toBeUndefined()
  })
})
