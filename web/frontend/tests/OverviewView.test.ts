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
  vi.mocked(api).mockReset()
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
