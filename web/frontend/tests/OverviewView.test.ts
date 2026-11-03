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
})
