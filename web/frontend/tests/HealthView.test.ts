import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import HealthView from '../src/views/HealthView.vue'
import { health, monitorSettings, deferred } from './monitoring-fixtures'
import { snapshotExpired } from '../src/lib/monitoring'
vi.mock('../src/lib/api', async (original) => ({ ...(await original<typeof import('../src/lib/api')>()), api: vi.fn() }))
let wrapper: VueWrapper | undefined
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.mocked(api).mockReset(); vi.useRealTimers(); document.body.innerHTML = '' })
function button(label: string) { return wrapper!.findAll('button').find((node) => node.text() === label)! }
describe('运行健康', () => {
  it('展示五项真实健康和升级记录，并按时间找最近停服原因', async () => {
    const value = health()
    value.events = [
      { at: '2026-11-02T01:00:00Z', category: 'fault', status: 'blocked', stage: 'tls', message: '旧证书不可用' },
      { at: '2026-11-03T03:00:00Z', category: 'recovery', status: 'running', stage: 'running', message: '服务已恢复' },
      { at: '2026-11-03T02:00:00Z', category: 'maintenance', status: 'stopped', stage: 'shutdown', message: '升级期间主动停止' },
    ]
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? value : monitorSettings())
    wrapper = mount(HealthView)
    await flushPromises()
    expect(wrapper.findAll('.health-component')).toHaveLength(5)
    expect(wrapper.get('.health-runtime-card').text()).not.toContain('状态未知')
    expect(wrapper.get('.health-last-stop').text()).toContain('升级期间主动停止')
    expect(wrapper.get('.health-last-stop').text()).not.toContain('旧证书不可用')
    expect(wrapper.get('.health-events-card .ant-timeline-item').text()).toContain('服务已恢复')
    expect(wrapper.text()).toContain('升级完成')
    expect(wrapper.text()).toContain('a***@example.com')
  })
  it('服务器过期快照保留参考指标，但容器与所有健康项均不标绿', async () => {
    const value = health(); value.runtime.stale = true; value.monitor.stale = true
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? value : monitorSettings())
    wrapper = mount(HealthView); await flushPromises()
    expect(wrapper.get('.health-runtime-card').findAll('.ant-tag-success')).toHaveLength(0)
    expect(wrapper.get('.health-runtime-card').text()).toContain('当前服务状态未知')
    expect(wrapper.get('.health-container-details').text()).not.toContain('运行中')
    expect(wrapper.get('.health-container-details').text()).toContain('1 小时 0 分')
    expect(wrapper.get('.health-monitor-card').text()).toContain('状态未知')
  })
  it('本地单调时间推进后自动转未知，不受电脑日期跳变影响且离开页面停止计时', async () => {
    vi.useFakeTimers()
    let monotonic = 1000
    vi.spyOn(performance, 'now').mockImplementation(() => monotonic)
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? health() : monitorSettings())
    wrapper = mount(HealthView); await flushPromises()
    vi.setSystemTime(new Date('2099-01-01T00:00:00Z'))
    await vi.advanceTimersByTimeAsync(1000)
    expect(wrapper.get('.health-runtime-card').text()).not.toContain('状态未知')
    monotonic += 46000; await vi.advanceTimersByTimeAsync(1000)
    expect(wrapper.get('.health-runtime-card').text()).toContain('状态未知')
    expect(wrapper.get('.health-monitor-card').text()).not.toContain('状态未知')
    monotonic += 135000; await vi.advanceTimersByTimeAsync(1000)
    expect(wrapper.get('.health-monitor-card').text()).toContain('状态未知')
    const calls = vi.mocked(api).mock.calls.length
    wrapper.unmount(); wrapper = undefined
    await vi.advanceTimersByTimeAsync(600000)
    expect(api).toHaveBeenCalledTimes(calls)
  })
  it('任务暂停不显示正常，仍展示证书到期预警和失败通知状态', async () => {
    const value = health(); value.monitor.task_enabled = false; value.monitor.certificate_remaining_seconds = -1
    value.monitor.delivery = { enabled: false, recipient: '', last_error: '邮件服务器连接失败' }
    value.monitor.alerts = [{ code: 'certificate_expiry', label: '证书已到期', since: value.server_time, message: '请检查续期任务', notification_status: 'disabled' }]
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? value : monitorSettings())
    wrapper = mount(HealthView); await flushPromises()
    const panel = wrapper.get('.health-monitor-card')
    expect(panel.text()).toContain('自动续期任务已暂停')
    expect(panel.findAll('.ant-tag-success')).toHaveLength(0)
    expect(panel.text()).toContain('需要关注')
    expect(panel.text()).toContain('证书已到期')
    expect(panel.text()).toContain('邮件服务器连接失败')
    expect(panel.text()).toContain('通知已关闭')
    expect(panel.text()).not.toContain('本次监测未发现预警')
  })
  it('关闭监测、未知计划和未记录时间均不冒充正常执行', async () => {
    const value = health(); value.monitor.status = 'disabled'; value.monitor.schedule_supported = false
    value.monitor.last_completed_at = value.monitor.next_expected_at = null; value.monitor.missed_runs = null
    value.monitor.certificate_remaining_seconds = null
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? value : monitorSettings())
    wrapper = mount(HealthView); await flushPromises()
    const panel = wrapper.get('.health-monitor-card')
    expect(panel.text()).toContain('监测已关闭')
    expect(panel.text()).toContain('漏跑监测结果待确认')
    expect(panel.text()).toContain('暂无记录')
    expect(panel.text()).not.toContain('本次监测未发现预警')
  })
  it('初始加载、失败、重试和刷新旧数据各有提示，设置独立可读', async () => {
    const pending = deferred<ReturnType<typeof health>>()
    let reads = 0
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/monitor') return monitorSettings()
      if (++reads === 1) return pending.promise
      if (reads === 3) throw new ApiError('健康读取失败')
      return health()
    })
    wrapper = mount(HealthView); await flushPromises()
    expect(wrapper.text()).toContain('正在读取运行健康')
    pending.reject(new ApiError('初始连接失败')); await flushPromises()
    expect(wrapper.text()).toContain('暂时无法读取运行健康')
    expect(wrapper.text()).toContain('开启主动监测')
    await button('重新连接').trigger('click'); await flushPromises()
    await button('刷新健康状态').trigger('click'); await flushPromises()
    expect(wrapper.text()).toContain('下方保留上次读取的快照')
    expect(wrapper.get('.health-runtime-card').text()).toContain('状态未知')
    await button('刷新健康状态').trigger('click'); await flushPromises()
    expect(wrapper.text()).not.toContain('健康读取失败')
    expect(wrapper.get('.health-runtime-card').text()).not.toContain('状态未知')
  })
  it('缺失或未来检查时间视为未知，当前时区不参与快照计算', () => {
    expect(snapshotExpired('2026-11-03T04:00:00Z', null, 45, 0)).toBe(true)
    expect(snapshotExpired('2026-11-03T04:00:00Z', '2026-11-03T04:01:00Z', 45, 0)).toBe(true)
    expect(snapshotExpired('2026-11-03T12:00:00+08:00', '2026-11-03T04:00:00Z', 45, 1)).toBe(false)
  })
  it('监测状态未知且无预警记录时，不断言本次检查正常', async () => {
    const value = health(); value.monitor.status = 'unknown'
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? value : monitorSettings())
    wrapper = mount(HealthView); await flushPromises()
    const panel = wrapper.get('.health-monitor-card')
    expect(panel.text()).toContain('当前状态待确认')
    expect(panel.text()).not.toContain('本次监测未发现预警')
  })
  it.each(['disabled', 'stale'] as const)('%s快照投递关闭时不误判当前失败通知邮箱配置', async (mode) => {
    const value = health(); value.monitor.delivery.enabled = false
    if (mode === 'disabled') { value.monitor.status = 'disabled'; value.monitor.settings.enabled = false }
    else value.monitor.stale = true
    vi.mocked(api).mockImplementation(async (path) => path === '/api/health' ? value : monitorSettings())
    wrapper = mount(HealthView); await flushPromises()
    const panel = wrapper.get('.health-monitor-card')
    expect(panel.text()).not.toContain('失败通知已关闭或尚未配置收件邮箱')
    expect(panel.text()).toContain(mode === 'disabled' ? '主动监测已关闭' : '下方为最近监测记录')
  })
})
