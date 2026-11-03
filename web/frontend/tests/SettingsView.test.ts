import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { api, ApiError } from '../src/lib/api'
import SettingsView from '../src/views/SettingsView.vue'
import { settings } from './fixtures'
vi.mock('../src/lib/api', async (original) => ({
  ...(await original<typeof import('../src/lib/api')>()),
  api: vi.fn(),
}))
let wrapper: VueWrapper | undefined
afterEach(() => {
  wrapper?.unmount()
  vi.mocked(api).mockReset()
})
function input(label: string) {
  return wrapper!
    .findAll('label')
    .find((node) => node.text().includes(label))!
    .get('input')
}
describe('配置编辑完整状态', () => {
  it('不兼容证书禁选并显示原因，旧数据省略字段仍可选择', async () => {
    const value = settings()
    value.certificates[1].selectable = false
    value.certificates[1].reason = '未覆盖管理域名 ttxli.cn'
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { props: { section: 'certificate' } })
    await flushPromises()
    const disabled = wrapper.get('option[value="b"]')
    expect(disabled.attributes('disabled')).toBeDefined()
    expect(disabled.text()).toContain('未覆盖管理域名 ttxli.cn')
    expect(
      wrapper.get('option[value="a"]').attributes('disabled'),
    ).toBeUndefined()
  })
  it('保存冲突保留邮箱和新密钥草稿，不尝试覆盖其他用户修改', async () => {
    vi.mocked(api)
      .mockResolvedValueOnce(settings())
      .mockRejectedValueOnce(
        new ApiError('服务器配置已经改变', 409, 'revision_conflict'),
      )
    wrapper = mount(SettingsView, { props: { section: 'certificate' } })
    await flushPromises()
    expect(input('新 SecretId').element.value).toBe('')
    await input('证书注册邮箱').setValue('updated@example.com')
    await input('新 SecretId').setValue('AKIDnew')
    await input('新 SecretKey').setValue('new-secret')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('当前草稿已保留')
    expect(input('证书注册邮箱').element.value).toBe('updated@example.com')
    expect(input('新 SecretKey').element.value).toBe('new-secret')
    expect(
      wrapper
        .findAll('button')
        .find((button) => button.text() === '保存配置')!
        .attributes('disabled'),
    ).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenCalledTimes(2)
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([true])
  })
  it('成功保存后清空新密钥，并恢复已保存状态', async () => {
    const latest = settings()
    latest.revision = 'revision-two'
    vi.mocked(api)
      .mockResolvedValueOnce(settings())
      .mockResolvedValueOnce(latest)
    wrapper = mount(SettingsView, { props: { section: 'certificate' } })
    await flushPromises()
    await input('新 SecretId').setValue('AKIDnew')
    await input('新 SecretKey').setValue('new-secret')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('配置已保存并生效')
    expect(input('新 SecretId').element.value).toBe('')
    expect(input('新 SecretKey').element.value).toBe('')
    expect(wrapper.emitted('dirty')?.at(-1)).toEqual([false])
  })
  it('读取失败显示错误且允许重新读取，无假配置兜底', async () => {
    vi.mocked(api)
      .mockRejectedValueOnce(new ApiError('连接不可用'))
      .mockResolvedValueOnce(settings())
    wrapper = mount(SettingsView, { props: { section: 'renewal' } })
    await flushPromises()
    expect(wrapper.text()).toContain('连接不可用')
    expect(wrapper.find('form').exists()).toBe(false)
    await wrapper
      .findAll('button')
      .find((button) => button.text() === '重试')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.find('form').exists()).toBe(true)
  })
  it('未知计划只读，不允许按默认时间覆盖', async () => {
    const value = settings()
    value.schedule.mode = 'unsupported'
    value.schedule.editable = false
    vi.mocked(api).mockResolvedValueOnce(value)
    wrapper = mount(SettingsView, { props: { section: 'renewal' } })
    await flushPromises()
    expect(wrapper.text()).toContain('配置已设为只读')
    expect(
      wrapper.get('fieldset.settings-fields').attributes('disabled'),
    ).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api).toHaveBeenCalledOnce()
  })
})
