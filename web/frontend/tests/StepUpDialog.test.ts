import { afterEach, describe, expect, it } from 'vitest'
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import StepUpDialog from '../src/components/StepUpDialog.vue'
let wrapper: VueWrapper | undefined
const meta = { challenge_id: 'challenge-a', email_masked: 'a***@example.com', expires_in: 300, resend_after: 60, operation: 'sessions.revoke' }
const props = { open: true, busy: false, error: '', operation: '撤销登录会话', challenge: meta, expiresIn: 300, resendAfter: 60, recoverSend: false, verifyUnknown: false }
const dom = () => new DOMWrapper(document.body)
const button = (label: string) => dom().findAll('button').find(node => node.text() === label)!
function render(overrides = {}) {
  wrapper = mount(StepUpDialog, { props: { ...props, ...overrides }, attachTo: document.body })
  return flushPromises()
}
afterEach(() => { wrapper?.unmount(); document.body.innerHTML = '' })
describe('真实 Ant 二次验证表单', () => {
  it('点击提交按钮会执行表单验证完成事件，发出验证码并立即清空输入', async () => {
    await render()
    await dom().get('input[name="stepup_code"]').setValue('123456')
    button('验证并执行本次操作').element.click()
    await flushPromises()
    expect(wrapper!.emitted('verify')).toEqual([['123456']])
    expect((dom().get('input[name="stepup_code"]').element as HTMLInputElement).value).toBe('')
    expect(dom().get('input[name="stepup_code"]').attributes('autocomplete')).toBe('one-time-code')
  })
  it('键盘提交同样触发验证，忙碌和过期状态禁用输入与提交按钮', async () => {
    await render()
    await dom().get('input[name="stepup_code"]').setValue('654321')
    await dom().get('form').trigger('submit')
    await flushPromises()
    expect(wrapper!.emitted('verify')).toEqual([['654321']])
    await wrapper!.setProps({ busy: true })
    expect(button('验证并执行本次操作').attributes('disabled')).toBeDefined()
    expect(dom().get('input').attributes('disabled')).toBeDefined()
    await wrapper!.setProps({ busy: false, expiresIn: 0 })
    expect(button('验证并执行本次操作').attributes('disabled')).toBeDefined()
    expect(dom().text()).toContain('验证码已过期')
  })
  it('发送必须主动触发，未知验证结果只提供取消且不会再次提交', async () => {
    await render({ challenge: null })
    expect(dom().find('input').exists()).toBe(false)
    await button('发送本次操作验证码').trigger('click')
    expect(wrapper!.emitted('send')).toHaveLength(1)
    await wrapper!.setProps({ challenge: meta, verifyUnknown: true, error: '验证结果尚未确认，本次操作未执行' })
    expect(dom().find('form').exists()).toBe(false)
    expect(dom().text()).toContain('本次操作未执行')
    await button('取消本次操作').trigger('click')
    expect(wrapper!.emitted('cancel')).toHaveLength(1)
    expect(wrapper!.emitted('verify')).toBeUndefined()
  })
})
