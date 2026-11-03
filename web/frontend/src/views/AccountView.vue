<script setup lang="ts">
import { reactive, shallowRef } from 'vue'
import { Button as AButton, Card as ACard, Form as AForm, Input as AInput, Tag as ATag } from 'ant-design-vue'
import { api, errorText } from '../lib/api'
import type { Session } from '../types'
import NoticeBar from '../components/NoticeBar.vue'
import '../styles/shell.css'
const AFormItem = AForm.Item
const AInputPassword = AInput.Password
defineProps<{ session: Session }>()
const emit = defineEmits<{
  changed: [session: Session]
  busy: [value: boolean]
}>()
const form = reactive({ current: '', next: '', confirm: '' })
const busy = shallowRef(false), error = shallowRef(''), success = shallowRef('')
async function submit() {
  if (busy.value) return
  error.value = ''
  success.value = ''
  if (form.next.length < 12 || form.next.length > 128 || /[\x00-\x1f\x7f]/.test(form.next)) {
    error.value = '新密码须为 12～128 个字符，且不能包含控制字符。'
    return
  }
  if (form.next !== form.confirm) {
    error.value = '两次输入的新密码不一致。'
    return
  }
  if (form.next === form.current) {
    error.value = '新密码不能与当前密码相同。'
    return
  }
  const body = { current_password: form.current, new_password: form.next }
  form.current = form.next = form.confirm = ''
  busy.value = true
  emit('busy', true)
  try {
    emit('changed', await api<Session>('/api/password', { method: 'POST', body }))
    success.value = '密码已更新，其他登录会话已退出。'
  } catch (cause) {
    error.value = errorText(cause)
  } finally {
    body.current_password = body.new_password = ''
    busy.value = false
    emit('busy', false)
  }
}
</script>
<template>
  <div class="page-heading">
    <div>
      <h1>{{ session.must_change_password ? '设置专用登录密码' : '账户设置' }}</h1>
      <p>管理账号 {{ session.username }} 的登录密码。</p>
    </div>
    <ATag color="blue">管理员账户</ATag>
  </div>
  <NoticeBar v-if="session.must_change_password" type="warning">首次登录需要更换初始密码，完成后即可管理证书。</NoticeBar>
  <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
  <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
  <ACard class="cert-account-card cert-login-verification" title="登录验证">
    <ATag :color="session.email_verification_enabled ? 'success' : 'default'">{{ session.email_verification_enabled ? '邮箱二步验证已启用' : '邮箱二步验证未启用' }}</ATag>
    <p v-if="session.email_verification_enabled">密码验证后，还需通过 {{ session.login_email_masked || '已绑定邮箱' }} 接收的验证码完成登录。</p>
    <p v-else>当前使用管理员账号和密码登录。</p>
    <p class="monitoring-muted">登录验证邮箱与证书通知邮箱独立，修改通知邮箱不会更改登录验证邮箱。</p>
  </ACard>
  <ACard class="cert-account-card" title="修改密码">
    <AForm :model="form" layout="vertical" class="cert-account-form" :required-mark="false" :disabled="busy" @finish="submit">
      <input class="visually-hidden" autocomplete="username" :value="session.username" tabindex="-1" aria-hidden="true" />
      <AFormItem label="当前密码" html-for="account-current-password" name="current" :rules="[{ required: true, message: '请输入当前密码' }]">
        <AInputPassword id="account-current-password" v-model:value="form.current" name="current_password" autocomplete="current-password" :maxlength="128" />
      </AFormItem>
      <AFormItem label="新密码" html-for="account-new-password" name="next" extra="12～128 个字符，建议使用独立的长密码。" :rules="[{ required: true, message: '请输入新密码' }]">
        <AInputPassword id="account-new-password" v-model:value="form.next" name="new_password" autocomplete="new-password" :maxlength="128" />
      </AFormItem>
      <AFormItem label="再次输入新密码" html-for="account-confirm-password" name="confirm" :rules="[{ required: true, message: '请再次输入新密码' }]">
        <AInputPassword id="account-confirm-password" v-model:value="form.confirm" name="confirm_password" autocomplete="new-password" :maxlength="128" />
      </AFormItem>
      <div class="cert-account-actions">
        <AButton type="primary" html-type="submit" :loading="busy" :disabled="busy">{{ busy ? '正在更新…' : '更新密码' }}</AButton>
      </div>
    </AForm>
  </ACard>
</template>
