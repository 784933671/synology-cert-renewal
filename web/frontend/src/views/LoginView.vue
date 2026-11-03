<script setup lang="ts">
import { reactive, watch } from 'vue'
import { Button as AButton, Card as ACard, Form as AForm, Input as AInput, Space as ASpace } from 'ant-design-vue'
import type { LoginChallenge } from '../types'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import '../styles/shell.css'
const AFormItem = AForm.Item
const AInputPassword = AInput.Password
const props = withDefaults(defineProps<{
  busy: boolean
  error: string
  challenge?: LoginChallenge | null
  expiresIn?: number
  resendAfter?: number
  recoveryRequired?: boolean
}>(), { challenge: null, expiresIn: 0, resendAfter: 0, recoveryRequired: false })
const emit = defineEmits<{
  login: [username: string, password: string]
  verify: [code: string]
  resend: []
  cancel: []
  recover: []
}>()
const form = reactive({ username: '', password: '', code: '' })
function submit() {
  if (props.busy || props.recoveryRequired || !form.username.trim() || !form.password) return
  const password = form.password
  form.password = ''
  emit('login', form.username.trim(), password)
}
function verify() {
  if (props.busy || props.recoveryRequired || !props.expiresIn || !/^[0-9]{6}$/.test(form.code)) return
  const code = form.code
  form.code = ''
  emit('verify', code)
}
function resend() {
  form.code = ''
  emit('resend')
}
function cancel() {
  form.password = form.code = ''
  emit('cancel')
}
watch(() => props.challenge, () => { form.password = form.code = '' })
</script>
<template>
  <main class="cert-login-page">
    <div class="cert-login-brand">
      <span class="cert-brand-mark"><AppIcon name="shield" /></span>
      <strong>证书管家</strong>
    </div>
    <ACard class="cert-login-card" :bordered="false">
      <div class="cert-login-heading">
        <h1>{{ challenge ? '验证登录邮箱' : '登录证书管家' }}</h1>
        <p v-if="challenge">请输入发送至 {{ challenge.email_masked }} 的验证码</p>
        <p v-else>使用管理员账号访问管理中心</p>
      </div>
      <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
      <template v-if="recoveryRequired">
        <NoticeBar type="warning">登录状态尚未确认，请重新连接后继续。</NoticeBar>
        <AButton type="primary" block :loading="busy" :disabled="busy" @click="emit('recover')">重新确认登录状态</AButton>
      </template>
      <AForm v-else-if="challenge" :model="form" layout="vertical" class="cert-login-form" :required-mark="false" @finish="verify">
        <AFormItem label="邮箱验证码" html-for="login-code" name="code" :rules="[{ required: true, pattern: /^[0-9]{6}$/, message: '请输入 6 位数字验证码' }]">
          <AInput id="login-code" v-model:value="form.code" name="code" :maxlength="6" inputmode="numeric" autocomplete="one-time-code" :disabled="busy || !expiresIn" size="large" />
        </AFormItem>
        <p class="cert-login-countdown" role="status">{{ expiresIn ? `验证码 ${expiresIn} 秒内有效` : '验证码已过期或暂不可用，请重新发送。' }}</p>
        <AButton type="primary" html-type="submit" size="large" block :loading="busy" :disabled="busy || !expiresIn">验证并登录</AButton>
        <ASpace class="cert-login-secondary" wrap>
          <AButton :disabled="busy || resendAfter > 0" @click="resend">{{ resendAfter ? `${resendAfter} 秒后可重新发送` : '重新发送验证码' }}</AButton>
          <AButton type="link" :disabled="busy" @click="cancel">返回登录</AButton>
        </ASpace>
      </AForm>
      <AForm v-else :model="form" layout="vertical" class="cert-login-form" :required-mark="false" @finish="submit">
        <AFormItem label="管理员账号" html-for="login-username" name="username" :rules="[{ required: true, whitespace: true, message: '请输入管理员账号' }]">
          <AInput id="login-username" v-model:value="form.username" name="username" :maxlength="64" autocomplete="username" autofocus :disabled="busy" size="large">
            <template #prefix><AppIcon name="account" /></template>
          </AInput>
        </AFormItem>
        <AFormItem label="登录密码" html-for="login-password" name="password" :rules="[{ required: true, message: '请输入登录密码' }]">
          <AInputPassword id="login-password" v-model:value="form.password" name="password" :maxlength="128" autocomplete="current-password" :disabled="busy" size="large">
            <template #prefix><AppIcon name="security" /></template>
          </AInputPassword>
        </AFormItem>
        <AButton type="primary" html-type="submit" size="large" block :loading="busy" :disabled="busy">{{ busy ? '正在登录…' : '登录' }}</AButton>
      </AForm>
      <p class="cert-login-security"><AppIcon name="security" />请在受信任的设备上管理证书。</p>
    </ACard>
    <p class="cert-login-footer">证书状态 · 自动续期 · 通知与审计</p>
  </main>
</template>
