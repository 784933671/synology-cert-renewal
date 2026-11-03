<script setup lang="ts">
import { reactive } from 'vue'
import { Button as AButton, Card as ACard, Form as AForm, Input as AInput } from 'ant-design-vue'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import '../styles/shell.css'
const AFormItem = AForm.Item
const AInputPassword = AInput.Password
const props = defineProps<{ busy: boolean; error: string }>()
const emit = defineEmits<{ login: [username: string, password: string] }>()
const form = reactive({ username: '', password: '' })
function submit() {
  if (props.busy || !form.username.trim() || !form.password) return
  emit('login', form.username.trim(), form.password)
  form.password = ''
}
</script>
<template>
  <main class="cert-login-page">
    <div class="cert-login-brand">
      <span class="cert-brand-mark"><AppIcon name="shield" /></span>
      <strong>证书管家</strong>
    </div>
    <ACard class="cert-login-card" :bordered="false">
      <div class="cert-login-heading">
        <h1>登录证书管家</h1>
        <p>使用管理员账号访问管理中心</p>
      </div>
      <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
      <AForm :model="form" layout="vertical" class="cert-login-form" :required-mark="false" @finish="submit">
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
        <AButton type="primary" html-type="submit" size="large" block :loading="busy" :disabled="busy">
          {{ busy ? '正在登录…' : '登录' }}
        </AButton>
      </AForm>
      <p class="cert-login-security"><AppIcon name="security" />请在受信任的设备上管理证书。</p>
    </ACard>
    <p class="cert-login-footer">证书状态 · 自动续期 · 通知与审计</p>
  </main>
</template>
