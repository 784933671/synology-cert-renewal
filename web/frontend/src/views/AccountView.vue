<script setup lang="ts">
import { computed, onUnmounted, reactive, shallowRef, watch } from 'vue'
import { Button as AButton, Card as ACard, Form as AForm, Input as AInput, Tag as ATag } from 'ant-design-vue'
import { api, ApiError, errorText, isAborted } from '../lib/api'
import type { Session } from '../types'
import NoticeBar from '../components/NoticeBar.vue'
import '../styles/shell.css'
const AFormItem = AForm.Item
const AInputPassword = AInput.Password
const props = withDefaults(defineProps<{
  session: Session
  restoreSession: (signal?: AbortSignal) => Promise<Session | null | undefined>
  sessionBusy?: boolean
}>(), { sessionBusy: false })
const emit = defineEmits<{
  changed: [session: Session]
  busy: [value: boolean]
  relogin: []
}>()
const form = reactive({ current: '', next: '', confirm: '' })
const busy = shallowRef(false), error = shallowRef(''), success = shallowRef('')
const uncertain = shallowRef(false), recovering = shallowRef(false)
const locked = computed(() => busy.value || uncertain.value)
const controller = new AbortController()
let disposed = false, previousCsrf = ''
watch(locked, (value) => emit('busy', value), { flush: 'sync' })
async function confirmSession() {
  if (disposed || recovering.value || !uncertain.value) return
  recovering.value = true
  error.value = ''
  try {
    const current = await props.restoreSession(controller.signal)
    if (disposed) return
    if (current) {
      if (current.csrf_token !== previousCsrf) {
        uncertain.value = false
        success.value = '登录状态已恢复，可以继续操作。'
      } else error.value = '密码更新仍未确认，请继续确认，或退出后重新登录。'
    } else if (current === undefined) {
      error.value = '暂时无法确认登录状态，请恢复连接后重新确认。'
    }
  } catch (cause) {
    if (!disposed && !isAborted(cause)) error.value = '暂时无法确认登录状态，请恢复连接后重新确认。'
  } finally {
    recovering.value = false
  }
}
async function submit() {
  if (locked.value || disposed) return
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
  previousCsrf = props.session.csrf_token
  try {
    const current = await api<Session>('/api/password', { method: 'POST', body, signal: controller.signal })
    if (disposed) return
    emit('changed', current)
    success.value = '密码已更新，其他登录会话已退出。'
  } catch (cause) {
    if (disposed || isAborted(cause)) return
    if (!(cause instanceof ApiError) || !cause.status || cause.status >= 500 || cause.code === 'invalid_response') {
      // Cookie 可能已轮换；先同步会话，避免继续使用旧 CSRF 重复改密。
      uncertain.value = true
      await confirmSession()
    } else error.value = errorText(cause)
  } finally {
    body.current_password = body.new_password = ''
    busy.value = false
  }
}
onUnmounted(() => {
  disposed = true
  controller.abort()
  form.current = form.next = form.confirm = ''
  emit('busy', false)
})
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
  <NoticeBar v-if="uncertain" type="warning">
    密码更新结果尚未确认，可能已经生效。请先确认登录状态，避免重复修改密码。
    <AButton html-type="button" :loading="recovering" :disabled="recovering || busy || sessionBusy" @click="confirmSession">{{ recovering ? '正在确认登录状态…' : '重新确认登录状态' }}</AButton>
    <AButton html-type="button" type="link" :loading="sessionBusy && !recovering" :disabled="recovering || busy || sessionBusy" @click="emit('relogin')">退出并重新登录</AButton>
  </NoticeBar>
  <ACard class="cert-account-card cert-login-verification" title="登录验证">
    <ATag :color="session.email_verification_enabled ? 'success' : 'default'">{{ session.email_verification_enabled ? '邮箱二步验证已启用' : '邮箱二步验证未启用' }}</ATag>
    <p v-if="session.email_verification_enabled">密码验证后，还需通过 {{ session.login_email_masked || '已绑定邮箱' }} 接收的验证码完成登录。</p>
    <p v-else>当前使用管理员账号和密码登录。</p>
    <p class="monitoring-muted">登录验证邮箱与证书通知邮箱独立，修改通知邮箱不会更改登录验证邮箱。</p>
  </ACard>
  <ACard class="cert-account-card" title="修改密码">
    <AForm :model="form" layout="vertical" class="cert-account-form" :required-mark="false" :disabled="locked" @finish="submit">
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
        <AButton type="primary" html-type="submit" :loading="busy" :disabled="locked">{{ busy ? '正在更新…' : '更新密码' }}</AButton>
      </div>
    </AForm>
  </ACard>
</template>
