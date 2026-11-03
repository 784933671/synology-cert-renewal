<script setup lang="ts">
import { reactive, shallowRef } from 'vue'
import { api, errorText } from '../lib/api'
import type { Session } from '../types'
import NoticeBar from '../components/NoticeBar.vue'
defineProps<{ session: Session }>()
const emit = defineEmits<{
  changed: [session: Session]
  busy: [value: boolean]
}>()
const form = reactive({ current: '', next: '', confirm: '' })
const busy = shallowRef(false),
  error = shallowRef(''),
  success = shallowRef('')
async function submit() {
  if (busy.value) return
  error.value = ''
  success.value = ''
  if (
    form.next.length < 12 ||
    form.next.length > 128 ||
    /[\x00-\x1f\x7f]/.test(form.next)
  ) {
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
  form.current = ''
  form.next = ''
  form.confirm = ''
  busy.value = true
  emit('busy', true)
  try {
    emit(
      'changed',
      await api<Session>('/api/password', { method: 'POST', body }),
    )
    success.value = '密码已更新，其他登录会话已退出。'
  } catch (cause) {
    error.value = errorText(cause)
  } finally {
    body.current_password = ''
    body.new_password = ''
    busy.value = false
    emit('busy', false)
  }
}
</script>
<template>
  <div class="page-heading">
    <div>
      <h1>
        {{ session.must_change_password ? '设置专用登录密码' : '账户设置' }}
      </h1>
      <p>管理账号 {{ session.username }} 的登录密码。</p>
    </div>
  </div>
  <NoticeBar v-if="session.must_change_password" type="warning">
    首次登录需要更换初始密码，完成后即可管理证书。
  </NoticeBar>
  <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
  <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
  <form class="panel account-form" @submit.prevent="submit">
    <header class="panel-heading"><h2>修改密码</h2></header>
    <fieldset class="panel-body form-stack" :disabled="busy">
      <input
        class="visually-hidden"
        autocomplete="username"
        :value="session.username"
        tabindex="-1"
        aria-hidden="true"
      />
      <label class="field">
        当前密码
        <input
          v-model="form.current"
          class="input"
          type="password"
          autocomplete="current-password"
          required
          maxlength="128"
        />
      </label>
      <label class="field">
        新密码
        <input
          v-model="form.next"
          class="input"
          type="password"
          autocomplete="new-password"
          required
          minlength="12"
          maxlength="128"
        />
        <span class="help">12～128 个字符，建议使用独立的长密码。</span>
      </label>
      <label class="field">
        再次输入新密码
        <input
          v-model="form.confirm"
          class="input"
          type="password"
          autocomplete="new-password"
          required
          minlength="12"
          maxlength="128"
        />
      </label>
      <div class="form-actions">
        <button class="button primary" type="submit">
          {{ busy ? '正在更新…' : '更新密码' }}
        </button>
      </div>
    </fieldset>
  </form>
</template>
