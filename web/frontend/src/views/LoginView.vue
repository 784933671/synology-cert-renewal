<script setup lang="ts">
import { reactive } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
const props = defineProps<{ busy: boolean; error: string }>()
const emit = defineEmits<{ login: [username: string, password: string] }>()
const form = reactive({ username: '', password: '' })
function submit() {
  if (props.busy) return
  emit('login', form.username.trim(), form.password)
  form.password = ''
}
</script>
<template>
  <main class="login-page">
    <section class="login-art">
      <span class="brand-mark"><AppIcon name="shield" /></span>
      <h1>
        群晖证书，
        <br />
        有序管理。
      </h1>
      <p>
        查看证书状态、设置自动续期，
        <br />
        让每次更新都有迹可循。
      </p>
      <div class="login-service">
        <AppIcon name="server" />
        NAS CERTIFICATE MANAGER
      </div>
    </section>
    <section class="login-panel">
      <form class="login-form" @submit.prevent="submit">
        <h2>登录证书管家</h2>
        <p class="muted">使用管理员账号访问管理中心</p>
        <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
        <label class="field">
          管理员账号
          <input
            v-model="form.username"
            class="input"
            name="username"
            required
            maxlength="64"
            autocomplete="username"
            autofocus
            :disabled="busy"
          />
        </label>
        <label class="field">
          登录密码
          <input
            v-model="form.password"
            class="input"
            name="password"
            type="password"
            required
            maxlength="128"
            autocomplete="current-password"
            :disabled="busy"
          />
        </label>
        <button class="button primary" type="submit" :disabled="busy">
          {{ busy ? '正在登录…' : '登录' }}
        </button>
        <p class="help">
          <AppIcon name="security" />
          请在受信任的设备上管理证书。
        </p>
      </form>
    </section>
  </main>
</template>
