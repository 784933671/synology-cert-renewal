<script setup lang="ts">
import { computed, onMounted, onUnmounted, shallowRef, watch } from 'vue'
import { ConfigProvider as AConfigProvider, Spin as ASpin } from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import { useSession } from './composables/useSession'
import type { Page, SettingsPage } from './types'
import AppShell from './components/AppShell.vue'
import NoticeBar from './components/NoticeBar.vue'
import LoginView from './views/LoginView.vue'
import OverviewView from './views/OverviewView.vue'
import SettingsView from './views/SettingsView.vue'
import FailuresView from './views/FailuresView.vue'
import AuditView from './views/AuditView.vue'
import SecurityView from './views/SecurityView.vue'
import AccountView from './views/AccountView.vue'
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content || ''
const theme = {
  token: {
    colorPrimary: '#1677ff', colorBgLayout: '#f5f7fa', borderRadius: 8,
    fontSize: 14, controlHeight: 36,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  },
}
const { session, challenge, recoveryRequired, expiresIn, resendAfter, ready, busy, error, accept, login, verify, resend, cancel, logout, restore } = useSession()
const pages: Page[] = [
  'overview',
  'certificate',
  'renewal',
  'notifications',
  'failures',
  'audit',
  'security',
  'account',
]
const fromHash = () => {
  const value = location.hash.slice(1) as Page
  return pages.includes(value) ? value : 'overview'
}
const selected = shallowRef<Page>(fromHash()),
  dirty = shallowRef(false),
  working = shallowRef(false),
  notice = shallowRef('')
const page = computed(() =>
  session.value?.must_change_password ? 'account' : selected.value,
)
const settingsSection = computed(() =>
  ['certificate', 'renewal', 'notifications'].includes(page.value)
    ? (page.value as SettingsPage)
    : null,
)
function canLeave() {
  if (working.value) {
    notice.value = '当前操作尚未完成，请先确认操作结果。'
    return false
  }
  return (
    !dirty.value ||
    window.confirm('当前修改尚未保存，离开将放弃修改。是否继续？')
  )
}
function navigate(value: Page) {
  if (value === page.value || !canLeave()) return
  selected.value = value
  dirty.value = false
  notice.value = ''
  history.pushState(null, '', `#${value}`)
}
function hashChanged() {
  const value = fromHash()
  if (value === selected.value) return
  if (canLeave()) {
    selected.value = value
    dirty.value = false
    notice.value = ''
  } else history.replaceState(null, '', `#${selected.value}`)
}
async function signOut() {
  if (!canLeave()) return
  await logout()
}
function beforeUnload(event: BeforeUnloadEvent) {
  if (dirty.value || working.value) {
    event.preventDefault()
    event.returnValue = ''
  }
}
watch(session, (value) => {
  if (!value) {
    dirty.value = false
    working.value = false
    notice.value = ''
  }
})
watch(
  [page, session],
  ([value, currentSession]) => {
    window.scrollTo(0, 0)
    document.title = currentSession ? `${{ overview: '运行概览', certificate: '证书管理', renewal: '续期计划', notifications: '邮件通知', failures: '失败记录', audit: '操作审计', security: '访问安全', account: '账户设置' }[value]} · 证书管家` : '登录 · 证书管家'
  },
  { immediate: true },
)
onMounted(() => {
  window.addEventListener('hashchange', hashChanged)
  window.addEventListener('popstate', hashChanged)
  window.addEventListener('beforeunload', beforeUnload)
})
onUnmounted(() => {
  window.removeEventListener('hashchange', hashChanged)
  window.removeEventListener('popstate', hashChanged)
  window.removeEventListener('beforeunload', beforeUnload)
})
</script>
<template>
  <AConfigProvider :locale="zhCN" :theme="theme" :csp="{ nonce }" :wave="{ disabled: true }" :auto-insert-space-in-button="false">
  <div v-if="!ready" class="startup" role="status"><ASpin size="large" /><p>正在连接证书管理服务…</p></div>
  <LoginView v-else-if="!session" :busy="busy" :error="error" :challenge="challenge" :expires-in="expiresIn" :resend-after="resendAfter" :recovery-required="recoveryRequired" @login="login" @verify="verify" @resend="resend" @cancel="cancel" @recover="restore" />
  <AppShell
    v-else
    :page="page"
    :username="session.username"
    :locked="session.must_change_password"
    :busy="busy"
    @navigate="navigate"
    @logout="signOut"
  >
    <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
    <NoticeBar v-if="notice" type="warning">{{ notice }}</NoticeBar>
    <OverviewView v-if="page === 'overview'" />
    <SettingsView
      v-else-if="settingsSection"
      :key="settingsSection"
      :section="settingsSection"
      @dirty="dirty = $event"
      @busy="working = $event"
    />
    <FailuresView v-else-if="page === 'failures'" />
    <AuditView v-else-if="page === 'audit'" />
    <SecurityView
      v-else-if="page === 'security'"
      @dirty="dirty = $event"
      @busy="working = $event"
    />
    <AccountView
      v-else
      :session="session"
      :restore-session="restore"
      :session-busy="busy"
      @changed="accept"
      @busy="working = $event"
      @relogin="logout"
    />
  </AppShell>
  </AConfigProvider>
</template>
