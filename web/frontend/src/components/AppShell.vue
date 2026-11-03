<script setup lang="ts">
import { shallowRef, watch } from 'vue'
import AppIcon from './AppIcon.vue'
import type { Page } from '../types'
const props = defineProps<{
  page: Page
  username: string
  locked: boolean
  busy: boolean
}>()
const emit = defineEmits<{ navigate: [page: Page]; logout: [] }>()
const open = shallowRef(false)
const items: { id: Page; label: string }[] = [
  { id: 'overview', label: '运行概览' },
  { id: 'certificate', label: '证书管理' },
  { id: 'renewal', label: '续期计划' },
  { id: 'notifications', label: '邮件通知' },
  { id: 'failures', label: '失败记录' },
  { id: 'audit', label: '操作审计' },
  { id: 'security', label: '访问安全' },
]
watch(
  () => props.page,
  () => {
    open.value = false
  },
)
function navigate(page: Page) {
  emit('navigate', page)
  open.value = false
}
</script>
<template>
  <div class="shell" @keydown.esc="open = false">
    <button
      v-if="open"
      class="nav-scrim"
      aria-label="关闭导航"
      @click="open = false"
    />
    <aside id="main-navigation" :class="['sidebar', { open }]">
      <div class="brand">
        <span class="brand-mark"><AppIcon name="shield" /></span>
        <div>
          <div class="brand-name">证书管家</div>
          <span class="brand-subtitle">NAS CERTIFICATE MANAGER</span>
        </div>
      </div>
      <div class="nav-label">管理中心</div>
      <nav aria-label="管理导航">
        <button
          v-for="item in items"
          :key="item.id"
          :class="['nav-item', { active: page === item.id }]"
          :aria-current="page === item.id ? 'page' : undefined"
          :disabled="locked"
          @click="navigate(item.id)"
        >
          <AppIcon :name="item.id" />
          {{ item.label }}
        </button>
      </nav>
      <div class="sidebar-footer">
        <button
          :class="['nav-item', { active: page === 'account' }]"
          @click="navigate('account')"
        >
          <AppIcon name="account" />
          账户设置
        </button>
        <div class="device-card">
          <AppIcon name="server" />
          <div>
            群晖证书管理
            <span>自动检查 · 按需续期</span>
          </div>
        </div>
      </div>
    </aside>
    <div class="main">
      <header class="topbar">
        <button
          class="icon-button mobile-menu"
          aria-label="打开导航"
          aria-controls="main-navigation"
          :aria-expanded="open"
          @click="open = !open"
        >
          <AppIcon name="menu" />
        </button>
        <div class="breadcrumb">
          管理中心
          <span>/</span>
          <b>
            {{ items.find((item) => item.id === page)?.label || '账户设置' }}
          </b>
        </div>
        <div class="topbar-actions">
          <button class="user-button" @click="navigate('account')">
            <span class="avatar"><AppIcon name="account" /></span>
            <span class="user-name">{{ username }}</span>
          </button>
          <button
            class="icon-button"
            aria-label="退出登录"
            title="退出登录"
            :disabled="busy"
            @click="emit('logout')"
          >
            <AppIcon name="logout" />
          </button>
        </div>
      </header>
      <main id="main-content" class="page"><slot /></main>
    </div>
  </div>
</template>
