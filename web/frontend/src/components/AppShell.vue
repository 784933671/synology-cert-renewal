<script setup lang="ts">
import { computed, h, shallowRef, watch } from 'vue'
import { Avatar as AAvatar, Breadcrumb as ABreadcrumb, Button as AButton, Drawer as ADrawer, Layout, Menu as AMenu, type MenuProps } from 'ant-design-vue'
import AppIcon from './AppIcon.vue'
import type { Page } from '../types'
import '../styles/shell.css'
const { Sider: ALayoutSider, Header: ALayoutHeader, Content: ALayoutContent } = Layout
const ABreadcrumbItem = ABreadcrumb.Item
const props = defineProps<{
  page: Page
  username: string
  locked: boolean
  busy: boolean
}>()
const emit = defineEmits<{ navigate: [page: Page]; logout: [] }>()
const open = shallowRef(false)
const labels: Record<Page, string> = {
  overview: '运行概览', certificate: '证书管理', renewal: '续期计划',
  notifications: '邮件通知', failures: '失败记录', audit: '操作审计',
  security: '访问安全', account: '账户设置',
}
const groups: { key: string; label: string; pages: Page[] }[] = [
  { key: 'certificate-group', label: '证书与续期', pages: ['overview', 'certificate', 'renewal', 'notifications'] },
  { key: 'activity-group', label: '运行维护', pages: ['failures', 'audit'] },
  { key: 'system-group', label: '系统设置', pages: ['security', 'account'] },
]
const items = computed<MenuProps['items']>(() => groups.map((group) => ({
  key: group.key,
  type: 'group',
  label: group.label,
  children: group.pages.map((page) => ({
    key: page,
    label: labels[page],
    icon: () => h(AppIcon, { name: page }),
    disabled: props.locked && page !== 'account',
  })),
})))
watch(() => props.page, () => { open.value = false })
function navigate(page: Page) {
  if (props.locked && page !== 'account') return
  emit('navigate', page)
  open.value = false
}
const menuClick: MenuProps['onClick'] = ({ key }) => {
  if (typeof key === 'string' && key in labels) navigate(key as Page)
}
</script>
<template>
  <Layout class="cert-shell">
    <ALayoutSider class="cert-sidebar" theme="light" :width="232">
      <div class="cert-brand">
        <span class="cert-brand-mark"><AppIcon name="shield" /></span>
        <div><strong>证书管家</strong><span>NAS 管理中心</span></div>
      </div>
      <nav aria-label="管理导航" class="cert-navigation">
        <AMenu mode="inline" :selected-keys="[page]" :items="items" @click="menuClick" />
      </nav>
      <div class="cert-sidebar-status">
        <AppIcon name="server" />
        <div><strong>群晖证书管理</strong><span>自动检查 · 按需续期</span></div>
      </div>
    </ALayoutSider>
    <Layout class="cert-main-layout">
      <ALayoutHeader class="cert-header">
        <AButton
          class="cert-mobile-menu"
          type="text"
          aria-label="打开导航"
          aria-controls="mobile-navigation"
          :aria-expanded="open"
          @click="open = true"
        ><template #icon><AppIcon name="menu" /></template></AButton>
        <ABreadcrumb class="cert-breadcrumb">
          <ABreadcrumbItem>管理中心</ABreadcrumbItem>
          <ABreadcrumbItem>{{ labels[page] }}</ABreadcrumbItem>
        </ABreadcrumb>
        <div class="cert-header-actions">
          <AButton class="cert-account-trigger" aria-label="账户设置" type="text" @click="navigate('account')">
            <AAvatar :size="28"><template #icon><AppIcon name="account" /></template></AAvatar>
            <span class="cert-user-name">{{ username }}</span>
          </AButton>
          <AButton type="text" aria-label="退出登录" title="退出登录" :loading="busy" :disabled="busy" @click="emit('logout')">
            <template #icon><AppIcon name="logout" /></template>
          </AButton>
        </div>
      </ALayoutHeader>
      <ALayoutContent class="cert-content">
        <div id="main-content" class="cert-page"><slot /></div>
      </ALayoutContent>
    </Layout>
    <ADrawer v-model:open="open" title="证书管家" placement="left" :width="280" root-class-name="cert-mobile-drawer">
      <nav id="mobile-navigation" aria-label="移动管理导航">
        <AMenu mode="inline" :selected-keys="[page]" :items="items" @click="menuClick" />
      </nav>
    </ADrawer>
  </Layout>
</template>
