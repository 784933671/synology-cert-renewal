<script setup lang="ts">
import type { Component } from 'vue'
import {
  SafetyCertificateOutlined, AppstoreOutlined, FileProtectOutlined, StopOutlined,
  ClockCircleOutlined, MailOutlined, WarningOutlined, AuditOutlined,
  LockOutlined, UserOutlined, ReloadOutlined, CheckOutlined,
  MenuOutlined, CloseOutlined, LogoutOutlined, PlusOutlined, CloudServerOutlined, HeartOutlined, HistoryOutlined,
} from '@ant-design/icons-vue'
defineProps<{ name: string }>()
const icons: Record<string, Component> = {
  shield: SafetyCertificateOutlined, overview: AppstoreOutlined,
  health: HeartOutlined, runs: HistoryOutlined, abuse: StopOutlined,
  certificate: FileProtectOutlined, renewal: ClockCircleOutlined,
  notifications: MailOutlined, failures: WarningOutlined, audit: AuditOutlined,
  security: LockOutlined, account: UserOutlined, refresh: ReloadOutlined,
  check: CheckOutlined, menu: MenuOutlined, close: CloseOutlined,
  logout: LogoutOutlined, plus: PlusOutlined, server: CloudServerOutlined,
}
</script>
<template>
  <component :is="icons[name] || icons.shield" class="icon" aria-hidden="true" />
</template>
