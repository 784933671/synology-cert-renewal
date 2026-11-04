<script setup lang="ts">
import { computed } from 'vue'
import { Button, Card, Empty, Table, Tag, type TableColumnsType } from 'ant-design-vue'
import { useResource } from '../composables/useResource'
import { dateText } from '../lib/format'
import { deviceText } from '../lib/security'
import type { SecurityAlert } from '../types'
import NoticeBar from './NoticeBar.vue'
defineProps<{ email?: string; enabled: boolean }>()
const { data, loading, error, reload } = useResource<{ items: SecurityAlert[]; pending_count: number }>('/api/security-alerts')
const rows = computed(() => Array.isArray(data.value?.items) ? data.value.items : [])
const events = { new_login: '新来源登录', login_failures: '连续登录失败', security_change: '安全设置变更' }
const statuses = { pending: '等待发送', sending: '正在发送', sent: '已发送', failed: '发送失败' }
const colors = { pending: 'warning', sending: 'processing', sent: 'success', failed: 'error' }
const columns: TableColumnsType<SecurityAlert> = [
  { title: '事件', dataIndex: 'event_type', key: 'event_type' }, { title: '时间', key: 'at', width: 180 },
  { title: '来源', key: 'source' }, { title: '邮件状态', key: 'status', width: 120 },
]
</script>
<template>
  <Card title="登录安全提醒" class="cert-security-card">
    <template #extra><Button :loading="loading" @click="reload">刷新提醒</Button></template>
    <Tag :color="enabled ? 'success' : 'warning'">{{ enabled ? '安全邮件提醒已启用' : '登录邮箱尚未启用' }}</Tag>
    <p>提醒发送至 {{ email || '已绑定登录邮箱' }}，与证书通知邮箱独立。</p>
    <p class="monitoring-muted">新来源登录、连续登录失败和安全设置变更将触发提醒；同类重复事件按服务器规则合并，避免重复发信。</p>
    <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方保留上次读取的记录。</span></NoticeBar>
    <NoticeBar v-if="data?.pending_count" type="warning">{{ data.pending_count }} 封安全提醒正在等待发送或重试，邮件失败不会中断自动续期。</NoticeBar>
    <Table :columns="columns" :data-source="rows" row-key="id" :loading="loading" :pagination="{ pageSize: 5, showSizeChanger: false }" :scroll="{ x: 680 }">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'event_type'">{{ events[record.event_type as keyof typeof events] || '安全事件' }}</template>
        <template v-else-if="column.key === 'at'">{{ dateText(record.at) }}</template>
        <template v-else-if="column.key === 'source'">{{ record.source_ip || '来源未知' }}<div class="monitoring-muted">{{ deviceText(record.device) }}</div></template>
        <template v-else-if="column.key === 'status'"><Tag :color="colors[record.status as keyof typeof colors]">{{ statuses[record.status as keyof typeof statuses] || '状态待确认' }}</Tag></template>
      </template>
      <template #emptyText><Empty :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="loading ? '正在读取安全提醒…' : error ? '暂时无法读取提醒' : '暂无安全提醒记录'" /></template>
    </Table>
  </Card>
</template>
