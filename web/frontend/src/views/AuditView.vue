<script setup lang="ts">
import { computed } from 'vue'
import { Button, Card, Empty, Table, Tag, type TableColumnsType } from 'ant-design-vue'
import { useResource } from '../composables/useResource'
import type { AuditItem } from '../types'
import { dateText } from '../lib/format'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'

const { data, loading, error, reload } = useResource<{ items: AuditItem[] }>('/api/audit')
const rows = computed(() => data.value?.items.map((item, index) => ({ ...item, key: `${item.at}-${index}` })) || [])
const actions: Record<string, string> = {
  initialize: '初始化管理员', password_reset: '重置管理员密码', login: '登录', logout: '退出登录',
  password: '修改密码', 'password.change': '修改密码', 'settings.update': '更新配置',
  'monitor.update': '修改预警设置',
  'security.update': '修改访问模式', run: '手动运行任务', check: '手动检查',
  'actions.run': '手动运行任务', 'actions.check': '手动检查',
}
const columns: TableColumnsType<AuditItem> = [
  { title: '时间', key: 'at', dataIndex: 'at', width: 190 },
  { title: '操作', key: 'action', dataIndex: 'action', width: 170 },
  { title: '结果', key: 'success', dataIndex: 'success', width: 100 },
  { title: '说明', key: 'message', dataIndex: 'message' },
]
const pagination = { pageSize: 10, showSizeChanger: false, showTotal: (total: number) => `共 ${total} 条记录` }
</script>

<template>
  <div class="monitoring-page">
    <div class="page-heading">
      <div><h1>操作审计</h1><p>查询登录、配置修改和手动操作记录。</p></div>
      <Button :loading="loading" @click="reload">
        <template #icon><AppIcon name="refresh" /></template>
        {{ loading ? '读取中…' : '刷新记录' }}
      </Button>
    </div>
    <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方为上次读取的记录。</span></NoticeBar>
    <Card title="最近操作" class="monitoring-table-card">
      <template #extra><Tag v-if="data">{{ data.items.length }} 条记录</Tag></template>
      <Table :columns="columns" :data-source="rows" row-key="key" :loading="{ spinning: loading, tip: '正在读取操作记录…' }" :pagination="pagination" :scroll="{ x: 760 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'at'"><span class="monitoring-nowrap">{{ dateText(record.at) }}</span></template>
          <template v-else-if="column.key === 'action'">{{ actions[record.action] || record.action }}</template>
          <template v-else-if="column.key === 'success'"><Tag :color="record.success ? 'success' : 'error'">{{ record.success ? '成功' : '失败' }}</Tag></template>
          <template v-else-if="column.key === 'message'"><span class="monitoring-break-word">{{ record.message || '—' }}</span></template>
        </template>
        <template #emptyText>
          <Empty :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="loading ? '正在读取操作记录…' : data ? '暂无操作记录' : '暂时无法读取记录'">
            <p v-if="!loading" class="monitoring-muted">登录与关键操作将自动记录。</p>
          </Empty>
        </template>
      </Table>
    </Card>
  </div>
</template>
