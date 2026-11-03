<script setup lang="ts">
import { shallowRef } from 'vue'
import { Button, Card, Empty, Table, Tag, type TableColumnsType } from 'ant-design-vue'
import { useResource } from '../composables/useResource'
import type { FailureItem } from '../types'
import { dateText } from '../lib/format'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import DialogPanel from '../components/DialogPanel.vue'
import FailureDetailPanel from '../components/FailureDetailPanel.vue'

const { data, loading, error, reload } = useResource<{ items: FailureItem[] }>('/api/failures')
const selected = shallowRef('')
const columns: TableColumnsType<FailureItem> = [
  { title: '发生时间', key: 'at', dataIndex: 'at', width: 190 },
  { title: '失败阶段', key: 'stage_label', dataIndex: 'stage_label', width: 210 },
  { title: '错误摘要', key: 'summary', dataIndex: 'summary' },
  { title: '操作', key: 'action', width: 110, fixed: 'right' },
]
const pagination = { pageSize: 10, showSizeChanger: false, showTotal: (total: number) => `共 ${total} 条记录` }
</script>

<template>
  <div class="monitoring-page">
    <div class="page-heading">
      <div><h1>失败记录</h1><p>查看失败阶段、错误摘要与保留的脱敏日志。</p></div>
      <Button :loading="loading" @click="reload">
        <template #icon><AppIcon name="refresh" /></template>
        {{ loading ? '读取中…' : '刷新记录' }}
      </Button>
    </div>
    <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方为上次读取的记录。</span></NoticeBar>
    <Card title="失败归档" class="monitoring-table-card">
      <template #extra><Tag v-if="data">{{ data.items.length }} 条记录</Tag></template>
      <Table :columns="columns" :data-source="data?.items || []" row-key="id" :loading="{ spinning: loading, tip: '正在读取失败记录…' }" :pagination="pagination" :scroll="{ x: 820 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'at'"><span class="monitoring-nowrap">{{ dateText(record.at) }}</span></template>
          <template v-else-if="column.key === 'stage_label'"><Tag color="error">{{ record.stage_label || '未记录阶段' }}</Tag></template>
          <template v-else-if="column.key === 'summary'"><span class="monitoring-break-word">{{ record.summary || record.code || '未提供摘要' }}</span></template>
          <template v-else-if="column.key === 'action'"><Button type="link" size="small" @click="selected = record.id">查看详情</Button></template>
        </template>
        <template #emptyText>
          <Empty :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="loading ? '正在读取失败记录…' : data ? '暂无失败记录' : '暂时无法读取记录'">
            <p v-if="!loading" class="monitoring-muted">{{ data ? '任务失败后，相关阶段和日志将显示在这里。' : '请检查连接后重试。' }}</p>
          </Empty>
        </template>
      </Table>
    </Card>
    <DialogPanel v-if="selected" title="失败记录详情" @close="selected = ''">
      <FailureDetailPanel :id="selected" :key="selected" />
    </DialogPanel>
  </div>
</template>
