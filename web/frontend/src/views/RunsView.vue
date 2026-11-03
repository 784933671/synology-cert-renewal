<script setup lang="ts">
import { computed, shallowRef } from 'vue'
import { Button, Card, Empty, Table, Tag, type TableColumnsType } from 'ant-design-vue'
import { useRuns } from '../composables/useRuns'
import type { RunRecord } from '../types'
import { dateText } from '../lib/format'
import { durationText, runKind, runState } from '../lib/monitoring'
import AppIcon from '../components/AppIcon.vue'
import DialogPanel from '../components/DialogPanel.vue'
import RunDetailPanel from '../components/RunDetailPanel.vue'
import NoticeBar from '../components/NoticeBar.vue'
import '../styles/health.css'
const { data, offset, total, limit, loading, error, reload, changePage } = useRuns()
const selected = shallowRef('')
const columns: TableColumnsType<RunRecord> = [
  { title: '开始时间', key: 'started_at', width: 190 }, { title: '执行类型', key: 'kind', width: 120 },
  { title: '状态', key: 'status', width: 110 }, { title: '耗时', key: 'duration_seconds', width: 130 },
  { title: '执行摘要', key: 'summary' }, { title: '操作', key: 'action', width: 110, fixed: 'right' },
]
const pagination = computed(() => ({ current: Math.floor(offset.value / limit) + 1, pageSize: limit, total: total.value, showSizeChanger: false, hideOnSinglePage: false, showTotal: (total: number) => `共 ${total} 条记录`, onChange: changePage }))
</script>
<template>
  <div class="monitoring-page runs-page">
    <div class="page-heading"><div><h1>执行记录</h1><p>查看每次检查、换证和恢复过程，包括正常跳过与失败阶段。</p></div><Button :loading="loading" @click="reload"><template #icon><AppIcon name="refresh" /></template>{{ loading ? '正在读取…' : '刷新执行记录' }}</Button></div>
    <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方为本页上次读取的记录。</span></NoticeBar>
    <NoticeBar v-if="data?.warning" type="warning">{{ data.warning }}</NoticeBar>
    <Card title="执行历史" class="monitoring-table-card">
      <template #extra><Tag v-if="data">共 {{ data.total }} 条记录</Tag></template>
      <Table :columns="columns" :data-source="data?.items || []" row-key="id" :loading="{ spinning: loading, tip: '正在读取执行记录…' }" :pagination="pagination" :scroll="{ x: 940 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'started_at'"><span class="monitoring-nowrap">{{ dateText(record.started_at) }}</span></template>
          <template v-else-if="column.key === 'kind'">{{ runKind(record.kind) }}</template>
          <template v-else-if="column.key === 'status'"><Tag :color="runState(record.status).color">{{ runState(record.status).label }}</Tag></template>
          <template v-else-if="column.key === 'duration_seconds'">{{ durationText(record.duration_seconds) }}</template>
          <template v-else-if="column.key === 'summary'"><span class="monitoring-break-word">{{ record.summary || '未提供摘要' }}</span></template>
          <template v-else-if="column.key === 'action'"><Button type="link" size="small" @click="selected = record.id">查看时间线</Button></template>
        </template>
        <template #emptyText><Empty :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="loading ? '正在读取执行记录…' : data ? '暂无执行记录' : '暂时无法读取执行记录'"><Button v-if="!loading && !data" @click="reload">重新读取</Button><p v-else-if="!loading" class="monitoring-muted">后续执行完成或运行中时，将在这里显示记录。</p></Empty></template>
      </Table>
    </Card>
    <DialogPanel v-if="selected" title="执行记录详情" @close="selected = ''"><RunDetailPanel :key="selected" :id="selected" /></DialogPanel>
  </div>
</template>
