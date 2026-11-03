<script setup lang="ts">
import { Button, Descriptions, DescriptionsItem, Empty, Spin, Tabs, TabPane, Tag } from 'ant-design-vue'
import { useResource } from '../composables/useResource'
import type { FailureDetail } from '../types'
import { dateText } from '../lib/format'
import NoticeBar from './NoticeBar.vue'

const props = defineProps<{ id: string }>()
const { data, loading, error, reload } = useResource<FailureDetail>(`/api/failures/${encodeURIComponent(props.id)}`)
</script>

<template>
  <div class="failure-detail">
    <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
    <Spin v-if="loading" tip="正在读取失败记录…"><div class="monitoring-loading" role="status">正在读取失败记录…</div></Spin>
    <template v-else-if="data">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem label="发生时间">{{ dateText(data.report.at) }}</DescriptionsItem>
        <DescriptionsItem label="失败阶段">{{ data.report.stage_label || data.report.stage || '未记录阶段' }}</DescriptionsItem>
        <DescriptionsItem label="错误码"><Tag color="error">{{ data.report.code || '未提供' }}</Tag></DescriptionsItem>
        <DescriptionsItem v-if="data.report.archive_path" label="失败记录"><span class="monitoring-break-word">{{ data.report.archive_path }}</span></DescriptionsItem>
      </Descriptions>
      <NoticeBar type="warning">{{ data.report.summary || data.report.message || '未提供错误摘要' }}</NoticeBar>
      <p v-if="data.report.hint" class="monitoring-result-message">{{ data.report.hint }}</p>
      <NoticeBar v-if="data.report.archive_error" type="warning">{{ data.report.archive_error }}</NoticeBar>
      <Tabs v-if="data.logs.length" class="failure-log-tabs">
        <TabPane v-for="(log, index) in data.logs" :key="`${log.name}-${index}`" :tab="log.name">
          <pre class="monitoring-event-log">{{ log.text || '该日志没有内容。' }}</pre>
        </TabPane>
      </Tabs>
      <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂无可用的脱敏日志。" />
    </template>
    <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取失败详情">
      <Button type="primary" @click="reload">重新读取</Button>
    </Empty>
  </div>
</template>
