<script setup lang="ts">
import { Button, Descriptions, DescriptionsItem, Empty, Space, Spin, Tag, Timeline, TimelineItem } from 'ant-design-vue'
import { useResource } from '../composables/useResource'
import type { RunRecord } from '../types'
import { dateText } from '../lib/format'
import { durationText, runKind, runState } from '../lib/monitoring'
import NoticeBar from './NoticeBar.vue'
const props = defineProps<{ id: string }>()
const { data, loading, error, reload } = useResource<RunRecord>(`/api/runs/${encodeURIComponent(props.id)}`)
function color(status: string) { return status === 'succeeded' ? 'green' : status === 'failed' ? 'red' : status === 'running' ? 'blue' : 'gray' }
</script>
<template>
  <div class="run-detail">
    <div class="run-detail-toolbar"><span class="monitoring-muted">运行中的记录可手动刷新，查看后续阶段。</span><Button :loading="loading" @click="reload">刷新详情</Button></div>
    <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方为上次读取的执行详情。</span></NoticeBar>
    <Spin v-if="loading && !data" tip="正在读取执行详情…"><div class="monitoring-loading" role="status">正在读取执行详情…</div></Spin>
    <template v-else-if="data">
      <Descriptions :column="{ xs: 1, sm: 2 }" bordered size="small">
        <DescriptionsItem label="执行类型">{{ runKind(data.kind) }}</DescriptionsItem>
        <DescriptionsItem label="执行状态"><Tag :color="runState(data.status).color">{{ runState(data.status).label }}</Tag></DescriptionsItem>
        <DescriptionsItem label="开始时间">{{ dateText(data.started_at) }}</DescriptionsItem>
        <DescriptionsItem label="结束时间">{{ data.finished_at ? dateText(data.finished_at) : data.status === 'running' ? '尚未结束' : '未记录' }}</DescriptionsItem>
        <DescriptionsItem label="耗时">{{ durationText(data.duration_seconds) }}</DescriptionsItem>
        <DescriptionsItem label="证书条目">{{ data.certificate_id || '未记录' }}</DescriptionsItem>
        <DescriptionsItem label="覆盖域名"><Space wrap><Tag v-for="domain in data.domains" :key="domain">{{ domain }}</Tag><span v-if="!data.domains.length">未记录域名</span></Space></DescriptionsItem>
      </Descriptions>
      <NoticeBar :type="data.status === 'failed' ? 'error' : data.status === 'interrupted' ? 'warning' : 'info'">{{ data.summary || '未提供执行摘要' }}</NoticeBar>
      <h3 class="monitoring-section-title">执行时间线</h3>
      <Timeline v-if="data.stages.length" class="run-timeline">
        <TimelineItem v-for="(stage, index) in data.stages" :key="`${stage.stage}-${index}`" :color="color(stage.status)">
          <div class="run-stage-heading"><strong>{{ stage.label || '执行阶段' }}</strong><Tag :color="runState(stage.status).color">{{ runState(stage.status).label }}</Tag></div>
          <p class="monitoring-muted">{{ dateText(stage.started_at) }}<span v-if="stage.finished_at"> → {{ dateText(stage.finished_at) }}</span><span v-if="stage.duration_seconds !== null"> · {{ durationText(stage.duration_seconds) }}</span></p>
          <p v-if="stage.message" class="monitoring-result-message">{{ stage.message }}</p>
        </TimelineItem>
      </Timeline>
      <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="尚无阶段记录" />
    </template>
    <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取执行详情"><Button @click="reload">重新读取</Button></Empty>
  </div>
</template>
