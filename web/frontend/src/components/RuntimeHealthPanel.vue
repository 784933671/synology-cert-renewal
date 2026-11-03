<script setup lang="ts">
import { Card, Descriptions, DescriptionsItem, Tag } from 'ant-design-vue'
import type { HealthSnapshot } from '../types'
import { dateText } from '../lib/format'
import { durationText, healthState } from '../lib/monitoring'
import NoticeBar from './NoticeBar.vue'
defineProps<{ runtime: HealthSnapshot['runtime']; stale: boolean; timezone: string }>()
</script>
<template>
  <Card title="服务健康" class="health-runtime-card">
    <NoticeBar v-if="stale" type="warning">健康快照已过期或无法确认，当前服务状态未知。请刷新后再判断；下方保留最近检查结果。</NoticeBar>
    <div class="health-component-grid">
      <div v-for="item in runtime.components" :key="item.key" class="health-component">
        <div class="health-component-heading"><h3>{{ item.label }}</h3><Tag :color="healthState(stale ? 'unknown' : item.status).color">{{ healthState(stale ? 'unknown' : item.status).label }}</Tag></div>
        <p>{{ stale ? '最近记录：' : '' }}{{ item.message || '尚无检查说明' }}</p>
      </div>
    </div>
    <p v-if="!runtime.components.length" class="monitoring-muted">暂无服务检查结果。</p>
    <Descriptions title="最近容器快照" :column="{ xs: 1, sm: 2, lg: 3 }" size="small" class="health-container-details">
      <DescriptionsItem label="运行状态">{{ stale || runtime.container.running === null ? '待确认' : runtime.container.running ? '运行中' : '已停止' }}</DescriptionsItem>
      <DescriptionsItem label="健康探测">{{ stale ? '待确认' : ({ healthy: '健康', unhealthy: '异常', starting: '启动中' } as Record<string, string>)[runtime.container.health] || '待确认' }}</DescriptionsItem>
      <DescriptionsItem label="重启次数">{{ runtime.container.restart_count ?? '未记录' }}</DescriptionsItem>
      <DescriptionsItem label="内存终止记录">{{ runtime.container.oom_killed === null ? '未记录' : runtime.container.oom_killed ? '有内存终止记录' : '未发现' }}</DescriptionsItem>
      <DescriptionsItem label="启动时间">{{ dateText(runtime.container.started_at, timezone) }}</DescriptionsItem>
      <DescriptionsItem label="快照运行时长">{{ durationText(runtime.container.uptime_seconds) }}</DescriptionsItem>
    </Descriptions>
    <p class="monitoring-card-note">检查时间：{{ dateText(runtime.checked_at, timezone) }}</p>
  </Card>
</template>
