<script setup lang="ts">
import { computed } from 'vue'
import { Card, Descriptions, DescriptionsItem, Empty, Tag } from 'ant-design-vue'
import type { HealthSnapshot } from '../types'
import { dateText, remainingText } from '../lib/format'
import { healthState, notificationState } from '../lib/monitoring'
import NoticeBar from './NoticeBar.vue'
const props = defineProps<{ monitor: HealthSnapshot['monitor']; stale: boolean; timezone: string }>()
const state = computed(() => props.stale ? 'unknown' : props.monitor.task_enabled === false && props.monitor.status === 'ok' ? 'warning' : props.monitor.status)
</script>
<template>
  <Card title="监测预警" class="health-monitor-card">
    <template #extra><Tag :color="healthState(state).color">{{ healthState(state).label }}</Tag></template>
    <NoticeBar v-if="stale" type="warning">监测快照已过期或暂不可用，尚不能确认当前预警状态。下方为最近监测记录。</NoticeBar>
    <NoticeBar v-if="monitor.task_enabled === false" type="warning">{{ stale ? '最近记录显示：' : '' }}自动续期任务已暂停，不会按计划自动续期；证书临期风险仍需关注。</NoticeBar>
    <NoticeBar v-if="monitor.schedule_supported === false" type="warning">当前任务计划无法计算预期执行时间，漏跑监测结果待确认。</NoticeBar>
    <NoticeBar v-if="!stale && monitor.status === 'disabled'" type="info">主动监测已关闭。关闭监测不会暂停原证书续期任务。</NoticeBar>
    <Descriptions :column="{ xs: 1, sm: 2 }" size="small">
      <DescriptionsItem label="自动续期计划">{{ stale || monitor.task_enabled === null ? '待确认' : monitor.task_enabled ? '已开启' : '已暂停' }}</DescriptionsItem>
      <DescriptionsItem label="漏跑次数">{{ monitor.missed_runs ?? '待确认' }}</DescriptionsItem>
      <DescriptionsItem label="最近执行完成">{{ dateText(monitor.last_completed_at, timezone) }}</DescriptionsItem>
      <DescriptionsItem label="下次预期执行">{{ monitor.task_enabled === false ? '任务已暂停' : dateText(monitor.next_expected_at, timezone) }}</DescriptionsItem>
      <DescriptionsItem label="证书剩余时间">{{ monitor.certificate_remaining_seconds === null ? '待确认' : remainingText(monitor.certificate_remaining_seconds) }}</DescriptionsItem>
      <DescriptionsItem label="预警收件邮箱">{{ monitor.delivery.recipient || '未配置' }}</DescriptionsItem>
    </Descriptions>
    <NoticeBar v-if="!stale && monitor.settings.enabled && !monitor.delivery.enabled" type="warning">失败通知已关闭或尚未配置收件邮箱，监测预警不会发送邮件。请到“邮件通知”检查失败通知设置。</NoticeBar>
    <NoticeBar v-if="monitor.delivery.last_error" type="error">最近通知异常：{{ monitor.delivery.last_error }}</NoticeBar>
    <div v-if="monitor.alerts.length" class="health-alert-list">
      <div v-for="alert in monitor.alerts" :key="`${alert.code}-${alert.since}`" class="health-alert-item">
        <div class="health-component-heading"><h3>{{ alert.label || '监测预警' }}</h3><Tag>{{ notificationState(alert.notification_status) }}</Tag></div>
        <p>{{ alert.message || '请检查相关服务状态。' }}</p>
        <span class="monitoring-muted">首次发现：{{ dateText(alert.since, timezone) }}</span>
      </div>
    </div>
    <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="stale || monitor.status === 'unknown' ? '最近快照未记录预警，当前状态待确认' : monitor.status === 'disabled' ? '主动监测未开启' : monitor.task_enabled === false ? '任务已暂停，当前没有其他预警记录' : '本次监测未发现预警'" />
    <p class="monitoring-card-note">监测时间：{{ dateText(monitor.checked_at, timezone) }}</p>
  </Card>
</template>
