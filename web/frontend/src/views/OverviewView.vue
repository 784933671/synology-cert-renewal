<script setup lang="ts">
import { computed, shallowRef } from 'vue'
import {
  Badge,
  Button,
  Card,
  Collapse,
  CollapsePanel,
  Descriptions,
  DescriptionsItem,
  Divider,
  Empty,
  Modal,
  Space,
  Spin,
  Statistic,
  Steps,
  Tag,
} from 'ant-design-vue'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import { dateText, remainingText } from '../lib/format'
import { useStatus } from '../composables/useStatus'

const { status, loading, error, actionError, message, waiting, busy, manualRunning, pendingRecovery, cooldownActive, renewDisabled, refresh, execute } = useStatus()
const renewConfirmOpen = shallowRef(false)
async function confirmRenewal() {
  if (renewDisabled.value) return
  renewConfirmOpen.value = false
  await execute('renew')
}
const manualState = computed(() => status.value?.manual_renewal?.state)
const manualLabel = computed(() => ({ queued: '等待立即换证', running: '正在申请并替换', succeeded: '申请替换成功', failed: '申请替换失败', expired: '申请请求已过期' })[manualState.value || 'queued'])
const manualColor = computed(() => manualState.value === 'succeeded' ? 'success' : manualState.value === 'failed' || manualState.value === 'expired' ? 'error' : 'processing')
const pending = computed(() =>
  status.value
    ? [
        status.value.pending.deployment && '证书部署',
        status.value.pending.dns_cleanup && 'DNS 验证记录清理',
        status.value.pending.notification && '邮件通知',
        status.value.pending.interrupted && '中断恢复',
      ].filter(Boolean)
    : [],
)
const attention = computed(() => Boolean(
  pending.value.length || status.value?.last_result?.success === false ||
  (status.value && status.value.certificate.remaining_seconds <= 0),
))
const taskLabel = computed(() => status.value?.task.running
  ? '续期任务运行中'
  : status.value?.check.running
    ? '正在检查'
    : manualRunning.value ? manualLabel.value : waiting.value ? '等待任务启动' : '空闲')
const renewalSteps = [
  { title: '检查有效期', description: '按计划检查' },
  { title: 'DNSPod 验证', description: '进入续期窗口' },
  { title: '申请新证书', description: '完成域名验证' },
  { title: '替换并验证', description: '确认服务生效' },
  { title: '邮件通知', description: '按通知配置发送' },
]
</script>

<template>
  <div class="monitoring-page">
    <div class="page-heading">
      <div>
        <h1>运行概览</h1>
        <p>查看证书状态，掌握每一次自动续期。</p>
      </div>
      <Space wrap>
        <Button :loading="loading" @click="refresh">
          <template #icon><AppIcon name="refresh" /></template>
          {{ loading ? '刷新中…' : '刷新状态' }}
        </Button>
        <Button type="primary" :loading="busy" :disabled="busy || !status || !!error" @click="execute('check')">
          <template #icon><AppIcon name="check" /></template>
          {{ busy ? '任务处理中' : '立即检查' }}
        </Button>
      </Space>
    </div>
    <NoticeBar v-if="error" type="error">
      {{ error }}<span v-if="status">下方为上次读取的状态。</span>
    </NoticeBar>
    <NoticeBar v-if="actionError" type="error">{{ actionError }}</NoticeBar>
    <NoticeBar v-if="message">{{ message }}</NoticeBar>

    <Card v-if="!status" class="monitoring-empty-card">
      <Spin v-if="loading" tip="正在读取证书状态…">
        <div class="monitoring-loading" role="status">正在读取证书状态…</div>
      </Spin>
      <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取证书状态">
        <p class="monitoring-muted">连接成功后将显示群晖的实际证书与任务状态。</p>
        <Button type="primary" @click="refresh">重新连接</Button>
      </Empty>
    </Card>
    <template v-else>
      <Card class="certificate-hero">
        <div class="certificate-hero-content">
          <div class="certificate-hero-main">
            <Space class="certificate-kicker" wrap>
              <AppIcon name="certificate" />
              <span>当前管理的证书</span>
              <Badge :status="attention ? 'warning' : busy ? 'processing' : 'default'" :text="attention ? '需要关注' : busy ? '任务处理中' : '状态已读取'" />
            </Space>
            <h2 class="certificate-domain">{{ status.certificate.domains[0] || '域名待确认' }}</h2>
            <p class="monitoring-muted">{{ status.certificate.description || '未设置证书描述' }}</p>
            <Space v-if="status.certificate.domains.length > 1" wrap class="certificate-aliases">
              <Tag v-for="domain in status.certificate.domains.slice(1)" :key="domain" color="blue">{{ domain }}</Tag>
            </Space>
            <p class="certificate-expiry">
              <AppIcon name="renewal" />
              {{ dateText(status.certificate.not_after, status.timezone) }} 到期
            </p>
          </div>
          <Statistic title="距离证书到期" :value="remainingText(status.certificate.remaining_seconds)" :class="['certificate-countdown', { 'is-expired': status.certificate.remaining_seconds <= 0 }]" />
        </div>
      </Card>

      <div class="monitoring-metrics">
        <Card>
          <Statistic title="续期触发时间" prefix="提前" :value="status.renew_before_days" suffix="天" />
          <p class="monitoring-card-note">{{ dateText(status.certificate.renew_at, status.timezone) }}</p>
        </Card>
        <Card>
          <Statistic title="自动检查计划" :value="status.task.enabled ? '已开启' : '已暂停'" />
          <p class="monitoring-card-note">{{ status.task.schedule_text || '计划待确认' }}</p>
        </Card>
        <Card>
          <Statistic title="当前任务" :value="taskLabel" class="task-statistic" />
          <p class="monitoring-card-note"><Badge :status="busy ? 'processing' : 'default'" />普通检查不发送邮件</p>
        </Card>
      </div>
      <NoticeBar v-if="pending.length" type="warning">
        待完成操作：{{ pending.join('、') }}。后续运行将继续处理，请查看最近执行结果。
      </NoticeBar>
      <NoticeBar v-if="!status.task.enabled" type="warning">
        自动检查已暂停。可在“续期计划”中重新启用；手动运行仍可执行。
      </NoticeBar>

      <Card title="自动续期流程" class="renewal-flow-card">
        <Steps :items="renewalSteps" :current="-1" size="small" :responsive="true" />
        <p class="monitoring-card-note">进入续期窗口后自动执行申请与替换；未到续期时间时正常跳过。</p>
      </Card>

      <div class="monitoring-results-grid">
        <Card title="最近执行结果">
          <template v-if="status.last_result">
            <Tag :color="status.last_result.success === true ? 'success' : status.last_result.success === false ? 'error' : 'default'">
              {{ status.last_result.success === true ? '执行成功' : status.last_result.success === false ? '执行失败' : '结果待确认' }}
            </Tag>
            <p class="monitoring-result-message">{{ status.last_result.message || '未提供结果摘要' }}</p>
            <Descriptions :column="1" size="small">
              <DescriptionsItem v-if="status.last_result.failure?.stage_label" label="失败阶段">{{ status.last_result.failure.stage_label }}</DescriptionsItem>
              <DescriptionsItem label="执行时间">{{ dateText(status.last_result.at, status.timezone) }}</DescriptionsItem>
            </Descriptions>
          </template>
          <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="尚无执行结果。任务运行后将在这里显示。" />
          <Divider />
          <h3 class="monitoring-section-title">最近手动检查</h3>
          <p class="monitoring-result-message">{{ status.check.last_result?.message || '暂无手动检查记录' }}</p>
          <p v-if="status.check.last_result" class="monitoring-muted">{{ dateText(status.check.last_result.at, status.timezone) }}</p>
        </Card>
        <Card title="手动运行" class="manual-run-card">
          <p class="monitoring-description">按当前计划规则检查有效期，进入续期窗口后申请、替换并验证证书，同时处理未完成操作。</p>
          <Button :loading="busy" :disabled="busy || !!error" @click="execute('run')">
            <template #icon><AppIcon name="refresh" /></template>
            {{ busy ? '任务处理中…' : '运行一次续期任务' }}
          </Button>
          <NoticeBar>“立即检查”仅检查状态，不申请或替换证书。运行结果会自动更新。</NoticeBar>
          <Divider />
          <h3 class="monitoring-section-title">立即申请并替换</h3>
          <p class="monitoring-description">无需等待证书到期，立即申请新证书并替换，随后验证服务证书。</p>
          <Button type="primary" :disabled="renewDisabled" @click="renewConfirmOpen = true">
            <template #icon><AppIcon name="renewal" /></template>
            立即申请并替换证书
          </Button>
          <p v-if="pendingRecovery" class="monitoring-card-note">存在待完成操作，请先运行一次续期任务完成恢复。</p>
          <p v-if="cooldownActive" class="monitoring-card-note">立即申请间隔至少一小时，下次可申请时间：{{ dateText(status.manual_renewal?.cooldown_until, status.timezone) }}。</p>
          <div v-if="status.manual_renewal" class="manual-renewal-result" role="status">
            <Divider />
            <h3 class="monitoring-section-title">最近立即申请记录</h3>
            <Tag :color="manualColor">{{ manualLabel }}</Tag>
            <p class="monitoring-result-message">{{ status.manual_renewal.message || '正在等待服务器确认执行结果。' }}</p>
            <p class="monitoring-muted">申请时间：{{ dateText(status.manual_renewal.requested_at, status.timezone) }}</p>
            <p v-if="status.manual_renewal.completed_at" class="monitoring-muted">完成时间：{{ dateText(status.manual_renewal.completed_at, status.timezone) }}</p>
          </div>
        </Card>
      </div>
      <Collapse class="certificate-fingerprint" :bordered="false">
        <CollapsePanel key="fingerprint" header="查看证书指纹">
          <code class="monitoring-fingerprint">{{ status.certificate.fingerprint || '暂无指纹' }}</code>
        </CollapsePanel>
      </Collapse>
      <footer class="monitoring-footer">状态时间：{{ dateText(status.server_time, status.timezone) }} · {{ status.timezone }}</footer>
    </template>
    <Modal v-model:open="renewConfirmOpen" title="立即申请并替换证书" ok-text="确认申请并替换" cancel-text="取消" :ok-button-props="{ disabled: renewDisabled }" :destroy-on-close="true" @ok="confirmRenewal">
      <p>会立即申请、替换并验证证书，CA 有申请频率限制。</p>
      <p>即使当前证书尚未进入续期窗口，也会申请新证书。两次立即申请至少间隔一小时。</p>
    </Modal>
  </div>
</template>
