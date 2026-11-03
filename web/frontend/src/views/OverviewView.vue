<script setup lang="ts">
import { computed } from 'vue'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import { dateText, remainingText } from '../lib/format'
import { useStatus } from '../composables/useStatus'
const {
  status,
  loading,
  error,
  actionError,
  message,
  waiting,
  busy,
  refresh,
  execute,
} = useStatus()
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
const attention = computed(() =>
  Boolean(
    pending.value.length ||
    status.value?.last_result?.success === false ||
    (status.value && status.value.certificate.remaining_seconds <= 0),
  ),
)
</script>
<template>
  <div class="page-heading">
    <div>
      <h1>运行概览</h1>
      <p>查看证书状态，掌握每一次自动续期。</p>
    </div>
    <div class="heading-actions">
      <button class="button" :disabled="loading" @click="refresh">
        <AppIcon name="refresh" />
        {{ loading ? '刷新中…' : '刷新状态' }}
      </button>
      <button
        class="button primary"
        :disabled="busy || !status || !!error"
        @click="execute('check')"
      >
        <AppIcon name="check" />
        {{ busy ? '任务处理中' : '立即检查' }}
      </button>
    </div>
  </div>
  <NoticeBar v-if="error" type="error">
    {{ error }}
    <span v-if="status">下方为上次读取的状态。</span>
  </NoticeBar>
  <NoticeBar v-if="actionError" type="error">{{ actionError }}</NoticeBar>
  <NoticeBar v-if="message">{{ message }}</NoticeBar>
  <div v-if="!status" class="empty-state">
    <AppIcon name="certificate" />
    <h2>{{ loading ? '正在读取证书状态…' : '暂时无法读取证书状态' }}</h2>
    <p>连接成功后将显示群晖的实际证书与任务状态。</p>
    <button v-if="!loading" class="button" @click="refresh">重新连接</button>
  </div>
  <div v-else class="dashboard">
    <section class="hero-panel">
      <div class="hero-copy">
        <div class="hero-kicker">
          <AppIcon name="certificate" />
          当前管理的证书
          <span :class="['badge', attention ? 'warning' : 'neutral']">
            {{ attention ? '需要关注' : busy ? '任务处理中' : '状态已读取' }}
          </span>
        </div>
        <h2 class="hero-domain">
          {{ status.certificate.domains[0] || '域名待确认' }}
        </h2>
        <p class="domain-alias">
          {{ status.certificate.description || '未设置证书描述' }}
        </p>
        <div class="tag-list">
          <span
            v-for="domain in status.certificate.domains.slice(1)"
            :key="domain"
            class="badge neutral"
          >
            {{ domain }}
          </span>
        </div>
        <div class="hero-footer">
          <span>
            <AppIcon name="renewal" />
            {{ dateText(status.certificate.not_after, status.timezone) }} 到期
          </span>
        </div>
      </div>
      <div class="hero-countdown">
        <div class="countdown-number">
          {{ remainingText(status.certificate.remaining_seconds) }}
        </div>
        <p>距离证书到期</p>
      </div>
    </section>
    <div class="metric-row">
      <section class="metric-card">
        <span class="metric-label">续期触发时间</span>
        <div class="metric-value">
          提前 {{ status.renew_before_days }}
          <small>天</small>
        </div>
        <p class="metric-note">
          {{ dateText(status.certificate.renew_at, status.timezone) }}
        </p>
      </section>
      <section class="metric-card">
        <span class="metric-label">自动检查计划</span>
        <div class="metric-value">
          {{ status.task.enabled ? '已开启' : '已暂停' }}
        </div>
        <p class="metric-note">
          {{ status.task.schedule_text || '计划待确认' }}
        </p>
      </section>
      <section class="metric-card">
        <span class="metric-label">当前任务</span>
        <div class="metric-value">
          {{
            status.task.running
              ? '续期任务运行中'
              : status.check.running
                ? '正在检查'
                : waiting
                  ? '等待任务启动'
                  : '空闲'
          }}
        </div>
        <p class="metric-note">普通检查不发送邮件</p>
      </section>
    </div>
    <NoticeBar v-if="pending.length" type="warning">
      待完成操作：{{
        pending.join('、')
      }}。后续运行将继续处理，请查看最近执行结果。
    </NoticeBar>
    <NoticeBar v-if="!status.task.enabled" type="warning">
      自动检查已暂停。可在“续期计划”中重新启用；手动运行仍可执行。
    </NoticeBar>
    <div class="dashboard-bottom">
      <section class="panel">
        <header class="panel-heading"><h2>最近执行结果</h2></header>
        <div class="panel-body">
          <template v-if="status.last_result">
            <div
              :class="[
                'badge',
                status.last_result.success === true
                  ? 'success'
                  : status.last_result.success === false
                    ? 'warning'
                    : 'neutral',
              ]"
            >
              {{
                status.last_result.success === true
                  ? '执行成功'
                  : status.last_result.success === false
                    ? '执行失败'
                    : '结果待确认'
              }}
            </div>
            <p class="result-message">
              {{ status.last_result.message || '未提供结果摘要' }}
            </p>
            <p v-if="status.last_result.failure?.stage_label">
              失败阶段：{{ status.last_result.failure.stage_label }}
            </p>
            <p class="help">
              {{ dateText(status.last_result.at, status.timezone) }}
            </p>
          </template>
          <p v-else class="muted">尚无执行结果。任务运行后将在这里显示。</p>
          <hr />
          <h3>最近手动检查</h3>
          <p class="result-message">
            {{ status.check.last_result?.message || '暂无手动检查记录' }}
          </p>
          <p v-if="status.check.last_result" class="help">
            {{ dateText(status.check.last_result.at, status.timezone) }}
          </p>
        </div>
      </section>
      <section class="panel">
        <header class="panel-heading"><h2>手动运行</h2></header>
        <div class="panel-body form-stack">
          <p>
            按当前计划规则检查有效期，进入续期窗口后申请、替换并验证证书，同时处理未完成操作。
          </p>
          <button
            class="button"
            :disabled="busy || !!error"
            @click="execute('run')"
          >
            <AppIcon name="refresh" />
            {{ busy ? '任务处理中…' : '运行一次续期任务' }}
          </button>
          <p class="help">
            “立即检查”仅检查状态，不申请或替换证书。运行结果会自动更新。
          </p>
        </div>
      </section>
    </div>
    <details class="panel certificate-details">
      <summary>查看证书指纹</summary>
      <p class="fingerprint">
        {{ status.certificate.fingerprint || '暂无指纹' }}
      </p>
    </details>
    <footer class="page-footer">
      状态时间：{{ dateText(status.server_time, status.timezone) }} ·
      {{ status.timezone }}
    </footer>
  </div>
</template>
