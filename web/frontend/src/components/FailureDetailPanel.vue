<script setup lang="ts">
import { useResource } from '../composables/useResource'
import type { FailureDetail } from '../types'
import { dateText } from '../lib/format'
import NoticeBar from './NoticeBar.vue'
const props = defineProps<{ id: string }>()
const { data, loading, error, reload } = useResource<FailureDetail>(
  `/api/failures/${encodeURIComponent(props.id)}`,
)
</script>
<template>
  <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
  <p v-if="loading" role="status">正在读取失败记录…</p>
  <template v-else-if="data">
    <dl class="detail-list">
      <div class="detail-row">
        <dt>发生时间</dt>
        <dd>{{ dateText(data.report.at) }}</dd>
      </div>
      <div class="detail-row">
        <dt>失败阶段</dt>
        <dd>
          {{ data.report.stage_label || data.report.stage || '未记录阶段' }}
        </dd>
      </div>
      <div class="detail-row">
        <dt>错误码</dt>
        <dd>{{ data.report.code || '未提供' }}</dd>
      </div>
    </dl>
    <NoticeBar type="warning">
      {{ data.report.summary || data.report.message || '未提供错误摘要' }}
    </NoticeBar>
    <p v-if="data.report.hint" class="result-message">{{ data.report.hint }}</p>
    <p v-if="data.report.archive_path" class="help break-word">
      失败记录：{{ data.report.archive_path }}
    </p>
    <NoticeBar v-if="data.report.archive_error" type="warning">
      {{ data.report.archive_error }}
    </NoticeBar>
    <section v-for="log in data.logs" :key="log.name" class="log-section">
      <h3>{{ log.name }}</h3>
      <pre class="event-log">{{ log.text || '该日志没有内容。' }}</pre>
    </section>
    <p v-if="!data.logs.length" class="empty-inline">暂无可用的脱敏日志。</p>
  </template>
  <button v-if="!loading && !data" class="button" @click="reload">
    重新读取
  </button>
</template>
