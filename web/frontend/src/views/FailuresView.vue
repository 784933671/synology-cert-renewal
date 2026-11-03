<script setup lang="ts">
import { shallowRef } from 'vue'
import { useResource } from '../composables/useResource'
import type { FailureItem } from '../types'
import { dateText } from '../lib/format'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import DialogPanel from '../components/DialogPanel.vue'
import FailureDetailPanel from '../components/FailureDetailPanel.vue'
const { data, loading, error, reload } = useResource<{ items: FailureItem[] }>(
  '/api/failures',
)
const selected = shallowRef('')
</script>
<template>
  <div class="page-heading">
    <div>
      <h1>失败记录</h1>
      <p>查看失败阶段、错误摘要与保留的脱敏日志。</p>
    </div>
    <button class="button" :disabled="loading" @click="reload">
      <AppIcon name="refresh" />
      {{ loading ? '读取中…' : '刷新记录' }}
    </button>
  </div>
  <NoticeBar v-if="error" type="error">
    {{ error }}
    <span v-if="data">下方为上次读取的记录。</span>
  </NoticeBar>
  <section class="panel">
    <header class="panel-heading">
      <h2>失败归档</h2>
      <span v-if="data" class="help">{{ data.items.length }} 条记录</span>
    </header>
    <div v-if="loading && !data" class="empty-state" role="status">
      正在读取失败记录…
    </div>
    <div v-else-if="!data || !data.items.length" class="empty-state">
      <AppIcon name="failures" />
      <h2>{{ data ? '暂无失败记录' : '暂时无法读取记录' }}</h2>
      <p>
        {{
          data
            ? '任务失败后，相关阶段和日志将显示在这里。'
            : '请检查连接后重试。'
        }}
      </p>
    </div>
    <div v-else class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>发生时间</th>
            <th>失败阶段</th>
            <th>错误摘要</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in data.items" :key="item.id">
            <td class="nowrap">{{ dateText(item.at) }}</td>
            <td>{{ item.stage_label || '未记录阶段' }}</td>
            <td class="summary-cell">
              {{ item.summary || item.code || '未提供摘要' }}
            </td>
            <td>
              <button class="text-button nowrap" @click="selected = item.id">
                查看详情
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
  <DialogPanel v-if="selected" title="失败记录详情" @close="selected = ''">
    <FailureDetailPanel :key="selected" :id="selected" />
  </DialogPanel>
</template>
