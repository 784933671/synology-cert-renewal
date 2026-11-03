<script setup lang="ts">
import { useResource } from '../composables/useResource'
import type { AuditItem } from '../types'
import { dateText } from '../lib/format'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
const { data, loading, error, reload } = useResource<{ items: AuditItem[] }>(
  '/api/audit',
)
const actions: Record<string, string> = {
  initialize: '初始化管理员',
  password_reset: '重置管理员密码',
  login: '登录',
  logout: '退出登录',
  password: '修改密码',
  'password.change': '修改密码',
  'settings.update': '更新配置',
  run: '手动运行任务',
  check: '手动检查',
  'actions.run': '手动运行任务',
  'actions.check': '手动检查',
}
</script>
<template>
  <div class="page-heading">
    <div>
      <h1>操作审计</h1>
      <p>查询登录、配置修改和手动操作记录。</p>
    </div>
    <button class="button" :disabled="loading" @click="reload">
      <AppIcon name="refresh" />
      {{ loading ? '读取中…' : '刷新记录' }}
    </button>
  </div>
  <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
  <section class="panel">
    <header class="panel-heading"><h2>最近操作</h2></header>
    <div v-if="loading && !data" class="empty-state" role="status">
      正在读取操作记录…
    </div>
    <div v-else-if="!data || !data.items.length" class="empty-state">
      <AppIcon name="audit" />
      <h2>{{ data ? '暂无操作记录' : '暂时无法读取记录' }}</h2>
      <p>登录与关键操作将自动记录。</p>
    </div>
    <div v-else class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>操作</th>
            <th>结果</th>
            <th>说明</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(item, index) in data.items" :key="`${item.at}-${index}`">
            <td class="nowrap">{{ dateText(item.at) }}</td>
            <td>{{ actions[item.action] || item.action }}</td>
            <td>
              <span :class="['badge', item.success ? 'success' : 'warning']">
                {{ item.success ? '成功' : '失败' }}
              </span>
            </td>
            <td class="summary-cell">{{ item.message || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
