<script setup lang="ts">
import { computed, onUnmounted, shallowRef, watch } from 'vue'
import { Button, Card, Empty, Table, Tag, type TableColumnsType } from 'ant-design-vue'
import { api, ApiError, errorText, isAborted } from '../lib/api'
import { dateText } from '../lib/format'
import { useResource } from '../composables/useResource'
import type { LoginSession } from '../types'
import NoticeBar from './NoticeBar.vue'
import { deviceText } from '../lib/security'
const props = withDefaults(defineProps<{ disabled?: boolean }>(), { disabled: false })
const emit = defineEmits<{ busy: [value: boolean]; revoked: [] }>()
const { data, loading, error: loadError, reload } = useResource<{ items: LoginSession[] }>('/api/sessions')
const rows = computed(() => Array.isArray(data.value?.items) ? data.value.items : [])
const busy = shallowRef(false), error = shallowRef(''), success = shallowRef(''), uncertain = shallowRef(false)
const controller = new AbortController()
let disposed = false
const columns: TableColumnsType<LoginSession> = [
  { title: '设备 / 来源', key: 'source' }, { title: '登录时间', key: 'created_at', width: 180 },
  { title: '最近活动', key: 'last_seen', width: 180 }, { title: '操作', key: 'action', width: 120 },
]
watch(busy, (value) => emit('busy', value), { flush: 'sync' })
async function refresh() {
  if (busy.value || props.disabled) return
  await reload()
  if (!disposed && !loadError.value && Array.isArray(data.value?.items)) {
    if (uncertain.value) { error.value = ''; success.value = '会话列表已更新，请确认待撤销会话的状态。' }
    uncertain.value = false
  }
}
async function revoke(item?: LoginSession) {
  if (busy.value || loading.value || props.disabled || uncertain.value || disposed) return
  if (!window.confirm(item?.current ? '退出当前登录会话？完成验证后将返回登录页面。'
    : item ? '撤销这个登录会话？该设备需要重新登录。' : '退出其他所有登录会话？当前会话将保留。')) return
  busy.value = true
  error.value = success.value = ''
  try {
    const result = await api<{ current_revoked: boolean }>(item ? '/api/sessions/revoke' : '/api/sessions/revoke-others', {
      method: 'POST', body: item ? { id: item.id } : {}, signal: controller.signal,
    })
    if (disposed) return
    if (!result || typeof result.current_revoked !== 'boolean') throw new ApiError('无法确认会话撤销结果。', 200, 'invalid_response')
    if (result.current_revoked) { emit('revoked'); return }
    success.value = item ? '指定会话已退出。' : '其他登录会话已退出。'
    await reload()
  } catch (cause) {
    if (disposed || isAborted(cause)) return
    uncertain.value = !(cause instanceof ApiError) || !cause.status || cause.status >= 500 || cause.code === 'invalid_response'
    error.value = uncertain.value ? '会话撤销结果尚未确认，请刷新会话列表后再操作，不会自动重复提交。' : errorText(cause)
  } finally { if (!disposed) busy.value = false }
}
onUnmounted(() => { disposed = true; controller.abort(); emit('busy', false) })
</script>
<template>
  <Card title="登录会话" class="cert-security-card">
    <template #extra>
      <div class="cert-security-actions">
        <Button :loading="loading" :disabled="busy || disabled" @click="refresh">刷新会话</Button>
        <Button danger :disabled="busy || loading || disabled || uncertain || !rows.some(item => !item.current)" @click="revoke()">退出其他会话</Button>
      </div>
    </template>
    <p class="monitoring-muted">查看仍有效的登录会话。撤销会话需要邮箱二次验证，不影响后台自动续期。</p>
    <NoticeBar v-if="loadError || error" type="error">{{ error || loadError }}</NoticeBar>
    <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
    <Table :columns="columns" :data-source="rows" row-key="id" :loading="loading" :pagination="false" :scroll="{ x: 700 }">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'source'">{{ deviceText(record.device) }} <Tag v-if="record.current" color="blue">当前会话</Tag><div>{{ record.ip || '来源未知' }}</div></template>
        <template v-else-if="column.key === 'created_at'">{{ dateText(record.created_at) }}</template>
        <template v-else-if="column.key === 'last_seen'">{{ dateText(record.last_seen) }}</template>
        <template v-else-if="column.key === 'action'"><Button type="link" danger :disabled="busy || loading || disabled || uncertain" @click="revoke(record as LoginSession)">{{ record.current ? '退出当前' : '撤销会话' }}</Button></template>
      </template>
      <template #emptyText><Empty :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="loading ? '正在读取登录会话…' : loadError ? '暂时无法读取会话' : '暂无有效会话'" /></template>
    </Table>
  </Card>
</template>
