<script setup lang="ts">
import { computed, onUnmounted, shallowRef, watch } from 'vue'
import { Button, Card, Empty, Table, Tag, type TableColumnsType } from 'ant-design-vue'
import { api, ApiError, errorText, isAborted, isUnknownResult } from '../lib/api'
import { useResource } from '../composables/useResource'
import { dateText } from '../lib/format'
import type { AbuseBlock } from '../types'
import NoticeBar from './NoticeBar.vue'
const props = defineProps<{ disabled: boolean }>()
const emit = defineEmits<{ busy: [value: boolean] }>()
const { data, loading, error: loadError, reload } = useResource<{ items: AbuseBlock[] }>('/api/abuse/blocks')
const rows = computed(() => Array.isArray(data.value?.items) ? data.value.items : [])
const busy = shallowRef(false), uncertain = shallowRef(false), error = shallowRef(''), success = shallowRef('')
const controller = new AbortController()
let disposed = false
const columns: TableColumnsType<AbuseBlock> = [
  { title: '来源 IP', key: 'ip' }, { title: '封禁原因', key: 'reason' },
  { title: '开始时间', key: 'blocked_at', width: 180 }, { title: '自动解除时间', key: 'expires_at', width: 180 },
  { title: '操作', key: 'action', width: 110 },
]
watch(busy, value => emit('busy', value), { flush: 'sync' })
async function refresh() {
  if (busy.value || props.disabled) return
  await reload()
  if (!disposed && !loadError.value && Array.isArray(data.value?.items)) {
    uncertain.value = false; error.value = ''; success.value = ''
  }
}
async function unblock(item: AbuseBlock) {
  if (disposed || props.disabled || busy.value || loading.value || uncertain.value) return
  if (!window.confirm(`解除 ${item.ip} 的临时封禁？继续超限仍可能再次触发封禁。`)) return
  busy.value = true
  error.value = success.value = ''
  try {
    const result = await api<{ ok: boolean; removed: boolean }>('/api/abuse/unblock', { method: 'POST', body: { ip: item.ip }, signal: controller.signal })
    if (disposed) return
    if (!result?.ok || typeof result.removed !== 'boolean') throw new ApiError('无法确认解封结果。', 200, 'invalid_response')
    success.value = result.removed ? '临时封禁已解除。' : '该来源已解除封禁或封禁已到期。'
    await reload()
  } catch (cause) {
    if (disposed || isAborted(cause)) return
    uncertain.value = isUnknownResult(cause)
    error.value = uncertain.value ? '解封结果尚未确认，请刷新封禁列表后再操作，不会自动重复提交。' : errorText(cause)
  } finally { if (!disposed) busy.value = false }
}
onUnmounted(() => { disposed = true; controller.abort(); emit('busy', false) })
</script>
<template>
  <Card title="临时封禁" class="settings-card">
    <template #extra><Button :loading="loading" :disabled="busy || disabled" @click="refresh">刷新封禁列表</Button></template>
    <p class="settings-help">封禁到期自动解除；管理员可通过邮箱二次验证提前解封。当前来源被封禁时，仍可使用本页和验证入口进行恢复。</p>
    <NoticeBar v-if="error || loadError" type="error">{{ error || loadError }}<span v-if="loadError && data">下方保留上次读取的记录。</span></NoticeBar>
    <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
    <Table :columns="columns" :data-source="rows" row-key="ip" :loading="loading" :pagination="{ pageSize: 10, showSizeChanger: false }" :scroll="{ x: 760 }">
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'ip'"><code>{{ record.ip }}</code> <Tag v-if="record.current" color="blue">当前来源</Tag></template>
        <template v-else-if="column.key === 'reason'">{{ record.reason === 'ip_rate_exceeded' ? 'IP 请求持续超限' : '请求异常' }}</template>
        <template v-else-if="column.key === 'blocked_at'">{{ dateText(record.blocked_at) }}</template>
        <template v-else-if="column.key === 'expires_at'">{{ dateText(record.expires_at) }}</template>
        <template v-else-if="column.key === 'action'"><Button type="link" :disabled="disabled || busy || loading || uncertain" @click="unblock(record as AbuseBlock)">解除封禁</Button></template>
      </template>
      <template #emptyText><Empty :image="Empty.PRESENTED_IMAGE_SIMPLE" :description="loading ? '正在读取封禁列表…' : loadError ? '暂时无法读取封禁列表' : '当前没有临时封禁的来源'" /></template>
    </Table>
  </Card>
</template>
