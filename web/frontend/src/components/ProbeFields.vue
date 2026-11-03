<script setup lang="ts">
import { Button, Card, Empty, FormItem, Input, InputNumber } from 'ant-design-vue'
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons-vue'
import type { Probe } from '../types'
const model = defineModel<Probe[]>({ required: true })
const props = defineProps<{ domains: string[] }>()
function edit(index: number, key: keyof Probe, value: string | number) {
  model.value = model.value.map((item, i) => i === index ? { ...item, [key]: value } : item)
}
function add() {
  if (model.value.length >= 8) return
  model.value = [...model.value, {
    host: '', port: 443,
    server_name: props.domains.find((domain) => !domain.startsWith('*.')) || '',
  }]
}
function remove(index: number) {
  if (model.value.length > 1) model.value = model.value.filter((_, i) => i !== index)
}
</script>
<template>
  <Card title="HTTPS 验证目标" class="settings-card">
    <template #extra>
      <Button html-type="button" :disabled="model.length >= 8 || undefined" @click="add">
        <template #icon><PlusOutlined /></template>
        添加目标
      </Button>
    </template>
    <p class="settings-help settings-intro">
      替换后验证证书链、服务域名和实际证书是否一致。连接地址可以是 NAS 内网 IP，服务域名须由所选证书覆盖，最多添加 8 个目标。
    </p>
    <Empty v-if="!model.length" :image="Empty.PRESENTED_IMAGE_SIMPLE" description="尚未配置验证目标，请添加一个目标。" />
    <div v-for="(probe, index) in model" :key="index" class="settings-probe-row" role="group" :aria-labelledby="`probe-title-${index}`">
      <div class="settings-probe-heading">
        <h3 :id="`probe-title-${index}`">目标 {{ index + 1 }}</h3>
        <Button type="text" danger html-type="button" :aria-label="`移除目标 ${index + 1}`" :disabled="model.length <= 1 || undefined" @click="remove(index)">
          <template #icon><DeleteOutlined /></template>
          移除此目标
        </Button>
      </div>
      <div class="settings-probe-grid">
        <FormItem label="连接地址" :html-for="`probe-host-${index}`">
          <Input :id="`probe-host-${index}`" :name="`probe_host_${index}`" :value="probe.host" :maxlength="253" placeholder="请输入 IP 或域名" @update:value="edit(index, 'host', $event)" />
        </FormItem>
        <FormItem label="端口" :html-for="`probe-port-${index}`">
          <InputNumber :id="`probe-port-${index}`" :name="`probe_port_${index}`" :min="1" :max="65535" :precision="0" :value="Number.isFinite(probe.port) ? probe.port : ''" @update:value="edit(index, 'port', $event === null ? NaN : Number($event))" />
        </FormItem>
        <FormItem label="服务域名（SNI）" :html-for="`probe-server-name-${index}`">
          <Input :id="`probe-server-name-${index}`" :name="`probe_server_name_${index}`" :value="probe.server_name" :maxlength="253" @update:value="edit(index, 'server_name', $event)" />
        </FormItem>
      </div>
    </div>
  </Card>
</template>
