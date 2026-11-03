<script setup lang="ts">
import type { Probe } from '../types'
import AppIcon from './AppIcon.vue'
const model = defineModel<Probe[]>({ required: true })
const props = defineProps<{ domains: string[] }>()
function edit(index: number, key: keyof Probe, value: string | number) {
  model.value = model.value.map((item, i) =>
    i === index ? { ...item, [key]: value } : item,
  )
}
function add() {
  model.value = [
    ...model.value,
    {
      host: '',
      port: 443,
      server_name:
        props.domains.find((domain) => !domain.startsWith('*.')) || '',
    },
  ]
}
function remove(index: number) {
  model.value = model.value.filter((_, i) => i !== index)
}
</script>
<template>
  <section class="panel">
    <header class="panel-heading">
      <h2>HTTPS 验证目标</h2>
      <button
        class="button"
        type="button"
        :disabled="model.length >= 8"
        @click="add"
      >
        <AppIcon name="plus" />
        添加目标
      </button>
    </header>
    <div class="panel-body">
      <p class="help">
        替换后验证证书链、服务域名和实际证书是否一致。连接地址可以是 NAS 内网
        IP，服务域名须由所选证书覆盖，最多添加 8 个目标。
      </p>
      <div v-if="!model.length" class="empty-inline">
        尚未配置验证目标，请添加一个目标。
      </div>
      <fieldset v-for="(probe, index) in model" :key="index" class="probe-row">
        <legend>目标 {{ index + 1 }}</legend>
        <div class="form-grid probe-grid">
          <label class="field">
            连接地址
            <input
              class="input"
              :value="probe.host"
              maxlength="253"
              placeholder="IP 或域名，不含 https://"
              @input="
                edit(index, 'host', ($event.target as HTMLInputElement).value)
              "
            />
          </label>
          <label class="field">
            端口
            <input
              class="input"
              type="number"
              min="1"
              max="65535"
              :value="probe.port"
              @input="
                edit(
                  index,
                  'port',
                  ($event.target as HTMLInputElement).valueAsNumber,
                )
              "
            />
          </label>
          <label class="field">
            服务域名（SNI）
            <input
              class="input"
              :value="probe.server_name"
              maxlength="253"
              @input="
                edit(
                  index,
                  'server_name',
                  ($event.target as HTMLInputElement).value,
                )
              "
            />
          </label>
        </div>
        <button
          type="button"
          class="text-button danger"
          :disabled="model.length <= 1"
          @click="remove(index)"
        >
          移除此目标
        </button>
      </fieldset>
    </div>
  </section>
</template>
