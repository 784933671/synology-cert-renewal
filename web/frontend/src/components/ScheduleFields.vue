<script setup lang="ts">
import { computed } from 'vue'
import { Card, FormItem, InputNumber, Select, Switch } from 'ant-design-vue'
import type { Schedule } from '../types'
const model = defineModel<Schedule>({ required: true })
const days = defineModel<number>('days', { required: true })
const modeOptions = computed(() => [
  { value: 'hourly', label: '每隔数小时' },
  { value: 'daily', label: '每天固定时间' },
  ...(model.value.mode === 'unsupported' ? [{ value: 'unsupported', label: '当前计划暂不支持编辑', disabled: true }] : []),
])
const intervalOptions = [1, 2, 3, 4, 6, 8, 12].map((hours) => ({ value: hours, label: `每 ${hours} 小时` }))
function update<K extends keyof Schedule>(key: K, value: Schedule[K]) {
  model.value = { ...model.value, [key]: value }
}
</script>
<template>
  <Card title="自动检查" class="settings-card">
    <div class="settings-toggle-row">
      <div>
        <label class="settings-field-label" for="schedule-enabled">启用自动检查</label>
        <p class="settings-help">到达计划时间自动检查有效期，符合条件时续期。</p>
      </div>
      <Switch id="schedule-enabled" :checked="model.enabled" aria-label="启用自动检查" @update:checked="update('enabled', Boolean($event))" />
    </div>
  </Card>
  <Card title="检查与续期规则" class="settings-card">
    <div class="settings-form-grid">
      <FormItem class="settings-full-width" label="提前续期时间" html-for="renew-before-days" extra="按证书实际到期时间计算。提前 2 天即进入到期前 48 小时的续期窗口。">
        <InputNumber id="renew-before-days" name="renew_before_days" :value="Number.isFinite(days) ? days : ''" :min="1" :max="30" :precision="0" addon-after="天" @update:value="days = $event === null ? NaN : Number($event)" />
      </FormItem>
      <FormItem label="检查方式" html-for="schedule-mode">
        <Select id="schedule-mode" name="schedule_mode" :value="model.mode" :options="modeOptions" @update:value="update('mode', $event as Schedule['mode'])" />
      </FormItem>
      <FormItem v-if="model.mode === 'hourly'" label="检查频率" html-for="schedule-interval">
        <Select id="schedule-interval" name="interval_hours" :value="model.interval_hours" :options="intervalOptions" @update:value="update('interval_hours', Number($event))" />
      </FormItem>
      <FormItem v-else-if="model.mode === 'daily'" label="检查小时" html-for="schedule-hour">
        <InputNumber id="schedule-hour" name="hour" :value="Number.isFinite(model.hour) ? model.hour : ''" :min="0" :max="23" :precision="0" addon-after="时" @update:value="update('hour', $event === null ? NaN : Number($event))" />
      </FormItem>
      <FormItem label="检查分钟" html-for="schedule-minute">
        <InputNumber id="schedule-minute" name="minute" :value="Number.isFinite(model.minute) ? model.minute : ''" :min="0" :max="59" :precision="0" addon-after="分" @update:value="update('minute', $event === null ? NaN : Number($event))" />
      </FormItem>
    </div>
    <p class="settings-help">每次检查不一定申请新证书。只有进入续期窗口，或存在待恢复操作时，任务才继续处理。</p>
  </Card>
</template>
