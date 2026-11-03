<script setup lang="ts">
import type { Schedule } from '../types'
const model = defineModel<Schedule>({ required: true })
const days = defineModel<number>('days', { required: true })
function update<K extends keyof Schedule>(key: K, value: Schedule[K]) {
  model.value = { ...model.value, [key]: value }
}
</script>
<template>
  <section class="panel">
    <header class="panel-heading"><h2>自动检查</h2></header>
    <div class="panel-body">
      <label class="setting-row">
        <span>
          <strong>启用自动检查</strong>
          <span class="help">到达计划时间自动检查有效期，符合条件时续期。</span>
        </span>
        <input
          class="switch"
          type="checkbox"
          :checked="model.enabled"
          @change="
            update('enabled', ($event.target as HTMLInputElement).checked)
          "
        />
      </label>
    </div>
  </section>
  <section class="panel">
    <header class="panel-heading"><h2>检查与续期规则</h2></header>
    <div class="panel-body form-grid">
      <label class="field full">
        提前续期时间
        <div class="field-unit">
          <input
            v-model.number="days"
            class="input"
            type="number"
            min="1"
            max="30"
          />
          <span>天</span>
        </div>
        <span class="help">
          按证书实际到期时间计算。提前 2 天即进入到期前 48 小时的续期窗口。
        </span>
      </label>
      <label class="field">
        检查方式
        <select
          class="input"
          :value="model.mode"
          @change="
            update(
              'mode',
              ($event.target as HTMLSelectElement).value as Schedule['mode'],
            )
          "
        >
          <option value="hourly">每隔数小时</option>
          <option value="daily">每天固定时间</option>
          <option v-if="model.mode === 'unsupported'" value="unsupported">
            当前计划暂不支持编辑
          </option>
        </select>
      </label>
      <label v-if="model.mode === 'hourly'" class="field">
        检查频率
        <select
          class="input"
          :value="model.interval_hours"
          @change="
            update(
              'interval_hours',
              Number(($event.target as HTMLSelectElement).value),
            )
          "
        >
          <option
            v-for="hours in [1, 2, 3, 4, 6, 8, 12]"
            :key="hours"
            :value="hours"
          >
            每 {{ hours }} 小时
          </option>
        </select>
      </label>
      <label v-else-if="model.mode === 'daily'" class="field">
        检查小时
        <input
          class="input"
          type="number"
          min="0"
          max="23"
          :value="model.hour"
          @input="
            update('hour', ($event.target as HTMLInputElement).valueAsNumber)
          "
        />
      </label>
      <label class="field">
        检查分钟
        <input
          class="input"
          type="number"
          min="0"
          max="59"
          :value="model.minute"
          @input="
            update('minute', ($event.target as HTMLInputElement).valueAsNumber)
          "
        />
      </label>
      <p class="help full">
        每次检查不一定申请新证书。只有进入续期窗口，或存在待恢复操作时，任务才继续处理。
      </p>
    </div>
  </section>
</template>
