<script setup lang="ts">
import type { Notifications } from '../types'
const model = defineModel<Notifications>({ required: true })
function update<K extends keyof Notifications>(
  key: K,
  value: Notifications[K],
) {
  model.value = { ...model.value, [key]: value }
}
</script>
<template>
  <section class="panel">
    <header class="panel-heading"><h2>续期成功通知</h2></header>
    <div class="panel-body form-stack">
      <label class="setting-row">
        <span>
          <strong>续期并替换成功后通知</strong>
          <span class="help">新证书完成替换并确认 HTTPS 生效后发送。</span>
        </span>
        <input
          class="switch"
          type="checkbox"
          :checked="model.success_enabled"
          @change="
            update(
              'success_enabled',
              ($event.target as HTMLInputElement).checked,
            )
          "
        />
      </label>
      <label class="field">
        成功通知邮箱
        <input
          class="input"
          :value="model.success_email"
          type="email"
          maxlength="254"
          :disabled="!model.success_enabled"
          @input="
            update('success_email', ($event.target as HTMLInputElement).value)
          "
        />
      </label>
    </div>
  </section>
  <section class="panel">
    <header class="panel-heading"><h2>执行失败通知</h2></header>
    <div class="panel-body form-stack">
      <label class="setting-row">
        <span>
          <strong>任务失败后通知</strong>
          <span class="help">包含失败阶段、脱敏摘要、错误码和日志位置。</span>
        </span>
        <input
          class="switch"
          type="checkbox"
          :checked="model.failure_enabled"
          @change="
            update(
              'failure_enabled',
              ($event.target as HTMLInputElement).checked,
            )
          "
        />
      </label>
      <label class="field">
        失败通知邮箱
        <input
          class="input"
          :value="model.failure_email"
          type="email"
          maxlength="254"
          :disabled="!model.failure_enabled"
          @input="
            update('failure_email', ($event.target as HTMLInputElement).value)
          "
        />
      </label>
    </div>
  </section>
  <div class="notice notice-info">
    正常检查且无需续期时不发送邮件。发件服务沿用群晖当前的邮件通知配置。
  </div>
</template>
