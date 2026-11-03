<script setup lang="ts">
import { Card, FormItem, Input, Switch } from 'ant-design-vue'
import type { Notifications } from '../types'
import NoticeBar from './NoticeBar.vue'
const model = defineModel<Notifications>({ required: true })
function update<K extends keyof Notifications>(key: K, value: Notifications[K]) {
  model.value = { ...model.value, [key]: value }
}
</script>
<template>
  <Card title="续期成功通知" class="settings-card">
    <div class="settings-toggle-row settings-intro">
      <div>
        <label class="settings-field-label" for="notification-success-enabled">续期并替换成功后通知</label>
        <p class="settings-help">新证书完成替换并确认 HTTPS 生效后发送。</p>
      </div>
      <Switch id="notification-success-enabled" :checked="model.success_enabled" aria-label="续期并替换成功后通知" @update:checked="update('success_enabled', Boolean($event))" />
    </div>
    <FormItem label="成功通知邮箱" html-for="notification-success-email">
      <Input id="notification-success-email" name="success_email" :value="model.success_email" type="email" :maxlength="254" autocomplete="email" :disabled="!model.success_enabled || undefined" @update:value="update('success_email', $event)" />
    </FormItem>
  </Card>
  <Card title="执行失败通知" class="settings-card">
    <div class="settings-toggle-row settings-intro">
      <div>
        <label class="settings-field-label" for="notification-failure-enabled">任务失败后通知</label>
        <p class="settings-help">包含失败阶段、脱敏摘要、错误码和日志位置。</p>
      </div>
      <Switch id="notification-failure-enabled" :checked="model.failure_enabled" aria-label="任务失败后通知" @update:checked="update('failure_enabled', Boolean($event))" />
    </div>
    <FormItem label="失败通知邮箱" html-for="notification-failure-email">
      <Input id="notification-failure-email" name="failure_email" :value="model.failure_email" type="email" :maxlength="254" autocomplete="email" :disabled="!model.failure_enabled || undefined" @update:value="update('failure_email', $event)" />
    </FormItem>
  </Card>
  <NoticeBar type="info">正常检查且无需续期时不发送邮件。发件服务沿用群晖当前的邮件通知配置。</NoticeBar>
</template>
