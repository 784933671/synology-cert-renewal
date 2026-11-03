<script setup lang="ts">
import { onUnmounted, watch } from 'vue'
import { Button, Card, Empty, Form, FormItem, InputNumber, Space, Spin, Switch, Tag } from 'ant-design-vue'
import { useMonitorSettings } from '../composables/useMonitorSettings'
import NoticeBar from './NoticeBar.vue'
const emit = defineEmits<{ dirty: [value: boolean]; busy: [value: boolean]; saved: [] }>()
const { data, draft, loading, saving, error, success, validation, conflict, uncertain, dirty, reload, save, reset } = useMonitorSettings()
watch(dirty, (value) => emit('dirty', value), { immediate: true, flush: 'sync' })
watch(saving, (value) => emit('busy', value), { flush: 'sync' })
async function submit() { if (await save()) emit('saved') }
onUnmounted(() => { emit('dirty', false); emit('busy', false) })
</script>
<template>
  <Card title="监测配置" class="health-settings-card">
    <template #extra><Button :loading="loading" :disabled="saving" @click="reload">重新读取配置</Button></template>
    <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
    <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
    <NoticeBar v-if="conflict" type="warning">监测配置已在其他位置修改，草稿已保留。请重新读取最新配置后再保存。</NoticeBar>
    <NoticeBar v-if="uncertain" type="warning">保存结果尚未确认，请重新读取配置后再操作，避免重复提交。</NoticeBar>
    <NoticeBar v-if="validation.length" type="error"><ul class="validation-list"><li v-for="message in validation" :key="message">{{ message }}</li></ul></NoticeBar>
    <div v-if="!draft || !data" class="health-settings-empty">
      <Spin v-if="loading" tip="正在读取监测配置…"><div class="monitoring-loading" role="status">正在读取监测配置…</div></Spin>
      <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取监测配置"><Button @click="reload">重试</Button></Empty>
    </div>
    <Form v-else layout="vertical" :model="draft" :disabled="loading || saving" @submit.prevent="submit">
      <div class="settings-toggle-row health-monitor-toggle">
        <div><label class="settings-field-label" for="monitor-enabled">开启主动监测</label><p class="settings-help">监测任务漏跑和证书临期；发现异常时按通知设置提醒。</p></div>
        <Switch id="monitor-enabled" :checked="draft.enabled" aria-label="开启主动监测" @update:checked="draft.enabled = Boolean($event)" />
      </div>
      <div class="health-monitor-fields">
        <FormItem label="连续漏跑次数" html-for="monitor-missed-runs" extra="达到此次数后提醒，范围 1～6 次。">
          <InputNumber id="monitor-missed-runs" :value="Number.isFinite(draft.missed_runs) ? draft.missed_runs : ''" :min="1" :max="6" :precision="0" addon-after="次" @update:value="draft.missed_runs = $event === null ? NaN : Number($event)" />
        </FormItem>
        <FormItem label="执行宽限时间" html-for="monitor-grace-minutes" extra="为计划执行预留等待时间，范围 5～120 分钟。">
          <InputNumber id="monitor-grace-minutes" :value="Number.isFinite(draft.grace_minutes) ? draft.grace_minutes : ''" :min="5" :max="120" :precision="0" addon-after="分钟" @update:value="draft.grace_minutes = $event === null ? NaN : Number($event)" />
        </FormItem>
        <FormItem label="证书临期提醒" html-for="monitor-expiry-hours" extra="剩余时间低于此值时提醒，范围 1～168 小时。">
          <InputNumber id="monitor-expiry-hours" :value="Number.isFinite(draft.expiry_hours) ? draft.expiry_hours : ''" :min="1" :max="168" :precision="0" addon-after="小时" @update:value="draft.expiry_hours = $event === null ? NaN : Number($event)" />
        </FormItem>
      </div>
      <NoticeBar :type="data.notification_enabled ? 'info' : 'warning'">预警沿用“邮件通知”中的失败通知邮箱：{{ data.recipient || '未配置' }}。{{ data.notification_enabled ? '监测间隔为 ' + data.interval_seconds + ' 秒。' : '失败通知已关闭或未配置，当前不会发送预警邮件。' }}</NoticeBar>
      <p class="settings-help">临期提醒仅用于预警，不会改变“续期计划”中的提前续期时间。任务暂停时不会将漏跑状态显示为正常。</p>
      <div class="settings-save-bar settings-save-bar-inline">
        <span class="settings-save-note"><Tag :color="dirty || uncertain || conflict ? 'warning' : 'default'">{{ uncertain || conflict ? '待确认' : dirty ? '未保存' : '已同步' }}</Tag>{{ uncertain || conflict ? '请重新读取服务器上的监测配置' : dirty ? '监测配置有尚未保存的修改' : '监测配置与服务器一致' }}</span>
        <Space wrap>
          <Button html-type="button" :disabled="loading || saving || !dirty" @click="reset">放弃修改</Button>
          <Button type="primary" html-type="submit" :loading="saving" :disabled="loading || saving || !dirty || conflict || uncertain">保存监测配置</Button>
        </Space>
      </div>
    </Form>
  </Card>
</template>
