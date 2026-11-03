<script setup lang="ts">
import { computed, onUnmounted, watch } from 'vue'
import { Button, Card, Empty, Form, Spin, Tag } from 'ant-design-vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import type { SettingsPage } from '../types'
import { useSettingsDraft } from '../composables/useSettingsDraft'
import CertificateFields from '../components/CertificateFields.vue'
import ProbeFields from '../components/ProbeFields.vue'
import ScheduleFields from '../components/ScheduleFields.vue'
import NotificationFields from '../components/NotificationFields.vue'
import NoticeBar from '../components/NoticeBar.vue'
const props = defineProps<{ section: SettingsPage }>()
const emit = defineEmits<{ dirty: [value: boolean]; busy: [value: boolean] }>()
const {
  settings,
  draft,
  loading,
  saving,
  error,
  success,
  conflict,
  validation,
  dirty,
  writable,
  reload,
  save,
  reset,
} = useSettingsDraft()
const copy = computed(
  () =>
    ({
      certificate: ['证书管理', '配置群晖证书、域名验证与 HTTPS 验证目标。'],
      renewal: ['续期计划', '设置检查频率，以及距离到期多久开始续期。'],
      notifications: ['邮件通知', '重要结果及时送达，正常检查保持安静。'],
    })[props.section],
)
const domains = computed(
  () =>
    settings.value?.certificates.find(
      (item) => item.id === draft.value?.certificate_id,
    )?.domains || [],
)
const fieldsDisabled = computed(() => saving.value || loading.value || !writable.value)
watch(dirty, (value) => emit('dirty', value), { immediate: true })
watch(saving, (value) => emit('busy', value))
onUnmounted(() => {
  emit('dirty', false)
  emit('busy', false)
})
</script>
<template>
  <div class="page-heading">
    <div><h1>{{ copy[0] }}</h1><p>{{ copy[1] }}</p></div>
    <Button :loading="loading" :disabled="saving" @click="reload">
      <template #icon><ReloadOutlined /></template>
      {{ loading ? '读取中…' : '重新读取' }}
    </Button>
  </div>
  <NoticeBar v-if="error" type="error">{{ error }}</NoticeBar>
  <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
  <NoticeBar v-if="conflict" type="warning">
    配置已在其他位置修改，当前草稿已保留。请记录需要保留的修改，再点击“重新读取”获取最新配置；不会覆盖服务器配置。
  </NoticeBar>
  <NoticeBar v-if="validation.length" type="error">
    <ul class="validation-list"><li v-for="item in validation" :key="item">{{ item }}</li></ul>
  </NoticeBar>
  <Card v-if="!draft || !settings" class="settings-empty-card">
    <div v-if="loading" class="settings-loading" role="status"><Spin /><p>正在读取配置…</p></div>
    <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取配置，读取群晖当前配置后即可修改。">
      <Button @click="reload">重试</Button>
    </Empty>
  </Card>
  <template v-else>
    <NoticeBar v-if="!writable" type="warning">
      {{ draft.schedule.message || '群晖当前任务计划暂不支持网页编辑。为保留原计划，配置已设为只读。' }}
    </NoticeBar>
    <div class="settings-page-layout">
      <Form class="settings-form" layout="vertical" :disabled="fieldsDisabled" :model="draft" novalidate @submit.prevent="save">
        <div class="settings-section-stack">
          <template v-if="section === 'certificate'">
            <CertificateFields v-model="draft" :settings="settings" />
            <ProbeFields v-model="draft.probes" :domains="domains" />
          </template>
          <ScheduleFields v-else-if="section === 'renewal'" v-model="draft.schedule" v-model:days="draft.renew_before_days" />
          <NotificationFields v-else v-model="draft.notifications" />
        </div>
        <div class="settings-save-bar">
          <span class="settings-save-note"><Tag :color="dirty ? 'warning' : 'default'">{{ dirty ? '未保存' : '已同步' }}</Tag>{{ dirty ? '有尚未保存的修改' : '配置与服务器一致' }}</span>
          <div class="settings-action-buttons">
            <Button html-type="button" :disabled="fieldsDisabled || !dirty" @click="reset">放弃修改</Button>
            <Button type="primary" html-type="submit" :loading="saving" :disabled="fieldsDisabled || !dirty || conflict">{{ saving ? '正在保存…' : '保存配置' }}</Button>
          </div>
        </div>
      </Form>
      <Card class="settings-side-note" size="small" :title="section === 'notifications' ? '只在需要时提醒' : section === 'renewal' ? '检查不等于续期' : '自动验证，自动部署'">
        <p v-if="section === 'certificate'">DNSPod 验证无需开放公网 80 端口。证书替换后，通过配置的目标确认实际服务证书。</p>
        <p v-else-if="section === 'renewal'">未进入续期窗口时正常跳过；异常会记录失败阶段，后续任务继续重试。</p>
        <p v-else>成功和失败可以使用不同的收件邮箱。关闭通知不会暂停证书任务。</p>
        <p class="settings-help">时区：{{ settings.timezone }}</p>
      </Card>
    </div>
  </template>
</template>
