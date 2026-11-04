<script setup lang="ts">
import { computed, onUnmounted, shallowRef, watch } from 'vue'
import { Button, Card, Empty, Form, FormItem, InputNumber, Spin, Tag } from 'ant-design-vue'
import { abuseFields, useAbusePolicy } from '../composables/useAbusePolicy'
import AbuseBlocksPanel from '../components/AbuseBlocksPanel.vue'
import NoticeBar from '../components/NoticeBar.vue'
const emit = defineEmits<{ dirty: [value: boolean]; busy: [value: boolean] }>()
const { data, draft, loading, saving, conflict, uncertain, error, success, validation, dirty, reload, save, reset } = useAbusePolicy()
const blocksBusy = shallowRef(false)
const busy = computed(() => saving.value || blocksBusy.value)
const locked = computed(() => loading.value || busy.value)
watch(dirty, value => emit('dirty', value), { immediate: true })
watch(busy, value => emit('busy', value), { flush: 'sync' })
onUnmounted(() => { emit('dirty', false); emit('busy', false) })
</script>
<template>
  <div class="page-heading">
    <div><h1>接口防护</h1><p>限制异常请求频率，查看并处理临时封禁。</p></div>
    <Button :loading="loading" :disabled="busy" @click="reload">重新读取防护设置</Button>
  </div>
  <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">当前草稿已保留。</span></NoticeBar>
  <NoticeBar v-if="conflict" type="warning">配置已在其他位置修改，请记录要保留的修改后重新读取，避免覆盖最新设置。</NoticeBar>
  <NoticeBar v-if="uncertain" type="warning">保存结果尚未确认，请重新读取后再操作，不会自动重复提交。</NoticeBar>
  <NoticeBar v-if="success" type="success">{{ success }}</NoticeBar>
  <NoticeBar v-if="validation.length" type="error"><ul class="validation-list"><li v-for="item in validation" :key="item">{{ item }}</li></ul></NoticeBar>
  <div class="settings-section-stack">
    <Card v-if="!data || !draft" class="settings-card">
      <div v-if="loading" class="settings-loading" role="status"><Spin /><p>正在读取接口防护设置…</p></div>
      <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取接口防护设置"><Button @click="reload">重试读取</Button></Empty>
    </Card>
    <Card v-else title="请求频率限制" class="settings-card">
      <template #extra><Tag color="success">持续启用</Tag></template>
      <p class="settings-help">额度按令牌桶持续补充，桶容量等于每分钟补充额度，允许短时突发请求。单个会话额度耗尽时暂缓请求；同一 IP 持续超限才触发临时封禁。自动续期任务不受影响。</p>
      <Form :model="draft" layout="vertical" :disabled="locked" @finish="!blocksBusy && save()">
        <div class="settings-form-grid">
          <FormItem v-for="field in abuseFields" :key="field.key" :name="field.key" :label="field.label" :html-for="`abuse-${field.key}`">
            <InputNumber :id="`abuse-${field.key}`" v-model:value="draft[field.key]" :min="field.min" :max="field.max" :precision="0" :addon-after="field.unit" />
            <p class="settings-help">允许 {{ field.min }}～{{ field.max }} {{ field.unit }}</p>
          </FormItem>
        </div>
        <p class="settings-help">会话补充额度不得超过 IP 补充额度。同一公网 IP 下多台设备会共享 IP 额度，请结合实际访问量设置。</p>
        <div class="settings-save-bar settings-save-bar-inline">
          <span class="settings-save-note">{{ uncertain ? '保存结果尚未确认，请重新读取' : conflict ? '服务器配置已变化，请重新读取' : dirty ? '有尚未保存的修改' : '配置与服务器一致' }}</span>
          <div class="settings-action-buttons">
            <Button :disabled="locked || !dirty" @click="reset">放弃修改</Button>
            <Button type="primary" html-type="submit" :loading="saving" :disabled="locked || !dirty || uncertain || conflict">保存防护设置</Button>
          </div>
        </div>
      </Form>
    </Card>
    <AbuseBlocksPanel :disabled="saving" @busy="blocksBusy = $event" />
  </div>
</template>
