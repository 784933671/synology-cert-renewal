<script setup lang="ts">
import { computed, onUnmounted, watch } from 'vue'
import { Button, Card, Descriptions, DescriptionsItem, Divider, Empty, Form, FormItem, Radio, RadioGroup, Spin, Tag } from 'ant-design-vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import { useAccessPolicy } from '../composables/useAccessPolicy'
import NoticeBar from '../components/NoticeBar.vue'
const emit = defineEmits<{ dirty: [value: boolean]; busy: [value: boolean] }>()
const {
  data, mode, loading, saving, error, conflict, uncertain, pollPaused,
  dirty, locked, saveMessage, reload, save, reset,
} = useAccessPolicy()
const appliedLabel = computed(() =>
  data.value?.applied_mode === 'public' ? '允许外网'
    : data.value?.applied_mode === 'lan' ? '仅内网' : '尚未确认',
)
watch(dirty, (value) => emit('dirty', value), { immediate: true })
watch(saving, (value) => emit('busy', value))
onUnmounted(() => {
  emit('dirty', false)
  emit('busy', false)
})
</script>
<template>
  <div class="page-heading">
    <div><h1>访问安全</h1><p>配置管理页面的访问范围，查看当前应用状态与登录会话策略。</p></div>
    <Button :loading="loading" :disabled="saving" @click="reload">
      <template #icon><ReloadOutlined /></template>
      {{ loading ? '读取中…' : '重新读取' }}
    </Button>
  </div>
  <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方为上次读取的配置。</span></NoticeBar>
  <NoticeBar v-if="conflict" type="warning">
    配置已在其他位置修改，当前草稿已保留。请记录需要保留的修改，再点击“重新读取”获取最新配置。
  </NoticeBar>
  <NoticeBar v-if="uncertain" type="warning">
    保存结果尚未确认，请重新读取后再操作。若刚切换为仅内网，请连接内网后访问。
  </NoticeBar>
  <NoticeBar v-if="saveMessage" :type="data?.pending ? 'info' : 'success'">{{ saveMessage }}</NoticeBar>
  <NoticeBar v-else-if="data?.pending && !pollPaused" type="info">
    已保存的访问模式正在应用，页面会自动确认结果，期间可能短暂断开连接。
  </NoticeBar>
  <NoticeBar v-if="pollPaused" type="warning">
    尚未确认访问规则的应用结果，请点击“重新读取”。若已切换为仅内网，请连接内网后访问。
  </NoticeBar>
  <Card v-if="!data" class="settings-empty-card">
    <div v-if="loading" class="settings-loading" role="status"><Spin /><p>正在读取安全设置…</p></div>
    <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取安全设置，连接成功后显示服务器实际生效的策略。">
      <Button @click="reload">重试</Button>
    </Empty>
  </Card>
  <div v-else class="settings-section-stack">
    <Card title="管理入口" class="settings-card">
      <Form layout="vertical" :disabled="locked" @submit.prevent="save">
        <FormItem label="访问模式" html-for="access-mode-lan">
          <RadioGroup id="access-mode" v-model:value="mode" name="access_mode" class="settings-access-options" aria-label="访问模式">
            <Radio id="access-mode-lan" value="lan" class="settings-access-option">
              <span class="settings-access-option-title">仅内网</span>
              <span class="settings-help">仅允许指定局域网中的设备访问</span>
            </Radio>
            <Radio id="access-mode-public" value="public" class="settings-access-option">
              <span class="settings-access-option-title">允许外网</span>
              <span class="settings-help">允许通过外网入口访问管理页面</span>
            </Radio>
          </RadioGroup>
        </FormItem>
        <p class="settings-help">允许外网时仍需登录并使用 HTTPS；路由器需配置对应端口的访问入口。</p>
        <NoticeBar type="warning">切回“仅内网”后，外网连接可能立即断开；请在内网重新访问。</NoticeBar>
        <div class="settings-save-bar settings-save-bar-inline">
          <span class="settings-save-note">{{ dirty ? '有尚未保存的修改' : data.pending ? '访问规则正在应用' : '配置与服务器一致' }}</span>
          <div class="settings-action-buttons">
            <Button html-type="button" :disabled="locked || !dirty" @click="reset">放弃修改</Button>
            <Button type="primary" html-type="submit" :loading="saving" :disabled="locked || !dirty || conflict || uncertain">{{ saving ? '正在保存…' : '保存访问模式' }}</Button>
          </div>
        </div>
      </Form>
      <Divider />
      <div class="access-policy-status">
        <Descriptions title="当前安全状态" :column="1" size="small">
          <DescriptionsItem label="服务器已应用模式">
            <Tag :color="data.pending ? 'processing' : 'success'">{{ appliedLabel }}</Tag>
            <span class="settings-help">{{ data.pending ? '正在同步最新设置，下方为最近确认的模式。' : '访问规则已与保存的设置同步。' }}</span>
          </DescriptionsItem>
          <DescriptionsItem label="HTTPS 加密连接"><Tag :color="data.https ? 'success' : 'warning'">{{ data.https ? '已启用' : '未启用' }}</Tag></DescriptionsItem>
          <DescriptionsItem label="已保存的访问范围">
            <div class="settings-tags">
              <Tag v-if="data.access_mode === 'public'">所有 IPv4 地址</Tag>
              <template v-else>
                <Tag v-for="network in data.allowed_networks" :key="network"><code>{{ network }}</code></Tag>
                <span v-if="!data.allowed_networks.length" class="settings-help">未返回允许访问的网络</span>
              </template>
            </div>
          </DescriptionsItem>
        </Descriptions>
      </div>
    </Card>
    <Card title="登录会话" class="settings-card">
      <Descriptions :column="1" size="small">
        <DescriptionsItem label="闲置自动退出">{{ data.session_idle_minutes }} 分钟</DescriptionsItem>
        <DescriptionsItem label="最长登录时长">{{ data.session_absolute_hours }} 小时</DescriptionsItem>
      </Descriptions>
      <p class="settings-help settings-session-note">修改访问模式不会暂停证书续期任务。修改密码会撤销其他登录会话。</p>
    </Card>
  </div>
</template>
