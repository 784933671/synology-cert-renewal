<script setup lang="ts">
import { computed } from 'vue'
import { Card, FormItem, Input, Select, Tag } from 'ant-design-vue'
import type { Draft, Settings } from '../types'
import NoticeBar from './NoticeBar.vue'
const InputPassword = Input.Password
const model = defineModel<Draft>({ required: true })
const props = defineProps<{ settings: Settings }>()
const selected = computed(() =>
  props.settings.certificates.find((item) => item.id === model.value.certificate_id),
)
const credentialsConfigured = computed(() =>
  props.settings.secret_id_configured && props.settings.secret_key_configured,
)
const certificateOptions = computed(() => props.settings.certificates.map((certificate) => ({
  value: certificate.id,
  disabled: certificate.available === false || certificate.selectable === false,
  label: `${certificate.description || '未命名证书'} · ${certificate.domains.join('、') || certificate.id}${certificate.selectable === false ? `（${certificate.reason || '暂不可选'}）` : ''}`,
})))
function update<K extends keyof Draft>(key: K, value: Draft[K]) {
  model.value = { ...model.value, [key]: value }
}
</script>
<template>
  <Card title="证书与域名" class="settings-card">
    <FormItem label="群晖证书" html-for="certificate-id" extra="域名与描述来自群晖证书，更新时沿用该证书的服务绑定。">
      <Select
        id="certificate-id"
        name="certificate_id"
        :value="model.certificate_id"
        :options="certificateOptions"
        :virtual="false"
        option-label-prop="label"
        @update:value="update('certificate_id', String($event))"
      />
    </FormItem>
    <div class="settings-domain-field">
      <span class="settings-field-label">覆盖的域名</span>
      <div class="settings-tags">
        <Tag v-for="domain in selected?.domains || []" :key="domain" color="blue">{{ domain }}</Tag>
        <span v-if="!selected?.domains.length" class="settings-help">暂无域名</span>
      </div>
    </div>
    <FormItem label="证书注册邮箱" html-for="certificate-email">
      <Input
        id="certificate-email"
        name="email"
        :value="model.email"
        type="email"
        :maxlength="254"
        autocomplete="email"
        @update:value="update('email', $event)"
      />
    </FormItem>
    <NoticeBar v-if="model.certificate_id !== settings.certificate_id" type="warning">
      更换证书后，请确认下方所有 HTTPS 验证目标的服务域名均受新证书保护。
    </NoticeBar>
  </Card>
  <Card title="DNSPod 域名验证" class="settings-card">
    <template #extra>
      <Tag :color="credentialsConfigured ? 'success' : 'warning'">
        {{ credentialsConfigured ? '凭据已配置' : '凭据待配置' }}
      </Tag>
    </template>
    <p id="dns-credentials-help" class="settings-help settings-intro">
      已保存的凭据不会显示。留空保持不变；更换时请同时填写两项。
    </p>
    <div class="settings-form-grid">
      <FormItem label="新 SecretId" html-for="dns-secret-id">
        <InputPassword
          id="dns-secret-id"
          name="secret_id"
          :value="model.secret_id"
          autocomplete="new-password"
          :spellcheck="false"
          :maxlength="256"
          aria-describedby="dns-credentials-help"
          placeholder="留空保持现有值"
          @update:value="update('secret_id', $event)"
        />
      </FormItem>
      <FormItem label="新 SecretKey" html-for="dns-secret-key">
        <InputPassword
          id="dns-secret-key"
          name="secret_key"
          :value="model.secret_key"
          autocomplete="new-password"
          :spellcheck="false"
          :maxlength="256"
          aria-describedby="dns-credentials-help"
          placeholder="留空保持现有值"
          @update:value="update('secret_key', $event)"
        />
      </FormItem>
    </div>
  </Card>
</template>
