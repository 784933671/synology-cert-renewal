<script setup lang="ts">
import { computed } from 'vue'
import type { Draft, Settings } from '../types'
import NoticeBar from './NoticeBar.vue'
const model = defineModel<Draft>({ required: true })
const props = defineProps<{ settings: Settings }>()
const selected = computed(() =>
  props.settings.certificates.find(
    (item) => item.id === model.value.certificate_id,
  ),
)
function update<K extends keyof Draft>(key: K, value: Draft[K]) {
  model.value = { ...model.value, [key]: value }
}
</script>
<template>
  <section class="panel">
    <header class="panel-heading"><h2>证书与域名</h2></header>
    <div class="panel-body form-grid">
      <label class="field full">
        群晖证书
        <select
          class="input"
          :value="model.certificate_id"
          @change="
            update('certificate_id', ($event.target as HTMLSelectElement).value)
          "
        >
          <option
            v-for="certificate in settings.certificates"
            :key="certificate.id"
            :value="certificate.id"
            :disabled="
              certificate.available === false ||
              certificate.selectable === false
            "
          >
            {{ certificate.description || '未命名证书' }} ·
            {{ certificate.domains.join('、') || certificate.id }}
            {{
              certificate.selectable === false
                ? `（${certificate.reason || '暂不可选'}）`
                : ''
            }}
          </option>
        </select>
        <span class="help">
          域名与描述来自群晖证书，更新时沿用该证书的服务绑定。
        </span>
      </label>
      <div class="field full">
        <span>覆盖的域名</span>
        <div class="tag-list">
          <span
            v-for="domain in selected?.domains || []"
            :key="domain"
            class="badge neutral"
          >
            {{ domain }}
          </span>
          <span v-if="!selected?.domains.length" class="muted">暂无域名</span>
        </div>
      </div>
      <label class="field full">
        证书注册邮箱
        <input
          :value="model.email"
          class="input"
          type="email"
          maxlength="254"
          autocomplete="email"
          @input="update('email', ($event.target as HTMLInputElement).value)"
        />
      </label>
      <NoticeBar
        v-if="model.certificate_id !== settings.certificate_id"
        type="warning"
      >
        更换证书后，请确认下方所有 HTTPS 验证目标的服务域名均受新证书保护。
      </NoticeBar>
    </div>
  </section>
  <section class="panel">
    <header class="panel-heading">
      <h2>DNSPod 域名验证</h2>
      <span
        :class="[
          'badge',
          settings.secret_id_configured && settings.secret_key_configured
            ? 'success'
            : 'warning',
        ]"
      >
        {{
          settings.secret_id_configured && settings.secret_key_configured
            ? '凭据已配置'
            : '凭据待配置'
        }}
      </span>
    </header>
    <div class="panel-body form-grid">
      <p class="help full">
        已保存的凭据不会显示。留空保持不变；更换时请同时填写两项。
      </p>
      <label class="field">
        新 SecretId
        <input
          class="input"
          :value="model.secret_id"
          type="password"
          autocomplete="new-password"
          spellcheck="false"
          maxlength="256"
          placeholder="留空保持现有值"
          @input="
            update('secret_id', ($event.target as HTMLInputElement).value)
          "
        />
      </label>
      <label class="field">
        新 SecretKey
        <input
          class="input"
          :value="model.secret_key"
          type="password"
          autocomplete="new-password"
          spellcheck="false"
          maxlength="256"
          placeholder="留空保持现有值"
          @input="
            update('secret_key', ($event.target as HTMLInputElement).value)
          "
        />
      </label>
    </div>
  </section>
</template>
