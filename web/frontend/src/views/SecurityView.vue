<script setup lang="ts">
import { computed, onUnmounted, watch } from 'vue'
import { useAccessPolicy } from '../composables/useAccessPolicy'
import AppIcon from '../components/AppIcon.vue'
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
    <div>
      <h1>访问安全</h1>
      <p>配置管理页面的访问范围，查看当前应用状态与登录会话策略。</p>
    </div>
    <button class="button" :disabled="loading || saving" @click="reload">
      <AppIcon name="refresh" />
      {{ loading ? '读取中…' : '重新读取' }}
    </button>
  </div>
  <NoticeBar v-if="error" type="error">
    {{ error }}
    <span v-if="data">下方为上次读取的配置。</span>
  </NoticeBar>
  <NoticeBar v-if="conflict" type="warning">
    配置已在其他位置修改，当前草稿已保留。请记录需要保留的修改，再点击“重新读取”获取最新配置。
  </NoticeBar>
  <NoticeBar v-if="uncertain" type="warning">
    保存结果尚未确认，请重新读取后再操作。若刚切换为仅内网，请连接内网后访问。
  </NoticeBar>
  <NoticeBar v-if="saveMessage" :type="data?.pending ? 'info' : 'success'">
    {{ saveMessage }}
  </NoticeBar>
  <NoticeBar v-else-if="data?.pending && !pollPaused" type="info">
    已保存的访问模式正在应用，页面会自动确认结果，期间可能短暂断开连接。
  </NoticeBar>
  <NoticeBar v-if="pollPaused" type="warning">
    尚未确认访问规则的应用结果，请点击“重新读取”。若已切换为仅内网，请连接内网后访问。
  </NoticeBar>
  <div v-if="!data" class="empty-state">
    <h2>{{ loading ? '正在读取安全设置…' : '暂时无法读取安全设置' }}</h2>
    <p>连接成功后显示服务器实际生效的策略。</p>
    <button v-if="!loading" class="button" @click="reload">重试</button>
  </div>
  <template v-else>
    <section class="panel">
      <header class="panel-heading"><h2>管理入口</h2></header>
      <form class="panel-body" @submit.prevent="save">
        <fieldset class="form-stack access-policy-fields" :disabled="locked">
          <label class="field access-mode-field" for="access-mode">
            访问模式
            <select id="access-mode" v-model="mode" class="input" name="access_mode">
              <option value="lan">仅内网</option>
              <option value="public">允许外网</option>
            </select>
          </label>
          <p class="help">
            允许外网时仍需登录并使用 HTTPS；路由器需配置对应端口的访问入口。
          </p>
          <div class="access-policy-actions">
            <p class="help">
              切回“仅内网”后，外网连接可能立即断开；请在内网重新访问。
            </p>
            <div class="form-actions">
              <span class="save-note">
                {{ dirty ? '有尚未保存的修改' : data.pending ? '访问规则正在应用' : '配置与服务器一致' }}
              </span>
              <button type="button" class="button" :disabled="!dirty" @click="reset">
                放弃修改
              </button>
              <button type="submit" class="button primary" :disabled="!dirty || conflict || uncertain">
                {{ saving ? '正在保存…' : '保存访问模式' }}
              </button>
            </div>
          </div>
        </fieldset>
      </form>
      <div class="panel-body access-policy-status">
        <div class="setting-row">
          <span>
            <strong>服务器已应用模式</strong>
            <span class="help">{{ data.pending ? '正在同步最新设置，下方为最近确认的模式。' : '访问规则已与保存的设置同步。' }}</span>
          </span>
          <span :class="['badge', data.pending ? 'warning' : 'success']">
            {{ appliedLabel }}
          </span>
        </div>
        <div class="setting-row">
          <span><strong>HTTPS 加密连接</strong></span>
          <span :class="['badge', data.https ? 'success' : 'warning']">
            {{ data.https ? '已启用' : '未启用' }}
          </span>
        </div>
        <div class="form-stack network-list">
          <h3>已保存的访问范围</h3>
          <div class="tag-list">
            <span v-if="data.access_mode === 'public'" class="badge neutral">所有 IPv4 地址</span>
            <template v-else>
              <code
                v-for="network in data.allowed_networks"
                :key="network"
                class="badge neutral"
              >
                {{ network }}
              </code>
              <span v-if="!data.allowed_networks.length" class="muted">
                未返回允许访问的网络
              </span>
            </template>
          </div>
        </div>
      </div>
    </section>
    <section class="panel section-gap">
      <header class="panel-heading"><h2>登录会话</h2></header>
      <div class="panel-body">
        <div class="setting-row">
          <strong>闲置自动退出</strong>
          <span>{{ data.session_idle_minutes }} 分钟</span>
        </div>
        <div class="setting-row">
          <strong>最长登录时长</strong>
          <span>{{ data.session_absolute_hours }} 小时</span>
        </div>
      </div>
    </section>
    <p class="help section-gap">
      修改访问模式不会暂停证书续期任务。修改密码会撤销其他登录会话。
    </p>
  </template>
</template>
