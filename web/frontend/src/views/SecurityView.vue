<script setup lang="ts">
import { useResource } from '../composables/useResource'
import type { Security } from '../types'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
const { data, loading, error, reload } = useResource<Security>('/api/security')
</script>
<template>
  <div class="page-heading">
    <div>
      <h1>访问安全</h1>
      <p>查看管理服务当前的访问范围与会话策略。</p>
    </div>
    <button class="button" :disabled="loading" @click="reload">
      <AppIcon name="refresh" />
      {{ loading ? '读取中…' : '刷新设置' }}
    </button>
  </div>
  <NoticeBar v-if="error" type="error">
    {{ error }}
    <span v-if="data">下方为上次读取的配置。</span>
  </NoticeBar>
  <div v-if="!data" class="empty-state">
    <h2>{{ loading ? '正在读取安全设置…' : '暂时无法读取安全设置' }}</h2>
    <p>连接成功后显示服务器实际生效的策略。</p>
  </div>
  <template v-else>
    <section class="panel">
      <header class="panel-heading"><h2>管理入口</h2></header>
      <div class="panel-body">
        <div class="setting-row">
          <span>
            <strong>访问范围</strong>
            <span class="help">以服务器实际配置的网络范围为准。</span>
          </span>
          <span :class="['badge', data.lan_only ? 'success' : 'warning']">
            {{ data.lan_only ? '仅允许内网' : '未限制为内网' }}
          </span>
        </div>
        <div class="setting-row">
          <span><strong>HTTPS 加密连接</strong></span>
          <span :class="['badge', data.https ? 'success' : 'warning']">
            {{ data.https ? '已启用' : '未启用' }}
          </span>
        </div>
        <div class="form-stack network-list">
          <h3>允许访问的网络</h3>
          <div class="tag-list">
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
      安全策略由管理员在服务配置中维护。修改密码会撤销其他登录会话。
    </p>
  </template>
</template>
