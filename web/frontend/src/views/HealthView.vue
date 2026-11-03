<script setup lang="ts">
import { computed } from 'vue'
import { Button, Card, Descriptions, DescriptionsItem, Empty, Spin, Tag, Timeline, TimelineItem } from 'ant-design-vue'
import { useHealth } from '../composables/useHealth'
import { dateText } from '../lib/format'
import RuntimeHealthPanel from '../components/RuntimeHealthPanel.vue'
import MonitorSummary from '../components/MonitorSummary.vue'
import MonitorSettingsPanel from '../components/MonitorSettingsPanel.vue'
import AppIcon from '../components/AppIcon.vue'
import NoticeBar from '../components/NoticeBar.vue'
import '../styles/health.css'
const emit = defineEmits<{ dirty: [value: boolean]; busy: [value: boolean] }>()
const { data, loading, error, reload, runtimeStale, monitorStale } = useHealth()
const events = computed(() => [...(data.value?.events || [])].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)))
const lastStop = computed(() => events.value.find((event) => ['stopping', 'stopped', 'blocked'].includes(event.status)))
const stageLabels: Record<string, string> = { policy: '访问规则', tls: 'HTTPS 证书', bridge: '群晖桥接', docker: '容器状态', start: '启动容器', shutdown: '停止服务', stability: '等待环境稳定', credentials: '账户初始化', running: '运行中' }
const eventLabels = { maintenance: '维护', fault: '异常', recovery: '恢复', info: '状态变化' }
</script>
<template>
  <div class="monitoring-page health-page">
    <div class="page-heading"><div><h1>运行健康</h1><p>查看管理服务与主动监测状态，及时发现续期任务漏跑和证书临期。</p></div><Button :loading="loading" @click="reload"><template #icon><AppIcon name="refresh" /></template>{{ loading ? '正在刷新…' : '刷新健康状态' }}</Button></div>
    <NoticeBar v-if="error" type="error">{{ error }}<span v-if="data">下方保留上次读取的快照，当前状态待确认。</span></NoticeBar>
    <Card v-if="!data" class="monitoring-empty-card">
      <Spin v-if="loading" tip="正在读取运行健康…"><div class="monitoring-loading" role="status">正在读取运行健康…</div></Spin>
      <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂时无法读取运行健康"><Button @click="reload">重新连接</Button></Empty>
    </Card>
    <template v-else>
      <RuntimeHealthPanel :runtime="data.runtime" :stale="runtimeStale" :timezone="data.timezone" />
      <div class="health-summary-grid">
        <Card title="服务维护与最近停服">
          <Descriptions :column="1" size="small">
            <DescriptionsItem label="升级状态">{{ data.upgrade?.label || '暂无升级记录' }}</DescriptionsItem>
            <DescriptionsItem label="最近监督状态">{{ data.supervisor?.message || '暂无监督状态记录' }}</DescriptionsItem>
            <DescriptionsItem v-if="data.supervisor" label="记录时间">{{ dateText(data.supervisor.at, data.timezone) }}</DescriptionsItem>
          </Descriptions>
          <div v-if="lastStop" class="health-last-stop"><Tag :color="lastStop.category === 'fault' ? 'error' : 'default'">{{ eventLabels[lastStop.category] }}</Tag><strong>{{ stageLabels[lastStop.stage] || '服务检查' }}</strong><p>{{ lastStop.message }}</p><span class="monitoring-muted">{{ dateText(lastStop.at, data.timezone) }}</span></div>
          <p v-else class="monitoring-card-note">尚无停服原因记录。</p>
        </Card>
        <Card title="最近服务事件" class="health-events-card">
          <Timeline v-if="events.length">
            <TimelineItem v-for="(event, index) in events.slice(0, 10)" :key="`${event.at}-${index}`" :color="event.category === 'fault' ? 'red' : event.category === 'recovery' ? 'green' : 'blue'">
              <p class="health-event-heading"><Tag>{{ eventLabels[event.category] }}</Tag><time>{{ dateText(event.at, data.timezone) }}</time></p>
              <p class="monitoring-result-message">{{ event.message || '未提供事件说明' }}</p>
            </TimelineItem>
          </Timeline>
          <Empty v-else :image="Empty.PRESENTED_IMAGE_SIMPLE" description="暂无服务事件记录" />
        </Card>
      </div>
      <MonitorSummary :monitor="data.monitor" :stale="monitorStale" :timezone="data.timezone" />
      <p class="monitoring-footer">本次读取：{{ dateText(data.server_time, data.timezone) }} · 快照过期后显示为未知，请手动刷新。</p>
    </template>
    <MonitorSettingsPanel @dirty="emit('dirty', $event)" @busy="emit('busy', $event)" @saved="reload" />
  </div>
</template>
