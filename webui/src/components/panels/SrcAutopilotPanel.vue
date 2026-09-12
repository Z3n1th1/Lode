<script setup lang="ts">
import { computed, h } from 'vue'
import { NAlert, NButton, NCard, NDataTable, NEmpty, NProgress, NSpace, NTag, type DataTableColumns } from 'naive-ui'
import { RefreshCw } from '@lucide/vue'
import {
  srcAutopilot, reloadSrcAutopilot, formatTimestamp, pageLoading
} from '../../store'
import type { SrcCandidate } from '../../api'

const run = computed(() => srcAutopilot.value.run || {})
const progress = computed(() => {
  const current = Number(run.value.round || 0)
  const total = Number(run.value.max_rounds || 0)
  return total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0
})
const statusType = (status: string): 'default' | 'info' | 'success' | 'warning' | 'error' => {
  if (status === 'completed' || status === 'done') return 'success'
  if (status === 'claimed' || status === 'running') return 'info'
  if (status === 'dead_end' || status === 'blocked') return 'error'
  if (status === 'queued' || status === 'awaiting_next_round') return 'warning'
  return 'default'
}
const phaseLabel = (phase: string) => ({
  'A-passive-triage': 'A · 被动分诊',
  'B-authorized-review': 'B · 授权复核',
  'C-human-gated-verification': 'C · 人工门复核'
}[phase] || phase || '—')

const candidateColumns: DataTableColumns<SrcCandidate> = [
  { title: '优先级', key: 'priority', width: 78, sorter: (a, b) => b.priority - a.priority },
  { title: '路径', key: 'path', minWidth: 240, ellipsis: { tooltip: true } },
  { title: '来源', key: 'sources', minWidth: 120, render: row => row.sources.join(' · ') || '—' },
  { title: '阶段', key: 'phase', width: 156, render: row => h(NTag, { size: 'small', bordered: false, type: row.phase.startsWith('C-') ? 'error' : (row.phase.startsWith('B-') ? 'warning' : 'info') }, { default: () => phaseLabel(row.phase) }) },
  { title: '状态', key: 'status', width: 96, render: row => h(NTag, { size: 'small', bordered: false, type: statusType(row.status) }, { default: () => row.status || 'queued' }) },
  { title: '更新', key: 'updated_at', width: 118, render: row => formatTimestamp(row.updated_at) }
]
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div>
        <p class="eyebrow">SRC AUTOPILOT</p>
        <h1>SRC 自动化</h1>
        <p>黑板驱动的候选分诊 · 有限轮次 · 每个 intent 都保留授权和人工复核门</p>
      </div>
      <n-space align="center" size="small">
        <n-tag :bordered="false" :type="srcAutopilot.available ? 'success' : 'default'">{{ srcAutopilot.available ? '黑板在线' : '等待黑板' }}</n-tag>
        <n-button quaternary circle title="刷新 SRC 状态" aria-label="刷新 SRC 状态" :loading="pageLoading" @click="reloadSrcAutopilot"><template #icon><RefreshCw :size="15" /></template></n-button>
      </n-space>
    </section>

    <n-alert v-if="!srcAutopilot.available" type="info" :show-icon="false" style="margin-bottom:16px">
      尚未发现 SRC 黑板。完成第一轮授权 surface 分诊后，这里会显示候选和 worker 租约。
    </n-alert>

    <section v-if="srcAutopilot.available" class="src-summary-grid">
      <div class="src-stat"><span>当前轮次</span><strong>{{ run.round || 0 }}<small>/{{ run.max_rounds || '—' }}</small></strong><n-progress type="line" :percentage="progress" :show-indicator="false" :height="4" /></div>
      <div class="src-stat"><span>候选</span><strong>{{ srcAutopilot.candidates.length }}</strong><small>{{ run.no_new_rounds || 0 }} 轮没有新增</small></div>
      <div class="src-stat"><span>进行中租约</span><strong>{{ srcAutopilot.claims.length }}</strong><small>{{ srcAutopilot.intents.filter(i => i.status === 'queued').length }} 个待 claim</small></div>
      <div class="src-stat"><span>死路记录</span><strong>{{ srcAutopilot.dead_ends.length }}</strong><small>不会自动重试</small></div>
    </section>

    <n-card v-if="srcAutopilot.available" class="data-panel" :bordered="false">
      <template #header><div><span class="panel-kicker">CANDIDATE QUEUE</span><h2>候选队列</h2></div></template>
      <template #header-extra><n-tag size="small" :bordered="false" type="warning">只读 · 需要人工/授权 runner</n-tag></template>
      <n-empty v-if="!srcAutopilot.candidates.length" size="small" description="暂无候选，等待下一份 SrcSurfaceResult" />
      <n-data-table v-else :columns="candidateColumns" :data="srcAutopilot.candidates" :loading="pageLoading" :pagination="{ pageSize: 20 }" :bordered="false" :single-line="false" :scroll-x="900" />
    </n-card>

    <section v-if="srcAutopilot.available" class="src-detail-grid">
      <n-card class="data-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">LEASES</span><h2>Worker 租约</h2></div></template>
        <n-empty v-if="!srcAutopilot.claims.length" size="small" description="当前没有 worker claim" />
        <div v-else class="pending-list">
          <article v-for="claim in srcAutopilot.claims" :key="claim.intent_id" class="pending-row">
            <div class="src-row-head"><strong>{{ claim.intent_id }}</strong><n-tag size="tiny" :bordered="false" type="info">{{ claim.worker_id }}</n-tag></div>
            <small>心跳 {{ formatTimestamp(claim.heartbeat_at) }} · 租约至 {{ formatTimestamp(claim.lease_expires_at) }}</small>
          </article>
        </div>
      </n-card>
      <n-card class="data-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">DEAD ENDS & HINTS</span><h2>死路与提示</h2></div></template>
        <n-empty v-if="!srcAutopilot.dead_ends.length && !srcAutopilot.hints.length" size="small" description="暂无记录" />
        <div v-else class="pending-list">
          <article v-for="dead in srcAutopilot.dead_ends" :key="dead.intent_id + dead.reason" class="pending-row">
            <div class="src-row-head"><n-tag size="tiny" :bordered="false" type="error">死路</n-tag><strong>{{ dead.intent_id }}</strong></div>
            <span>{{ dead.reason }}{{ dead.detail ? ' · ' + dead.detail : '' }}</span>
          </article>
          <article v-for="hint in srcAutopilot.hints" :key="hint.intent_id + hint.created_at" class="pending-row">
            <div class="src-row-head"><n-tag size="tiny" :bordered="false" type="info">提示</n-tag><strong>{{ hint.intent_id }}</strong></div>
            <span>{{ hint.hint }}</span><small>{{ hint.source }} · {{ formatTimestamp(hint.created_at) }}</small>
          </article>
        </div>
      </n-card>
    </section>
  </main>
</template>
