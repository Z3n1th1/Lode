<script setup lang="ts">
import { computed, h } from 'vue'
import { NAlert, NButton, NCard, NDataTable, NEmpty, NProgress, NSpace, NTag, type DataTableColumns } from 'naive-ui'
import { RefreshCw } from '@lucide/vue'
import {
  srcAutopilot, reloadSrcAutopilot, formatTimestamp, pageLoading
} from '../../store'
import type { SrcCandidate, SrcIntent } from '../../api'

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

const shortId = (id: string) => (id || '').replace(/^I-/, '').slice(0, 8)
const hostOf = (url?: string) => (url || '').replace(/^https?:\/\//, '').split('/')[0]

// ---- 依赖分层(DAG):无依赖 = L0,有依赖 = max(依赖层)+1,带环保护 ----
interface DagLevel { level: number; items: SrcIntent[] }
const dag = computed<DagLevel[]>(() => {
  const intents = srcAutopilot.value.intents || []
  const byId = new Map(intents.map(i => [i.intent_id, i]))
  const memo = new Map<string, number>()
  const depth = (id: string, seen: Set<string>): number => {
    const cached = memo.get(id)
    if (cached !== undefined) return cached
    if (seen.has(id)) return 0
    seen.add(id)
    const it = byId.get(id)
    if (!it) return 0
    const deps = (it.depends_on || []).filter(d => byId.has(d))
    const d = deps.length ? Math.max(...deps.map(x => depth(x, seen))) + 1 : 0
    memo.set(id, d)
    return d
  }
  const levels = new Map<number, SrcIntent[]>()
  for (const it of intents) {
    const d = depth(it.intent_id, new Set())
    const bucket = levels.get(d) || []
    bucket.push(it)
    levels.set(d, bucket)
  }
  return [...levels.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([level, items]) => ({ level, items }))
})

const edgeCount = computed(() =>
  (srcAutopilot.value.intents || []).reduce((a, i) => a + ((i.depends_on || []).length), 0))
const retryingCount = computed(() =>
  (srcAutopilot.value.intents || []).filter(i => (i.attempts || 0) > 0).length)

const workmem = computed(() => srcAutopilot.value.workmem || {})
const todos = computed(() => workmem.value.todos || [])
const openTodos = computed(() => todos.value.filter(t => t.status === 'open'))
const timeline = computed(() => (srcAutopilot.value.timeline || []).slice(-25).reverse())

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
        <h1>SRC 黑板</h1>
        <p>候选分诊 · 依赖图 · 失败重试 · 工作记忆,每个 intent 都保留授权和人工复核门</p>
      </div>
      <n-space align="center" size="small">
        <n-tag :bordered="false" :type="srcAutopilot.available ? 'success' : 'default'">{{ srcAutopilot.available ? '黑板在线' : '等待黑板' }}</n-tag>
        <n-button quaternary circle title="刷新 SRC 状态" aria-label="刷新 SRC 状态" :loading="pageLoading" @click="reloadSrcAutopilot"><template #icon><RefreshCw :size="15" /></template></n-button>
      </n-space>
    </section>

    <n-alert v-if="!srcAutopilot.available" type="info" :show-icon="false" style="margin-bottom:16px">
      尚未发现 SRC 黑板。完成第一轮授权 surface 分诊后,这里会显示候选、依赖图和工作记忆。
    </n-alert>

    <section v-if="srcAutopilot.available" class="src-summary-grid">
      <div class="src-stat"><span>当前轮次</span><strong>{{ run.round || 0 }}<small>/{{ run.max_rounds || '—' }}</small></strong><n-progress type="line" :percentage="progress" :show-indicator="false" :height="4" /></div>
      <div class="src-stat"><span>候选</span><strong>{{ srcAutopilot.candidates.length }}</strong><small>{{ run.no_new_rounds || 0 }} 轮没有新增</small></div>
      <div class="src-stat"><span>依赖边</span><strong>{{ edgeCount }}</strong><small>{{ srcAutopilot.intents.length }} 个 intent · {{ retryingCount }} 个在重试</small></div>
      <div class="src-stat"><span>死路记录</span><strong>{{ srcAutopilot.dead_ends.length }}</strong><small>超过重试上限才收敛</small></div>
    </section>

    <!-- 依赖图(DAG) -->
    <n-card v-if="srcAutopilot.available" class="data-panel dag-panel" :bordered="false">
      <template #header><div><span class="panel-kicker">DEPENDENCY DAG</span><h2>任务依赖图</h2></div></template>
      <template #header-extra>
        <n-tag size="small" :bordered="false" type="info">{{ dag.length }} 层 · {{ edgeCount }} 条边</n-tag>
      </template>
      <n-empty v-if="!srcAutopilot.intents.length" size="small" description="还没有 intent" />
      <div v-else class="dag">
        <div v-for="lane in dag" :key="lane.level" class="dag-lane">
          <div class="dag-lane-label">L{{ lane.level }}</div>
          <div class="dag-nodes">
            <div
              v-for="it in lane.items"
              :key="it.intent_id"
              class="dag-node"
              :class="'st-' + it.status"
              :title="it.target || it.intent_id"
            >
              <div class="dag-node-top">
                <span class="dag-dot" :class="'st-' + it.status" />
                <span class="dag-id">{{ shortId(it.intent_id) }}</span>
                <span v-if="(it.depends_on || []).length" class="dag-dep">← {{ (it.depends_on || []).length }}</span>
              </div>
              <div class="dag-host">{{ hostOf(it.target) || it.candidate_id }}</div>
              <div class="dag-node-bottom">
                <n-tag size="tiny" :bordered="false" :type="statusType(it.status)">{{ it.status }}</n-tag>
                <span
                  v-if="(it.attempts || 0) > 0"
                  class="dag-retry"
                  :class="{ warn: it.status === 'queued' }"
                >重试 {{ it.attempts }}/{{ it.max_attempts || 3 }}</span>
              </div>
              <div v-if="it.last_error" class="dag-err">{{ it.last_error }}</div>
            </div>
          </div>
        </div>
      </div>
    </n-card>

    <!-- 工作记忆 -->
    <section v-if="srcAutopilot.available" class="src-detail-grid">
      <n-card class="data-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">WORKING MEMORY</span><h2>工作记忆</h2></div></template>
        <template #header-extra>
          <n-tag size="small" :bordered="false" :type="openTodos.length ? 'warning' : 'success'">
            {{ openTodos.length ? openTodos.length + ' 项未完成' : '无未完成项' }}
          </n-tag>
        </template>
        <p v-if="workmem.goal" class="wm-goal"><b>目标</b>{{ workmem.goal }}</p>
        <p v-if="workmem.focus" class="wm-focus"><b>当前焦点</b>{{ workmem.focus }}</p>
        <n-empty v-if="!todos.length" size="small" description="暂无 TODO" />
        <ul v-else class="wm-todos">
          <li v-for="t in todos" :key="t.todo_id" :class="'todo-' + t.status">
            <span class="todo-mark" />{{ t.text }}
          </li>
        </ul>
      </n-card>

      <n-card class="data-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">TIMELINE</span><h2>时间线</h2></div></template>
        <n-empty v-if="!timeline.length" size="small" description="暂无观察记录" />
        <div v-else class="tl">
          <div v-for="(ev, i) in timeline" :key="i" class="tl-row">
            <span class="tl-time">{{ formatTimestamp(ev.at) }}</span>
            <n-tag size="tiny" :bordered="false" :type="ev.kind === 'dead_end' ? 'error' : (ev.kind === 'finding' ? 'success' : 'default')">{{ ev.kind }}</n-tag>
            <span class="tl-sum">{{ ev.summary }}</span>
          </div>
        </div>
      </n-card>
    </section>

    <n-card v-if="srcAutopilot.available" class="data-panel" :bordered="false">
      <template #header><div><span class="panel-kicker">CANDIDATE QUEUE</span><h2>候选队列</h2></div></template>
      <template #header-extra><n-tag size="small" :bordered="false" type="warning">只读 · 需要人工/授权 runner</n-tag></template>
      <n-empty v-if="!srcAutopilot.candidates.length" size="small" description="暂无候选,等待下一份 SrcSurfaceResult" />
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

<style scoped>
/* ---- 依赖图 ---- */
.dag { display: flex; flex-direction: column; gap: 14px; overflow-x: auto; }
.dag-lane { display: flex; align-items: stretch; gap: 12px; }
.dag-lane-label {
  flex: 0 0 34px; display: grid; place-items: center;
  font-family: var(--pa-mono); font-size: 11px; font-weight: 700; color: var(--pa-text-3);
  background: var(--pa-bg); border: 1px solid var(--pa-border-soft); border-radius: 8px;
}
.dag-nodes { display: flex; flex-wrap: wrap; gap: 10px; }
.dag-node {
  min-width: 190px; max-width: 260px; padding: 10px 12px;
  border: 1px solid var(--pa-border); border-left-width: 3px; border-radius: 10px;
  background: var(--pa-surface); box-shadow: var(--pa-shadow-soft);
  transition: transform .12s, box-shadow .12s;
}
.dag-node:hover { transform: translateY(-1px); box-shadow: var(--pa-shadow-pop); }
.dag-node.st-queued { border-left-color: var(--pa-warning); }
.dag-node.st-claimed { border-left-color: var(--pa-info); }
.dag-node.st-completed { border-left-color: var(--pa-success); }
.dag-node.st-blocked { border-left-color: var(--pa-danger); }
.dag-node.st-dead_end { border-left-color: var(--pa-text-3); opacity: .72; }
.dag-node-top { display: flex; align-items: center; gap: 6px; }
.dag-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--pa-text-3); flex: 0 0 auto; }
.dag-dot.st-queued { background: var(--pa-warning); }
.dag-dot.st-claimed { background: var(--pa-info); animation: dag-pulse 1.4s infinite; }
.dag-dot.st-completed { background: var(--pa-success); }
.dag-dot.st-blocked { background: var(--pa-danger); }
@keyframes dag-pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.dag-id { font-family: var(--pa-mono); font-size: 12px; font-weight: 600; color: var(--pa-text); }
.dag-dep { margin-left: auto; font-size: 10px; color: var(--pa-primary); font-family: var(--pa-mono); }
.dag-host {
  margin: 5px 0 7px; font-size: 12px; color: var(--pa-text-2);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dag-node-bottom { display: flex; align-items: center; gap: 8px; }
.dag-retry { font-size: 10px; color: var(--pa-text-3); font-family: var(--pa-mono); }
.dag-retry.warn { color: var(--pa-warning); font-weight: 600; }
.dag-err {
  margin-top: 6px; font-size: 10.5px; color: var(--pa-danger);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* ---- 工作记忆 ---- */
.wm-goal, .wm-focus { margin: 0 0 8px; font-size: 13px; color: var(--pa-text); line-height: 1.6; }
.wm-goal b, .wm-focus b {
  display: inline-block; margin-right: 8px; padding: 1px 7px; border-radius: 5px;
  font-size: 11px; font-weight: 600; color: var(--pa-primary);
  background: color-mix(in srgb, var(--pa-primary) 10%, transparent);
}
.wm-todos { margin: 6px 0 0; padding: 0; list-style: none; display: grid; gap: 7px; }
.wm-todos li { display: flex; align-items: flex-start; gap: 8px; font-size: 13px; color: var(--pa-text); }
.todo-mark { width: 8px; height: 8px; margin-top: 6px; border-radius: 50%; flex: 0 0 auto; background: var(--pa-text-3); }
.todo-open .todo-mark { background: var(--pa-warning); }
.todo-done .todo-mark { background: var(--pa-success); }
.todo-done { color: var(--pa-text-3); text-decoration: line-through; }
.todo-blocked .todo-mark { background: var(--pa-danger); }

/* ---- 时间线 ---- */
.tl { display: grid; gap: 2px; max-height: 320px; overflow-y: auto; }
.tl-row { display: flex; align-items: baseline; gap: 9px; padding: 6px 0; border-top: 1px solid var(--pa-border-soft); }
.tl-time { flex: 0 0 118px; font-size: 11px; color: var(--pa-text-3); font-family: var(--pa-mono); }
.tl-sum { flex: 1; min-width: 0; font-size: 12.5px; color: var(--pa-text-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
