<script setup lang="ts">
import { NButton, NCard, NEmpty, NInput, NScrollbar, NTag, NTimeline, NTimelineItem } from 'naive-ui'
import {
  selectedProjectId, projectDetail, selectedSessionId, selectedSession, trajectoryEvents, pageLoading,
  selectSession, trajType, trajKindLabel, taskTagType, taskStatusLabel,
  guidanceText, guidanceErr, guidanceOk, guidanceRows, submitGuidance, forkSession, forkMsg,
  formatTimestamp
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">TRAJECTORY</p><h1>会话 / 轨迹</h1><p>{{ projectDetail?.target || '从「项目」页选择一个项目' }}</p></div>
      <n-tag v-if="projectDetail" :bordered="false" type="info">{{ projectDetail.sessions.length }} 会话</n-tag>
    </section>
    <n-empty v-if="!selectedProjectId" size="small" description="从「项目」页点「查看会话」进入" />
    <template v-else>
      <n-card class="data-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">SESSIONS</span><h2>会话</h2></div></template>
        <n-empty v-if="!projectDetail?.sessions.length" size="small" description="该项目暂无会话" />
        <div v-else class="session-chips">
          <button v-for="s in projectDetail?.sessions ?? []" :key="s.session_id"
            type="button" class="session-chip" :class="{ active: s.session_id === selectedSessionId }"
            @click="selectSession(s.session_id)">
            <span class="sc-id">{{ s.session_id }}</span>
            <span class="sc-meta">{{ s.profile_name }} · {{ s.audited_endpoint_count }}/{{ s.endpoint_count || '—' }} 接口 · 发现 {{ s.finding_count }}</span>
            <n-tag size="tiny" :type="s.status === 'running' ? 'info' : 'success'" :bordered="false">{{ s.status === 'running' ? '进行中' : '已结束' }}</n-tag>
          </button>
        </div>
      </n-card>

      <n-card v-if="selectedSession" class="data-panel" :bordered="false" style="margin-top:16px">
        <template #header><div><span class="panel-kicker">AGENTS</span><h2>谁在跑</h2></div></template>
        <n-empty v-if="!selectedSession.tasks.length" size="small" description="该会话暂无 Strix 任务" />
        <dl v-else class="status-list">
          <div v-for="t in selectedSession.tasks" :key="t.task_id">
            <dt>{{ t.task_id }}<small v-if="t.run_id" style="color:var(--pa-text-3)"> · {{ t.run_id }}</small></dt>
            <dd><n-tag :type="taskTagType(t.status)" size="small" :bordered="false">{{ taskStatusLabel(t.status) }}</n-tag></dd>
          </div>
        </dl>
      </n-card>

      <n-card class="data-panel" :bordered="false" style="margin-top:16px">
        <template #header><div><span class="panel-kicker">FLOW</span><h2>流程轨迹 <small style="color:var(--pa-text-3)">{{ trajectoryEvents.length }} 步</small></h2></div></template>
        <n-empty v-if="!trajectoryEvents.length && !pageLoading" size="small" description="该会话暂无轨迹事件" />
        <n-scrollbar v-else style="max-height:52vh">
          <n-timeline>
            <n-timeline-item v-for="e in trajectoryEvents" :key="e.seq"
              :type="trajType(e.source)"
              :title="trajKindLabel[e.kind] || e.kind || e.source"
              :content="e.summary"
              :time="e.ts ? formatTimestamp(e.ts) : ''" />
          </n-timeline>
        </n-scrollbar>
      </n-card>

      <n-card v-if="selectedSession" class="data-panel" :bordered="false" style="margin-top:16px">
        <template #header><div><span class="panel-kicker">GUIDANCE</span><h2>追加指导 / 继续深挖 <small style="color:var(--pa-text-3)">(提交=意图,走确认门后续跑,不自动执行)</small></h2></div></template>
        <n-input v-model:value="guidanceText" type="textarea" :rows="3" placeholder="看哪不足?写继续深挖的指导(如:重点测 /api/order 越权 + 试 IDOR→接管 组合链)" />
        <div style="display:flex;align-items:center;gap:10px;margin-top:8px;flex-wrap:wrap">
          <n-button type="primary" size="small" :disabled="!guidanceText.trim()" @click="submitGuidance">提交指导(续跑,不自动)</n-button>
          <n-button size="small" ghost :disabled="!projectDetail" @click="forkSession">复刻续跑 fork(同目标+同策略新建,走确认门)</n-button>
          <span v-if="guidanceErr" style="color:var(--pa-danger);font-size:13px">{{ guidanceErr }}</span>
          <span v-if="guidanceOk" style="color:var(--pa-success);font-size:13px">{{ guidanceOk }}</span>
          <span v-if="forkMsg" style="color:var(--pa-success);font-size:13px">{{ forkMsg }}</span>
        </div>
        <div v-if="guidanceRows.length" class="pending-list" style="margin-top:12px">
          <article v-for="g in guidanceRows" :key="g.id" class="pending-row">
            <span>{{ g.guidance }}</span>
            <small><n-tag size="tiny" :bordered="false" type="warning">{{ g.status }}</n-tag>{{ g.created_at ? ' · ' + formatTimestamp(g.created_at) : '' }}</small>
          </article>
        </div>
      </n-card>
    </template>
  </main>
</template>
