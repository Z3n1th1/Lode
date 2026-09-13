<script setup lang="ts">
import { NButton, NCard, NEmpty, NTag } from 'naive-ui'
import {
  projectRows, intakeRows, pageLoading,
  projectStatusType, openProject, openProjectResults, openNewProject, formatTimestamp
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><h1>项目</h1><p>一个目标就是一个项目,点「查看会话」进流程轨迹</p></div>
      <div style="display:flex;align-items:center;gap:10px">
        <n-tag :bordered="false" type="info">{{ projectRows.length }} 个</n-tag>
        <n-button type="primary" size="small" @click="openNewProject">+ 新建项目</n-button>
      </div>
    </section>
    <n-empty v-if="!projectRows.length && !pageLoading" size="small" description="暂无项目(有目标运行后自动归集)" />
    <section v-else class="metric-grid">
      <n-card v-for="p in projectRows" :key="p.project_id" class="metric-card project-card" :bordered="false">
        <div class="proj-head">
          <strong class="proj-target" :title="p.target">{{ p.target }}</strong>
          <n-tag size="small" :type="projectStatusType(p.status)" :bordered="false">{{ p.status === 'running' ? '进行中' : '已结束' }}</n-tag>
        </div>
        <div class="proj-meta">{{ (p.profiles || []).join(' · ') || '—' }}</div>
        <div class="proj-stats">
          <span>会话 {{ p.session_count }}</span><span>任务 {{ p.task_count }}</span>
          <span>发现 {{ p.finding_count }}<em v-if="p.verified_finding_count"> (复核 {{ p.verified_finding_count }})</em></span>
        </div>
        <div class="proj-foot">
          <small>{{ p.last_activity ? formatTimestamp(p.last_activity) : '—' }}</small>
          <div style="display:flex;gap:4px">
            <n-button size="small" quaternary @click="openProjectResults(p.project_id)">看成果</n-button>
            <n-button size="small" type="primary" quaternary @click="openProject(p.project_id)">查看会话</n-button>
          </div>
        </div>
      </n-card>
    </section>
    <n-card v-if="intakeRows.length" class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header><div><h2>已提交待确认 <small style="color:var(--pa-text-3)">(console 提交意图,执行仍走 agent 确认门)</small></h2></div></template>
      <div class="pending-list">
        <article v-for="it in intakeRows" :key="it.intake_id" class="pending-row">
          <strong>{{ it.name || it.target_url }}</strong>
          <span>{{ it.engagement_profile }} · {{ it.toggle_on.join('/') || '默认开关' }} · <n-tag size="tiny" :bordered="false" type="warning">{{ it.status }}</n-tag></span>
          <small>{{ it.target_url }}{{ it.created_at ? ' · ' + formatTimestamp(it.created_at) : '' }}</small>
        </article>
      </div>
    </n-card>
  </main>
</template>
