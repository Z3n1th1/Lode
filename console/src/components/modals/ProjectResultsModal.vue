<script setup lang="ts">
import { NButton, NDataTable, NEmpty, NModal, NSpin, NTag } from 'naive-ui'
import { projectResultsModal, projectResults, projectResultsLoading, findingColumns, openReport } from '../../store'
</script>

<template>
  <n-modal v-model:show="projectResultsModal" preset="card" :title="'成果 · ' + (projectResults?.target || '')" :style="{ width: '92vw', maxWidth: '760px' }" :bordered="false">
    <n-spin v-if="projectResultsLoading" size="large" />
    <template v-else-if="projectResults">
      <div class="results-summary">
        <n-tag :bordered="false" type="error" size="small">严重 {{ projectResults.severity.critical || 0 }}</n-tag>
        <n-tag :bordered="false" type="error" size="small">高 {{ projectResults.severity.high || 0 }}</n-tag>
        <n-tag :bordered="false" type="warning" size="small">中 {{ projectResults.severity.medium || 0 }}</n-tag>
        <n-tag :bordered="false" type="success" size="small">低 {{ projectResults.severity.low || 0 }}</n-tag>
        <n-tag :bordered="false" size="small">{{ projectResults.session_count }} 会话</n-tag>
      </div>
      <div v-if="projectResults.reports.length" class="results-reports">
        <span class="rr-label">报告:</span>
        <n-button v-for="r in projectResults.reports" :key="r.task_id" size="small" quaternary type="primary" @click="openReport(r.task_id)">{{ r.task_id }}</n-button>
      </div>
      <n-empty v-if="!projectResults.findings.length" size="small" description="该项目暂无候选发现" style="margin-top:12px" />
      <n-data-table v-else :columns="findingColumns" :data="projectResults.findings" :pagination="{ pageSize: 15 }" :bordered="false" :single-line="false" style="margin-top:12px" />

      <template v-if="projectResults.ptt && (projectResults.ptt.top_leaves || []).length">
        <h4 style="margin:16px 0 6px">🌳 PTT 活树(高价值待深挖叶子 · 共 {{ projectResults.ptt.total }} 节点)</h4>
        <p style="color:#9ca3af;font-size:12px;margin:0 0 8px">层级任务树(资产→功能点→假设→验证步),每轮开跑复诵这些高价值未完成叶子抗上下文漂移。</p>
        <div class="pending-list">
          <article v-for="(l, i) in projectResults.ptt.top_leaves" :key="i" class="pending-row" style="flex-direction:row;align-items:center;gap:8px">
            <n-tag size="tiny" :bordered="false" :type="l.status === 'done' ? 'success' : (l.status === 'na' ? 'default' : 'warning')">{{ l.status }}</n-tag>
            <span style="color:#b45309;min-width:44px">价值 {{ l.value }}</span>
            <strong>{{ l.label }}</strong>
            <small style="color:#9ca3af">{{ l.kind }}</small>
          </article>
        </div>
      </template>

      <template v-if="projectResults.attack_graph && (projectResults.attack_graph.chains || []).length">
        <h4 style="margin:16px 0 6px">🕸️ 联动候选链(attack-graph · {{ (projectResults.attack_graph.artifacts || []).length }} 类能力凑齐)</h4>
        <p style="color:#9ca3af;font-size:12px;margin:0 0 8px">provides/requires 可达性检索出的候选链假设;闭合的危险链深利用前必须人工门 + Verifier 二次,本层不自动执行。</p>
        <div class="pending-list">
          <article v-for="(c, i) in projectResults.attack_graph.chains" :key="i" class="pending-row">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <n-tag size="tiny" :bordered="false" :type="c.status === 'candidate' ? 'error' : 'warning'">{{ c.status === 'candidate' ? '闭合候选' : '部分满足' }}</n-tag>
              <strong>{{ c.goal }}</strong>
              <span style="color:#b45309">价值 {{ c.value }}</span>
              <n-tag v-if="c.need_human" size="tiny" :bordered="false" type="error">需人工门</n-tag>
              <n-tag v-if="c.need_verify" size="tiny" :bordered="false" type="info">需二次复核</n-tag>
            </div>
            <span v-if="c.satisfied_by.length" style="color:#159c84">已凑齐: {{ c.satisfied_by.join('、') }}</span>
            <span v-if="c.missing.length" style="color:#6b7280">还差: {{ c.missing.join('、') }}</span>
            <small>{{ c.note }}</small>
          </article>
        </div>
      </template>
    </template>
    <n-empty v-else size="small" description="读取失败" />
  </n-modal>
</template>
