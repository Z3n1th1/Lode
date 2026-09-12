<script setup lang="ts">
import { NButton, NCard, NDataTable, NEmpty, NSelect, NSpace, NTag } from 'naive-ui'
import {
  findingRows, findingColumns, sinkKb, sinkKbFilter, sinkKbFilterOpts, pageLoading,
  reloadSinkKb, decideSinkKb
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">FINDINGS</p><h1>发现与证据</h1><p>SARIF 候选发现 · 需二次确认</p></div>
      <n-tag :bordered="false" type="info">{{ findingRows.length }} 条候选</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!findingRows.length && !pageLoading" size="small" description="暂无发现" />
      <n-data-table v-else :columns="findingColumns" :data="findingRows" :pagination="{ pageSize: 20 }" :bordered="false" :single-line="false" :loading="pageLoading" />
    </n-card>

    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header>
        <div><span class="panel-kicker">SINK KB</span>
        <h2>Sink 签名库 <small style="color:#9ca3af">(代码审计护城河 · source→sink 形状积累 · approve 才进生效库)</small></h2></div>
      </template>
      <template #header-extra>
        <n-space size="small">
          <n-tag size="small" :bordered="false" type="success">生效 {{ sinkKb.stats.approved || 0 }}</n-tag>
          <n-tag size="small" :bordered="false" type="warning">待审 {{ sinkKb.stats.pending || 0 }}</n-tag>
          <n-select v-model:value="sinkKbFilter" size="small" style="width:120px" :options="sinkKbFilterOpts" @update:value="reloadSinkKb" />
          <n-button size="small" quaternary @click="reloadSinkKb">刷新</n-button>
        </n-space>
      </template>
      <n-empty v-if="!sinkKb.rows.length && !pageLoading" size="small" description="库为空(可在 VPS seed_builtin 或导 Semgrep 规则)" />
      <div v-else class="pending-list">
        <article v-for="s in sinkKb.rows" :key="s.id" class="pending-row">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <n-tag size="tiny" :bordered="false" type="error">{{ s.vuln_class }}</n-tag>
            <n-tag size="tiny" :bordered="false">{{ s.language }}</n-tag>
            <strong>{{ s.sink_symbol }}</strong>
            <n-tag size="tiny" :bordered="false" :type="s.status === 'approved' ? 'success' : (s.status === 'pending' ? 'warning' : 'default')">{{ s.status }}</n-tag>
            <span v-if="s.cwe" style="color:#6b7280">{{ s.cwe }}</span>
          </div>
          <span>source: {{ s.source || '?' }} · 缺失: {{ s.sanitizer_missing || '?' }}</span>
          <n-space v-if="s.status === 'pending'" size="small" style="margin-top:4px">
            <n-button size="small" type="primary" @click="decideSinkKb(s.id, 'approve')">批准</n-button>
            <n-button size="small" type="error" ghost @click="decideSinkKb(s.id, 'reject')">拒绝</n-button>
          </n-space>
        </article>
      </div>
    </n-card>
  </main>
</template>
