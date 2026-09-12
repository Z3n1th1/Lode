<script setup lang="ts">
import { NButton, NCard, NEmpty, NSpace, NTag } from 'naive-ui'
import {
  assetChangeRows, fpCorrRows, pageLoading,
  reloadFpCorr, decideFpCorr, formatTimestamp
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">ASSET MONITOR</p><h1>资产与指纹</h1><p>目标资产 hash 变化监控 · JS/端点/页面 diff · 变化告警(深挖默认关)</p></div>
      <n-tag :bordered="false" type="info">{{ assetChangeRows.length }} 条变化</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!assetChangeRows.length && !pageLoading" size="small" description="暂无资产变化(scheduler 巡检到变化后写入;首轮建基线不告警)" />
      <div v-else class="pending-list">
        <article v-for="(a, i) in assetChangeRows" :key="i" class="pending-row">
          <strong>{{ a.target }}</strong>
          <span>{{ a.summary }}</span>
          <span v-if="a.new_endpoints.length" style="color:#b45309">新接口: {{ a.new_endpoints.join('、') }}</span>
          <span v-if="a.changed_artifacts.length" style="color:#6b7280">变更: {{ a.changed_artifacts.join('、') }}</span>
          <small>{{ a.ts ? formatTimestamp(a.ts) : '' }}</small>
        </article>
      </div>
    </n-card>

    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header>
        <div><span class="panel-kicker">FINGERPRINT SELF-CORRECT</span>
        <h2>指纹自修正 <small style="color:#9ca3af">(agent 提修正卡 → 人工 approve → scheduler 合并进可逆 overlay,pending/reject 永不生效)</small></h2></div>
      </template>
      <template #header-extra>
        <n-space size="small">
          <n-tag size="small" :bordered="false" type="warning">待确认 {{ fpCorrRows.filter(c => c.status === 'pending').length }}</n-tag>
          <n-button size="small" quaternary @click="reloadFpCorr">刷新</n-button>
        </n-space>
      </template>
      <n-empty v-if="!fpCorrRows.length && !pageLoading" size="small" description="暂无指纹修正卡(agent 识别到漏报/误报时提交;也可让 agent 在续跑里提)" />
      <div v-else class="pending-list">
        <article v-for="c in fpCorrRows" :key="c.id" class="pending-row">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <n-tag size="tiny" :bordered="false" :type="c.kind === 'false_positive' ? 'error' : 'info'">{{ c.kind }}</n-tag>
            <strong>{{ c.name }}</strong>
            <n-tag size="tiny" :bordered="false" :type="c.status === 'applied' ? 'success' : (c.status === 'pending' ? 'warning' : 'default')">{{ c.status }}</n-tag>
            <span v-if="c.risk" style="color:#b45309">risk={{ c.risk }}</span>
            <span v-if="c.poc_tags.length" style="color:#6b7280">poc: {{ c.poc_tags.join('、') }}</span>
          </div>
          <span>{{ c.evidence }}</span>
          <small>{{ c.source }}{{ c.target ? ' · ' + c.target : '' }}{{ c.created_at ? ' · ' + formatTimestamp(c.created_at) : '' }}</small>
          <n-space v-if="c.status === 'pending'" size="small" style="margin-top:4px">
            <n-button size="small" type="primary" @click="decideFpCorr(c.id, 'approve')">批准(approve)</n-button>
            <n-button size="small" type="error" ghost @click="decideFpCorr(c.id, 'reject')">拒绝(reject)</n-button>
          </n-space>
        </article>
      </div>
    </n-card>
  </main>
</template>
