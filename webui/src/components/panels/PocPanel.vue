<script setup lang="ts">
import { NButton, NCard, NEmpty, NSpace, NTag } from 'naive-ui'
import { pocData, pageLoading, reloadPoc, confirmPocRow, formatTimestamp } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">POC APPROVAL</p><h1>PoC 关联 / 审批</h1><p>情报→PoC 同步待人工确认 · approve 入库 / reject 丢弃(替代 pa-poc-admin)</p></div>
      <n-tag :bordered="false" type="warning">{{ pocData.pending.length }} 待确认</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <template #header><div><span class="panel-kicker">PENDING</span><h2>待确认 PoC</h2></div></template>
      <template #header-extra><n-button size="small" quaternary @click="reloadPoc">刷新</n-button></template>
      <n-empty v-if="!pocData.pending.length && !pageLoading" size="small" description="无待确认 PoC(可信源自动入库,未知源才进这里)" />
      <div v-else class="pending-list">
        <article v-for="p in pocData.pending" :key="p.id" class="pending-row">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <n-tag size="tiny" :bordered="false" :type="p.severity && p.severity.toLowerCase().includes('crit') ? 'error' : 'warning'">{{ p.severity || '?' }}</n-tag>
            <strong>{{ p.title || p.id }}</strong>
            <span v-if="p.cve" style="color:#b45309">{{ p.cve }}</span>
            <span style="color:#6b7280">来源 {{ p.source || '?' }}</span>
          </div>
          <span v-if="p.reason">原因: {{ p.reason }}</span>
          <a v-if="p.url" :href="p.url" target="_blank" rel="noreferrer noopener" style="font-size:12px">{{ p.url }}</a>
          <n-space size="small" style="margin-top:4px">
            <n-button size="small" type="primary" @click="confirmPocRow(p.id, true)">批准入库</n-button>
            <n-button size="small" type="error" ghost @click="confirmPocRow(p.id, false)">拒绝</n-button>
          </n-space>
        </article>
      </div>
    </n-card>
    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header><div><span class="panel-kicker">SYNC LOG</span><h2>同步流水</h2></div></template>
      <n-empty v-if="!pocData.log.length && !pageLoading" size="small" description="暂无流水" />
      <div v-else class="pending-list">
        <article v-for="(l, i) in pocData.log" :key="i" class="pending-row" style="flex-direction:row;align-items:center;gap:8px">
          <n-tag size="tiny" :bordered="false">{{ l.action || '?' }}</n-tag>
          <span>{{ l.title || l.cve || '' }}</span>
          <small style="color:#9ca3af">{{ l.source || '' }}{{ l.ts ? ' · ' + formatTimestamp(l.ts) : '' }}</small>
        </article>
      </div>
    </n-card>
  </main>
</template>
