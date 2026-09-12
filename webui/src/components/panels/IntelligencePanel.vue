<script setup lang="ts">
import { NButton, NCard, NDataTable, NEmpty, NInput, NSelect, NSwitch, NTag } from 'naive-ui'
import {
  intelRows, intelColumns, intelSourceRows, intelWatch, srcForm, srcErr, pageLoading,
  submitIntelSource, toggleSrc, removeSrc
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">PUBLIC RADAR</p><h1>资讯雷达</h1><p>安全漏洞、AI/开发者动态、财经与市场公开 RSS/Atom</p></div>
      <div style="display:flex;gap:8px;align-items:center">
        <n-tag :bordered="false" type="info">{{ intelRows.length }} 条</n-tag>
        <n-tag :bordered="false" :type="intelWatch.status === 'running' ? 'success' : (intelWatch.status === 'failed' ? 'error' : 'default')">
          collector {{ intelWatch.status }} · {{ intelWatch.runs_completed }} runs
        </n-tag>
      </div>
    </section>
    <n-card class="data-panel" :bordered="false" style="margin-bottom:16px">
      <template #header><div><span class="panel-kicker">DATA SOURCES</span><h2>数据源管理 <small style="color:#9ca3af">({{ intelSourceRows.length }} 源)</small></h2></div></template>
      <div class="src-add">
        <n-select v-model:value="srcForm.kind" size="small" style="width:180px" :options="[{ label: '页面监控 page_watch', value: 'page_watch' }, { label: 'RSS', value: 'rss' }, { label: 'Twitter/X API', value: 'twitter' }]" />
        <n-input v-model:value="srcForm.url" size="small" :placeholder="srcForm.kind === 'twitter' ? '可留空(默认 api.x.com)' : 'https://vendor.example.com/security(公网 http(s))'" />
        <n-input v-model:value="srcForm.name" size="small" placeholder="名称(可选)" style="max-width:140px" />
        <n-input v-if="srcForm.kind === 'twitter'" v-model:value="srcForm.query" size="small" placeholder="X 搜索规则，如 example.com" style="max-width:240px" />
        <n-input v-else v-model:value="srcForm.extract_hint" size="small" placeholder="抽取提示 如 新CVE" style="max-width:140px" />
        <n-button size="small" type="primary" @click="submitIntelSource">+ 加源</n-button>
      </div>
      <p v-if="srcErr" style="color:#dc2626;font-size:13px;margin:6px 0 0">{{ srcErr }}</p>
      <div class="src-list">
        <article v-for="s in intelSourceRows" :key="s.id" class="src-row">
          <n-switch :value="s.enabled" size="small" @update:value="() => toggleSrc(s)" />
          <strong>{{ s.name }}</strong>
          <n-tag size="tiny" :bordered="false" :type="s.kind === 'builtin' ? 'default' : (s.kind === 'rss' ? 'info' : 'warning')">{{ s.kind }}</n-tag>
          <n-tag v-if="!s.trusted" size="tiny" :bordered="false" type="warning">不可信</n-tag>
          <span class="src-url">{{ s.url || '—' }}</span>
          <n-tag size="tiny" :bordered="false" :type="s.status === 'error' ? 'error' : (s.status === 'ok' ? 'success' : 'default')">
            {{ s.status || 'untested' }}<span v-if="s.item_count"> · {{ s.item_count }}</span>
          </n-tag>
          <span v-if="s.last_error" class="src-error" :title="s.last_error">{{ s.last_error }}</span>
          <n-button v-if="s.kind !== 'builtin'" size="small" quaternary @click="removeSrc(s)">删</n-button>
        </article>
      </div>
    </n-card>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!intelRows.length && !pageLoading" size="small" description="暂无资讯(下一轮调度写入)" />
      <n-data-table v-else :columns="intelColumns" :data="intelRows" :pagination="{ pageSize: 20 }" :bordered="false" :single-line="false" :loading="pageLoading" :scroll-x="1260" />
    </n-card>
  </main>
</template>
