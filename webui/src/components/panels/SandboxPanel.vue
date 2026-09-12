<script setup lang="ts">
import { NCard, NDataTable, NEmpty, NTag } from 'naive-ui'
import { snapshot, sandboxColumns } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">TOOL ISOLATION</p><h1>工具隔离</h1><p>Strix 沙箱运行卡 · 网络/rootless</p></div>
      <n-tag :bordered="false" type="info">{{ snapshot?.sandbox_runs.length ?? 0 }} 条</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!(snapshot?.sandbox_runs.length)" size="small" description="暂无沙箱运行记录" />
      <n-data-table v-else :columns="sandboxColumns" :data="snapshot?.sandbox_runs ?? []" :pagination="false" :bordered="false" :single-line="false" />
    </n-card>
  </main>
</template>
