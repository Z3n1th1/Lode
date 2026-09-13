<script setup lang="ts">
import { NCard, NDataTable, NEmpty, NTag } from 'naive-ui'
import { findingRows, findingColumns, pageLoading } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><h1>发现与证据</h1><p>SARIF 候选,需二次确认</p></div>
      <n-tag :bordered="false" type="info">{{ findingRows.length }} 条候选</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!findingRows.length && !pageLoading" size="small" description="暂无发现" />
      <n-data-table v-else :columns="findingColumns" :data="findingRows" :pagination="{ pageSize: 20 }" :bordered="false" :single-line="false" :loading="pageLoading" />
    </n-card>
  </main>
</template>
