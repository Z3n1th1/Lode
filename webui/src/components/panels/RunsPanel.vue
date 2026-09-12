<script setup lang="ts">
import { NCard, NDataTable, NEmpty, NTag } from 'naive-ui'
import { snapshot, taskColumns } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">TASK ROUTER</p><h1>目标运行</h1><p>Strix 渗透任务</p></div>
      <n-tag :bordered="false" type="info">{{ snapshot?.tasks.length ?? 0 }} 个</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!(snapshot?.tasks.length)" size="small"
        description="暂无运行任务 —— 到『目标接入』新建项目并经确认后,由 scheduler 启动;启动后此处列出任务与状态" />
      <n-data-table v-else :columns="taskColumns" :data="snapshot?.tasks ?? []" :pagination="{ pageSize: 20 }" :bordered="false" :single-line="false" />
    </n-card>
  </main>
</template>
