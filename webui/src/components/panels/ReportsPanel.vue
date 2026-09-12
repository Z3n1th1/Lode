<script setup lang="ts">
import { NCard, NDataTable, NEmpty, NTag } from 'naive-ui'
import { snapshot, taskColumns } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">REPORTS</p><h1>报告与核销</h1><p>「看报告」查看标准报告全文 · 「详情」看覆盖/预期/验收/发现</p></div>
      <n-tag :bordered="false" type="info">{{ snapshot?.tasks.length ?? 0 }} 任务</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!(snapshot?.tasks.length)" size="small"
        description="暂无任务报告 —— 尚无运行任务;先到『目标接入』新建项目,任务跑完后此处可查看报告与核销" />
      <n-data-table v-else :columns="taskColumns" :data="snapshot?.tasks ?? []" :pagination="{ pageSize: 20 }" :bordered="false" :single-line="false" />
    </n-card>
  </main>
</template>
