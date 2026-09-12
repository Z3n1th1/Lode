<script setup lang="ts">
import { NCard, NDataTable, NEmpty, NTag } from 'naive-ui'
import { profileRows, profileColumns, pageLoading } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">ENGAGEMENT PROFILES</p><h1>测试策略档</h1><p>7 档 EngagementProfile · 决定范围与自动化边界</p></div>
      <n-tag :bordered="false" type="info">{{ profileRows.length }} 档</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <n-empty v-if="!profileRows.length && !pageLoading" size="small" description="暂无策略" />
      <n-data-table v-else :columns="profileColumns" :data="profileRows" :pagination="false" :bordered="false" :single-line="false" :loading="pageLoading" />
    </n-card>
  </main>
</template>
