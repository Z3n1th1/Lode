<script setup lang="ts">
import { NButton, NCard, NDataTable, NEmpty, NInput, NSwitch, NTag } from 'naive-ui'
import {
  keyRows, keyColumns, filteredKeyRows, keyHideInvalid, keySearch, keysUnlocked, keyUnlockModal,
  relockKeys, pageLoading
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">SECRET LEAK</p><h1>密钥状态</h1><p>GitHub 泄露 KEY 收集 · 加密封存 · 密码解锁看明文</p></div>
      <n-tag :bordered="false" type="info">{{ filteredKeyRows.length }} / {{ keyRows.length }} 条</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <div class="key-toolbar">
        <n-switch v-model:value="keyHideInvalid" size="small" /><span class="tb-label">隐藏无效</span>
        <n-input v-model:value="keySearch" size="small" clearable placeholder="搜索 服务/仓库/路径/端点/尾4位" style="max-width:280px" />
        <span class="tb-spacer" />
        <n-button v-if="!keysUnlocked" size="small" type="warning" secondary @click="keyUnlockModal = true">🔓 解锁明文</n-button>
        <template v-else>
          <n-tag type="success" size="small" :bordered="false">🔓 已解锁(2h 自动回掩)</n-tag>
          <n-button size="small" quaternary @click="relockKeys">回掩</n-button>
        </template>
      </div>
      <n-empty v-if="!keyRows.length && !pageLoading" size="small" description="暂无 KEY 收集记录(需 GITHUB_TOKEN)" />
      <n-data-table v-else :columns="keyColumns" :data="filteredKeyRows" :pagination="{ pageSize: 20, showSizePicker: true, pageSizes: [20, 50, 100] }" :bordered="false" :single-line="false" :loading="pageLoading" :scroll-x="1180" />
    </n-card>
  </main>
</template>
