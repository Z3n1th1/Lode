<script setup lang="ts">
import { NCard, NEmpty, NTag } from 'naive-ui'
import { snapshot, formatTimestamp } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">TARGET INTAKE</p><h1>目标接入</h1><p>待确认目标预检 · 资产/指纹/资讯雷达/PoC/代理开关(只读)</p></div>
      <n-tag :bordered="false" type="info">{{ snapshot?.pending_intakes.length ?? 0 }} 待接入</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <div v-if="snapshot?.pending_intakes.length" class="pending-list">
        <article v-for="item in snapshot?.pending_intakes ?? []" :key="item.intake_id" class="pending-row">
          <strong>{{ item.target }}</strong>
          <span>{{ item.profile_name }} · 资产{{ item.asset_inventory_enabled ? '✓' : '✗' }} 指纹{{ item.fingerprint_enabled ? '✓' : '✗' }} 雷达{{ item.intelligence_enabled ? '✓' : '✗' }} PoC{{ item.poc_research_enabled ? '✓' : '✗' }} 代理{{ item.proxy_route_enabled ? '✓' : '✗' }}</span>
          <small>截止 {{ formatTimestamp(item.expires_at) }}</small>
        </article>
      </div>
      <n-empty v-else size="small"
        description="没有等待接入的目标 —— 本页为预检接入(预览级):新建项目请求提交后在此排队,确认通过后进入运行" />
    </n-card>
  </main>
</template>
