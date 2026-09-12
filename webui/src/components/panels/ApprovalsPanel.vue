<script setup lang="ts">
import { NButton, NCard, NEmpty, NSpace, NTag } from 'naive-ui'
import { snapshot, evolveData, pageLoading, reloadEvolve, decideEvolve, formatTimestamp } from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">HUMAN GATE</p><h1>人工确认</h1><p>策略选择队列 · 确认在飞书回复编号(此处只读展示)</p></div>
      <n-tag :bordered="false" type="info">{{ snapshot?.pending_profiles.length ?? 0 }} 待确认</n-tag>
    </section>
    <n-card class="data-panel" :bordered="false">
      <div v-if="snapshot?.pending_profiles.length" class="pending-list">
        <article v-for="item in snapshot?.pending_profiles ?? []" :key="item.goal_id" class="pending-row">
          <strong>{{ item.target }}</strong>
          <span>{{ item.profiles.join(' · ') }}</span>
          <small>截止 {{ formatTimestamp(item.expires_at) }}</small>
        </article>
      </div>
      <n-empty v-else size="small" description="没有等待确认的策略" />
    </n-card>

    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header>
        <div><span class="panel-kicker">SELF-EVOLVE</span>
        <h2>自进化反思 <small style="color:#9ca3af">(#60 · 跑完抽教训→approve 进生效库→下次跑注入,闭环)</small></h2></div>
      </template>
      <template #header-extra>
        <n-space size="small">
          <n-tag size="small" :bordered="false" type="success">生效 {{ evolveData.stats.lessons || 0 }}</n-tag>
          <n-tag size="small" :bordered="false" type="warning">待审 {{ evolveData.stats.pending || 0 }}</n-tag>
          <n-button size="small" quaternary @click="reloadEvolve">刷新</n-button>
        </n-space>
      </template>
      <n-empty v-if="!evolveData.rows.length && !pageLoading" size="small" description="暂无反思卡(跑完有信号时自动产,或人工补录)" />
      <div v-else class="pending-list">
        <article v-for="c in evolveData.rows" :key="c.id" class="pending-row">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <n-tag size="tiny" :bordered="false" type="info">{{ c.kind }}</n-tag>
            <n-tag size="tiny" :bordered="false" :type="c.status === 'approved' ? 'success' : (c.status === 'pending' ? 'warning' : 'default')">{{ c.status }}</n-tag>
            <span v-if="c.category" style="color:#6b7280">{{ c.category }}</span>
            <small style="color:#9ca3af">{{ c.source }}</small>
          </div>
          <span>{{ c.text }}</span>
          <n-space v-if="c.status === 'pending'" size="small" style="margin-top:4px">
            <n-button size="small" type="primary" @click="decideEvolve(c.id, 'approve')">批准(进生效库)</n-button>
            <n-button size="small" type="error" ghost @click="decideEvolve(c.id, 'reject')">拒绝</n-button>
          </n-space>
        </article>
      </div>
    </n-card>
  </main>
</template>
