<script setup lang="ts">
import { NCard, NDataTable, NEmpty, NProgress, NTag } from 'naive-ui'
import { ShieldAlert } from '@lucide/vue'
import {
  snapshot, view, stateStatusLabel, transportError,
  taskColumns, goalColumns, goalCoverage, goalStopLabel, formatTimestamp
} from '../../store'
</script>

<template>
  <main v-if="snapshot && view" class="workbench">
    <section class="page-heading">
      <div>
        <p class="eyebrow">OPERATIONS OVERVIEW</p>
        <h1>工作台</h1>
        <p>上次同步 {{ formatTimestamp(snapshot.generated_at) }}</p>
      </div>
      <n-tag :type="snapshot.state_dir_status === 'available' ? 'success' : 'warning'" :bordered="false">{{ stateStatusLabel }}</n-tag>
    </section>

    <p v-if="transportError" class="transport-error"><ShieldAlert :size="16" />{{ transportError }}</p>

    <section class="metric-grid" aria-label="运行摘要">
      <n-card class="metric-card" :bordered="false">
        <span>活动 Goal</span><strong>{{ view.metrics.activeGoals }}</strong><small>目标运行中</small>
      </n-card>
      <n-card class="metric-card" :bordered="false">
        <span>活动任务</span><strong>{{ view.metrics.activeTasks }}</strong><small>持久状态投影</small>
      </n-card>
      <n-card class="metric-card alert" :bordered="false">
        <span>阻断执行</span><strong>{{ view.metrics.blockedTasks }}</strong><small>宿主直跑拒绝</small>
      </n-card>
      <n-card class="metric-card" :bordered="false">
        <span>待选策略</span><strong>{{ view.metrics.pendingProfiles }}</strong><small>等待人工选择</small>
      </n-card>
      <n-card class="metric-card" :bordered="false">
        <span>待确认目标</span><strong>{{ view.metrics.pendingIntakes }}</strong><small>未启动外部能力</small>
      </n-card>
    </section>

    <section class="workspace-grid">
      <n-card class="data-panel task-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">TASK ROUTER</span><h2>目标运行</h2></div></template>
        <n-data-table :columns="taskColumns" :data="snapshot.tasks" :pagination="false" :bordered="false" :single-line="false" />
      </n-card>

      <n-card class="data-panel isolation-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">TOOLRUNNER</span><h2>工具隔离</h2></div></template>
        <div class="isolation-state">
          <span class="status-dot" :class="view.metrics.blockedTasks ? 'blocked' : 'neutral'"></span>
          <strong>{{ view.sandboxLabel }}</strong>
        </div>
        <dl class="status-list">
          <div><dt>执行后端</dt><dd>{{ view.capabilities.toolRunner }}</dd></div>
          <div><dt>网络策略</dt><dd>{{ snapshot.sandbox_runs[0]?.network === 'none' ? '无网络' : '未记录' }}</dd></div>
          <div><dt>Rootless</dt><dd>{{ snapshot.sandbox_runs[0]?.rootless ? '已启用' : '未启用' }}</dd></div>
        </dl>
      </n-card>

      <n-card class="data-panel goals-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">GOAL CONTRACT</span><h2>核销进度</h2></div></template>
        <div v-if="snapshot.goals.length" class="goal-list">
          <article v-for="goal in snapshot.goals" :key="goal.goal_id" class="goal-row">
            <div class="goal-title"><strong>{{ goal.target }}</strong><n-tag size="small" :type="goal.stop_condition ? 'success' : 'info'" :bordered="false">{{ goalStopLabel(goal.stop_condition) }}</n-tag></div>
            <div class="goal-meta"><span>{{ goal.profile_name }}</span><span>{{ goal.audited_endpoint_count }}/{{ goal.endpoint_count || '—' }} 接口</span></div>
            <n-progress type="line" :percentage="goalCoverage(goal)" :show-indicator="false" :height="4" :processing="false" />
          </article>
        </div>
        <n-empty v-else size="small" description="暂无 Goal 记录" />
      </n-card>

      <n-card class="data-panel pending-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">PROFILE GATE</span><h2>待选策略</h2></div></template>
        <div v-if="snapshot.pending_profiles.length" class="pending-list">
          <article v-for="item in snapshot.pending_profiles" :key="item.goal_id" class="pending-row">
            <strong>{{ item.target }}</strong>
            <span>{{ item.profiles.join(' · ') }}</span>
            <small>截止 {{ formatTimestamp(item.expires_at) }}</small>
          </article>
        </div>
        <n-empty v-else size="small" description="没有等待确认的策略" />
      </n-card>

      <n-card class="data-panel pending-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">TARGET INTAKE</span><h2>待确认目标</h2></div></template>
        <div v-if="snapshot.pending_intakes.length" class="pending-list">
          <article v-for="item in snapshot.pending_intakes" :key="item.intake_id" class="pending-row">
            <strong>{{ item.target }}</strong>
            <span>{{ item.profile_name }} · 资产{{ item.asset_inventory_enabled ? '✓' : '✗' }} 指纹{{ item.fingerprint_enabled ? '✓' : '✗' }} 雷达{{ item.intelligence_enabled ? '✓' : '✗' }} PoC{{ item.poc_research_enabled ? '✓' : '✗' }} 代理{{ item.proxy_route_enabled ? '✓' : '✗' }}</span>
            <small>截止 {{ formatTimestamp(item.expires_at) }}</small>
          </article>
        </div>
        <n-empty v-else size="small" description="没有等待确认的目标" />
      </n-card>
    </section>

    <section class="lower-grid">
      <n-card class="data-panel capabilities-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">CONTROL PLANE</span><h2>能力状态</h2></div></template>
        <dl class="capability-list">
          <div><dt>目标预检</dt><dd>{{ view.capabilities.targetIntake }}</dd></div>
          <div><dt>人工确认</dt><dd>{{ view.capabilities.approvals }}</dd></div>
          <div><dt>资讯雷达</dt><dd>{{ view.capabilities.intelligence }}</dd></div>
          <div><dt>发现与证据</dt><dd>{{ view.capabilities.findings }}</dd></div>
          <div><dt>密钥 Broker</dt><dd>{{ view.capabilities.secretBroker }}</dd></div>
          <div><dt>系统健康</dt><dd>{{ view.capabilities.systemHealth }}</dd></div>
          <div><dt>报告核销</dt><dd>{{ view.capabilities.reports }}</dd></div>
        </dl>
      </n-card>
      <n-card class="data-panel goals-table-panel" :bordered="false">
        <template #header><div><span class="panel-kicker">DURABLE STATE</span><h2>Goal 列表</h2></div></template>
        <n-data-table :columns="goalColumns" :data="snapshot.goals" :pagination="false" :bordered="false" :single-line="false" />
      </n-card>
    </section>
  </main>
  <n-empty v-else class="workbench" description="状态读取中(或控制面不可读)" style="padding-top:60px" />
</template>
