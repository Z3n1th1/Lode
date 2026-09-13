<script setup lang="ts">
// 子任务卡片:一个 job 折成的节点(见 chatEvents.foldSubtasks)。
// 挂在它第一条事件的位置上渲染,所以对话顺序不乱、也不会重复出现。
import { computed } from 'vue'

import type { SubtaskNode, SubtaskStatus } from '../../chatEvents'

const props = defineProps<{ node: SubtaskNode }>()

const STATUS: Record<SubtaskStatus, string> = {
  running: '进行中',
  completed: '已完成',
  failed: '失败'
}

const KIND_LABEL: Record<string, string> = {
  src_loop: 'SRC 黑盒扫描',
  ctf_solve: 'CTF 解题',
  code_audit: '代码审计',
  surface_scan: '攻击面侦察',
  chat_turn: '对话回合'
}

const statusLabel = computed(() => STATUS[props.node.status])
const title = computed(
  () => props.node.title || KIND_LABEL[props.node.kind] || props.node.kind || '子任务'
)
</script>

<template>
  <article class="subtask" :class="`subtask--${node.status}`">
    <header class="subtask-head">
      <span class="dot" aria-hidden="true" />
      <h3 class="kind">{{ title }}</h3>
      <code v-if="node.target" class="target">{{ node.target }}</code>
      <span class="spacer" />
      <span v-if="node.findings" class="findings">{{ node.findings }} 发现</span>
      <span class="pill">{{ statusLabel }}</span>
    </header>

    <ol v-if="node.updates.length" class="steps">
      <li v-for="(update, index) in node.updates" :key="index">
        <span class="step-phase">{{ update.phase }}</span>
        <span v-if="update.detail" class="step-detail">{{ update.detail }}</span>
      </li>
    </ol>

    <p v-if="node.error" class="err">{{ node.error }}</p>
  </article>
</template>

<style scoped>
.subtask {
  width: 100%;
  padding: 12px 14px;
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius);
  background: var(--pa-surface);
  box-shadow: var(--pa-shadow-soft);
}

.subtask--failed { border-color: color-mix(in srgb, var(--pa-danger) 55%, var(--pa-border)); }

.subtask-head {
  display: flex;
  align-items: center;
  gap: 9px;
  flex-wrap: wrap;
}

.dot {
  flex: 0 0 auto;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--pa-text-3);
}

.subtask--running .dot {
  background: var(--pa-primary-hover);
  box-shadow: 0 0 0 3px var(--pa-primary-soft);
  animation: breathe 1.6s ease-in-out infinite;
}

.subtask--completed .dot { background: var(--pa-success); }
.subtask--failed .dot { background: var(--pa-danger); }

@keyframes breathe {
  0%, 100% { box-shadow: 0 0 0 3px var(--pa-primary-soft); }
  50% { box-shadow: 0 0 0 6px transparent; }
}

.kind {
  margin: 0;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 620;
}

.target {
  padding: 2px 7px;
  border-radius: 6px;
  background: var(--pa-surface-3);
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  overflow-wrap: anywhere;
}

.spacer { flex: 1; }

.findings {
  color: var(--pa-primary-hover);
  font-size: var(--pa-fs-xs);
  font-weight: 600;
}

.pill {
  padding: 2px 9px;
  border-radius: var(--pa-radius-pill);
  background: var(--pa-surface-3);
  color: var(--pa-text-2);
  font-size: var(--pa-fs-xs);
  font-weight: 600;
}

.subtask--running .pill { background: var(--pa-primary-soft); color: var(--pa-primary-hover); }
.subtask--completed .pill { background: color-mix(in srgb, var(--pa-success) 16%, transparent); color: var(--pa-success); }
.subtask--failed .pill { background: var(--pa-danger-soft); color: var(--pa-danger); }

/* 阶段:左侧导轨 + 节点,读起来像时间线 */
.steps {
  margin: 11px 0 0;
  padding: 0 0 0 3px;
  list-style: none;
}

.steps li {
  position: relative;
  padding: 0 0 8px 16px;
  color: var(--pa-text-2);
  font-size: var(--pa-fs-xs);
  line-height: 1.6;
}

.steps li:last-child { padding-bottom: 0; }

.steps li::before {
  content: "";
  position: absolute;
  left: 0;
  top: 5px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--pa-border);
}

.steps li:not(:last-child)::after {
  content: "";
  position: absolute;
  left: 2.5px;
  top: 13px;
  bottom: 0;
  width: 1px;
  background: var(--pa-border);
}

.steps li:last-child::before { background: var(--pa-primary); }

.step-phase { color: var(--pa-text); font-family: var(--pa-mono); }
.step-detail { margin-left: 6px; }

.err {
  margin: 10px 0 0;
  color: var(--pa-danger);
  font-size: var(--pa-fs-xs);
  overflow-wrap: anywhere;
}
</style>
