<script setup lang="ts">
// 子任务:一个 job 折成的节点(见 chatEvents.foldSubtasks),挂在它第一条事件的位置。
// 版式克制:描边分块、状态用文字+刻度而不是彩色胶囊、阶段当日志尾读。
import { computed } from 'vue'

import type { SubtaskNode, SubtaskStatus } from '../../chatEvents'

const props = defineProps<{ node: SubtaskNode }>()

const STATE: Record<SubtaskStatus, string> = {
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

const state = computed(() => STATE[props.node.status])
const title = computed(
  () => props.node.title || KIND_LABEL[props.node.kind] || props.node.kind || '子任务'
)
/** 最后一条阶段就是当前所在的那一步,提亮它,其余压暗 —— 不排队号、不画箭头。 */
const lastIndex = computed(() => props.node.updates.length - 1)
</script>

<template>
  <section class="task" :class="`is-${node.status}`">
    <header class="task-head">
      <span class="tick" aria-hidden="true" />
      <h3 class="task-title">{{ title }}</h3>
      <code v-if="node.target" class="task-target">{{ node.target }}</code>
      <span class="grow" />
      <span v-if="node.findings" class="task-count">{{ node.findings }} 个发现</span>
      <span class="task-state">{{ state }}</span>
    </header>

    <ol v-if="node.updates.length" class="phases">
      <li v-for="(update, index) in node.updates" :key="index" :class="{ 'is-current': index === lastIndex }">
        <span class="phase">{{ update.phase }}</span>
        <span v-if="update.detail" class="phase-detail">{{ update.detail }}</span>
      </li>
    </ol>

    <p v-if="node.error" class="task-error">{{ node.error }}</p>
  </section>
</template>

<style scoped>
.task {
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius);
  background: var(--pa-surface);
  padding: 11px 14px;
}

.task.is-failed { border-color: var(--pa-danger); }

.task-head {
  display: flex;
  align-items: baseline;
  gap: 9px;
  flex-wrap: wrap;
}

.tick {
  align-self: center;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--pa-text-3);
}

.task.is-running .tick { background: var(--pa-primary-hover); animation: live 1.6s ease-in-out infinite; }
.task.is-completed .tick { background: var(--pa-success); }
.task.is-failed .tick { background: var(--pa-danger); }

@keyframes live {
  0%, 100% { opacity: 1; }
  50% { opacity: .25; }
}

.task-title {
  margin: 0;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 620;
}

.task-target {
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  overflow-wrap: anywhere;
}

.grow { flex: 1; }

.task-count { color: var(--pa-text-2); font-size: var(--pa-fs-sm); font-variant-numeric: tabular-nums; }
.task-state { color: var(--pa-text-3); font-size: var(--pa-fs-sm); }
.task.is-running .task-state { color: var(--pa-primary-hover); }
.task.is-failed .task-state { color: var(--pa-danger); }

/* 阶段:当日志尾读,当前那步提亮 */
.phases {
  margin: 9px 0 0;
  padding: 0;
  list-style: none;
  display: grid;
  gap: 2px;
}

.phases li {
  color: var(--pa-text-3);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  line-height: 1.7;
  overflow-wrap: anywhere;
}

.phases li.is-current { color: var(--pa-text); }

.phase-detail { margin-left: 8px; color: var(--pa-text-3); }

.task-error {
  margin: 9px 0 0;
  color: var(--pa-danger);
  font-size: var(--pa-fs-sm);
  overflow-wrap: anywhere;
}
</style>
