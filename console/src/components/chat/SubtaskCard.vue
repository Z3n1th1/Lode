<script setup lang="ts">
// 子任务卡片:一个 job 折成的节点(见 chatEvents.foldSubtasks)。
// 挂在它第一条事件的位置上渲染,所以对话顺序不乱、也不会重复出现。
import { computed } from 'vue'
import { NTag, type TagProps } from 'naive-ui'

import type { SubtaskNode, SubtaskStatus } from '../../chatEvents'

const props = defineProps<{ node: SubtaskNode }>()

const STATUS: Record<SubtaskStatus, { label: string; type: TagProps['type'] }> = {
  running: { label: '进行中', type: 'info' },
  completed: { label: '已完成', type: 'success' },
  failed: { label: '失败', type: 'error' }
}

const KIND_LABEL: Record<string, string> = {
  src_loop: 'SRC 黑盒扫描',
  ctf_solve: 'CTF 解题',
  code_audit: '代码审计',
  surface_scan: '攻击面侦察',
  chat_turn: '对话回合'
}

const status = computed(() => STATUS[props.node.status])
const title = computed(
  () => props.node.title || KIND_LABEL[props.node.kind] || props.node.kind || '子任务'
)
</script>

<template>
  <div class="subtask" :class="`subtask--${node.status}`">
    <div class="subtask-head">
      <n-tag :type="status.type" size="small" :bordered="false">{{ status.label }}</n-tag>
      <span class="subtask-title">{{ title }}</span>
      <span v-if="node.target" class="subtask-target">{{ node.target }}</span>
      <span v-if="node.findings" class="subtask-findings">发现 {{ node.findings }}</span>
    </div>

    <ol v-if="node.updates.length" class="subtask-phases">
      <li v-for="(update, index) in node.updates" :key="index">
        {{ update.phase }}<template v-if="update.detail"> — {{ update.detail }}</template>
      </li>
    </ol>

    <p v-if="node.error" class="subtask-error">{{ node.error }}</p>
  </div>
</template>

<style scoped>
.subtask {
  border: 1px solid var(--pa-border);
  border-left: 3px solid var(--pa-text-3);
  border-radius: var(--pa-radius-sm);
  padding: 10px 12px;
  background: var(--pa-surface);
}

.subtask--running {
  border-left-color: var(--pa-primary);
}

.subtask--completed {
  border-left-color: var(--pa-success);
}

.subtask--failed {
  border-left-color: var(--pa-danger);
}

.subtask-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.subtask-title {
  font-size: var(--pa-fs-base);
  font-weight: 600;
}

.subtask-target {
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-2);
  overflow-wrap: anywhere;
}

.subtask-findings {
  font-size: var(--pa-fs-xs);
  color: var(--pa-primary);
}

.subtask-phases {
  margin: 8px 0 0;
  padding-left: 18px;
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-2);
}

.subtask-error {
  margin: 8px 0 0;
  font-size: var(--pa-fs-xs);
  color: var(--pa-danger);
  overflow-wrap: anywhere;
}
</style>
