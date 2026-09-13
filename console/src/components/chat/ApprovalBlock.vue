<script setup lang="ts">
// 阻塞式审批气泡:`approval_required` 未解决前,输入框应当被禁用。
//
// 注意:当前后端只声明了 approval_required / approval_resolved 两个事件类型,
// 还没有对应的"批准"端点,所以这里不摆假的批准按钮 —— 只展示门禁内容,
// 并把唯一真实的动作(停止本轮)交出去。
import { NButton } from 'naive-ui'

import type { ChatEvent } from '../../api'

defineProps<{ event: ChatEvent }>()
const emit = defineEmits<{ (e: 'stop'): void }>()

const GATE_LABEL: Record<string, string> = {
  write_action: '写操作',
  scope_change: '范围变更',
  outbound: '对外请求'
}

function labelFor(gate: unknown): string {
  const key = String(gate ?? '')
  return GATE_LABEL[key] ?? (key || '需要人工确认')
}
</script>

<template>
  <div class="approval" role="alert">
    <div class="approval-head">
      <span class="approval-badge">待确认</span>
      <span class="approval-gate">{{ labelFor(event.gate) }}</span>
    </div>
    <p class="approval-message">{{ event.message || '该动作需要人工确认后才能继续。' }}</p>
    <div class="approval-actions">
      <n-button size="small" quaternary type="error" @click="emit('stop')">停止本轮</n-button>
    </div>
  </div>
</template>

<style scoped>
.approval {
  border: 1px solid var(--pa-danger);
  border-radius: var(--pa-radius-sm);
  padding: 10px 12px;
  background: #fdf3f2;
}

.approval-head {
  display: flex;
  align-items: center;
  gap: 8px;
}

.approval-badge {
  padding: 1px 6px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-danger);
  color: #fff;
  font-size: var(--pa-fs-xs);
}

.approval-gate {
  font-size: var(--pa-fs-base);
  font-weight: 600;
}

.approval-message {
  margin: 8px 0 0;
  font-size: var(--pa-fs-sm);
  color: var(--pa-text-2);
  overflow-wrap: anywhere;
}

.approval-actions {
  margin-top: 10px;
  display: flex;
  justify-content: flex-end;
}
</style>
