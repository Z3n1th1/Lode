<script setup lang="ts">
// 阻塞式审批:`approval_required` 未解决前输入框禁用。
//
// 后端目前只声明了 approval_required / approval_resolved 两个事件类型,还没有对应的
// "批准"端点,所以这里不摆假的批准按钮 —— 只说明门禁内容,并把唯一真实的动作交出去。
import { computed } from 'vue'
import { NButton } from 'naive-ui'

import type { ChatEvent } from '../../api'

const props = defineProps<{ event: ChatEvent }>()
const emit = defineEmits<{ (e: 'stop'): void }>()

const GATE: Record<string, string> = {
  write_action: '写操作',
  scope_change: '范围变更',
  outbound: '对外请求'
}

const gate = computed(() => {
  const key = String(props.event.gate ?? '')
  return GATE[key] ?? (key || '需要人工确认')
})
</script>

<template>
  <section class="gate" role="alert">
    <div class="gate-body">
      <p class="gate-title">停在人工门:{{ gate }}</p>
      <p class="gate-message">{{ event.message || '这一步需要你先确认,才会继续。' }}</p>
    </div>
    <n-button size="small" quaternary type="error" @click="emit('stop')">停止本轮</n-button>
  </section>
</template>

<style scoped>
.gate {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  border: 1px solid var(--pa-border);
  border-left: 2px solid var(--pa-warning);
  border-radius: var(--pa-radius);
  background: var(--pa-surface);
  padding: 11px 14px;
}

.gate-body { flex: 1; min-width: 0; }

.gate-title {
  margin: 0;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 620;
}

.gate-message {
  margin: 5px 0 0;
  max-width: var(--pa-prose);
  color: var(--pa-text-2);
  font-size: var(--pa-fs-base);
  line-height: 1.65;
  overflow-wrap: anywhere;
}
</style>
