<script setup lang="ts">
// 阻塞式审批气泡:`approval_required` 未解决前,输入框应当被禁用。
//
// 注意:当前后端只声明了 approval_required / approval_resolved 两个事件类型,
// 还没有对应的"批准"端点,所以这里不摆假的批准按钮 —— 只展示门禁内容,
// 并把唯一真实的动作(停止本轮)交出去。
import { computed } from 'vue'
import { NButton } from 'naive-ui'

import type { ChatEvent } from '../../api'

const props = defineProps<{ event: ChatEvent }>()
const emit = defineEmits<{ (e: 'stop'): void }>()

const GATE_LABEL: Record<string, string> = {
  write_action: '写操作',
  scope_change: '范围变更',
  outbound: '对外请求'
}

const gate = computed(() => {
  const key = String(props.event.gate ?? '')
  return GATE_LABEL[key] ?? (key || '需要人工确认')
})
</script>

<template>
  <div class="approval" role="alert">
    <span class="icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="15" height="15">
        <path d="M12 3 2.5 20h19L12 3Z" fill="none" stroke="currentColor"
              stroke-width="1.8" stroke-linejoin="round" />
        <path d="M12 10v4.6M12 17.4v.2" fill="none" stroke="currentColor"
              stroke-width="1.8" stroke-linecap="round" />
      </svg>
    </span>
    <div class="body">
      <p class="gate">{{ gate }}</p>
      <p class="message">{{ event.message || '该动作需要人工确认后才能继续。' }}</p>
    </div>
    <n-button size="small" quaternary type="error" @click="emit('stop')">停止本轮</n-button>
  </div>
</template>

<style scoped>
.approval {
  width: 100%;
  display: flex;
  align-items: flex-start;
  gap: 11px;
  padding: 12px 14px;
  border: 1px solid color-mix(in srgb, var(--pa-warning) 45%, var(--pa-border));
  border-radius: var(--pa-radius);
  background: var(--pa-warning-soft);
}

.icon {
  display: grid;
  place-items: center;
  flex: 0 0 auto;
  width: 26px;
  height: 26px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--pa-warning) 22%, transparent);
  color: var(--pa-warning);
}

.body { flex: 1; min-width: 0; }

.gate {
  margin: 0;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 620;
}

.message {
  margin: 4px 0 0;
  color: var(--pa-text-2);
  font-size: var(--pa-fs-base);
  line-height: 1.6;
  overflow-wrap: anywhere;
}
</style>
