<script setup lang="ts">
import { computed } from 'vue'
import { NSelect } from 'naive-ui'

import type { ChatMode } from '../../api'

const props = defineProps<{
  modes: ChatMode[]
  value: string
  disabled?: boolean
}>()

const emit = defineEmits<{ (e: 'update:value', value: string): void }>()

const AUTONOMY_LABEL: Record<string, string> = {
  none: '纯对话,不自动动手',
  ask: '自动动手前需确认',
  auto: '自动执行'
}

const options = computed(() => props.modes.map((mode) => ({ label: mode.title, value: mode.name })))

const hint = computed(() => {
  const mode = props.modes.find((item) => item.name === props.value)
  if (!mode) return ''
  return AUTONOMY_LABEL[mode.autonomy] ?? mode.autonomy
})
</script>

<template>
  <div class="mode-select">
    <n-select
      size="small"
      :value="value"
      :options="options"
      :disabled="disabled"
      :consistent-menu-width="false"
      @update:value="emit('update:value', $event)"
    />
    <span v-if="hint" class="mode-hint">{{ hint }}</span>
  </div>
</template>

<style scoped>
.mode-select {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 210px;
}

.mode-hint {
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
  white-space: nowrap;
}
</style>
