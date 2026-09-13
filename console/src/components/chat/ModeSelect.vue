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

// 自治级别写进选项里,而不是在 select 旁边挂一段游离文字 —— 那样在顶栏会读成错位的注解
const options = computed(() => props.modes.map((mode) => ({
  label: `${mode.title}(${AUTONOMY_LABEL[mode.autonomy] ?? mode.autonomy})`,
  value: mode.name
})))
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
  </div>
</template>

<style scoped>
.mode-select {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 210px;
}
</style>
