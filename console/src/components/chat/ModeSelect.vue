<script setup lang="ts">
import { computed, h } from 'vue'
import { NSelect } from 'naive-ui'
import type { SelectOption } from 'naive-ui'

import type { ChatMode } from '../../api'

const props = defineProps<{
  modes: ChatMode[]
  value: string
  disabled?: boolean
}>()

const emit = defineEmits<{ (e: 'update:value', value: string): void }>()

// 自治级别不进模式名 —— 名字要短到一眼读完(用户的原话:简单一点)。
// 能不能自己动手改成菜单里那颗点的颜色 + 一个词:信息还在,噪音没了。
const AUTONOMY: Record<string, { label: string; tone: string }> = {
  none: { label: '只讨论', tone: 'idle' },
  ask: { label: '动手前确认', tone: 'ask' },
  auto: { label: '自动执行', tone: 'auto' }
}

const autonomyOf = computed(() => new Map(props.modes.map(
  (mode) => [mode.name, AUTONOMY[mode.autonomy] ?? { label: mode.autonomy, tone: 'idle' }]
)))

const options = computed<SelectOption[]>(() => props.modes.map(
  (mode) => ({ value: mode.name, label: mode.title })
))

// 下拉挂在 body 上,拿不到 scoped 的 data 属性,所以 .mode-opt* 得走全局样式(见下)。
//
// 注意:render-label 同时给"收起时的当前值"和"展开后的菜单项"用(naive-ui 就是这么
// 调的)。当前值里塞说明文字会在顶栏变成一段游离的注解 —— 上一版就栽在这。
// 所以拆开:收起态只渲染名字,菜单项走 render-option,那里才有自治级别。
const renderLabel = (option: SelectOption) => String(option.label)

const renderOption = ({ option }: { option: SelectOption }) => {
  const autonomy = autonomyOf.value.get(String(option.value))
  return h('span', { class: 'mode-opt' }, [
    h('span', { class: ['mode-dot', autonomy?.tone ?? 'idle'] }),
    h('span', { class: 'mode-opt-name' }, String(option.label)),
    h('span', { class: 'mode-opt-note' }, autonomy?.label ?? '')
  ])
}
</script>

<template>
  <div class="mode-select">
    <n-select
      size="small"
      :value="value"
      :options="options"
      :render-label="renderLabel"
      :render-option="renderOption"
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
  min-width: 118px;
}
</style>

<style>
.mode-opt {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  min-width: 0;
  padding-right: 2px;
}
.mode-opt-name { color: var(--pa-text); }
.mode-opt-note { margin-left: auto; padding-left: 18px; color: var(--pa-text-3); font-size: var(--pa-fs-xs); }
.mode-dot { flex: 0 0 auto; width: 6px; height: 6px; border-radius: 50%; background: var(--pa-text-3); }
.mode-dot.ask { background: var(--pa-warning); }
.mode-dot.auto { background: var(--pa-success); }
</style>
