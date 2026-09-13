<script setup lang="ts">
// 一条 finding 事件。字段按 core/event_log.py 的 `finding` 载荷约定读取,
// 缺失的字段不编造 —— 只渲染事件里确实带了的证据。
import { computed } from 'vue'
import { NTag, type TagProps } from 'naive-ui'

import type { ChatEvent } from '../../api'

const props = defineProps<{ event: ChatEvent }>()

const SEVERITY: Record<string, TagProps['type']> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
  info: 'default'
}

const severity = computed(() => String(props.event.severity ?? '').toLowerCase())
const tagType = computed<TagProps['type']>(() => SEVERITY[severity.value] ?? 'default')
const title = computed(() => props.event.title || props.event.endpoint || '发现')
</script>

<template>
  <div class="finding">
    <div class="finding-head">
      <n-tag v-if="severity" :type="tagType" size="small" :bordered="false">{{ severity }}</n-tag>
      <span class="finding-title">{{ title }}</span>
      <span v-if="event.confidence" class="finding-confidence">置信度 {{ event.confidence }}</span>
    </div>

    <p v-if="event.endpoint && event.endpoint !== title" class="finding-endpoint">{{ event.endpoint }}</p>
    <p v-if="event.detail" class="finding-detail">{{ event.detail }}</p>
    <pre v-if="event.evidence" class="finding-evidence">{{ event.evidence }}</pre>
  </div>
</template>

<style scoped>
.finding {
  border: 1px solid var(--pa-border);
  border-left: 3px solid var(--pa-danger);
  border-radius: var(--pa-radius-sm);
  padding: 10px 12px;
  background: var(--pa-surface);
  box-shadow: var(--pa-shadow-soft);
}

.finding-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.finding-title {
  font-size: var(--pa-fs-base);
  font-weight: 600;
}

.finding-confidence {
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-3);
}

.finding-endpoint {
  margin: 6px 0 0;
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-2);
  overflow-wrap: anywhere;
}

.finding-detail {
  margin: 6px 0 0;
  font-size: var(--pa-fs-sm);
  color: var(--pa-text-2);
}

.finding-evidence {
  margin: 8px 0 0;
  padding: 8px 10px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-bg);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 240px;
  overflow-y: auto;
}
</style>
