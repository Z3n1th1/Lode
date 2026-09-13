<script setup lang="ts">
// 一条 finding 事件。字段按 core/event_log.py 的 `finding` 载荷约定读取,
// 缺失的字段不编造 —— 只渲染事件里确实带了的证据。
// 严重度在这里是语义(它决定风险等级),所以用色条 + 中文等级词,不做彩色胶囊堆砌。
import { computed } from 'vue'

import type { ChatEvent } from '../../api'

const props = defineProps<{ event: ChatEvent }>()

const LEVEL: Record<string, { text: string; color: string }> = {
  critical: { text: '严重', color: 'var(--pa-critical)' },
  high: { text: '高危', color: 'var(--pa-high)' },
  medium: { text: '中危', color: 'var(--pa-medium)' },
  low: { text: '低危', color: 'var(--pa-low)' },
  info: { text: '提示', color: 'var(--pa-text-3)' }
}

const severity = computed(() => String(props.event.severity ?? '').toLowerCase())
const level = computed(() => LEVEL[severity.value] ?? { text: severity.value || '未分级', color: 'var(--pa-text-3)' })
const title = computed(() => props.event.title || props.event.endpoint || '发现')
</script>

<template>
  <section class="finding" :style="{ '--sev': level.color }">
    <header class="finding-head">
      <span class="level">{{ level.text }}</span>
      <h3 class="finding-title">{{ title }}</h3>
      <span class="grow" />
      <span v-if="event.confidence" class="confidence">置信度 {{ event.confidence }}</span>
    </header>

    <code v-if="event.endpoint && event.endpoint !== title" class="endpoint">{{ event.endpoint }}</code>
    <p v-if="event.detail" class="detail">{{ event.detail }}</p>
    <pre v-if="event.evidence" class="evidence">{{ event.evidence }}</pre>
  </section>
</template>

<style scoped>
.finding {
  border: 1px solid var(--pa-border);
  border-left: 2px solid var(--sev);
  border-radius: var(--pa-radius);
  background: var(--pa-surface);
  padding: 11px 14px;
}

.finding-head {
  display: flex;
  align-items: baseline;
  gap: 9px;
  flex-wrap: wrap;
}

.level {
  color: var(--sev);
  font-size: var(--pa-fs-sm);
  font-weight: 700;
}

.finding-title {
  margin: 0;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 620;
}

.grow { flex: 1; }

.confidence { color: var(--pa-text-3); font-size: var(--pa-fs-sm); }

.endpoint {
  display: block;
  margin-top: 7px;
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  overflow-wrap: anywhere;
}

.detail {
  margin: 8px 0 0;
  max-width: var(--pa-prose);
  color: var(--pa-text-2);
  font-size: var(--pa-fs-base);
  line-height: 1.68;
}

.evidence {
  margin: 10px 0 0;
  padding: 11px 13px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-code-well);
  color: var(--pa-code-text);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-sm);
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 260px;
  overflow-y: auto;
}
</style>
