<script setup lang="ts">
// 一条 finding 事件。字段按 core/event_log.py 的 `finding` 载荷约定读取,
// 缺失的字段不编造 —— 只渲染事件里确实带了的证据。
import { computed } from 'vue'

import type { ChatEvent } from '../../api'

const props = defineProps<{ event: ChatEvent }>()

const SEVERITY: Record<string, string> = {
  critical: 'var(--pa-danger)',
  high: 'var(--pa-danger)',
  medium: 'var(--pa-warning)',
  low: 'var(--pa-primary-hover)',
  info: 'var(--pa-text-3)'
}

const severity = computed(() => String(props.event.severity ?? '').toLowerCase())
const accent = computed(() => SEVERITY[severity.value] ?? 'var(--pa-text-3)')
const title = computed(() => props.event.title || props.event.endpoint || '发现')
</script>

<template>
  <article class="finding" :style="{ '--sev': accent }">
    <header class="finding-head">
      <span v-if="severity" class="sev">{{ severity }}</span>
      <h3 class="finding-title">{{ title }}</h3>
      <span class="spacer" />
      <span v-if="event.confidence" class="confidence">置信度 {{ event.confidence }}</span>
    </header>

    <code v-if="event.endpoint && event.endpoint !== title" class="endpoint">{{ event.endpoint }}</code>
    <p v-if="event.detail" class="detail">{{ event.detail }}</p>
    <pre v-if="event.evidence" class="evidence">{{ event.evidence }}</pre>
  </article>
</template>

<style scoped>
.finding {
  width: 100%;
  padding: 12px 14px;
  border: 1px solid var(--pa-border);
  border-left: 3px solid var(--sev);
  border-radius: var(--pa-radius);
  background: var(--pa-surface);
  box-shadow: var(--pa-shadow-soft);
}

.finding-head {
  display: flex;
  align-items: center;
  gap: 9px;
  flex-wrap: wrap;
}

.sev {
  padding: 2px 8px;
  border-radius: var(--pa-radius-pill);
  background: color-mix(in srgb, var(--sev) 16%, transparent);
  color: var(--sev);
  font-size: var(--pa-fs-xs);
  font-weight: 700;
  letter-spacing: .3px;
  text-transform: uppercase;
}

.finding-title {
  margin: 0;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 620;
}

.spacer { flex: 1; }

.confidence { color: var(--pa-text-3); font-size: var(--pa-fs-xs); }

.endpoint {
  display: inline-block;
  margin-top: 8px;
  padding: 2px 7px;
  border-radius: 6px;
  background: var(--pa-surface-3);
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  overflow-wrap: anywhere;
}

.detail {
  margin: 8px 0 0;
  color: var(--pa-text-2);
  font-size: var(--pa-fs-base);
  line-height: 1.65;
}

.evidence {
  margin: 10px 0 0;
  padding: 10px 12px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-code-bg);
  color: var(--pa-code-text);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 260px;
  overflow-y: auto;
}
</style>
