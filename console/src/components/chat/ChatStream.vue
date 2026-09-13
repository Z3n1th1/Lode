<script setup lang="ts">
// 统一渲染器:把 append-only 的事件序列按 seq 顺序折成对话流。
//
// 分工:复杂形态各自成卡片(SubtaskCard / FindingCard / ApprovalBlock),
// 纯文本与工具气泡在这里内联渲染;工具气泡的摘要/展开判定与 JSON 高亮
// 复用 chatTools.ts(未改动)。折叠逻辑在 chatEvents.ts,可脱离组件单测。
import { computed, nextTick, ref, watch } from 'vue'
import { NButton } from 'naive-ui'
import { ArrowDown } from '@lucide/vue'

import type { ChatEvent, ChatMode } from '../../api'
import { foldSubtasks, isSubtaskEvent, pendingApprovals } from '../../chatEvents'
import {
  highlightJson,
  parseReasoningText,
  sliceRecent,
  summarizeToolResult,
  toolCallHasMore,
  toolCallSummary
} from '../../chatTools'
import ApprovalBlock from './ApprovalBlock.vue'
import FindingCard from './FindingCard.vue'
import SubtaskCard from './SubtaskCard.vue'

const PAGE_SIZE = 60
const STICK_SLACK = 56

const props = defineProps<{
  events: ChatEvent[]
  modes: ChatMode[]
  busy?: boolean
  /** 乐观回显:已发送但事件还没流回来的用户消息。 */
  echo?: string
}>()
const emit = defineEmits<{ (e: 'stop'): void }>()

const scroller = ref<HTMLElement | null>(null)
const renderCount = ref(PAGE_SIZE)
const stickBottom = ref(true)

const subtasks = computed(() => foldSubtasks(props.events))
const modeTitles = computed(() => new Map(props.modes.map((mode) => [mode.name, mode.title])))

/** 每个 job 的第一条*子任务*事件:卡片挂在这个位置,避免重复渲染。
 *  注意 ctx.emit 会给所有事件都带上 job_id,所以必须先过滤出子任务事件。 */
const firstSubtaskSeq = computed(() => {
  const first = new Map<string, number>()
  for (const event of props.events) {
    const jobId = String(event.job_id ?? '')
    if (!jobId || !isSubtaskEvent(event) || first.has(jobId)) continue
    first.set(jobId, event.seq)
  }
  return first
})

const pendingKeys = computed(
  () => new Set(pendingApprovals(props.events).map((event) => String(event.gate ?? event.job_id ?? event.seq)))
)

const visible = computed(() => sliceRecent(props.events, renderCount.value))
const hiddenCount = computed(() => Math.max(0, props.events.length - visible.value.length))

function approvalKey(event: ChatEvent): string {
  return String(event.gate ?? event.job_id ?? event.seq)
}

function shouldRenderSubtask(event: ChatEvent): boolean {
  return firstSubtaskSeq.value.get(String(event.job_id ?? '')) === event.seq
}

function onScroll(): void {
  const el = scroller.value
  if (!el) return
  stickBottom.value = el.scrollHeight - el.scrollTop - el.clientHeight < STICK_SLACK
}

function scrollToBottom(): void {
  const el = scroller.value
  if (el) el.scrollTop = el.scrollHeight
  stickBottom.value = true
}

function loadOlder(): void {
  const el = scroller.value
  const before = el?.scrollHeight ?? 0
  renderCount.value += PAGE_SIZE
  void nextTick(() => {
    if (el) el.scrollTop = el.scrollHeight - before + el.scrollTop
  })
}

// 只有用户没有主动往上翻时才跟随到底部,否则会打断阅读历史。
watch(
  () => props.events.length,
  () => {
    if (!stickBottom.value) return
    void nextTick(scrollToBottom)
  }
)
</script>

<template>
  <div ref="scroller" class="stream" role="log" aria-live="polite" aria-label="对话流" @scroll.passive="onScroll">
    <div v-if="hiddenCount" class="row row--center">
      <n-button size="tiny" quaternary @click="loadOlder">载入更早的 {{ hiddenCount }} 条</n-button>
    </div>

    <template v-for="event in visible" :key="event.seq">
      <!-- 用户:右侧浅色气泡 -->
      <div v-if="event.kind === 'user_message'" class="row row--user">
        <div class="bubble">{{ event.text }}</div>
      </div>

      <!-- 助手:左侧头像 + 开放文本(不用气泡,读起来更像文档) -->
      <div v-else-if="event.kind === 'assistant_message'" class="row row--assistant">
        <span class="msg-avatar" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="13" height="13">
            <path d="M12 2 3 6v6c0 5 3.8 8.6 9 10 5.2-1.4 9-5 9-10V6l-9-4Z"
                  fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" />
          </svg>
        </span>
        <div class="msg-body">{{ event.text }}</div>
      </div>

      <div v-else-if="event.kind === 'reasoning'" class="row row--assistant">
        <span class="msg-avatar msg-avatar--ghost" aria-hidden="true" />
        <details class="thinking">
          <summary>思考过程</summary>
          <pre>{{ parseReasoningText(String(event.reasoning ?? '')) }}</pre>
        </details>
      </div>

      <div v-else-if="event.kind === 'tool_call'" class="row row--assistant">
        <span class="msg-avatar msg-avatar--ghost" aria-hidden="true" />
        <div class="tool">
          <div class="tool-head">
            <span class="tool-dot" />
            <span class="tool-name">{{ toolCallSummary(event.tool, event.args ? String(event.args) : undefined) }}</span>
          </div>
          <details v-if="toolCallHasMore(event.args ? String(event.args) : undefined)">
            <summary>参数</summary>
            <pre class="raw" v-html="highlightJson(String(event.args ?? ''))"></pre>
          </details>
        </div>
      </div>

      <div v-else-if="event.kind === 'tool_result'" class="row row--assistant">
        <span class="msg-avatar msg-avatar--ghost" aria-hidden="true" />
        <div class="tool">
          <div class="tool-head">
            <span class="tool-dot tool-dot--ok" />
            <span class="tool-name">{{ summarizeToolResult(String(event.result ?? '')) || '结果' }}</span>
          </div>
          <details v-if="String(event.result ?? '').trim()">
            <summary>输出</summary>
            <pre class="raw" v-html="highlightJson(String(event.result ?? ''))"></pre>
          </details>
        </div>
      </div>

      <div v-else-if="event.kind === 'subtask_started'" class="row">
        <SubtaskCard v-if="shouldRenderSubtask(event)" :node="subtasks.get(String(event.job_id))!" />
      </div>

      <div v-else-if="event.kind === 'finding'" class="row">
        <FindingCard :event="event" />
      </div>

      <div v-else-if="event.kind === 'approval_required'" class="row">
        <ApprovalBlock
          v-if="pendingKeys.has(approvalKey(event))"
          :event="event"
          @stop="emit('stop')"
        />
      </div>

      <div v-else-if="event.kind === 'mode_changed'" class="row row--center">
        <span class="system-pill">已切换到 {{ modeTitles.get(String(event.mode ?? '')) ?? event.mode }}</span>
      </div>

      <div v-else-if="event.kind === 'error'" class="row row--assistant">
        <span class="msg-avatar msg-avatar--error" aria-hidden="true">!</span>
        <div class="msg-error">{{ event.message || event.detail || '出错了' }}</div>
      </div>
      <!-- 其余事件类型(assistant_delta / approval_resolved / subtask_progress /
           subtask_finished)不单独成行:它们的信息已折进上面的卡片。 -->
    </template>

    <div v-if="echo" class="row row--user">
      <div class="bubble bubble--pending">{{ echo }}</div>
    </div>

    <div v-if="busy" class="row row--assistant">
      <span class="msg-avatar" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="13" height="13">
          <path d="M12 2 3 6v6c0 5 3.8 8.6 9 10 5.2-1.4 9-5 9-10V6l-9-4Z"
                fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" />
        </svg>
      </span>
      <div class="typing" role="status" aria-label="思考中">
        <i /><i /><i />
      </div>
    </div>

    <div v-if="!stickBottom && events.length" class="jump">
      <n-button size="small" secondary round @click="scrollToBottom">
        <template #icon><ArrowDown :size="14" /></template>
        回到底部
      </n-button>
    </div>
  </div>
</template>

<style scoped>
.stream {
  overflow-y: auto;
  padding: 22px 18px 8px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.row {
  width: 100%;
  max-width: 780px;
  margin: 0 auto;
  display: flex;
  animation: rise .22s ease-out both;
}

.row--user { justify-content: flex-end; }
.row--assistant { align-items: flex-start; gap: 10px; }
.row--center { justify-content: center; }

@keyframes rise {
  from { opacity: 0; transform: translateY(5px); }
  to { opacity: 1; transform: none; }
}

/* 用户气泡:低饱和青,不用满色,免得整屏刺眼 */
.bubble {
  max-width: 78%;
  padding: 9px 14px;
  border-radius: var(--pa-radius-lg) var(--pa-radius-lg) 5px var(--pa-radius-lg);
  background: var(--pa-user-bubble);
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  line-height: 1.65;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.bubble--pending { opacity: .6; }

/* 助手:头像 + 开放文本 */
.msg-avatar {
  display: grid;
  place-items: center;
  flex: 0 0 auto;
  width: 26px;
  height: 26px;
  margin-top: 1px;
  border-radius: 8px;
  color: var(--pa-on-brand);
  background: var(--pa-brand-grad);
  font-size: 12px;
  font-weight: 700;
}

.msg-avatar--ghost { background: transparent; }
.msg-avatar--error { background: var(--pa-danger); color: #fff; }

.msg-body {
  min-width: 0;
  padding-top: 2px;
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  line-height: 1.78;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.msg-error {
  padding: 10px 13px;
  border: 1px solid var(--pa-danger);
  border-radius: var(--pa-radius-sm);
  background: var(--pa-danger-soft);
  color: var(--pa-danger);
  font-size: var(--pa-fs-base);
  line-height: 1.6;
  overflow-wrap: anywhere;
}

/* 思考 / 工具 */
.thinking,
.tool {
  min-width: 0;
  max-width: 100%;
  padding: 9px 12px;
  border: 1px solid var(--pa-border);
  border-left: 2px solid var(--pa-border);
  border-radius: var(--pa-radius-sm);
  background: var(--pa-surface-2);
  font-size: var(--pa-fs-sm);
}

.tool-head { display: flex; align-items: center; gap: 8px; }

.tool-dot {
  flex: 0 0 auto;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--pa-primary);
}

.tool-dot--ok { background: var(--pa-success); }

.tool-name {
  min-width: 0;
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  overflow-wrap: anywhere;
}

summary {
  cursor: pointer;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
  list-style: none;
}

summary::marker, summary::-webkit-details-marker { display: none; }

summary::before {
  content: "▸ ";
  color: var(--pa-text-3);
}

details[open] > summary::before { content: "▾ "; }

summary:hover { color: var(--pa-text-2); }

.thinking pre,
.raw {
  margin: 8px 0 0;
  padding: 10px 12px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-code-bg);
  color: var(--pa-code-text);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 280px;
  overflow-y: auto;
}

.system-pill {
  padding: 3px 12px;
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius-pill);
  background: var(--pa-surface-2);
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
}

/* 三点等待 */
.typing { display: flex; gap: 5px; padding: 9px 2px; }

.typing i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--pa-text-3);
  animation: blink 1.3s ease-in-out infinite;
}

.typing i:nth-child(2) { animation-delay: .18s; }
.typing i:nth-child(3) { animation-delay: .36s; }

@keyframes blink {
  0%, 60%, 100% { opacity: .25; transform: translateY(0); }
  30% { opacity: 1; transform: translateY(-2px); }
}

.jump {
  position: sticky;
  bottom: 4px;
  display: flex;
  justify-content: center;
  animation: rise .2s ease-out both;
}

/* JSON 高亮:这里写死颜色是有意的 —— 高亮块永远渲染在 --pa-code-bg 上,
   而那个 token 在两套主题里都是深色,所以语法色不需要跟着主题变。
   (scoped 下需 :deep 才能命中 v-html 注入的 span) */
.raw :deep(.tk-k) { color: #93c5fd; }
.raw :deep(.tk-s) { color: #a5d6a7; }
.raw :deep(.tk-n) { color: #f9c74f; }
.raw :deep(.tk-b) { color: #f28b82; }

@media (max-width: 720px) {
  .stream { padding: 16px 12px 6px; }
}
</style>
