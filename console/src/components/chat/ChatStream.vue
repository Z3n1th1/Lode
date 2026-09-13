<script setup lang="ts">
// 统一渲染器:把 append-only 的事件序列按 seq 顺序折成对话流。
//
// 分工:复杂形态各自成卡片(SubtaskCard / FindingCard / ApprovalBlock),
// 纯文本与工具气泡在这里内联渲染;工具气泡的摘要/展开判定与 JSON 高亮
// 复用 chatTools.ts(未改动)。折叠逻辑在 chatEvents.ts,可脱离组件单测。
import { computed, nextTick, ref, watch } from 'vue'
import { NButton } from 'naive-ui'

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
const STICK_SLACK = 48

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
  <div ref="scroller" class="stream" @scroll.passive="onScroll">
    <div v-if="!events.length" class="stream-empty">
      还没有对话。选一个模式,把目标或问题丢进来。
    </div>

    <div v-if="hiddenCount" class="stream-older">
      <n-button size="tiny" quaternary @click="loadOlder">载入更早的 {{ hiddenCount }} 条</n-button>
    </div>

    <template v-for="event in visible" :key="event.seq">
      <div v-if="event.kind === 'user_message'" class="row row--user">
        <div class="bubble bubble--user">{{ event.text }}</div>
      </div>

      <div v-else-if="event.kind === 'assistant_message'" class="row row--assistant">
        <div class="bubble bubble--assistant">{{ event.text }}</div>
      </div>

      <div v-else-if="event.kind === 'reasoning'" class="row">
        <details class="thinking">
          <summary>思考过程</summary>
          <pre>{{ parseReasoningText(String(event.reasoning ?? '')) }}</pre>
        </details>
      </div>

      <div v-else-if="event.kind === 'tool_call'" class="row">
        <div class="tool">
          <span class="tool-name">{{ toolCallSummary(event.tool, event.args ? String(event.args) : undefined) }}</span>
          <details v-if="toolCallHasMore(event.args ? String(event.args) : undefined)">
            <summary>参数</summary>
            <pre class="raw" v-html="highlightJson(String(event.args ?? ''))"></pre>
          </details>
        </div>
      </div>

      <div v-else-if="event.kind === 'tool_result'" class="row">
        <div class="tool">
          <span class="tool-name">{{ summarizeToolResult(String(event.result ?? '')) || '结果' }}</span>
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

      <div v-else-if="event.kind === 'mode_changed'" class="row">
        <div class="system-line">
          已切换到「{{ modeTitles.get(String(event.mode ?? '')) ?? event.mode }}」模式
        </div>
      </div>

      <div v-else-if="event.kind === 'error'" class="row">
        <div class="bubble bubble--error">{{ event.message || event.detail || '出错了' }}</div>
      </div>
      <!-- 其余事件类型(assistant_delta / approval_resolved / subtask_progress /
           subtask_finished)不单独成行:它们的信息已折进上面的卡片。 -->
    </template>

    <div v-if="echo" class="row row--user">
      <div class="bubble bubble--user bubble--pending">{{ echo }}</div>
    </div>

    <div v-if="busy" class="row">
      <div class="bubble bubble--assistant bubble--busy">思考中…</div>
    </div>

    <div v-if="!stickBottom && events.length" class="stream-jump">
      <n-button size="tiny" secondary @click="scrollToBottom">回到底部</n-button>
    </div>
  </div>
</template>

<style scoped>
.stream {
  flex: 1;
  overflow-y: auto;
  padding: var(--pa-gap);
  display: flex;
  flex-direction: column;
  gap: 10px;
  scroll-behavior: smooth;
}

.stream-empty {
  margin: auto;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-sm);
}

.stream-older,
.stream-jump {
  display: flex;
  justify-content: center;
}

.stream-jump {
  position: sticky;
  bottom: 0;
}

.row {
  display: flex;
}

.row--user {
  justify-content: flex-end;
}

.bubble {
  max-width: 76%;
  padding: 8px 12px;
  border-radius: var(--pa-radius);
  font-size: var(--pa-fs-base);
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.bubble--user {
  background: var(--pa-primary);
  color: #fff;
}

.bubble--assistant {
  background: var(--pa-surface);
  border: 1px solid var(--pa-border);
}

.bubble--busy {
  color: var(--pa-text-3);
}

.bubble--pending {
  opacity: 0.68;
}

.bubble--error {
  background: #fdf3f2;
  border: 1px solid var(--pa-danger);
  color: var(--pa-danger);
}

.thinking,
.tool {
  max-width: 86%;
  border: 1px solid var(--pa-border-soft);
  border-radius: var(--pa-radius-sm);
  padding: 8px 10px;
  background: var(--pa-surface);
  font-size: var(--pa-fs-xs);
}

.tool-name {
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  overflow-wrap: anywhere;
}

summary {
  cursor: pointer;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
}

.thinking pre,
.raw {
  margin: 6px 0 0;
  padding: 8px 10px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-bg);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 260px;
  overflow-y: auto;
}

.system-line {
  margin: 0 auto;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
}

/* 从 ConsoleChat 移植的 JSON 高亮配色(scoped 下需 :deep 才能命中 v-html) */
.raw :deep(.tk-k) { color: #953800; }
.raw :deep(.tk-s) { color: #0a3069; }
.raw :deep(.tk-n) { color: #0550ae; }
.raw :deep(.tk-b) { color: #cf222e; }
</style>
