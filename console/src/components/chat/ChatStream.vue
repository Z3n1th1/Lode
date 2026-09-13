<script setup lang="ts">
// 统一渲染器:把 append-only 的事件序列按 seq 折成一条「战地日志」。
//
// 版式:左侧一条 gutter 承载时间戳与角色刻度,正文一律左对齐。不用气泡、不用圆形
// 头像 —— 层级来自刻度、字体和留白,而不是从盒子和颜色堆出来。
// 时间戳只在"分钟变了"的那一条显示,否则整列会全是噪音。
//
// 分工:复杂形态各自成卡片(SubtaskCard / FindingCard / ApprovalBlock),
// 纯文本与工具气泡在这里内联渲染;工具气泡的摘要/展开判定与 JSON 高亮复用
// chatTools.ts(未改动)。折叠逻辑在 chatEvents.ts,可脱离组件单测。
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

function clockOf(ts: unknown): string {
  const n = Number(ts)
  if (!Number.isFinite(n) || n <= 0) return ''
  const d = new Date(n * 1000)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/** 只在分钟变化时显示时间 —— 每条都标时间会让 gutter 变成噪音。 */
function clockFor(index: number): string {
  const event = visible.value[index]
  const previous = visible.value[index - 1]
  const stamp = clockOf(event?.ts)
  if (!stamp) return ''
  return clockOf(previous?.ts) === stamp ? '' : stamp
}

function approvalKey(event: ChatEvent): string {
  return String(event.gate ?? event.job_id ?? event.seq)
}

/** 回合本身(chat_turn)不画卡片 —— 它就是这段对话,再给它一张"已完成"的块纯属噪音。 */
const SUBTASK_KINDS = new Set(['src_loop', 'ctf_solve', 'code_audit', 'surface_scan'])

function shouldRenderSubtask(event: ChatEvent): boolean {
  const jobId = String(event.job_id ?? '')
  if (firstSubtaskSeq.value.get(jobId) !== event.seq) return false
  return SUBTASK_KINDS.has(String(subtasks.value.get(jobId)?.kind ?? ''))
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
  <div ref="scroller" class="log" role="log" aria-live="polite" aria-label="对话流" @scroll.passive="onScroll">
    <div v-if="hiddenCount" class="entry entry--center">
      <n-button size="tiny" quaternary @click="loadOlder">载入更早的 {{ hiddenCount }} 条</n-button>
    </div>

    <template v-for="(event, index) in visible" :key="event.seq">
      <!-- 你 -->
      <article v-if="event.kind === 'user_message'" class="entry entry--me">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <p class="turn">{{ event.text }}</p>
      </article>

      <!-- 助手 -->
      <article v-else-if="event.kind === 'assistant_message'" class="entry">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <p class="prose">{{ event.text }}</p>
      </article>

      <article v-else-if="event.kind === 'reasoning'" class="entry">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <details class="thinking">
          <summary>思考过程</summary>
          <pre>{{ parseReasoningText(String(event.reasoning ?? '')) }}</pre>
        </details>
      </article>

      <article v-else-if="event.kind === 'tool_call'" class="entry">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <div class="tool">
          <p class="tool-line">
            <span class="tool-sigil" aria-hidden="true">·</span>
            {{ toolCallSummary(event.tool, event.args ? String(event.args) : undefined) }}
          </p>
          <details v-if="toolCallHasMore(event.args ? String(event.args) : undefined)">
            <summary>参数</summary>
            <pre class="well" v-html="highlightJson(String(event.args ?? ''))"></pre>
          </details>
        </div>
      </article>

      <article v-else-if="event.kind === 'tool_result'" class="entry">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <div class="tool">
          <p class="tool-line">
            <span class="tool-sigil tool-sigil--ok" aria-hidden="true">·</span>
            {{ summarizeToolResult(String(event.result ?? '')) || '结果' }}
          </p>
          <details v-if="String(event.result ?? '').trim()">
            <summary>输出</summary>
            <pre class="well" v-html="highlightJson(String(event.result ?? ''))"></pre>
          </details>
        </div>
      </article>

      <article v-else-if="event.kind === 'subtask_started' && shouldRenderSubtask(event)" class="entry entry--wide">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <SubtaskCard :node="subtasks.get(String(event.job_id))!" />
      </article>

      <article v-else-if="event.kind === 'finding'" class="entry entry--wide">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <FindingCard :event="event" />
      </article>

      <article v-else-if="event.kind === 'approval_required'" class="entry entry--wide">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <ApprovalBlock
          v-if="pendingKeys.has(approvalKey(event))"
          :event="event"
          @stop="emit('stop')"
        />
        <span v-else class="spacer" />
      </article>

      <article v-else-if="event.kind === 'mode_changed'" class="entry">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <p class="note">已切到「{{ modeTitles.get(String(event.mode ?? '')) ?? event.mode }}」模式</p>
      </article>

      <article v-else-if="event.kind === 'error'" class="entry">
        <div class="gutter"><span class="clock">{{ clockFor(index) }}</span></div>
        <p class="fault">{{ event.message || event.detail || '出错了' }}</p>
      </article>
      <!-- 其余类型(assistant_delta / approval_resolved / subtask_progress /
           subtask_finished)不单独成条:信息已折进上面的卡片。 -->
    </template>

    <article v-if="echo" class="entry entry--me">
      <div class="gutter"><span class="clock" /></div>
      <p class="turn turn--pending">{{ echo }}</p>
    </article>

    <article v-if="busy" class="entry">
      <div class="gutter"><span class="clock" /></div>
      <p class="working" role="status">运行中<span class="dots"><i /><i /><i /></span></p>
    </article>

    <div v-if="!stickBottom && events.length" class="jump">
      <n-button size="small" secondary round @click="scrollToBottom">
        <template #icon><ArrowDown :size="14" /></template>
        回到底部
      </n-button>
    </div>
  </div>
</template>

<style scoped>
.log {
  --logw: 880px;          /* 日志列宽:超过这个宽度眼睛就要来回扫了 */
  overflow-y: auto;
  padding: 18px 22px 6px;
}

/* gutter 是这条日志唯一的结构装置:时间戳 + 一条贯通的导轨 */
.entry {
  position: relative;
  display: grid;
  grid-template-columns: 52px minmax(0, 1fr);
  gap: 12px;
  max-width: var(--logw);
  margin: 0 auto;
  padding: 9px 0;
}

.entry::before {
  content: "";
  position: absolute;
  left: 57px;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--pa-border-soft);
}

.entry--center {
  grid-template-columns: 1fr;
  justify-items: center;
}

.entry--center::before { display: none; }

.gutter { text-align: right; }

.clock {
  color: var(--pa-text-3);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  font-variant-numeric: tabular-nums;
}

/* 你那一轮:底色只裹正文,不横贯全宽 */
.turn {
  margin: 0;
  max-width: var(--pa-prose);
  padding: 8px 13px;
  border-radius: var(--pa-radius-sm);
  background: var(--pa-user-turn);
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 500;
  line-height: 1.7;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.turn--pending { opacity: .55; }

.prose {
  margin: 0;
  max-width: var(--pa-prose);
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  line-height: 1.75;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.note {
  margin: 0;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-sm);
}

.fault {
  margin: 0;
  max-width: var(--pa-prose);
  padding: 9px 12px;
  border-left: 2px solid var(--pa-danger);
  background: var(--pa-danger-soft);
  color: var(--pa-danger);
  font-size: var(--pa-fs-base);
  line-height: 1.6;
  overflow-wrap: anywhere;
}

/* 思考 / 工具:安静的行内块,不做成卡片 */
.thinking,
.tool {
  min-width: 0;
  max-width: var(--pa-prose);
}

.tool-line {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin: 0;
  color: var(--pa-text-2);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-sm);
  overflow-wrap: anywhere;
}

.tool-sigil { color: var(--pa-text-3); font-size: 18px; line-height: 1; }
.tool-sigil--ok { color: var(--pa-success); }

summary {
  margin-top: 4px;
  cursor: pointer;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-sm);
  list-style: none;
}

summary::marker, summary::-webkit-details-marker { display: none; }
summary::before { content: "▸ "; }
details[open] > summary::before { content: "▾ "; }
summary:hover { color: var(--pa-text-2); }

.well {
  margin: 7px 0 0;
  padding: 11px 13px;
  background: var(--pa-code-well);
  color: var(--pa-code-text);
  border-radius: var(--pa-radius-sm);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-sm);
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 300px;
  overflow-y: auto;
}

.thinking pre {
  margin: 6px 0 0;
  max-width: var(--pa-prose);
  color: var(--pa-text-2);
  font-family: var(--pa-ui);
  font-size: var(--pa-fs-base);
  line-height: 1.7;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.entry--wide { max-width: var(--logw); }

.spacer { display: block; }

/* 运行中:动作进行的唯一动效,和状态同义 */
.working {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 0;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-base);
}

.dots { display: inline-flex; gap: 3px; }

.dots i {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: var(--pa-primary-hover);
  animation: blink 1.2s ease-in-out infinite;
}

.dots i:nth-child(2) { animation-delay: .16s; }
.dots i:nth-child(3) { animation-delay: .32s; }

@keyframes blink {
  0%, 60%, 100% { opacity: .3; }
  30% { opacity: 1; }
}

.jump { position: sticky; bottom: 4px; display: flex; justify-content: center; }

/* JSON 高亮:写死颜色是有意的 —— 高亮块永远在 --pa-code-well 上,两套主题里都是深色。
   (scoped 下需 :deep 才能命中 v-html 注入的 span) */
.well :deep(.tk-k) { color: #8ab4f8; }
.well :deep(.tk-s) { color: #9ccc8f; }
.well :deep(.tk-n) { color: #e0c069; }
.well :deep(.tk-b) { color: #e8837c; }

@media (max-width: 720px) {
  .log { padding: 14px 12px 4px; }
  .entry { grid-template-columns: 1fr; }
  .entry::before { display: none; }
  .gutter { display: none; }
}
</style>
