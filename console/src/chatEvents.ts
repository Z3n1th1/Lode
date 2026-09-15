// 事件流的纯折叠:把 append-only 的事件序列折成渲染需要的形态。
//
// 放这里而不是放在组件里,是因为它可以在 vitest 的 node 环境下直接测
// (与 chatTools.ts / dashboard.ts 同一套路),不需要挂载组件或 jsdom。
import type { ChatEvent } from './api'

export const SUBTASK_EVENT_KINDS = ['subtask_started', 'subtask_progress', 'subtask_finished'] as const

export interface SubtaskUpdate {
  phase: string
  at: number
  detail: string
}

export type SubtaskStatus = 'running' | 'completed' | 'failed'

export interface SubtaskNode {
  jobId: string
  kind: string
  target: string
  title: string
  status: SubtaskStatus
  findings: number
  error: string
  startedAt: number
  updates: SubtaskUpdate[]
}

export function isSubtaskEvent(event: ChatEvent): boolean {
  return (SUBTASK_EVENT_KINDS as readonly string[]).includes(event?.kind)
}

function textOf(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/**
 * 子任务按 `job_id` 聚合:同一个 job 的 started/progress/finished 折成一个节点。
 * 顺序按首次出现,渲染时把节点挂在它第一条事件的位置上,这样对话顺序不乱。
 */
export function foldSubtasks(events: ChatEvent[]): Map<string, SubtaskNode> {
  const nodes = new Map<string, SubtaskNode>()
  const ensure = (jobId: string): SubtaskNode => {
    let node = nodes.get(jobId)
    if (!node) {
      node = { jobId, kind: '', target: '', title: '', status: 'running', findings: 0, error: '',
               startedAt: 0, updates: [] }
      nodes.set(jobId, node)
    }
    return node
  }

  for (const event of events) {
    const jobId = textOf(event?.job_id)
    if (!jobId || !isSubtaskEvent(event)) continue
    const node = ensure(jobId)

    if (event.kind === 'subtask_started') {
      node.kind = textOf(event.job_kind) || node.kind
      node.target = textOf(event.target) || node.target
      node.title = textOf(event.title) || node.title
      node.startedAt = node.startedAt || Number(event.ts) || 0
      continue
    }

    if (event.kind === 'subtask_progress') {
      node.updates.push({ phase: textOf(event.phase), at: Number(event.ts) || 0,
                          detail: textOf(event.detail) })
      const findings = Number(event.findings)
      if (Number.isFinite(findings)) node.findings = findings
      continue
    }

    const status = textOf(event.status)
    node.status = status === 'completed' ? 'completed' : 'failed'
    node.error = textOf(event.error)
  }

  return nodes
}

function approvalKey(event: ChatEvent): string {
  return textOf(event.gate) || textOf(event.job_id) || `seq-${event.seq}`
}

/** 已请求但尚未解决的审批门。非空时输入框应当被阻塞。 */
export function pendingApprovals(events: ChatEvent[]): ChatEvent[] {
  const open = new Map<string, ChatEvent>()
  for (const event of events) {
    if (event?.kind === 'approval_required') open.set(approvalKey(event), event)
    else if (event?.kind === 'approval_resolved') open.delete(approvalKey(event))
  }
  return [...open.values()]
}

/** 事件流的最新游标:重连/重放时作为 `since`。 */
export function lastSeq(events: ChatEvent[]): number {
  return events.reduce((max, event) => Math.max(max, Number(event?.seq) || 0), 0)
}

// ---- 连续同工具调用折成一行 ----
//
// 1qps 的只读侦察里,"调用 fetch_url / 结果 200"会成对地刷上几百行,每行还各带一个
// 折叠三角。账本按事件逐行渲染时这笔噪声会淹掉真正的发现与结论。这里把**连续**的同一
// 工具调用(连同它们各自的结果)折成一个 run,由渲染层画成一行。

/** 这些类型不单独成行(信息已折进子任务节点或所属行),所以不打断一个 run。 */
const INVISIBLE_KINDS = new Set([
  'assistant_delta',
  'approval_resolved',
  'subtask_progress',
  'subtask_finished'
])

/** 少于这个次数的调用不值得折叠:折一行反而多一层点击。 */
const RUN_MIN_CALLS = 2

export interface ToolRunPair {
  call: ChatEvent
  result?: ChatEvent
}

export type LedgerItem =
  | { type: 'event'; event: ChatEvent }
  | { type: 'run'; tool: string; seq: number; ts: number; pairs: ToolRunPair[] }

function nextSignificant(events: ChatEvent[], from: number): number {
  let index = from
  while (index < events.length && INVISIBLE_KINDS.has(String(events[index]?.kind))) index++
  return index
}

/**
 * 把事件序列折成渲染项:连续同工具的调用合成一个 run,其余原样。
 * `subtask_started` 不允许被跳过 —— 它可能自己就占一行(见 Ledger 的 SUBTASK_KINDS),
 * 所以它天然打断一个 run。
 */
export function groupToolRuns(events: ChatEvent[]): LedgerItem[] {
  const items: LedgerItem[] = []
  let index = 0

  while (index < events.length) {
    const head = events[index]
    if (head?.kind !== 'tool_call') {
      items.push({ type: 'event', event: head })
      index++
      continue
    }

    const tool = textOf(head.tool)
    const pairs: ToolRunPair[] = []
    let cursor = index

    if (tool) {
      while (cursor < events.length) {
        const at = nextSignificant(events, cursor)
        const call = events[at]
        // 换了工具、或者被别的行打断了,run 就到此为止
        if (!call || call.kind !== 'tool_call' || textOf(call.tool) !== tool) break
        const after = nextSignificant(events, at + 1)
        const result = events[after]?.kind === 'tool_result' ? events[after] : undefined
        pairs.push({ call, result })
        cursor = result ? after + 1 : at + 1
      }
    }

    if (pairs.length >= RUN_MIN_CALLS) {
      items.push({ type: 'run', tool, seq: pairs[0].call.seq,
                   ts: Number(pairs[0].call.ts) || 0, pairs })
      index = cursor
      continue
    }

    // 单次调用:调用行 + 结果行各自成行,和以前一样
    items.push({ type: 'event', event: head })
    if (pairs[0]?.result) items.push({ type: 'event', event: pairs[0].result })
    index = cursor > index ? cursor : index + 1
  }

  return items
}
