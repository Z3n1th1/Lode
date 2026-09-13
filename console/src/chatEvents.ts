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
