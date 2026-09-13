import { describe, expect, it } from 'vitest'

import { foldSubtasks, isSubtaskEvent, lastSeq, pendingApprovals } from './chatEvents'
import type { ChatEvent } from './api'

function ev(seq: number, kind: string, extra: Partial<ChatEvent> = {}): ChatEvent {
  return { seq, ts: 1000 + seq, kind, ...extra }
}

describe('isSubtaskEvent', () => {
  it('matches only the three subtask kinds', () => {
    expect(isSubtaskEvent(ev(1, 'subtask_started'))).toBe(true)
    expect(isSubtaskEvent(ev(1, 'subtask_progress'))).toBe(true)
    expect(isSubtaskEvent(ev(1, 'subtask_finished'))).toBe(true)
    expect(isSubtaskEvent(ev(1, 'assistant_message'))).toBe(false)
  })
})

describe('foldSubtasks', () => {
  it('folds one job\'s started/progress/finished into a single node', () => {
    const nodes = foldSubtasks([
      ev(1, 'subtask_started', { job_id: 'J-1', job_kind: 'src_loop', target: 'https://t.example', title: 'SRC 黑盒' }),
      ev(2, 'subtask_progress', { job_id: 'J-1', phase: 'autopilot' }),
      ev(3, 'subtask_progress', { job_id: 'J-1', phase: 'done', findings: 2 }),
      ev(4, 'subtask_finished', { job_id: 'J-1', status: 'completed' })
    ])
    const node = nodes.get('J-1')
    expect(node).toBeDefined()
    expect(node?.kind).toBe('src_loop')
    expect(node?.target).toBe('https://t.example')
    expect(node?.title).toBe('SRC 黑盒')
    expect(node?.status).toBe('completed')
    expect(node?.findings).toBe(2)
    expect(node?.startedAt).toBe(1001)
    expect(node?.updates.map((u) => u.phase)).toEqual(['autopilot', 'done'])
  })

  it('keeps separate jobs separate and preserves first-seen order', () => {
    const nodes = foldSubtasks([
      ev(1, 'subtask_started', { job_id: 'J-A', job_kind: 'ctf_solve' }),
      ev(2, 'subtask_started', { job_id: 'J-B', job_kind: 'code_audit' }),
      ev(3, 'subtask_finished', { job_id: 'J-A', status: 'failed', error: 'boom' })
    ])
    expect([...nodes.keys()]).toEqual(['J-A', 'J-B'])
    expect(nodes.get('J-A')?.status).toBe('failed')
    expect(nodes.get('J-A')?.error).toBe('boom')
    expect(nodes.get('J-B')?.status).toBe('running')
  })

  it('ignores non-subtask events and events without a job id', () => {
    const nodes = foldSubtasks([
      ev(1, 'user_message', { text: 'hi' }),
      ev(2, 'subtask_progress', { phase: 'orphan' })
    ])
    expect(nodes.size).toBe(0)
  })

  it('stays running when no terminal event has arrived', () => {
    const nodes = foldSubtasks([ev(1, 'subtask_started', { job_id: 'J-1', job_kind: 'src_loop' })])
    expect(nodes.get('J-1')?.status).toBe('running')
  })
})

describe('pendingApprovals', () => {
  it('lists an approval until it is resolved', () => {
    const requested = ev(1, 'approval_required', { gate: 'write_action', message: '要写目标吗?' })
    expect(pendingApprovals([requested])).toHaveLength(1)

    const resolved = ev(2, 'approval_resolved', { gate: 'write_action' })
    expect(pendingApprovals([requested, resolved])).toHaveLength(0)
  })

  it('keeps unrelated gates open', () => {
    const events = [
      ev(1, 'approval_required', { gate: 'write_action' }),
      ev(2, 'approval_required', { gate: 'exfiltrate' }),
      ev(3, 'approval_resolved', { gate: 'write_action' })
    ]
    expect(pendingApprovals(events).map((e) => e.gate)).toEqual(['exfiltrate'])
  })
})

describe('lastSeq', () => {
  it('returns the highest seq, or 0 for an empty stream', () => {
    expect(lastSeq([])).toBe(0)
    expect(lastSeq([ev(3, 'a'), ev(11, 'b'), ev(7, 'c')])).toBe(11)
  })
})
