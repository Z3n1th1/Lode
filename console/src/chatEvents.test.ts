import { describe, expect, it } from 'vitest'

import { foldSubtasks, groupToolRuns, isSubtaskEvent, lastSeq, pendingApprovals } from './chatEvents'
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

describe('groupToolRuns', () => {
  const call = (seq: number, tool: string, url: string): ChatEvent =>
    ev(seq, 'tool_call', { tool, args: JSON.stringify({ url }) })
  const result = (seq: number): ChatEvent => ev(seq, 'tool_result', { result: 'HTTP/1.1 200 OK' })

  it('collapses a run of consecutive same-tool calls into one item', () => {
    const events = [
      call(1, 'fetch_url', 'https://t.example/a'),
      result(2),
      call(3, 'fetch_url', 'https://t.example/b'),
      result(4),
      call(5, 'fetch_url', 'https://t.example/c'),
      result(6)
    ]
    const items = groupToolRuns(events)
    expect(items).toHaveLength(1)
    expect(items[0].type).toBe('run')
    if (items[0].type !== 'run') throw new Error('expected a run')
    expect(items[0].tool).toBe('fetch_url')
    expect(items[0].seq).toBe(1)
    expect(items[0].pairs).toHaveLength(3)
    expect(items[0].pairs[0].result?.seq).toBe(2)
    expect(items[0].pairs[2].call.seq).toBe(5)
  })

  it('leaves a single call as its own row (call + result)', () => {
    const items = groupToolRuns([call(1, 'fetch_url', 'https://t.example/a'), result(2)])
    expect(items.map((item) => item.type)).toEqual(['event', 'event'])
  })

  it('breaks the run when the tool changes', () => {
    const events = [
      call(1, 'fetch_url', 'https://t.example/a'),
      result(2),
      call(3, 'fetch_url', 'https://t.example/b'),
      result(4),
      call(5, 'run_shell', 'ls'),
      result(6)
    ]
    const items = groupToolRuns(events)
    expect(items.map((item) => item.type)).toEqual(['run', 'event', 'event'])
    if (items[0].type !== 'run') throw new Error('expected a run')
    expect(items[0].pairs).toHaveLength(2)
  })

  it('does not let an invisible event break a run, but a rendering row does', () => {
    const invisible = [
      call(1, 'fetch_url', 'https://t.example/a'),
      result(2),
      ev(3, 'subtask_progress', { phase: 'probe' }),
      call(4, 'fetch_url', 'https://t.example/b'),
      result(5)
    ]
    expect(groupToolRuns(invisible)).toHaveLength(1)

    const interrupted = [
      call(1, 'fetch_url', 'https://t.example/a'),
      result(2),
      ev(3, 'subtask_started', { job_id: 'J-2', job_kind: 'src_loop' }),
      call(4, 'fetch_url', 'https://t.example/b'),
      result(5)
    ]
    expect(groupToolRuns(interrupted).map((item) => item.type))
      .toEqual(['event', 'event', 'event', 'event', 'event'])
  })

  it('keeps the tail pair that has no result yet, and its neighbours', () => {
    const items = groupToolRuns([
      ev(1, 'user_message', { text: 'hi' }),
      call(2, 'fetch_url', 'https://t.example/a'),
      result(3),
      call(4, 'fetch_url', 'https://t.example/b'),
      result(5),
      call(6, 'fetch_url', 'https://t.example/c')
    ])
    expect(items.map((item) => item.type)).toEqual(['event', 'run'])
    if (items[1].type !== 'run') throw new Error('expected a run')
    expect(items[1].pairs).toHaveLength(3)
    expect(items[1].pairs[2].result).toBeUndefined()
  })

  it('never drops an event: the same events come back in order', () => {
    const events = [
      call(1, 'fetch_url', 'https://t.example/a'),
      result(2),
      call(3, 'fetch_url', 'https://t.example/b'),
      result(4),
      ev(5, 'finding', { title: 'x' }),
      ev(6, 'assistant_message', { text: 'done' })
    ]
    const seen = groupToolRuns(events).flatMap((item) =>
      item.type === 'run'
        ? item.pairs.flatMap((pair) => (pair.result ? [pair.call.seq, pair.result.seq] : [pair.call.seq]))
        : [item.event.seq]
    )
    expect(seen).toEqual(events.map((event) => event.seq))
  })
})
