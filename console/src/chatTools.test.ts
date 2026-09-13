import { describe, expect, it } from 'vitest'

import {
  highlightJson, parseReasoningText, parseResultMeta, parseToolArgs, sliceRecent,
  summarizeToolOutput, summarizeToolResult, toolCallHasMore, toolCallSummary, toolResultHasMore
} from './chatTools'

describe('parseToolArgs', () => {
  it('parses JSON object into kv rows', () => {
    expect(parseToolArgs('{"cmd":"ls","n":3,"ok":true}')).toEqual([
      { k: 'cmd', v: 'ls' },
      { k: 'n', v: '3' },
      { k: 'ok', v: 'true' }
    ])
  })
  it('returns null for non-JSON / arrays / empty', () => {
    expect(parseToolArgs('not json')).toBeNull()
    expect(parseToolArgs('[1,2]')).toBeNull()
    expect(parseToolArgs('')).toBeNull()
    expect(parseToolArgs(undefined)).toBeNull()
  })
  it('truncates long values', () => {
    const rows = parseToolArgs(JSON.stringify({ a: 'x'.repeat(300) }))
    expect(rows?.[0].v.length).toBeLessThanOrEqual(161)
    expect(rows?.[0].v.endsWith('…')).toBe(true)
  })
})

describe('summarizeToolOutput', () => {
  it('keeps first 3 non-empty lines and counts the rest', () => {
    const s = summarizeToolOutput('a\n\nb\nc\nd\ne')
    expect(s).toContain('a\nb\nc')
    expect(s).toContain('共 5 行')
  })
  it('truncates very long single output', () => {
    const s = summarizeToolOutput('y'.repeat(500))
    expect(s.length).toBeLessThanOrEqual(241)
  })
  it('empty input', () => {
    expect(summarizeToolOutput('')).toBe('')
  })
})

describe('sliceRecent', () => {
  it('windows to the last N entries', () => {
    expect(sliceRecent([1, 2, 3, 4, 5], 2)).toEqual([4, 5])
    expect(sliceRecent([1, 2], 60)).toEqual([1, 2])
    expect(sliceRecent([1], 0)).toEqual([])
  })
})

describe('toolCallSummary (R-A P0-1)', () => {
  it('summarizes primary arg in one line', () => {
    expect(toolCallSummary('exec_command', '{"cmd":"nmap -sV t.example"}'))
      .toBe('exec_command  cmd: nmap -sV t.example')
  })
  it('counts extra params and truncates long values', () => {
    const s = toolCallSummary('exec_command', JSON.stringify({ cmd: 'x'.repeat(200), timeout: 30 }))
    expect(s).toContain('+1 参数')
    expect(s.length).toBeLessThan(200)
    expect(s.endsWith('参数)')).toBe(true)
  })
  it('falls back for missing/non-JSON args', () => {
    expect(toolCallSummary('finish_scan', '')).toBe('finish_scan')
    expect(toolCallSummary(undefined, undefined)).toBe('tool')
    expect(toolCallSummary('t', 'not json')).toBe('t  not json')
  })
})

describe('toolCallHasMore (R-A P0-1 展开必须有新增信息)', () => {
  it('single short arg → no expand', () => {
    expect(toolCallHasMore('{"cmd":"ls"}')).toBe(false)
  })
  it('multi-key or long/multiline arg → expandable', () => {
    expect(toolCallHasMore('{"cmd":"ls","timeout":5}')).toBe(true)
    expect(toolCallHasMore(JSON.stringify({ cmd: 'y'.repeat(200) }))).toBe(true)
    expect(toolCallHasMore('{"cmd":"a\\nb"}')).toBe(true)
  })
  it('empty args → no expand', () => {
    expect(toolCallHasMore('')).toBe(false)
    expect(toolCallHasMore(undefined)).toBe(false)
  })
})

describe('parseResultMeta / summarizeToolResult (R-A P0-1)', () => {
  it('extracts exit code / success / duration', () => {
    expect(parseResultMeta('{"exit_code":0,"duration":1.234}')).toBe('退出码 0 · 耗时 1.2s')
    expect(parseResultMeta('{"success":false,"error":"boom"}')).toBe('失败 · 错误: boom')
    expect(parseResultMeta('plain output')).toBe('')
  })
  it('summarizeToolResult prefers meta, falls back to line summary', () => {
    expect(summarizeToolResult('{"exit_code":1}')).toBe('退出码 1')
    expect(summarizeToolResult('line1\nline2')).toContain('line1')
    expect(summarizeToolResult('')).toBe('')
  })
})

describe('toolResultHasMore (R-A P0-1)', () => {
  it('raw longer than summary → expandable; equal → not', () => {
    expect(toolResultHasMore('{"exit_code":0,"extra":"data"}', '退出码 0')).toBe(true)
    expect(toolResultHasMore('成功', '成功')).toBe(false)
    expect(toolResultHasMore('', '')).toBe(false)
  })
})

describe('parseReasoningText (R-A P0-2)', () => {
  it('unwraps [{"text":...,"type":"summary_text"}] JSON', () => {
    const raw = '[{"text":"先分析参数","type":"summary_text"},{"text":"再验证归属"}]'
    expect(parseReasoningText(raw)).toBe('先分析参数\n再验证归属')
  })
  it('handles python repr single quotes', () => {
    expect(parseReasoningText("[{'text': '端点未校验归属', 'type': 'summary_text'}]")).toBe('端点未校验归属')
  })
  it('plain text passes through; no JSON brackets leaked', () => {
    expect(parseReasoningText('直接推理文本')).toBe('直接推理文本')
    const out = parseReasoningText('[{"text":"abc"}]')
    expect(out).not.toContain('[{')
    expect(out).not.toContain('"text"')
  })
  it('empty/undefined → empty', () => {
    expect(parseReasoningText('')).toBe('')
    expect(parseReasoningText(undefined)).toBe('')
  })
})

describe('highlightJson', () => {
  it('escapes HTML before highlighting', () => {
    const html = highlightJson('{"x":"<script>"}')
    expect(html).not.toContain('<script>')
    expect(html).toContain('&lt;script&gt;')
  })
  it('highlights keys/strings/numbers/booleans', () => {
    const html = highlightJson('{"k":"v","n":12,"b":false}')
    expect(html).toContain('tk-k')
    expect(html).toContain('tk-s')
    expect(html).toContain('tk-n')
    expect(html).toContain('tk-b')
  })
  it('passes plain text through escaped', () => {
    expect(highlightJson('plain <b>text</b>')).toBe('plain &lt;b&gt;text&lt;/b&gt;')
  })
  it('truncates oversized raw bodies', () => {
    const html = highlightJson('z'.repeat(30000))
    expect(html).toContain('已截断')
  })
})
