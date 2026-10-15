import type { FindingRow, FindingRetestSummary } from './api'

export const MAX_RETEST_BATCH = 20

export const RETEST_LABEL: Record<string, string> = {
  none: '未复测',
  recorded: '待填写结果',
  pending_review: '需人工复核',
  queued: '排队中',
  running: '复测中',
  completed: '已完成',
  failed: '执行失败',
  stopped: '已停止',
  reproduced: '仍可复现',
  fixed: '修复证据齐全',
  inconclusive: '证据不足'
}

export function retestKey(retest?: FindingRetestSummary): string {
  if (!retest) return 'none'
  // A queued/running request must not inherit the last result's green badge.
  if (retest.status === 'queued' || retest.status === 'running') return retest.status
  return retest.verdict || retest.status || 'none'
}

export function findingRowKey(row: FindingRow): string {
  return row.finding_id || JSON.stringify([row.task, row.rule, row.title, row.target, row.ts])
}

export function filterFindings(rows: FindingRow[], query: string, severity: string, status: string): FindingRow[] {
  const words = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean)
  return rows.filter((row) => {
    if (severity && row.severity.toLowerCase() !== severity) return false
    if (status === 'review' && !row.retest?.human_review_required) return false
    if (status && status !== 'review' && retestKey(row.retest) !== status) return false
    const haystack = [row.title, row.target, row.rule, row.task, row.finding_id].join(' ').toLocaleLowerCase()
    return words.every((word) => haystack.includes(word))
  })
}

export function selectedFindingIds(selected: ReadonlySet<string>, rows: FindingRow[]): string[] {
  return [...new Set(rows.map((row) => row.finding_id).filter((id): id is string => Boolean(id && selected.has(id))))].slice(0, MAX_RETEST_BATCH)
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '请求失败，请重试'
}

export function downloadMarkdown(filename: string, markdown: string): void {
  const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename.replace(/[^a-zA-Z0-9._-]/g, '_')
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000)
}
