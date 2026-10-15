import { RefreshCw, RotateCcw, Search } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'

import { batchFindingRetests, type FindingRow, type FindingRetestBatchResult } from '../api'
import FindingModal from '../components/modals/FindingModal'
import PageHeader from '../components/shell/PageHeader'
import { Badge, severityTone } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import Table, { type Column } from '../components/ui/table'
import { formatTimestamp } from '../dashboard'
import { errorMessage, filterFindings, findingRowKey, MAX_RETEST_BATCH, RETEST_LABEL, retestKey, selectedFindingIds } from '../findings'
import { usePanels } from '../store/panels'

const SELECT_STYLE = 'h-9 rounded-md border border-line bg-surface px-2 text-xs text-fg-2'

export default function FindingsView() {
  const rows = usePanels((state) => state.findings)
  const loading = usePanels((state) => state.loading)
  const loadError = usePanels((state) => state.findingsError)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [opened, setOpened] = useState<FindingRow | null>(null)
  const [batchBusy, setBatchBusy] = useState(false)
  const batchLock = useRef(false)
  const [batchError, setBatchError] = useState('')
  const [batchResult, setBatchResult] = useState<FindingRetestBatchResult | null>(null)
  const visibleRows = useMemo(() => filterFindings(rows, query, severity, status), [rows, query, severity, status])
  const selectedIds = selectedFindingIds(selected, rows)
  const selectedSet = new Set(selectedIds)

  function toggle(row: FindingRow) {
    if (!row.finding_id) return
    const id = row.finding_id
    setSelected((current) => {
      const next = new Set(selectedFindingIds(current, rows))
      if (next.has(id)) next.delete(id)
      else if (next.size < MAX_RETEST_BATCH) next.add(id)
      return next
    })
  }

  async function submitBatch() {
    if (batchLock.current || !selectedIds.length) return
    batchLock.current = true
    setBatchBusy(true)
    setBatchError('')
    setBatchResult(null)
    try {
      const result = await batchFindingRetests(selectedIds, '')
      setBatchResult(result)
      const completed = new Set(result.results.filter((item) => !item.error).map((item) => item.finding_id))
      setSelected((current) => new Set([...current].filter((id) => !completed.has(id))))
      await usePanels.getState().load('findings')
    } catch (error) {
      setBatchError(errorMessage(error))
    } finally {
      batchLock.current = false
      setBatchBusy(false)
    }
  }

  const columns: Column<FindingRow>[] = [
    {
      key: 'select', header: '选择', width: 52,
      render: (row) => (
        <input
          type="checkbox"
          aria-label={`选择 ${row.title}`}
          checked={Boolean(row.finding_id && selectedSet.has(row.finding_id))}
          disabled={batchBusy || !row.finding_id || (selectedIds.length >= MAX_RETEST_BATCH && !selectedSet.has(row.finding_id))}
          onClick={(event) => event.stopPropagation()}
          onChange={() => toggle(row)}
          className="accent-accent"
        />
      )
    },
    { key: 'severity', header: '严重度', width: 92, render: (row) => <Badge tone={severityTone(row.severity)}>{row.severity || '?'}</Badge> },
    {
      key: 'title', header: '标题',
      render: (row) => (
        <button type="button" className="text-left text-fg hover:text-accent" onClick={(event) => { event.stopPropagation(); setOpened(row) }}>
          {row.title || '未命名发现'}
        </button>
      )
    },
    { key: 'rule', header: '类型', width: 130, mono: true },
    { key: 'target', header: '目标', width: 200, mono: true, render: (row) => <span className="break-all">{row.target || '—'}</span> },
    {
      key: 'retest', header: '最近复测', width: 130,
      render: (row) => {
        const key = retestKey(row.retest)
        return <span className="grid gap-1"><Badge tone={key === 'fixed' ? 'ok' : key === 'reproduced' ? 'warn' : key === 'running' ? 'accent' : 'neutral'}>{RETEST_LABEL[key] || key}</Badge>{row.retest?.human_review_required ? <span className="text-2xs text-warn">需人工复核</span> : null}</span>
      }
    },
    { key: 'ts', header: '时间', width: 110, mono: true, render: (row) => row.ts ? formatTimestamp(row.ts) : '—' }
  ]

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader title="发现" meta={`${visibleRows.length} / ${rows.length} 条候选`} actions={
        <Button variant="ghost" size="icon-sm" aria-label="刷新发现" disabled={loading} onClick={() => void usePanels.getState().load('findings')}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : undefined} />
        </Button>
      } />
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <div className="relative min-w-40 flex-1">
          <Search size={14} className="pointer-events-none absolute top-3 left-2.5 text-fg-4" />
          <Input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="搜索发现" placeholder="搜索标题、目标、规则或任务" className="pl-8" />
        </div>
        <select aria-label="严重度筛选" value={severity} onChange={(event) => setSeverity(event.target.value)} className={SELECT_STYLE}>
          <option value="">全部严重度</option>
          {['critical', 'high', 'medium', 'low', 'info'].map((level) => <option key={level} value={level}>{level.toUpperCase()}</option>)}
        </select>
        <select aria-label="复测状态筛选" value={status} onChange={(event) => setStatus(event.target.value)} className={SELECT_STYLE}>
          <option value="">全部复测状态</option>
          {Object.entries(RETEST_LABEL).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          <option value="review">需人工复核（所有结论）</option>
        </select>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-4 py-2 text-xs text-fg-3">
        <Button size="sm" variant="quiet" disabled={batchBusy || !visibleRows.some((row) => row.finding_id)} onClick={() => setSelected(new Set(visibleRows.flatMap((row) => row.finding_id ? [row.finding_id] : []).slice(0, MAX_RETEST_BATCH)))}>选择当前结果（最多 20）</Button>
        <Button size="sm" variant="quiet" disabled={batchBusy || !selectedIds.length} onClick={() => setSelected(new Set())}>清空选择</Button>
        <span className="flex-1">已选 {selectedIds.length} / {MAX_RETEST_BATCH}</span>
        <Button size="sm" variant="outline" disabled={batchBusy || !selectedIds.length} onClick={() => void submitBatch()}><RotateCcw size={13} className={batchBusy ? 'animate-spin' : undefined} />{batchBusy ? '提交中…' : '批量复测'}</Button>
      </div>
      {loadError || batchError ? <p role="alert" className="px-4 py-2 text-xs text-danger">{batchError || `发现列表读取失败：${loadError}`}</p> : null}
      {batchResult ? <div aria-live="polite" className="max-h-36 shrink-0 overflow-auto border-b border-line px-4 py-2 text-xs text-fg-3">
        <p>{batchResult.results.filter((item) => item.enqueued).length} 条已入队，{batchResult.results.filter((item) => !item.enqueued && !item.error).length} 条已有记录或需要补充证据，{batchResult.results.filter((item) => item.error).length} 条失败。</p>
        {batchResult.results.filter((item) => item.error || item.retest?.human_review_required).map((item) => <p key={item.finding_id} className="mt-1 break-all text-warn">{rows.find((row) => row.finding_id === item.finding_id)?.title || item.finding_id}：{item.error || item.retest?.review_reason || item.retest?.summary || '需人工复核'}</p>)}
      </div> : null}
      <Table columns={columns} rows={visibleRows} rowKey={findingRowKey} empty={loading ? '读取中…' : rows.length ? '没有匹配的发现' : '暂无候选发现'} emptyHint={rows.length ? '调整搜索或筛选条件' : '采集和验证结果会显示在这里'} onRowClick={setOpened} />
      {opened ? <FindingModal key={findingRowKey(opened)} row={opened} onClose={() => setOpened(null)} onChanged={() => void usePanels.getState().load('findings')} /> : null}
    </section>
  )
}
