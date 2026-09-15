import { RefreshCw } from 'lucide-react'
import type { ReactNode } from 'react'

import PageHeader from '../components/shell/PageHeader'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import EmptyState from '../components/ui/empty-state'
import Table, { type Column } from '../components/ui/table'
import { usePanels } from '../store/panels'
import type { SrcCandidate, SrcIntent } from '../api'

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="font-mono text-[10.5px] text-fg-4">{label}</span>
      <span className="font-mono text-[13px] text-fg tabular-nums">{value}</span>
    </div>
  )
}

const CANDIDATE_COLUMNS: Column<SrcCandidate>[] = [
  { key: 'priority', header: '优先级', width: 72, align: 'right', mono: true },
  { key: 'url', header: '目标', mono: true, render: (row) => <span className="break-all">{row.url}</span> },
  { key: 'phase', header: '阶段', width: 96, mono: true },
  { key: 'status', header: '状态', width: 96 },
  {
    key: 'review',
    header: '人工复核',
    width: 88,
    render: (row) => (row.requires_human_review ? <Badge tone="warn">需要</Badge> : <span className="text-fg-4">—</span>)
  }
]

const INTENT_COLUMNS: Column<SrcIntent>[] = [
  { key: 'priority', header: '优先级', width: 72, align: 'right', mono: true },
  { key: 'intent_id', header: '意图', width: 140, mono: true },
  { key: 'phase', header: '阶段', width: 96, mono: true },
  { key: 'status', header: '状态', width: 96 },
  { key: 'attempts', header: '尝试', width: 72, align: 'right', mono: true, render: (row) => `${row.attempts ?? 0}` },
  {
    key: 'error',
    header: '最近错误',
    mono: true,
    render: (row) => <span className="text-danger">{row.last_error || '—'}</span>
  }
]

export default function BlackboardView() {
  const view = usePanels((state) => state.srcAutopilot)
  const loading = usePanels((state) => state.loading)
  const reload = () => void usePanels.getState().load('blackboard')

  const run = view.run ?? {}

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="黑板"
        meta={`${view.available ? `revision ${view.revision ?? 0}` : '无数据'}`}
        actions={
          <Button variant="ghost" size="icon-sm" aria-label="刷新" onClick={reload} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : undefined} />
          </Button>
        }
      />

      <div className="flex shrink-0 flex-wrap items-center gap-x-6 gap-y-2 border-b border-line px-4 py-2.5">
        <Metric label="状态" value={run.status ?? '—'} />
        <Metric label="轮次" value={run.round != null ? `${run.round}/${run.max_rounds ?? '?'}` : '—'} />
        <Metric label="候选" value={run.candidate_count ?? view.candidates.length} />
        <Metric label="中断原因" value={run.stop_reason ?? '—'} />
      </div>

      {!view.available ? (
        <EmptyState
          title={view.error ? '读取黑板失败' : '还没有运行记录'}
          hint={view.error || '跑一轮黑盒挖掘,候选面与意图会落在这里'}
          className="flex-1"
        />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          <Section title="候选面" count={view.candidates.length}>
            <Table
              columns={CANDIDATE_COLUMNS}
              rows={view.candidates}
              rowKey={(row) => row.candidate_id}
              empty="暂无候选"
            />
          </Section>
          <Section title="意图" count={view.intents.length}>
            <Table
              columns={INTENT_COLUMNS}
              rows={view.intents}
              rowKey={(row) => row.intent_id}
              empty="暂无意图"
            />
          </Section>
          <Section title="死路与提示" count={view.dead_ends.length + view.hints.length}>
            <ul className="px-4 pb-4">
              {view.dead_ends.map((row) => (
                <li key={`d-${row.intent_id}-${row.created_at}`} className="border-b border-line/60 py-2">
                  <p className="font-mono text-[11.5px] text-danger">{row.reason}</p>
                  <p className="mt-0.5 text-[12.5px] text-fg-2">{row.detail}</p>
                </li>
              ))}
              {view.hints.map((row) => (
                <li key={`h-${row.intent_id}-${row.created_at}`} className="border-b border-line/60 py-2">
                  <p className="font-mono text-[11.5px] text-fg-4">{row.source}</p>
                  <p className="mt-0.5 text-[12.5px] text-fg-2">{row.hint}</p>
                </li>
              ))}
              {!view.dead_ends.length && !view.hints.length ? (
                <li className="py-6 text-center text-[13px] text-fg-3">暂无记录</li>
              ) : null}
            </ul>
          </Section>
        </div>
      )}
    </section>
  )
}

function Section({
  title,
  count,
  children
}: {
  title: string
  count: number
  children: ReactNode
}) {
  return (
    <section className="shrink-0">
      <h2 className="flex items-baseline gap-2 border-b border-line bg-raised/60 px-4 py-1.5">
        <span className="font-mono text-[10.5px] tracking-wide text-fg-3">{title}</span>
        <span className="font-mono text-[10.5px] text-fg-4 tabular-nums">{count}</span>
      </h2>
      {children}
    </section>
  )
}
