import { RefreshCw } from 'lucide-react'

import type { FindingRow } from '../api'
import PageHeader from '../components/shell/PageHeader'
import { Badge, severityTone } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import Table, { type Column } from '../components/ui/table'
import { formatTimestamp } from '../dashboard'
import { usePanels } from '../store/panels'

const COLUMNS: Column<FindingRow>[] = [
  {
    key: 'severity',
    header: '严重度',
    width: 92,
    render: (row) => (
      <Badge tone={severityTone(row.severity)}>{row.severity || '?'}</Badge>
    )
  },
  { key: 'title', header: '标题', render: (row) => <span className="text-fg">{row.title}</span> },
  { key: 'rule', header: '类型', width: 140, mono: true },
  {
    key: 'target',
    header: '目标',
    width: 220,
    mono: true,
    render: (row) => <span className="break-all">{row.target || '—'}</span>
  },
  { key: 'task', header: '任务', width: 96, mono: true },
  {
    key: 'ts',
    header: '时间',
    width: 116,
    mono: true,
    render: (row) => (row.ts ? formatTimestamp(row.ts) : '—')
  }
]

export default function FindingsView() {
  const rows = usePanels((state) => state.findings)
  const loading = usePanels((state) => state.loading)

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="发现"
        meta={`${rows.length} 条候选`}
        actions={
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="刷新"
            disabled={loading}
            onClick={() => void usePanels.getState().load('findings')}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : undefined} />
          </Button>
        }
      />
      <Table
        columns={COLUMNS}
        rows={rows}
        rowKey={(row, index) => `${row.task}-${row.rule}-${index}`}
        empty="暂无候选发现"
        emptyHint="跑一次扫描,结果会落在这里"
        onRowClick={(row) => usePanels.getState().openFinding(row)}
      />
    </section>
  )
}
