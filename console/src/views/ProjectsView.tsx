import { Plus, RefreshCw } from 'lucide-react'

import type { PendingIntakeRow, ProjectCard } from '../api'
import PageHeader from '../components/shell/PageHeader'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import Table, { type Column } from '../components/ui/table'
import { formatTimestamp } from '../dashboard'
import { OPTION_LABEL, projectStatusTone, usePanels } from '../store/panels'
import ProjectDetailPane from './ProjectDetailPane'

const PROJECT_COLUMNS: Column<ProjectCard>[] = [
  {
    key: 'target',
    header: '目标',
    mono: true,
    render: (row) => <span className="break-all text-fg">{row.target}</span>
  },
  { key: 'profiles', header: '策略档', width: 160, mono: true, render: (row) => row.profiles.join(', ') || '—' },
  { key: 'session_count', header: '会话', width: 64, align: 'right', mono: true },
  {
    key: 'finding_count',
    header: '发现',
    width: 84,
    align: 'right',
    mono: true,
    render: (row) => `${row.verified_finding_count}/${row.finding_count}`
  },
  {
    key: 'status',
    header: '状态',
    width: 84,
    render: (row) => <Badge tone={projectStatusTone(row.status)}>{row.status}</Badge>
  },
  {
    key: 'last_activity',
    header: '最近活动',
    width: 116,
    mono: true,
    render: (row) => formatTimestamp(row.last_activity)
  },
  {
    key: '_act',
    header: '',
    width: 110,
    render: (row) => (
      <Button
        variant="quiet"
        size="sm"
        onClick={(event) => {
          event.stopPropagation()
          void usePanels.getState().openResults(row.project_id)
        }}
      >
        成果
      </Button>
    )
  }
]

const INTAKE_COLUMNS: Column<PendingIntakeRow>[] = [
  { key: 'target', header: '目标', mono: true, render: (row) => <span className="break-all">{row.target}</span> },
  { key: 'profile_name', header: '策略档', width: 150, mono: true },
  {
    key: 'enabled_options',
    header: '开关',
    mono: true,
    render: (row) => row.enabled_options.map((key) => OPTION_LABEL[key] ?? key).join(' ') || '全部关闭'
  },
  {
    key: 'expires_at',
    header: '待确认至',
    width: 116,
    mono: true,
    render: (row) => formatTimestamp(row.expires_at)
  }
]

export default function ProjectsView() {
  const projects = usePanels((state) => state.projects)
  const intakes = usePanels((state) => state.intakes)
  const loading = usePanels((state) => state.loading)

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="项目"
        meta={`${projects.length} 个目标`}
        actions={
          <>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="刷新"
              disabled={loading}
              onClick={() => void usePanels.getState().load('projects')}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : undefined} />
            </Button>
            <Button variant="outline" size="sm" onClick={() => void usePanels.getState().openNewProject()}>
              <Plus size={13} />
              新建
            </Button>
          </>
        }
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        <Table
          columns={PROJECT_COLUMNS}
          rows={projects}
          rowKey={(row) => row.project_id}
          empty="暂无目标"
          emptyHint="新建一个目标后会出现在这里"
          onRowClick={(row) => usePanels.getState().selectProject(row.project_id)}
        />

        <ProjectDetailPane />

        {/* 队列空的时候整段不出现:常态是空的,占着一屏没信息 */}
        {intakes.length ? (
          <>
            <h2 className="border-y border-line bg-raised/60 px-4 py-1.5 font-mono text-[10.5px] tracking-wide text-fg-3">
              待确认 {intakes.length}
            </h2>
            <Table
              columns={INTAKE_COLUMNS}
              rows={intakes}
              rowKey={(row) => row.intake_id}
              empty="暂无待确认的建目标预览"
            />
          </>
        ) : null}
      </div>
    </section>
  )
}
