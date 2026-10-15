import { Plus, RefreshCw } from 'lucide-react'

import { PROJECT_PAGE_SIZES, type PendingIntakeRow, type ProjectCard } from '../api'
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
    width: 96,
    render: (row) => (
      // 在跑的那一行带脉冲点:光看 "running" 三个字母,在一屏 done 里不够扎眼。
      <span className="inline-flex items-center gap-1.5">
        {row.status === 'running' ? (
          <i className="inline-block size-1.5 shrink-0 animate-[pulse-dot_1.6s_ease-in-out_infinite] rounded-full bg-accent" />
        ) : null}
        <Badge tone={projectStatusTone(row.status)}>{row.status}</Badge>
      </span>
    )
  },
  {
    key: 'surface',
    header: '产出',
    width: 236,
    mono: true,
    render: (row) => {
      if (row.status === 'running') {
        return (
          <span className="text-accent">
            {row.batch_size > 1 ? `${row.batch_index}/${row.batch_size}` : '扫描中'}
          </span>
        )
      }
      // has_surface=false 是"这条路本来就不产生面计数"(auto 产出的是候选),
      // 跟"扫了但这台什么都没有"是两件事,不能都画成一个 0。
      if (!row.has_surface) return <span className="text-fg-4">—</span>
      if (row.surface_paths + row.surface_api + row.surface_scripts === 0) {
        return <span className="text-fg-4">未产出</span>
      }
      return `路径 ${row.surface_paths} · API ${row.surface_api} · 脚本 ${row.surface_scripts}`
    }
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
  const projectTotal = usePanels((state) => state.projectTotal)
  const projectOffset = usePanels((state) => state.projectOffset)
  const projectPageSize = usePanels((state) => state.projectPageSize)
  const projectRunning = usePanels((state) => state.projectRunning)
  const projectsMoreError = usePanels((state) => state.projectsMoreError)
  const intakes = usePanels((state) => state.intakes)
  const intakeQueueStatus = usePanels((state) => state.intakeQueueStatus)
  const loading = usePanels((state) => state.loading)

  // 列表是分页的:页头要写清"这一页是全部里的哪一段",不能把本页条数当总数。
  const pageSize = projectPageSize || PROJECT_PAGE_SIZES[0]
  const page = Math.floor(projectOffset / pageSize) + 1
  const pages = Math.max(1, Math.ceil(projectTotal / pageSize))
  const first = projectTotal ? projectOffset + 1 : 0
  const last = Math.min(projectOffset + pageSize, projectTotal)
  const shown = projectTotal ? `${first}–${last} / ${projectTotal} 个目标` : '0 个目标'
  const atStart = projectOffset <= 0
  const atEnd = projectOffset + pageSize >= projectTotal

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="项目"
        meta={shown}
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

      {/* 在跑的那台放在页头下面、滚动区外面 —— 翻到第 9 页也该看得见"现在在扫什么"。
          它读的是全局那一条,不是当前页里的,所以不受翻页影响。 */}
      {projectRunning ? (
        <div className="flex shrink-0 items-center gap-2 border-y border-line bg-accent-soft px-4 py-1.5 font-mono text-2xs text-accent">
          <i className="inline-block size-1.5 shrink-0 animate-[pulse-dot_1.6s_ease-in-out_infinite] rounded-full bg-accent" />
          <span className="truncate">
            正在扫描 {projectRunning.target}
            {projectRunning.batch_size > 1
              ? ` · ${projectRunning.batch_index}/${projectRunning.batch_size}`
              : ''}
          </span>
        </div>
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        <Table
          columns={PROJECT_COLUMNS}
          rows={projects}
          rowKey={(row) => row.project_id}
          empty="暂无目标"
          emptyHint="新建一个目标后会出现在这里"
          onRowClick={(row) => usePanels.getState().selectProject(row.project_id)}
        />

        {/* 翻页条。必须是 Table 的兄弟节点:Table 空行时会直接短路成 EmptyState,
            没有 footer 插槽。总数永远显示 —— 一个点了没反应的按钮,和当初那个
            静默截断是同一类毛病。 */}
        {projectTotal ? (
          <div className="flex shrink-0 items-center gap-3 border-b border-line px-3 py-2">
            <span className="font-mono text-2xs text-fg-4">
              第 {page} / {pages} 页 · 共 {projectTotal}
            </span>
            {projectsMoreError ? (
              <span className="text-xs text-warn">取页失败:{projectsMoreError}</span>
            ) : null}
            <span className="flex-1" />
            <select
              value={pageSize}
              disabled={loading}
              aria-label="每页条数"
              onChange={(event) =>
                void usePanels.getState().setProjectPage(0, Number(event.target.value))
              }
              className="rounded-sm border border-line bg-transparent px-1.5 py-1 font-mono text-2xs text-fg-3 disabled:opacity-50"
            >
              {PROJECT_PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size} / 页
                </option>
              ))}
            </select>
            <Button
              variant="quiet"
              size="sm"
              disabled={loading || atStart}
              onClick={() => void usePanels.getState().setProjectPage(projectOffset - pageSize)}
            >
              上一页
            </Button>
            <Button
              variant="quiet"
              size="sm"
              disabled={loading || atEnd}
              onClick={() => void usePanels.getState().setProjectPage(projectOffset + pageSize)}
            >
              下一页
            </Button>
          </div>
        ) : null}

        <ProjectDetailPane />

        {/* 队列空的时候整段不出现:常态是空的,占着一屏没信息。—— 但"台账读不到"
            不是常态。那种空要说出来,否则同一个空界面同时代表两件事。 */}
        {intakes.length ? (
          <>
            <h2 className="border-y border-line bg-raised/60 px-4 py-1.5 font-mono text-2xs tracking-wide text-fg-3">
              待确认 {intakes.length}
            </h2>
            <Table
              columns={INTAKE_COLUMNS}
              rows={intakes}
              rowKey={(row) => row.intake_id}
              empty="暂无待确认的建目标预览"
            />
          </>
        ) : intakeQueueStatus && intakeQueueStatus !== 'available' ? (
          <p className="border-t border-line px-4 py-2 text-sm text-warn">
            提交队列的台账读不到
            {intakeQueueStatus === 'missing'
              ? '(target_intakes.jsonl 还没有:提交第一个预览时才会建)'
              : '(文件或它的锁不可用)'}
            ,所以这里可能是空的、也可能有内容没显示出来。
          </p>
        ) : null}
      </div>
    </section>
  )
}
