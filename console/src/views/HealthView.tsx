import { RefreshCw } from 'lucide-react'

import { setActiveModel, type ModelProvider } from '../api'
import PageHeader from '../components/shell/PageHeader'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import Table, { type Column } from '../components/ui/table'
import { cn } from '../lib/utils'
import { usePanels } from '../store/panels'

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-mono text-[10.5px] text-fg-4">{label}</span>
      <span className={cn('font-mono text-[13px] tabular-nums', tone ?? 'text-fg')}>{value}</span>
    </div>
  )
}

/**
 * 服务状态是三态,不是布尔。systemd 的 is-active 会给出
 * active / inactive / failed / activating / unknown,拿不到时后端回 "n/a"。
 * 只把明确故障画成红色:否则"已停止"和"这台机器没有 systemd"看起来都像崩了。
 */
function serviceState(status: string | undefined): { label: string; dot: string } {
  const value = (status || '').trim()
  if (value === 'ok' || value === 'active') return { label: value, dot: 'bg-ok' }
  if (value === 'failed' || value === 'error') return { label: value, dot: 'bg-danger' }
  return { label: value || '—', dot: 'bg-fg-4' }
}

/** 有实报的状态才算一条服务 —— "n/a" 是"这台机器上没有它",不是一条信息。 */
function isReported(status: string | undefined): boolean {
  const value = (status || '').trim()
  return value !== '' && value !== 'n/a'
}

/** 取不到值的指标不进列表:一整排 "—" 只是把页面撑长。 */
function hasValue(value: unknown): boolean {
  return value !== undefined && value !== null && value !== ''
}

export default function HealthView() {
  const system = usePanels((state) => state.system)
  const models = usePanels((state) => state.models)
  const loading = usePanels((state) => state.loading)

  const columns: Column<ModelProvider>[] = [
    { key: 'name', header: '上游', width: 140, mono: true },
    { key: 'model', header: '模型', mono: true, render: (row) => <span className="break-all">{row.model}</span> },
    { key: 'host', header: 'Host', width: 200, mono: true, render: (row) => <span className="break-all">{row.host}</span> },
    {
      key: 'up',
      header: '状态',
      width: 84,
      render: (row) => <Badge tone={row.up ? 'ok' : 'danger'}>{row.up ? 'up' : 'down'}</Badge>
    },
    {
      key: 'latency_ms',
      header: '延迟',
      width: 84,
      align: 'right',
      mono: true,
      render: (row) => (row.latency_ms != null ? `${row.latency_ms}ms` : '—')
    },
    {
      key: 'active',
      header: '活跃',
      width: 76,
      render: (row) =>
        models?.active === row.name ? (
          <span className="text-accent">当前</span>
        ) : (
          <Button
            variant="quiet"
            size="sm"
            onClick={() =>
              void setActiveModel(row.name)
                .then(() => usePanels.getState().load('health'))
                .catch(() => undefined)
            }
          >
            切换
          </Button>
        )
    }
  ]

  const scheduler = system?.scheduler
  const services = Object.entries(system?.services ?? {}).filter(([, status]) => isReported(status))
  /**
   * 内存指标是宿主机的事实,读不到(比如 Windows)就整条不摆 —— 一排 "—" 不是信息。
   * 模型池是这台机器自己的状态,无论有没有值都留着:它是这一页的主角。
   */
  const memStats = [
    { label: '内存', value: system?.mem?.used_pct != null ? `${system.mem.used_pct}%` : '' },
    { label: '可用', value: system?.mem?.avail_mb != null ? `${Math.round(system.mem.avail_mb / 1024)} G` : '' },
    { label: '总计', value: system?.mem?.total_mb != null ? `${Math.round(system.mem.total_mb / 1024)} G` : '' }
  ].filter((stat) => hasValue(stat.value))
  const poolTotal = models?.total ?? 0
  const poolUp = models?.up ?? 0
  const tasks = [
    { label: 'rss 状态', value: scheduler?.rss_last_run ? `${Math.round(scheduler.rss_last_run)}` : '' },
    { label: 'rss 新增', value: hasValue(scheduler?.rss_last_new) ? `${scheduler?.rss_last_new}` : '' },
    { label: 'keyleak', value: scheduler?.keyleak_status ?? '' },
    { label: 'gh events', value: scheduler?.gh_events_status ?? '' },
    { label: 'socks', value: scheduler?.socks_status ?? '' }
  ].filter((task) => hasValue(task.value))

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="运行"
        meta={models?.checked_at ? `模型池 ${new Date(models.checked_at * 1000).toLocaleTimeString('zh-CN')}` : ''}
        actions={
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="刷新"
            disabled={loading}
            onClick={() => void usePanels.getState().load('health')}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : undefined} />
          </Button>
        }
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        <div className="flex flex-wrap gap-x-8 gap-y-3 border-b border-line px-4 py-3">
          {memStats.map((stat) => (
            <Stat key={stat.label} label={stat.label} value={stat.value} />
          ))}
          <Stat
            label="模型池"
            value={models ? `${poolUp}/${poolTotal}` : '—'}
            /* 没配过上游时 total=0:那不是"全挂了",别画红 */
            tone={poolTotal > 0 && poolUp === 0 ? 'text-danger' : undefined}
          />
          <Stat label="活跃模型" value={models?.active_model || '—'} />
        </div>

        {/* 全是 n/a 的时候整段不出现:这台机器上没有这些服务,列出来只是噪声 */}
        {services.length ? (
          <>
            <h2 className="border-b border-line bg-raised/60 px-4 py-1.5 font-mono text-[10.5px] tracking-wide text-fg-3">
              服务
            </h2>
            <div className="grid grid-cols-[repeat(auto-fill,minmax(15rem,1fr))] border-b border-line">
              {services.map(([name, status]) => {
                const state = serviceState(status)
                return (
                  <div
                    key={name}
                    className="flex items-center gap-2 border-r border-b border-line/60 px-4 py-2"
                  >
                    <span aria-hidden="true" className={cn('size-1.5 rounded-full', state.dot)} />
                    <span className="truncate font-mono text-[11.5px] text-fg-2">{name}</span>
                    <span className="flex-1" />
                    <span className="font-mono text-[11px] text-fg-4">{state.label}</span>
                  </div>
                )
              })}
            </div>
          </>
        ) : null}

        {tasks.length ? (
          <>
            <h2 className="border-b border-line bg-raised/60 px-4 py-1.5 font-mono text-[10.5px] tracking-wide text-fg-3">
              计划任务
            </h2>
            <div className="flex flex-wrap gap-x-8 gap-y-2 border-b border-line px-4 py-3">
              {tasks.map((task) => (
                <Stat key={task.label} label={task.label} value={task.value} />
              ))}
            </div>
          </>
        ) : null}

        <h2 className="border-b border-line bg-raised/60 px-4 py-1.5 font-mono text-[10.5px] tracking-wide text-fg-3">
          模型上游
        </h2>
        <Table
          columns={columns}
          rows={models?.providers ?? []}
          rowKey={(row) => row.name}
          empty="暂无模型上游记录"
          emptyHint="模型池连上之后,这里会列出每个上游的状态与延迟"
        />
      </div>
    </section>
  )
}
