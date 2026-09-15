import { formatTimestamp } from '../dashboard'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { cn } from '../lib/utils'
import { TRAJ_KIND_LABEL, projectStatusTone, usePanels } from '../store/panels'

const SOURCE_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'info' | 'neutral'> = {
  finding: 'warn',
  human_gate: 'danger',
  verifier: 'ok',
  tool: 'info',
  tool_call: 'info',
  tool_result: 'info'
}

/** 项目 → 会话 → 轨迹的钻取:选中项目后在项目页下方展开。 */
export default function ProjectDetailPane() {
  const detail = usePanels((state) => state.projectDetail)
  const selectedSessionId = usePanels((state) => state.selectedSessionId)
  const trajectory = usePanels((state) => state.trajectory)
  const guidanceRows = usePanels((state) => state.guidanceRows)
  const guidanceText = usePanels((state) => state.guidanceText)
  const guidanceError = usePanels((state) => state.guidanceError)
  const guidanceOk = usePanels((state) => state.guidanceOk)

  if (!detail) return null

  return (
    <section className="shrink-0 border-t border-line">
      <h2 className="flex items-baseline gap-3 border-b border-line bg-raised/60 px-4 py-1.5">
        <span className="font-mono text-[10.5px] tracking-wide text-fg-3">会话与轨迹</span>
        <span className="font-mono text-[10.5px] text-fg-4">{detail.sessions.length}</span>
      </h2>

      {detail.sessions.length ? (
        <ul className="border-b border-line">
          {detail.sessions.map((session) => {
            const active = session.session_id === selectedSessionId
            return (
              <li key={session.session_id}>
                <button
                  type="button"
                  onClick={() => void usePanels.getState().selectSession(session.session_id)}
                  className={cn(
                    'flex w-full flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-2 text-left transition-colors',
                    active ? 'bg-active' : 'hover:bg-hover'
                  )}
                >
                  <span className="font-mono text-[11.5px] text-fg">{session.session_id}</span>
                  <Badge tone={projectStatusTone(session.status)}>{session.status}</Badge>
                  <span className="font-mono text-[11px] text-fg-3 tabular-nums">
                    接口 {session.audited_endpoint_count}/{session.endpoint_count}
                  </span>
                  <span className="font-mono text-[11px] text-fg-3 tabular-nums">
                    发现 {session.verified_finding_count}/{session.finding_count}
                  </span>
                  <span className="font-mono text-[11px] text-fg-4">{session.profile_name}</span>
                  <span className="flex-1" />
                  <span className="font-mono text-[11px] text-fg-4">
                    {formatTimestamp(session.created_at)}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      ) : (
        <p className="px-4 py-6 text-center text-[13px] text-fg-3">该项目暂无会话</p>
      )}

      {selectedSessionId ? (
        <>
          <ul>
            {trajectory.length ? (
              trajectory.map((event) => (
                <li
                  key={`${event.seq}-${event.ts}`}
                  className="grid grid-cols-[2.5rem_7.5rem_minmax(0,1fr)] items-baseline gap-x-3 border-b border-line/60 px-4 py-1.5"
                >
                  <span className="text-right font-mono text-[10.5px] text-fg-4 tabular-nums">
                    {event.seq}
                  </span>
                  <span className="font-mono text-[11px] text-fg-4">
                    {TRAJ_KIND_LABEL[event.kind] ?? event.kind}
                  </span>
                  <span className="flex flex-wrap items-baseline gap-x-2 text-[12.5px] text-fg-2">
                    <Badge tone={SOURCE_TONE[event.source] ?? 'neutral'}>{event.source}</Badge>
                    {event.summary}
                    <span className="font-mono text-[10.5px] text-fg-4">
                      {formatTimestamp(event.ts)}
                    </span>
                  </span>
                </li>
              ))
            ) : (
              <li className="border-b border-line/60 px-4 py-6 text-center text-[13px] text-fg-3">
                该会话暂无可读轨迹
              </li>
            )}
          </ul>

          <div className="border-b border-line px-4 py-3">
            <p className="font-mono text-[10.5px] text-fg-4">续跑指导</p>
            <div className="mt-2 flex items-start gap-2">
              <textarea
                rows={2}
                value={guidanceText}
                onChange={(event) => usePanels.setState({ guidanceText: event.target.value })}
                placeholder="补充边界条件或下一步方向"
                className="min-h-9 flex-1 resize-none rounded-md border border-line bg-transparent px-2.5 py-1.5 text-[13px] text-fg transition-colors placeholder:text-fg-4 hover:border-line-strong focus:border-accent focus:outline-none"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => void usePanels.getState().submitGuidance()}
              >
                提交
              </Button>
              <Button variant="quiet" size="sm" onClick={() => void usePanels.getState().forkSession()}>
                复刻
              </Button>
            </div>
            <p
              className={cn(
                'mt-1.5 min-h-5 text-[12px]',
                guidanceError ? 'text-danger' : guidanceOk ? 'text-ok' : 'text-fg-4'
              )}
              role={guidanceError ? 'alert' : undefined}
            >
              {guidanceError || guidanceOk || '提交只创建意图,执行仍走 agent 确认门。'}
            </p>

            {guidanceRows.length ? (
              <ul className="mt-1 border-t border-line/60">
                {guidanceRows.map((row) => (
                  <li key={row.id} className="border-b border-line/60 py-1.5">
                    <p className="font-mono text-[10.5px] text-fg-4">
                      {row.id} · {row.status} · {formatTimestamp(row.created_at)}
                    </p>
                    <p className="mt-0.5 text-[12.5px] text-fg-2">{row.guidance}</p>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </>
      ) : null}
    </section>
  )
}
