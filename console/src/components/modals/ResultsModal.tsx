import { Button } from '../ui/button'
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '../ui/dialog'
import { Badge, severityTone } from '../ui/badge'
import { usePanels } from '../../store/panels'

export default function ResultsModal() {
  const open = usePanels((state) => state.resultsOpen)
  const results = usePanels((state) => state.results)
  const loading = usePanels((state) => state.resultsLoading)

  const severity = Object.entries(results?.severity ?? {})

  return (
    <Dialog open={open} onOpenChange={(next) => usePanels.getState().setResultsOpen(next)}>
      <DialogContent width={780}>
        <DialogHeader>
          <DialogTitle>成果</DialogTitle>
          <DialogDescription>{results?.target ?? ''}</DialogDescription>
        </DialogHeader>

        <DialogBody>
          {loading ? (
            <p className="text-sm text-fg-3">读取中…</p>
          ) : !results ? (
            <p className="text-sm text-fg-3">暂无成果数据。</p>
          ) : (
            <div className="grid gap-5">
              <div className="flex flex-wrap items-baseline gap-x-5 gap-y-2">
                <span className="font-mono text-2xs text-fg-4">会话 {results.session_count}</span>
                {severity.length ? (
                  severity.map(([level, count]) => (
                    <span key={level} className="flex items-baseline gap-1.5">
                      <Badge tone={severityTone(level)}>{level}</Badge>
                      <span className="font-mono text-xs text-fg tabular-nums">{count}</span>
                    </span>
                  ))
                ) : (
                  <span className="text-sm text-fg-3">无发现</span>
                )}
              </div>

              {results.findings.length ? (
                <ul className="border-t border-line">
                  {results.findings.map((finding, index) => (
                    <li
                      key={`${finding.task}-${index}`}
                      className="border-b border-line/60 py-2"
                    >
                      <div className="flex items-baseline gap-2.5">
                        <Badge tone={severityTone(finding.severity)}>{finding.severity || '?'}</Badge>
                        <span className="text-sm text-fg">{finding.title}</span>
                      </div>
                      <p className="mt-1 font-mono text-xs break-all text-fg-3">
                        {finding.target || '—'} · {finding.rule}
                      </p>
                    </li>
                  ))}
                </ul>
              ) : null}

              {results.attack_graph?.chains?.length ? (
                <section>
                  <h3 className="font-mono text-2xs text-fg-3">攻击链</h3>
                  <ul className="mt-2 border-t border-line">
                    {results.attack_graph.chains.map((chain, index) => (
                      <li key={index} className="border-b border-line/60 py-2">
                        <div className="flex items-baseline gap-2">
                          <Badge tone={chain.status === 'satisfied' ? 'ok' : 'warn'}>
                            {chain.status}
                          </Badge>
                          <span className="text-sm text-fg">{chain.goal}</span>
                          <span className="font-mono text-xs text-fg-4 tabular-nums">
                            价值 {chain.value}
                          </span>
                        </div>
                        {chain.missing.length ? (
                          <p className="mt-1 font-mono text-xs text-fg-3">
                            缺失:{chain.missing.join(' ')}
                          </p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}

              {results.reports.length ? (
                <section>
                  <h3 className="font-mono text-2xs text-fg-3">报告</h3>
                  <ul className="mt-2 border-t border-line">
                    {results.reports.map((report) => (
                      <li key={report.task_id} className="border-b border-line/60 py-1.5">
                        <button
                          type="button"
                          className="font-mono text-xs text-accent hover:underline"
                          onClick={() => void usePanels.getState().openReport(report.task_id)}
                        >
                          {report.task_id}
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}
            </div>
          )}
        </DialogBody>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">
              关闭
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
