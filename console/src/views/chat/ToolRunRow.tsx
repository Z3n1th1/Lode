import type { ToolRunPair } from '../../chatEvents'
import { highlightJson, summarizeToolResult, toolCallPrimaryArg, toolResultHasMore } from '../../chatTools'
import { Fold, Well } from '../../components/ui/fold'
import { cn } from '../../lib/utils'
import RowShell from './RowShell'

/**
 * 一次连续的同工具调用,折成账本里的一行。
 *
 * 侦察阶段这类调用是成串的(同一个工具连着打几十个 URL),逐条成行会把发现和结论冲走;
 * 所以这一行只留"工具 + 次数 + 目标区间",逐个的请求/响应收进「明细」。
 */
export default function ToolRunRow({
  seq,
  clock,
  tool,
  pairs
}: {
  seq: number | string
  clock: string
  tool: string
  pairs: ToolRunPair[]
}) {
  const first = toolCallPrimaryArg(pairs[0]?.call.args)
  const last = toolCallPrimaryArg(pairs[pairs.length - 1]?.call.args)
  const missing = pairs.filter((pair) => !pair.result).length

  return (
    <RowShell seq={seq} clock={clock}>
      <p className="font-mono text-xs leading-6 text-fg-2">
        <span className="mr-2 inline-block text-fg-4 select-none">调用</span>
        {tool}
        <span className="ml-2 tabular-nums text-fg-4">×{pairs.length}</span>
      </p>
      {first ? (
        <p className="font-mono text-xs leading-5 break-all text-fg-3">
          {first}
          {last && last !== first ? (
            <>
              <span className="mx-1.5 text-fg-4/60">→</span>
              {last}
            </>
          ) : null}
        </p>
      ) : null}
      {missing ? (
        <p className="font-mono text-xs leading-5 text-fg-4">{missing} 次没有结果</p>
      ) : null}

      <Fold label={`明细 ${pairs.length}`}>
        <ol className="divide-y divide-line/40 overflow-hidden rounded-sm border border-line">
          {pairs.map(({ call, result }) => {
            const raw = String(result?.result ?? '')
            const summary = summarizeToolResult(raw)
            const arg = toolCallPrimaryArg(call.args)
            return (
              <li key={call.seq} className="flex gap-3 px-2.5 py-1.5">
                <span className="w-8 shrink-0 text-right font-mono text-2xs text-fg-4 tabular-nums select-none">
                  {call.seq}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-xs leading-5 break-all text-fg-2">
                    {arg || '—'}
                  </p>
                  <p
                    className={cn(
                      'font-mono text-xs leading-5 break-all',
                      result ? 'text-fg-3' : 'text-fg-4'
                    )}
                  >
                    {result ? summary || '（空）' : '无结果'}
                  </p>
                  {result && toolResultHasMore(raw, summary) ? (
                    <Fold label="输出">
                      <Well>
                        <span dangerouslySetInnerHTML={{ __html: highlightJson(raw) }} />
                      </Well>
                    </Fold>
                  ) : null}
                </div>
              </li>
            )
          })}
        </ol>
      </Fold>
    </RowShell>
  )
}
