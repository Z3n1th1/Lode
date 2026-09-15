import type { ReactNode } from 'react'

import { cn } from '../../lib/utils'

/**
 * 行的骨架:gutter(序号 + 时间)| 正文。gutter 的竖线是这条日志的脊椎。
 *
 * 折叠多行(见 ToolRunRow)和折叠一行(见 LedgerRow)共用它 —— 账本只有一套左边缘,
 * 改就改 `--ledger-gutter`,别在这里写死宽度。
 */
export default function RowShell({
  seq,
  clock,
  tint,
  children
}: {
  seq: number | string
  clock: string
  tint?: boolean
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        'flex items-stretch border-b border-line/60 transition-colors',
        '[content-visibility:auto] [contain-intrinsic-size:auto_3.25rem]',
        tint ? 'bg-accent-soft' : 'hover:bg-hover/60'
      )}
    >
      <div className="flex w-[var(--ledger-gutter)] shrink-0 items-start gap-2.5 border-r border-line/50 py-2 pr-2 pl-2 md:pl-4">
        <span
          className={cn(
            'w-9 text-right font-mono text-[10.5px] tabular-nums select-none',
            tint ? 'text-accent' : 'text-fg-4'
          )}
        >
          {seq}
        </span>
        {/* 窄屏没有时间列的余地:序号是脊椎,时间可以省 */}
        <span className="hidden font-mono text-[10.5px] text-fg-4 tabular-nums select-none md:inline">
          {clock}
        </span>
      </div>
      <div className="min-w-0 max-w-[52rem] flex-1 px-3 py-2">{children}</div>
    </div>
  )
}
