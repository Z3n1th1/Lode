import type { ReactNode } from 'react'

import { cn } from '../../lib/utils'

/** 非对话页的页头:标题、等宽副信息、右侧动作。 */
export default function PageHeader({
  title,
  meta,
  actions,
  className
}: {
  title: string
  meta?: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <header
      className={cn(
        'flex h-11 shrink-0 items-center gap-3 border-b border-line px-4',
        className
      )}
    >
      <h1 className="text-sm font-semibold tracking-wide text-fg">{title}</h1>
      {meta ? <span className="truncate font-mono text-xs text-fg-3">{meta}</span> : null}
      <span className="flex-1" />
      {actions}
    </header>
  )
}
