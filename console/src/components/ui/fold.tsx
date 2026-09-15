import { ChevronRight } from 'lucide-react'
import type { ReactNode } from 'react'

/** 行内的折叠:默认收起,展开的必须是比摘要多出来的信息。 */
export function Fold({ label, children }: { label: string; children: ReactNode }) {
  return (
    <details className="group mt-1.5">
      <summary className="inline-flex cursor-pointer list-none items-center gap-1 font-mono text-[11px] text-fg-3 transition-colors hover:text-fg-2">
        <ChevronRight size={11} className="transition-transform group-open:rotate-90" />
        {label}
      </summary>
      <div className="mt-1.5">{children}</div>
    </details>
  )
}

/** 原文井:等宽、可滚、不换行截断。 */
export function Well({ children }: { children: ReactNode }) {
  return (
    <pre className="max-h-80 overflow-auto rounded-sm border border-line bg-raised p-2.5 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap text-fg-2">
      {children}
    </pre>
  )
}
