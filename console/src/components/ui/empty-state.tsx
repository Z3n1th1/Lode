import type { ReactNode } from 'react'

import { cn } from '../../lib/utils'

/**
 * 空态:居中在交给它的空间里,一行说明 + 可选的等宽提示、动作。
 *
 * 每个页面原来各写各的(表格里是一行贴顶的文字、面板里是 py-12、有的还是一个个
 * 撑满整页的空盒子),同一个"这里什么都没有"在不同页面长得不一样。统一走这里。
 * 文案规则:标题一句、不超过一行,别写营销句,别重复标题里的词。
 */
export default function EmptyState({
  title,
  hint,
  action,
  className
}: {
  title: string
  hint?: string
  action?: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2.5 px-6 py-10 text-center',
        className
      )}
    >
      <p className="text-[13px] text-fg-2">{title}</p>
      {hint ? (
        <p className="max-w-[46ch] font-mono text-[11.5px] leading-relaxed text-fg-4">{hint}</p>
      ) : null}
      {action}
    </div>
  )
}
