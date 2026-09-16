import type { ReactNode } from 'react'

import { cn } from '../../lib/utils'
import EmptyState from './empty-state'

export interface Column<T> {
  key: string
  header: string
  /** 固定列宽(px)。不填则吃掉剩余空间。 */
  width?: number
  align?: 'left' | 'right'
  mono?: boolean
  render?: (row: T) => ReactNode
}

/**
 * 表格:发丝分隔线 + 等宽数字,和日志同一套账本语言。
 * 不用卡片包行 —— 这本来就是一张表。
 */
export default function Table<T>({
  columns,
  rows,
  rowKey,
  empty = '暂无记录',
  emptyHint,
  onRowClick,
  className
}: {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T, index: number) => string
  empty?: string
  emptyHint?: string
  onRowClick?: (row: T) => void
  className?: string
}) {
  if (!rows.length) {
    // 空态也占满这张表本来占的位置,不再是一行贴在表头下面的字
    return <EmptyState title={empty} hint={emptyHint} className={cn('flex-1', className)} />
  }

  return (
    <div className={cn('min-h-0 flex-1 overflow-auto', className)}>
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-10 bg-bg">
          <tr className="border-b border-line">
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                style={column.width ? { width: column.width } : undefined}
                className={cn(
                  'px-3 py-2 text-left font-mono text-2xs font-normal tracking-wide text-fg-4',
                  column.align === 'right' && 'text-right'
                )}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={rowKey(row, index)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={cn(
                'border-b border-line/60 transition-colors',
                onRowClick && 'cursor-pointer hover:bg-hover',
                !onRowClick && 'hover:bg-hover/50'
              )}
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  style={column.width ? { width: column.width } : undefined}
                  className={cn(
                    'px-3 py-2 align-top text-fg-2',
                    column.mono && 'font-mono text-xs',
                    column.align === 'right' && 'text-right tabular-nums'
                  )}
                >
                  {column.render ? column.render(row) : String((row as Record<string, unknown>)[column.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
