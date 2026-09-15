import { cva, type VariantProps } from 'class-variance-authority'
import type { HTMLAttributes } from 'react'

import { cn } from '../../lib/utils'

const badge = cva(
  'inline-flex items-center gap-1 rounded-sm border px-1.5 py-px font-mono text-[10.5px] ' +
    'leading-4 tracking-wide uppercase',
  {
    variants: {
      tone: {
        neutral: 'border-line text-fg-3',
        accent: 'border-accent/40 bg-accent-soft text-accent',
        danger: 'border-danger/40 text-danger',
        warn: 'border-warn/40 text-warn',
        ok: 'border-ok/40 text-ok',
        info: 'border-info/40 text-info'
      }
    },
    defaultVariants: { tone: 'neutral' }
  }
)

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badge> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badge({ tone }), className)} {...props} />
}

/** 严重度 → 色调。全站唯一一处映射,免得每个面板各写一套。 */
export function severityTone(severity: string): NonNullable<BadgeProps['tone']> {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'danger'
    case 'medium':
      return 'warn'
    case 'low':
      return 'ok'
    case 'info':
      return 'info'
    default:
      return 'neutral'
  }
}
