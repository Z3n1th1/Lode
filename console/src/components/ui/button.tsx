import { cva, type VariantProps } from 'class-variance-authority'
import type { ButtonHTMLAttributes } from 'react'

import { cn } from '../../lib/utils'

const button = cva(
  'inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-md ' +
    'border border-transparent font-medium transition-colors select-none ' +
    'disabled:pointer-events-none disabled:opacity-40 ' +
    '[&_svg]:shrink-0',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-accent-fg hover:brightness-110 active:brightness-95',
        outline: 'border-line text-fg-2 hover:bg-hover hover:text-fg',
        ghost: 'text-fg-2 hover:bg-hover hover:text-fg',
        quiet: 'text-fg-3 hover:text-fg',
        danger: 'text-danger hover:bg-danger/10'
      },
      size: {
        sm: 'h-7 px-2 text-xs',
        md: 'h-9 px-3 text-sm',
        icon: 'size-8',
        'icon-sm': 'size-7'
      }
    },
    defaultVariants: { variant: 'ghost', size: 'md' }
  }
)

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export function Button({ className, variant, size, type = 'button', ...props }: ButtonProps) {
  return <button type={type} className={cn(button({ variant, size }), className)} {...props} />
}
