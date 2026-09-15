import * as SwitchPrimitive from '@radix-ui/react-switch'
import type { ComponentProps } from 'react'

import { cn } from '../../lib/utils'

export function Switch({ className, ...props }: ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        'relative h-4.5 w-8 shrink-0 rounded-full border border-line transition-colors',
        'data-[state=checked]:border-accent data-[state=checked]:bg-accent',
        'data-[state=unchecked]:bg-hover',
        'disabled:pointer-events-none disabled:opacity-40',
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          'block size-3 rounded-full bg-fg-3 transition-transform',
          'data-[state=checked]:translate-x-4 data-[state=checked]:bg-accent-fg',
          'data-[state=unchecked]:translate-x-0.5'
        )}
      />
    </SwitchPrimitive.Root>
  )
}

export function Separator({ className, ...props }: ComponentProps<'div'>) {
  return <div role="separator" className={cn('h-px shrink-0 bg-line', className)} {...props} />
}
