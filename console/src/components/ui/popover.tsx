import * as PopoverPrimitive from '@radix-ui/react-popover'
import type { ComponentProps } from 'react'

import { cn } from '../../lib/utils'

export const Popover = PopoverPrimitive.Root
export const PopoverTrigger = PopoverPrimitive.Trigger
export const PopoverAnchor = PopoverPrimitive.Anchor

export function PopoverContent({
  className,
  align = 'start',
  sideOffset = 6,
  ...props
}: ComponentProps<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        collisionPadding={10}
        className={cn(
          'z-50 min-w-[8rem] overflow-hidden rounded-md border border-line bg-surface py-1',
          'shadow-[0_10px_32px_-10px_rgb(0_0_0/55%)]',
          'data-[state=open]:animate-[row-in_110ms_ease-out]',
          className
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  )
}

export function MenuItem({
  className,
  selected,
  ...props
}: ComponentProps<'button'> & { selected?: boolean }) {
  return (
    <button
      type="button"
      className={cn(
        'flex w-full items-center gap-2.5 px-2.5 py-1.5 text-left text-sm transition-colors',
        'hover:bg-hover disabled:pointer-events-none disabled:opacity-40',
        selected ? 'text-fg' : 'text-fg-2',
        className
      )}
      {...props}
    />
  )
}

export function MenuLabel({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn('px-2.5 pt-2 pb-1 font-mono text-2xs tracking-wide text-fg-4', className)}
      {...props}
    />
  )
}

export function MenuSeparator({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('my-1 h-px bg-line', className)} {...props} />
}
