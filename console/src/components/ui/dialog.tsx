import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ComponentProps } from 'react'

import { cn } from '../../lib/utils'

export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

export function DialogContent({
  className,
  children,
  width = 560,
  ...props
}: ComponentProps<typeof DialogPrimitive.Content> & { width?: number }) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        className="fixed inset-0 z-50 bg-black/55 data-[state=open]:animate-[row-in_120ms_ease-out]"
      />
      <DialogPrimitive.Content
        style={{ width: `min(92vw, ${width}px)` }}
        className={cn(
          'fixed top-1/2 left-1/2 z-50 max-h-[85vh] -translate-x-1/2 -translate-y-1/2',
          'flex flex-col overflow-hidden rounded-lg border border-line bg-surface',
          'shadow-[0_16px_48px_-12px_rgb(0_0_0/60%)]',
          'data-[state=open]:animate-[row-in_140ms_ease-out]',
          className
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          aria-label="关闭"
          className="absolute top-3 right-3 grid size-7 place-items-center rounded-md text-fg-3 transition-colors hover:bg-hover hover:text-fg"
        >
          <X size={14} />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogHeader({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn('flex items-baseline gap-3 border-b border-line px-4 py-3 pr-12', className)}
      {...props}
    />
  )
}

export function DialogTitle({ className, ...props }: ComponentProps<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className={cn('text-sm font-semibold', className)} {...props} />
}

export function DialogDescription({
  className,
  ...props
}: ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      className={cn('font-mono text-xs text-fg-3', className)}
      {...props}
    />
  )
}

export function DialogBody({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('min-h-0 flex-1 overflow-y-auto px-4 py-3', className)} {...props} />
}

export function DialogFooter({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn(
        'flex items-center justify-end gap-2 border-t border-line px-4 py-3',
        className
      )}
      {...props}
    />
  )
}
