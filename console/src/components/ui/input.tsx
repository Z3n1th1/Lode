import type { InputHTMLAttributes, TextareaHTMLAttributes } from 'react'

import { cn } from '../../lib/utils'

const field =
  'w-full rounded-md border border-line bg-transparent text-fg placeholder:text-fg-4 ' +
  'transition-colors hover:border-line-strong ' +
  'focus:border-accent focus:outline-none focus-visible:outline-none ' +
  'disabled:cursor-not-allowed disabled:opacity-50'

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(field, 'h-9 px-2.5 text-sm', className)} {...props} />
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(field, 'resize-none px-2.5 py-2 text-sm', className)} {...props} />
}

/** 令牌/标识输入:等宽字体,便于比对。 */
export function MonoInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(field, 'h-9 px-2.5 font-mono text-xs', className)} {...props} />
}
