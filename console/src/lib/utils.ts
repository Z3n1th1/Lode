import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** 合并类名,后写的 Tailwind 类覆盖先写的同类。 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
