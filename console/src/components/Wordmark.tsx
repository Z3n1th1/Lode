import { cn } from '../lib/utils'

/**
 * 品牌标记:一块矿石切面(矿脉的隐喻)。
 * 用 currentColor 描边,所以在任何底色上都成立,不会被某个主题写死。
 */
export function GemMark({ size = 20, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {/* 一块矿石切面:外轮廓 + 一条切面线。多画几笔在 22px 下就糊成方块了 */}
      <path d="M12 2.8 20.2 8.9 17 20.2H7L3.8 8.9Z" />
      <path d="M3.8 8.9h16.4" opacity=".38" />
    </svg>
  )
}

export default function Wordmark({ className, size = 22 }: { className?: string; size?: number }) {
  return (
    <span className={cn('inline-flex items-center gap-2.5 text-fg', className)}>
      <GemMark size={size} />
      <span className="font-mono text-base leading-none font-medium tracking-[-.01em]">Lode</span>
    </span>
  )
}
