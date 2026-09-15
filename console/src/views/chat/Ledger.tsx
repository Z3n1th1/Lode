import { ArrowDown } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import type { ChatEvent, ChatMode } from '../../api'
import { foldSubtasks, groupToolRuns, isSubtaskEvent, pendingApprovals } from '../../chatEvents'
import { sliceRecent } from '../../chatTools'
import { Button } from '../../components/ui/button'
import LedgerRow from './LedgerRow'
import ToolRunRow from './ToolRunRow'

const PAGE_SIZE = 60
const STICK_SLACK = 56
/** 只有真正跑起来的子任务才单独成行:对话回合本身就是这段对话。
 *
 *  新加一种任务 kind 时要同步这里,否则那一整轮事件在对话里什么都不渲染 ——
 *  `subtask_progress` / `subtask_finished` 是折进节点里的,不会自己成行。
 *  `target_run` = 从「新建项目」的确认单开出来的那一轮,它没有对话回合可依附。 */
const SUBTASK_KINDS = new Set(['src_loop', 'surface_scan', 'target_run'])

function clockOf(ts: unknown): string {
  const value = Number(ts)
  if (!Number.isFinite(value) || value <= 0) return ''
  const date = new Date(value * 1000)
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}

interface Props {
  events: ChatEvent[]
  modes: ChatMode[]
  busy: boolean
  /** 乐观回显:已发出、事件还没流回来的那句话。 */
  echo: string
  onStop: () => void
}

export default function Ledger({ events, modes, busy, echo, onStop }: Props) {
  const scroller = useRef<HTMLDivElement>(null)
  const content = useRef<HTMLDivElement>(null)
  const stick = useRef(true)
  const pinning = useRef(false)
  const [showJump, setShowJump] = useState(false)
  const [renderCount, setRenderCount] = useState(PAGE_SIZE)

  const subtasks = useMemo(() => foldSubtasks(events), [events])

  /** 每个 job 的第一条子任务事件:行挂在这个位置,避免重复渲染。 */
  const firstSubtaskSeq = useMemo(() => {
    const first = new Map<string, number>()
    for (const event of events) {
      const jobId = String(event.job_id ?? '')
      if (!jobId || !isSubtaskEvent(event) || first.has(jobId)) continue
      first.set(jobId, event.seq)
    }
    return first
  }, [events])

  const pendingKeys = useMemo(
    () =>
      new Set(
        pendingApprovals(events).map((event) => String(event.gate ?? event.job_id ?? event.seq))
      ),
    [events]
  )

  const visible = useMemo(() => sliceRecent(events, renderCount), [events, renderCount])
  const hidden = Math.max(0, events.length - visible.length)
  /** 连续同工具调用折成一行 —— 逐事件渲染时一次 1qps 侦察就是几百行同款噪声。 */
  const items = useMemo(() => groupToolRuns(visible), [visible])

  // 跨行累积的最后一格时间刻度;每次渲染重置(见下面的 showClock)。
  let lastClock = ''

  /**
   * 跟随尾部:内容一长高就重新贴到底 —— 只要用户没往上翻。
   *
   * 不能只在 events.length 变化时滚一次:行上挂了 [content-visibility:auto],首帧的
   * scrollHeight 只是按 contain-intrinsic-size 估出来的,浏览器真正渲染那些行之后
   * 内容还会继续变高(实测 78 条事件从 2748 长到 3575,差了将近一整屏)。一次性的
   * scrollTop 会停在历史中间,之后也不再触发 scroll 事件,连"回到底部"都不出现 ——
   * 静默地不跟随。用 ResizeObserver 而不是轮询,是因为长高发生在 rAF 链结束之后,
   * 只盯几帧是抓不到的。
   */
  useEffect(() => {
    const element = scroller.current
    const box = content.current
    if (!element || !box) return

    const pin = (): void => {
      if (!stick.current) return
      // 自己滚出来的 scroll 事件不算"用户想上翻",否则会把跟随状态误关掉
      pinning.current = true
      element.scrollTop = element.scrollHeight
      setShowJump(false)
      requestAnimationFrame(() => {
        pinning.current = false
      })
    }

    pin()
    const observer = new ResizeObserver(pin)
    observer.observe(box)
    return () => observer.disconnect()
  }, [])

  function onScroll(): void {
    const element = scroller.current
    if (!element) return
    if (pinning.current) return
    const atBottom =
      element.scrollHeight - element.scrollTop - element.clientHeight < STICK_SLACK
    stick.current = atBottom
    setShowJump(!atBottom)
  }

  function toBottom(): void {
    const element = scroller.current
    if (!element) return
    element.scrollTop = element.scrollHeight
    stick.current = true
    setShowJump(false)
  }

  function loadOlder(): void {
    const element = scroller.current
    const before = element?.scrollHeight ?? 0
    setRenderCount((count) => count + PAGE_SIZE)
    // 保持视口锚点,否则载入历史后会被弹到别处
    requestAnimationFrame(() => {
      if (element) element.scrollTop = element.scrollHeight - before + element.scrollTop
    })
  }

  return (
    <div className="relative flex min-h-0 flex-1 flex-col">
      <div
        ref={scroller}
        role="log"
        aria-live="polite"
        aria-label="对话日志"
        onScroll={onScroll}
        className="min-h-0 flex-1 overflow-y-auto"
      >
        {/* 内容包一层:ResizeObserver 只能观察元素盒子,而 scrollHeight 不是元素尺寸,
            观察 scroller 本身永远不会触发 */}
        <div ref={content}>
          {hidden > 0 ? (
            <div className="border-b border-line/60 px-4 py-2 text-center">
              <Button variant="quiet" size="sm" onClick={loadOlder}>
                载入更早的 {hidden} 条
              </Button>
            </div>
          ) : null}

          {items.map((item) => {
            // 连续同工具调用合成的 run:一次调用只占一行
            if (item.type === 'run') {
              const stamp = clockOf(item.ts)
              const showClock = stamp !== '' && stamp !== lastClock
              if (stamp) lastClock = stamp
              return (
                <ToolRunRow
                  key={`run-${item.seq}`}
                  seq={item.seq}
                  clock={showClock ? stamp : ''}
                  tool={item.tool}
                  pairs={item.pairs}
                />
              )
            }

            const event = item.event
            const jobId = String(event.job_id ?? '')
            const node = jobId ? subtasks.get(jobId) : undefined
            // 只有子任务行值得画卡片,其余事件照常渲染
            if (
              event.kind === 'subtask_started' &&
              (!node || firstSubtaskSeq.get(jobId) !== event.seq || !SUBTASK_KINDS.has(node.kind))
            ) {
              return null
            }
            // 时间只在"真正渲染出来的行"之间比较:被上面过滤掉的事件不占行,
            // 拿它当基准会让整列都没有时间。首行总要有一个时间基准。
            const stamp = clockOf(event.ts)
            const showClock = stamp !== '' && stamp !== lastClock
            if (stamp) lastClock = stamp
            return (
              <LedgerRow
                key={event.seq}
                event={event}
                clock={showClock ? stamp : ''}
                node={node}
                modes={modes}
                pending={pendingKeys.has(String(event.gate ?? jobId ?? event.seq))}
                onStop={onStop}
              />
            )
          })}

          {echo ? (
            <div className="flex items-stretch border-b border-line/60 bg-accent-soft">
              <div className="flex w-[var(--ledger-gutter)] shrink-0 items-start gap-2.5 border-r border-line/50 py-2 pr-2 pl-2 md:pl-4">
                <span className="w-9 text-right font-mono text-[10.5px] text-accent select-none">
                  ·
                </span>
              </div>
              <div className="min-w-0 max-w-[52rem] flex-1 px-3 py-2">
                <p className="text-[14px] leading-[1.7] font-medium text-fg/60 whitespace-pre-wrap">
                  {echo}
                </p>
              </div>
            </div>
          ) : null}

          {busy ? (
            <div className="flex items-stretch border-b border-line/60">
              <div className="w-[var(--ledger-gutter)] shrink-0 border-r border-line/50 py-2 pr-2 pl-2 md:pl-4" />
              <div className="flex min-w-0 flex-1 items-center gap-2 px-3 py-2 font-mono text-[11.5px] text-fg-3">
                <span className="flex gap-1" aria-hidden="true">
                  <i className="size-1 animate-[pulse-dot_1.2s_ease-in-out_infinite] rounded-full bg-accent" />
                  <i className="size-1 animate-[pulse-dot_1.2s_ease-in-out_.2s_infinite] rounded-full bg-accent" />
                  <i className="size-1 animate-[pulse-dot_1.2s_ease-in-out_.4s_infinite] rounded-full bg-accent" />
                </span>
                运行中
              </div>
            </div>
          ) : null}
        </div>
      </div>

      <JumpToBottom visible={showJump} onClick={toBottom} />
    </div>
  )
}

/** 回到底部:只是一个按钮,但它的出现必须跟随真实滚动位置。 */
function JumpToBottom({ visible, onClick }: { visible: boolean; onClick: () => void }) {
  if (!visible) return null
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={onClick}
      className="absolute bottom-3 left-1/2 -translate-x-1/2 gap-1.5 bg-surface shadow-[0_8px_24px_-8px_rgb(0_0_0/60%)]"
    >
      <ArrowDown size={13} />
      回到底部
    </Button>
  )
}
