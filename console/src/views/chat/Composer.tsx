import { ArrowUp, Square } from 'lucide-react'
import type { KeyboardEvent } from 'react'

import { Button } from '../../components/ui/button'
import { Tooltip } from '../../components/ui/tooltip'
import { cn } from '../../lib/utils'
import ModeSelect from './ModeSelect'

interface Props {
  draft: string
  onDraft: (value: string) => void
  onSend: () => void
  onStop: () => void
  running: boolean
  blocked: boolean
  /** attach 到别人起的运行流:输入被锁住,只能停止。 */
  locked: boolean
}

export default function Composer({ draft, onDraft, onSend, onStop, running, blocked, locked }: Props) {
  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== 'Enter' || event.shiftKey) return
    event.preventDefault()
    onSend()
  }

  const canSend = Boolean(draft.trim()) && !running && !blocked

  return (
    <div className="shrink-0 border-t border-line bg-bg">
      {/* 正文缩进对齐日志的正文列:输入的文字和上面的记录在同一根竖线上 */}
      <div className="ledger-indent py-2.5 pr-4">
        <textarea
          value={draft}
          onChange={(event) => onDraft(event.target.value)}
          onKeyDown={onKeyDown}
          rows={Math.min(8, Math.max(1, draft.split('\n').length))}
          disabled={blocked || locked}
          aria-label="输入"
          placeholder={
            locked
              ? '这条运行流还在跑,等它结束或点停止'
              : blocked
                ? '等待人工确认,当前不可输入'
                : '输入目标或下一步动作'
          }
          className={cn(
            'block w-full resize-none bg-transparent text-base leading-[1.7] text-fg',
            'placeholder:text-fg-4 focus:outline-none disabled:cursor-not-allowed'
          )}
        />

        <div className="mt-1.5 flex items-center gap-2">
          <ModeSelect />

          <span className="hidden flex-1 items-center gap-1 font-mono text-2xs text-fg-4 sm:flex">
            <kbd className="rounded-sm border border-line px-1 leading-4">Enter</kbd>
            发送
            <kbd className="ml-1.5 rounded-sm border border-line px-1 leading-4">Shift</kbd>
            <kbd className="rounded-sm border border-line px-1 leading-4">Enter</kbd>
            换行
          </span>
          <span className="flex-1 sm:hidden" />

          {blocked ? (
            <span className="font-mono text-xs text-warn">等待人工确认</span>
          ) : null}
          {locked ? <span className="font-mono text-xs text-fg-4">运行中</span> : null}

          {running ? (
            <Tooltip label="停止本轮">
              <Button variant="danger" size="icon" onClick={onStop} aria-label="停止本轮">
                <Square size={13} />
              </Button>
            </Tooltip>
          ) : (
            <Button
              variant="primary"
              size="icon"
              onClick={onSend}
              disabled={!canSend}
              aria-label="发送"
            >
              <ArrowUp size={15} />
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
