import { Check, ChevronsUpDown } from 'lucide-react'

import { cn } from '../../lib/utils'
import { useChat } from '../../store/chat'
import { MenuItem, MenuLabel, Popover, PopoverContent, PopoverTrigger } from '../../components/ui/popover'

/** 自治级别 → 一个点 + 一个词。只出现在展开的列表里,收起时只显示模式名。 */
const AUTONOMY: Record<string, { label: string; dot: string }> = {
  none: { label: '不执行', dot: 'bg-fg-4' },
  ask: { label: '需确认', dot: 'bg-warn' },
  auto: { label: '自动执行', dot: 'bg-accent' }
}

export default function ModeSelect() {
  const modes = useChat((state) => state.modes)
  const mode = useChat((state) => state.mode)
  const setMode = useChat((state) => state.setMode)
  const current = modes.find((item) => item.name === mode)
  const autonomy = AUTONOMY[current?.autonomy ?? 'ask'] ?? AUTONOMY.ask

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label="对话模式"
          className="inline-flex h-7 items-center gap-1.5 rounded-md px-2 text-[12.5px] text-fg-2 transition-colors hover:bg-hover hover:text-fg"
        >
          <span className={cn('size-1.5 rounded-full', autonomy.dot)} aria-hidden="true" />
          <span className="font-medium">{current?.title ?? '对话'}</span>
          <ChevronsUpDown size={12} className="text-fg-4" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64">
        <MenuLabel>本轮执行方式</MenuLabel>
        {modes.map((item) => {
          const meta = AUTONOMY[item.autonomy] ?? AUTONOMY.ask
          return (
            <MenuItem
              key={item.name}
              selected={item.name === mode}
              onClick={() => setMode(item.name)}
            >
              <span className={cn('size-1.5 shrink-0 rounded-full', meta.dot)} aria-hidden="true" />
              <span className="flex-1 truncate font-medium">{item.title}</span>
              <span className="font-mono text-[10.5px] text-fg-3">{meta.label}</span>
              {item.name === mode ? <Check size={13} className="text-accent" /> : null}
            </MenuItem>
          )
        })}
      </PopoverContent>
    </Popover>
  )
}
