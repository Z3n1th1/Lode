import type { ReactNode } from 'react'

import type { ChatEvent, ChatMode } from '../../api'
import type { SubtaskNode } from '../../chatEvents'
import {
  highlightJson,
  parseReasoningText,
  summarizeToolResult,
  toolCallHasMore,
  toolCallSummary,
  toolResultHasMore
} from '../../chatTools'
import { cn } from '../../lib/utils'
import { Badge, severityTone } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Fold, Well } from '../../components/ui/fold'
import RowShell from './RowShell'

/** 严重度 → 左侧 2px 描边。全站唯一一处映射。 */
const SEVERITY_RULE: Record<string, string> = {
  danger: 'border-l-danger',
  warn: 'border-l-warn',
  ok: 'border-l-ok',
  info: 'border-l-info',
  neutral: 'border-l-line-strong'
}

/**
 * 兜底标题:正常情况下后端总会在 payload 里带上 title(= config/modes.yaml 的模式名),
 * 这里只在 title 缺失时用。所以这几个词必须和 modes.yaml 的 title 对齐 —— 改了模式名
 * 就顺手改这里,否则同一件事会在两处叫两个名字。
 */
const SUBTASK_LABEL: Record<string, string> = {
  src_loop: '挖洞',
  surface_scan: '攻击面侦察',
  target_run: '确认单运行',
  chat_turn: '对话'
}

const GATE_LABEL: Record<string, string> = {
  write_action: '写操作',
  scope_change: '范围变更',
  outbound: '对外请求'
}

const SUBTASK_STATE: Record<SubtaskNode['status'], string> = {
  running: '进行中',
  completed: '已完成',
  failed: '失败'
}

/** 直角左描边的小块:发现、人工门用它,而不用圆角卡片。 */
function Slab({
  rule,
  className,
  children
}: {
  rule: string
  className?: string
  children: ReactNode
}) {
  return (
    <div className={cn('border-l-2 py-0.5 pl-3', rule, className)}>{children}</div>
  )
}

interface Props {
  event: ChatEvent
  clock: string
  node?: SubtaskNode
  modes: ChatMode[]
  pending: boolean
  onStop: () => void
}

/** 一条事件 = 账本里的一行。四种对话行之外,其余都是内容列里的内联区块,没有卡片套卡片。 */
export default function LedgerRow({ event, clock, node, modes, pending, onStop }: Props) {
  const kind = event.kind

  if (kind === 'user_message') {
    return (
      <RowShell seq={event.seq} clock={clock} tint>
        <p className="text-[14px] leading-[1.7] font-medium text-fg whitespace-pre-wrap">
          {event.text}
        </p>
      </RowShell>
    )
  }

  if (kind === 'assistant_message') {
    return (
      <RowShell seq={event.seq} clock={clock}>
        <p className="max-w-[68ch] text-[14px] leading-[1.75] whitespace-pre-wrap text-fg">
          {event.text}
        </p>
      </RowShell>
    )
  }

  if (kind === 'reasoning') {
    const text = parseReasoningText(String(event.reasoning ?? ''))
    if (!text) return null
    return (
      <RowShell seq={event.seq} clock={clock}>
        <Fold label="思考过程">
          <Well>{text}</Well>
        </Fold>
      </RowShell>
    )
  }

  if (kind === 'tool_call') {
    const args = event.args ? String(event.args) : undefined
    return (
      <RowShell seq={event.seq} clock={clock}>
        <p className="font-mono text-[11.5px] leading-6 text-fg-2">
          <span className="mr-2 inline-block text-fg-4 select-none">调用</span>
          {toolCallSummary(event.tool, args)}
        </p>
        {toolCallHasMore(args) ? (
          <Fold label="参数">
            <Well>
              <span dangerouslySetInnerHTML={{ __html: highlightJson(String(args ?? '')) }} />
            </Well>
          </Fold>
        ) : null}
      </RowShell>
    )
  }

  if (kind === 'tool_result') {
    const raw = String(event.result ?? '')
    const summary = summarizeToolResult(raw)
    return (
      <RowShell seq={event.seq} clock={clock}>
        <p className="font-mono text-[11.5px] leading-6 text-fg-2">
          <span className="mr-2 inline-block text-fg-4 select-none">结果</span>
          {summary || '（空）'}
        </p>
        {/* 摘要已经把原文说完了(单行、没截断)就别再给一个折叠三角:展开只会看到同一句话 */}
        {toolResultHasMore(raw, summary) ? (
          <Fold label="输出">
            <Well>
              <span dangerouslySetInnerHTML={{ __html: highlightJson(raw) }} />
            </Well>
          </Fold>
        ) : null}
      </RowShell>
    )
  }

  if (kind === 'finding') {
    const tone = severityTone(String(event.severity ?? ''))
    return (
      <RowShell seq={event.seq} clock={clock}>
        <Slab rule={SEVERITY_RULE[tone] ?? SEVERITY_RULE.neutral}>
          <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
            <Badge tone={tone}>{String(event.severity ?? '?')}</Badge>
            <p className="text-[13.5px] leading-6 font-medium text-fg">{event.title}</p>
          </div>
          {event.endpoint || event.confidence ? (
            <p className="mt-1 font-mono text-[11px] break-all text-fg-3">
              {event.endpoint}
              {event.endpoint && event.confidence ? '  ·  ' : ''}
              {event.confidence ? `置信度 ${event.confidence}` : ''}
            </p>
          ) : null}
          {event.detail ? (
            <p className="mt-1.5 max-w-[68ch] text-[13px] leading-relaxed text-fg-2">
              {String(event.detail)}
            </p>
          ) : null}
          {event.evidence ? (
            <Fold label="证据">
              <Well>{String(event.evidence)}</Well>
            </Fold>
          ) : null}
        </Slab>
      </RowShell>
    )
  }

  if (kind === 'subtask_started' && node) {
    const title = node.title || SUBTASK_LABEL[node.kind] || node.kind || '子任务'
    return (
      <RowShell seq={event.seq} clock={clock}>
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
          <span
            aria-hidden="true"
            className={cn(
              'size-1.5 shrink-0 self-center rounded-full',
              node.status === 'running' && 'animate-[pulse-dot_1.6s_ease-in-out_infinite] bg-accent',
              node.status === 'completed' && 'bg-ok',
              node.status === 'failed' && 'bg-danger'
            )}
          />
          <p className="text-[13.5px] leading-6 font-medium text-fg">{title}</p>
          {node.target ? (
            <code className="font-mono text-[11px] break-all text-fg-3">{node.target}</code>
          ) : null}
          <span className="flex-1" />
          {node.findings ? (
            <span className="font-mono text-[11px] text-fg-2 tabular-nums">
              {node.findings} 个发现
            </span>
          ) : null}
          <span
            className={cn(
              'text-[11.5px]',
              node.status === 'running' && 'text-accent',
              node.status === 'failed' && 'text-danger',
              node.status === 'completed' && 'text-fg-3'
            )}
          >
            {SUBTASK_STATE[node.status]}
          </span>
        </div>
        {node.updates.length ? (
          <p className="mt-1 font-mono text-[11px] leading-6 break-all text-fg-4">
            {node.updates.map((update, index) => (
              <span key={index}>
                {index ? <span className="mx-1.5 text-fg-4/60">›</span> : null}
                <span className={index === node.updates.length - 1 ? 'text-fg-2' : undefined}>
                  {update.phase || '…'}
                </span>
              </span>
            ))}
          </p>
        ) : null}
        {node.error ? (
          <p className="mt-1 text-[12px] break-words text-danger">{node.error}</p>
        ) : null}
      </RowShell>
    )
  }

  if (kind === 'approval_required') {
    const gateKey = String(event.gate ?? '')
    const gate = GATE_LABEL[gateKey] ?? (gateKey || '需要人工确认')
    return (
      <RowShell seq={event.seq} clock={clock}>
        <Slab rule="border-l-warn">
          <div className="flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-1">
              <p className="text-[13.5px] leading-6 font-medium text-fg">
                需要人工确认:{gate}
              </p>
              <p className="mt-1 max-w-[68ch] text-[13px] leading-relaxed text-fg-2">
                {event.message || '该动作需确认后才会继续。'}
              </p>
            </div>
            {pending ? (
              <Button variant="danger" size="sm" onClick={onStop}>
                停止本轮
              </Button>
            ) : (
              <span className="font-mono text-[11px] text-fg-4">已放行</span>
            )}
          </div>
        </Slab>
      </RowShell>
    )
  }

  if (kind === 'mode_changed') {
    const title = modes.find((item) => item.name === event.mode)?.title ?? event.mode
    return (
      <RowShell seq={event.seq} clock={clock}>
        <p className="font-mono text-[11.5px] text-fg-3">
          已切到「{title}」
        </p>
      </RowShell>
    )
  }

  if (kind === 'error') {
    return (
      <RowShell seq={event.seq} clock={clock}>
        <p className="max-w-[68ch] text-[13px] break-words text-danger">
          {String(event.message ?? event.detail ?? '出错了')}
        </p>
      </RowShell>
    )
  }

  // 其余类型(assistant_delta / approval_resolved / subtask_progress /
  // subtask_finished)不单独成行:信息已经折进上面的行里。
  return null
}
