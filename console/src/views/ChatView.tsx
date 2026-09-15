import { Plus } from 'lucide-react'

import { pendingApprovals } from '../chatEvents'
import { Button } from '../components/ui/button'
import { Tooltip } from '../components/ui/tooltip'
import { cn } from '../lib/utils'
import { useChat } from '../store/chat'
import Composer from './chat/Composer'
import Ledger from './chat/Ledger'

/** 空状态起点:点一下填入正文,并切换到对应模式。 */
const STARTERS = [
  {
    label: '资产侦察',
    text: '在授权范围内对 https://example.com 做只读侦察,先摸清端点,再挑高价值面',
    mode: 'src_blackbox'
  },
  {
    label: '越权测试',
    text: '先抓一个带 id 的接口做基线,再替换 id 比对响应差异',
    mode: 'src_blackbox'
  },
  {
    label: '注入链追踪',
    text: '从外部输入一路追到危险 sink,给出可达的注入链与证据',
    mode: 'code_audit'
  },
  { label: 'CTF 解题', text: '先做文件指纹,再按题型决定切入点', mode: 'ctf' }
]

export default function ChatView() {
  const sessionId = useChat((state) => state.sessionId)
  const freshSession = useChat((state) => state.freshSession)
  const events = useChat((state) => state.events)
  const modes = useChat((state) => state.modes)
  const draft = useChat((state) => state.draft)
  const echo = useChat((state) => state.echo)
  const turnJobId = useChat((state) => state.turnJobId)
  const loading = useChat((state) => state.loading)
  const notice = useChat((state) => state.notice)
  const streamError = useChat((state) => state.streamError)
  const connected = useChat((state) => state.connected)
  const reconnecting = useChat((state) => state.reconnecting)

  const running = Boolean(turnJobId)
  const blocked = pendingApprovals(events).length > 0

  return (
    <section className="flex h-full min-h-0 flex-col bg-bg">
      <header className="flex h-11 shrink-0 items-center gap-3 border-b border-line px-4">
        <span className="text-[13px] font-semibold tracking-wide text-fg">对话</span>
        {/* 会话 id 只在"刚新建的这个会话"上出现:恢复的旧会话、从项目预览进来的
            运行流都不带它。
            font-bold 就是腾讯体的天花板:实测 600/700/800/900 全部落到同一个
            w7.woff2,再抬字重不会有任何变化,而 body 上 font-synthesis-weight:none
            禁止合成假粗体 —— 所以"更粗"只能靠字号和颜色,不是靠字重数字。 */}
        {freshSession ? (
          <span className="text-[16px] font-bold tracking-wide text-fg" title={sessionId}>
            {sessionId}
          </span>
        ) : null}
        <span className="flex-1" />
        <span className="flex items-center gap-1.5 text-[11.5px] text-fg-3">
          <span
            aria-hidden="true"
            className={cn(
              'size-1.5 rounded-full',
              reconnecting && 'animate-[pulse-dot_1.5s_ease-in-out_infinite] bg-warn',
              !reconnecting && connected && 'bg-ok',
              !reconnecting && !connected && 'bg-fg-4'
            )}
          />
          {reconnecting ? '重连中' : connected ? '已连接' : '未连接'}
        </span>
        <Tooltip label="新会话">
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="新会话"
            disabled={running}
            onClick={() => void useChat.getState().newSession()}
          >
            <Plus size={15} />
          </Button>
        </Tooltip>
      </header>

      {notice ? (
        <p
          role="alert"
          className="shrink-0 border-b border-line bg-danger/8 px-4 py-1.5 text-[12.5px] text-danger"
        >
          {notice}
        </p>
      ) : null}
      {streamError ? (
        <p className="shrink-0 border-b border-line bg-warn/8 px-4 py-1.5 text-[12.5px] text-warn">
          {streamError}
        </p>
      ) : null}

      {loading ? null : events.length === 0 ? (
        <Opening />
      ) : (
        <Ledger
          events={events}
          modes={modes}
          busy={running}
          echo={echo}
          onStop={() => void useChat.getState().stop()}
        />
      )}

      <Composer
        draft={draft}
        onDraft={(value) => useChat.getState().setDraft(value)}
        onSend={() => void useChat.getState().send()}
        onStop={() => void useChat.getState().stop()}
        running={running}
        blocked={blocked}
      />
    </section>
  )
}

function Opening() {
  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
      <div className="ledger-indent m-auto w-full py-10 pr-4">
        <p className="font-mono text-[10.5px] tracking-wide text-fg-4">起点</p>
        <p className="mt-2 max-w-[58ch] text-[13.5px] leading-relaxed text-fg-2">
          一句话给出目标和动作,即可升级为一个子任务。执行过程与发现记录在同一条时间线上。
        </p>

        <ul className="mt-7 max-w-[46rem] border-t border-line">
          {STARTERS.map((starter) => (
            <li key={starter.label} className="border-b border-line">
              <button
                type="button"
                onClick={() => {
                  useChat.getState().setDraft(starter.text)
                  useChat.getState().setMode(starter.mode)
                }}
                className="grid w-full grid-cols-[7.5rem_minmax(0,1fr)] items-baseline gap-4 py-3 text-left transition-colors hover:bg-hover"
              >
                <span className="text-[13.5px] font-medium text-fg">{starter.label}</span>
                <span className="truncate text-[13px] text-fg-3">{starter.text}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
