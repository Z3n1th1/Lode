// 对话状态 + SSE 引擎。
//
// 一条回合的流程:乐观回显 → POST messages(202,落成持久化任务)→ 事件从
// append-only 日志流回来 → 按 seq 折进这条时间线。重连只带 since,不会丢也不会重。
//
// 引擎是模块级函数而不是 hook:组件重挂载不应该把连接打断。
import { create } from 'zustand'

import {
  ApiError,
  loadChatEvents,
  loadChatModes as apiLoadChatModes,
  newChatSession,
  sendChatTurn,
  stopChatTurn,
  type ChatEvent,
  type ChatMode
} from '../api'
import { lastSeq } from '../chatEvents'

const SESSION_KEY = 'lode.chat.session'
const RECONNECT_MS = 3000
const STREAM_PATH = '/api/v1/chat/sessions'

function rememberSession(id: string): void {
  try {
    localStorage.setItem(SESSION_KEY, id)
  } catch {
    /* 隐私模式写不了,不影响功能 */
  }
}

function recallSession(): string {
  try {
    return localStorage.getItem(SESSION_KEY) || ''
  } catch {
    return ''
  }
}

// ------------------------------------------------------------------ SSE 引擎
let controller: AbortController | null = null
let retryTimer: ReturnType<typeof setTimeout> | null = null
let streamSessionId = ''
let stopped = true

type Sink = {
  push: (event: ChatEvent) => void
  connected: (value: boolean) => void
  reconnecting: (value: boolean) => void
  error: (message: string) => void
  cursor: () => number
}

function clearRetry(): void {
  if (retryTimer !== null) {
    clearTimeout(retryTimer)
    retryTimer = null
  }
}

function scheduleReconnect(sink: Sink): void {
  if (stopped) return
  sink.reconnecting(true)
  clearRetry()
  retryTimer = setTimeout(() => {
    retryTimer = null
    if (!stopped) void pump(sink)
  }, RECONNECT_MS)
}

/** 一帧 SSE:拼 `data:` 行(注释帧 `:` 与空行跳过)。 */
function consumeFrame(frame: string, sink: Sink): void {
  const data: string[] = []
  for (const line of frame.split('\n')) {
    if (!line || line.startsWith(':')) continue
    if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
  }
  if (!data.length) return
  try {
    sink.push(JSON.parse(data.join('\n')) as ChatEvent)
  } catch {
    /* 半截帧:丢掉,下一轮 since 会补回来 */
  }
}

async function pump(sink: Sink): Promise<void> {
  if (stopped || !streamSessionId) return
  controller = new AbortController()
  sink.error('')
  try {
    const response = await fetch(
      `${STREAM_PATH}/${encodeURIComponent(streamSessionId)}/stream?since=${sink.cursor()}`,
      { credentials: 'same-origin', cache: 'no-store', signal: controller.signal }
    )
    if (!response.ok) throw new Error(`连接失败 (http ${response.status})`)
    if (!response.body) throw new Error('当前环境不支持流式响应')

    sink.connected(true)
    sink.reconnecting(false)

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let sep = buffer.indexOf('\n\n')
      while (sep >= 0) {
        consumeFrame(buffer.slice(0, sep), sink)
        buffer = buffer.slice(sep + 2)
        sep = buffer.indexOf('\n\n')
      }
    }
  } catch (err) {
    const failure = err as Error
    if (!stopped && failure?.name !== 'AbortError') sink.error(failure?.message || '事件流中断')
  } finally {
    sink.connected(false)
    scheduleReconnect(sink) // 服务端一小时空闲会主动收尾,断了就续
  }
}

/** 游标由 sink.cursor() 提供,调用方必须先把它对齐到已回放的位置。 */
function startStream(id: string, sink: Sink): void {
  stopStream()
  streamSessionId = id
  stopped = false
  clearRetry()
  void pump(sink)
}

export function stopStream(): void {
  stopped = true
  clearRetry()
  controller?.abort()
  controller = null
}

// ------------------------------------------------------------------- store
interface ChatState {
  sessionId: string
  /** 这个会话是本次在对话里新建出来的 —— 只有它才在顶栏亮出会话 id。 */
  freshSession: boolean
  events: ChatEvent[]
  mode: string
  modes: ChatMode[]
  draft: string
  /** 已发出但还没回显到日志里的那句话(乐观回显)。 */
  echo: string
  turnJobId: string
  loading: boolean
  notice: string
  connected: boolean
  reconnecting: boolean
  streamError: string

  bootstrap: () => Promise<void>
  /** fresh=true 只由新建会话传入;恢复旧会话、被别处 attach 都走默认的 false。 */
  attach: (id: string, fresh?: boolean) => Promise<void>
  newSession: () => Promise<void>
  send: () => Promise<void>
  stop: () => Promise<void>
  setDraft: (value: string) => void
  setMode: (mode: string) => void
}

export const useChat = create<ChatState>()((set, get) => {
  let cursor = 0

  const sink: Sink = {
    push(event) {
      const seq = Number(event?.seq) || 0
      if (seq > cursor) cursor = seq
      set((state) => {
        if (state.events.some((existing) => existing.seq === event.seq)) return state
        const events = [...state.events, event].sort((a, b) => a.seq - b.seq)
        const patch: Partial<ChatState> = { events }
        if (event.kind === 'user_message' && state.echo && event.text === state.echo) patch.echo = ''
        if (
          event.kind === 'subtask_finished' &&
          String(event.job_id ?? '') === state.turnJobId
        ) {
          patch.turnJobId = ''
          patch.echo = ''
        }
        return patch
      })
    },
    connected(value) {
      set({ connected: value })
    },
    reconnecting(value) {
      set({ reconnecting: value })
    },
    error(message) {
      set({ streamError: message })
    },
    cursor() {
      return cursor
    }
  }

  return {
    sessionId: '',
    freshSession: false,
    events: [],
    mode: 'chat',
    modes: [],
    draft: '',
    echo: '',
    turnJobId: '',
    loading: true,
    notice: '',
    connected: false,
    reconnecting: false,
    streamError: '',

    setDraft(draft) {
      set({ draft })
    },

    setMode(mode) {
      set({ mode })
    },

    async attach(id, fresh = false) {
      stopStream()
      cursor = 0
      set({ sessionId: id, freshSession: fresh, events: [], echo: '', notice: '', streamError: '' })
      try {
        const page = await loadChatEvents(id, 0, 500)
        const events = [...page.events].sort((a, b) => a.seq - b.seq)
        cursor = lastSeq(events)
        set({ events })
      } catch (err) {
        set({ notice: `读取历史失败:${(err as Error).message}` })
      }
      startStream(id, sink)
      rememberSession(id)
    },

    async newSession() {
      try {
        const session = await newChatSession(get().mode)
        await get().attach(session.session_id, true)
      } catch (err) {
        set({ notice: `新建会话失败:${(err as Error).message}` })
      }
    },

    async bootstrap() {
      try {
        const view = await apiLoadChatModes()
        const mode = view.modes.some((m) => m.name === get().mode) ? get().mode : view.default
        set({ modes: view.modes, mode })
      } catch {
        /* 模式列表读不到不阻塞对话,沿用默认 */
      }
      const remembered = recallSession()
      if (remembered) await get().attach(remembered)
      else await get().newSession()
      set({ loading: false })
    },

    async send() {
      const text = get().draft.trim()
      const { sessionId, turnJobId } = get()
      if (!text || !sessionId || turnJobId) return
      set({ draft: '', echo: text })
      try {
        const turn = await sendChatTurn(sessionId, text, get().mode)
        set({ turnJobId: turn.job_id, notice: '' })
      } catch (err) {
        const failure = err as ApiError
        set({
          echo: '',
          notice:
            failure.status === 409 ? '上一轮还在跑,先等它结束' : `发送失败:${failure.message}`
        })
      }
    },

    async stop() {
      const { sessionId } = get()
      if (!sessionId) return
      try {
        await stopChatTurn(sessionId)
        set({ notice: '' })
      } catch (err) {
        set({ notice: `停止失败:${(err as Error).message}` })
      }
    }
  }
})

// 页面卸载时收尾,免得开发期热更新留下悬挂连接
if (import.meta.hot) {
  import.meta.hot.dispose(() => stopStream())
}
