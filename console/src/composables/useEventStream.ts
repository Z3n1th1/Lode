// SSE 事件流:原生 fetch + ReadableStream,带 `since` 游标与 3s 重连。
//
// 会话的事件日志是 append-only 的(每行一个 JSON,`seq` 单调),服务端按
// `seq > since` 回放,所以重连只要带上最后一帧的 `seq` 就不会丢事件、也不会重复。
// 服务端会在静默期发 `: keep-alive` 注释帧,这里直接忽略。
import { onBeforeUnmount, ref, type Ref } from 'vue'

import type { ChatEvent } from '../api'

const RECONNECT_MS = 3000
const STREAM_PATH = '/api/v1/chat/sessions'

export interface EventStreamHandle {
  connected: Ref<boolean>
  reconnecting: Ref<boolean>
  error: Ref<string>
  lastSeq: Ref<number>
  start: (sessionId: string, since?: number) => void
  stop: () => void
}

export function useEventStream(onEvent: (event: ChatEvent) => void): EventStreamHandle {
  const connected = ref(false)
  const reconnecting = ref(false)
  const error = ref('')
  const lastSeq = ref(0)

  let controller: AbortController | null = null
  let retryTimer: ReturnType<typeof setTimeout> | null = null
  let sessionId = ''
  let stopped = true

  function clearRetry(): void {
    if (retryTimer !== null) {
      clearTimeout(retryTimer)
      retryTimer = null
    }
  }

  function scheduleReconnect(): void {
    if (stopped) return
    reconnecting.value = true
    clearRetry()
    retryTimer = setTimeout(() => {
      retryTimer = null
      if (!stopped) void pump()
    }, RECONNECT_MS)
  }

  /** 一帧 SSE:取 `data:` 行拼起来(注释帧 `:` 与空行跳过)。 */
  function consumeFrame(frame: string): void {
    const data: string[] = []
    for (const line of frame.split('\n')) {
      if (!line || line.startsWith(':')) continue
      if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
    }
    if (!data.length) return
    try {
      const event = JSON.parse(data.join('\n')) as ChatEvent
      if (typeof event?.seq === 'number' && event.seq > lastSeq.value) lastSeq.value = event.seq
      onEvent(event)
    } catch {
      /* 半截帧:丢掉,下一轮 since 会把它补回来 */
    }
  }

  async function pump(): Promise<void> {
    if (stopped || !sessionId) return
    controller = new AbortController()
    error.value = ''
    try {
      const response = await fetch(
        `${STREAM_PATH}/${encodeURIComponent(sessionId)}/stream?since=${lastSeq.value}`,
        { credentials: 'same-origin', cache: 'no-store', signal: controller.signal }
      )
      if (!response.ok) throw new Error(`stream_failed_${response.status}`)
      if (!response.body) throw new Error('stream_unsupported')

      connected.value = true
      reconnecting.value = false

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        let sep = buffer.indexOf('\n\n')
        while (sep >= 0) {
          consumeFrame(buffer.slice(0, sep))
          buffer = buffer.slice(sep + 2)
          sep = buffer.indexOf('\n\n')
        }
      }
    } catch (err) {
      const failure = err as Error
      if (!stopped && failure?.name !== 'AbortError') error.value = failure?.message || 'stream_error'
    } finally {
      connected.value = false
      scheduleReconnect() // 服务端一小时空闲会主动收尾,断了就续
    }
  }

  function start(id: string, since = 0): void {
    sessionId = id
    lastSeq.value = since
    stopped = false
    clearRetry()
    void pump()
  }

  function stop(): void {
    stopped = true
    clearRetry()
    controller?.abort()
    controller = null
    connected.value = false
    reconnecting.value = false
  }

  onBeforeUnmount(stop)

  return { connected, reconnecting, error, lastSeq, start, stop }
}
