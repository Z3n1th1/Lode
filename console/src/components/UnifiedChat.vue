<script setup lang="ts">
// 统一对话主视图 —— 唯一的入口。
//
// 一个回合的流程:乐观回显 → POST /chat/sessions/{id}/messages(202,持久化任务)
// → 事件从 SSE 流回来 → 按 seq 折进对话流。模式决定这一轮注入哪个技能包、
// 以及意图路由会不会把这一轮升级成一个子任务(子任务进度同样流进这条对话)。
import { computed, onMounted, ref } from 'vue'
import { NButton, NInput, NSpin } from 'naive-ui'

import {
  ApiError,
  loadChatEvents,
  newChatSession,
  sendChatTurn,
  stopChatTurn,
  type ChatEvent
} from '../api'
import { lastSeq, pendingApprovals } from '../chatEvents'
import { useEventStream } from '../composables/useEventStream'
import { chatMode, chatModes, loadChatModes } from '../store'
import ChatStream from './chat/ChatStream.vue'

const STORAGE_KEY = 'lode.chat.session'

const sessionId = ref('')
const events = ref<ChatEvent[]>([])
const draft = ref('')
const echo = ref('')
const turnJobId = ref('')
const loading = ref(true)
const notice = ref('')

const {
  connected,
  reconnecting,
  error: streamError,
  start: startStream,
  stop: stopStream
} = useEventStream(onEvent)

const running = computed(() => Boolean(turnJobId.value))
const blocked = computed(() => pendingApprovals(events.value).length > 0)

function rememberSession(id: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, id)
  } catch {
    /* 隐私模式下写不了,不影响功能 */
  }
}

function recallSession(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) || ''
  } catch {
    return ''
  }
}

function onEvent(event: ChatEvent): void {
  if (!events.value.some((existing) => existing.seq === event.seq)) {
    events.value.push(event)
    events.value.sort((a, b) => a.seq - b.seq)
  }
  if (event.kind === 'user_message' && echo.value && event.text === echo.value) echo.value = ''
  if (event.kind === 'subtask_finished' && String(event.job_id ?? '') === turnJobId.value) {
    turnJobId.value = ''
    echo.value = ''
  }
}

async function attach(id: string): Promise<void> {
  stopStream()
  sessionId.value = id
  events.value = []
  echo.value = ''
  try {
    const page = await loadChatEvents(id, 0, 500)
    events.value = [...page.events].sort((a, b) => a.seq - b.seq)
  } catch (err) {
    notice.value = `读取历史失败:${(err as Error).message}`
  }
  startStream(id, lastSeq(events.value))
  rememberSession(id)
}

async function startNewSession(): Promise<void> {
  try {
    const session = await newChatSession(chatMode.value)
    await attach(session.session_id)
    notice.value = ''
  } catch (err) {
    notice.value = `新建会话失败:${(err as Error).message}`
  }
}

async function send(): Promise<void> {
  const text = draft.value.trim()
  if (!text || !sessionId.value || running.value || blocked.value) return
  draft.value = ''
  echo.value = text
  try {
    const turn = await sendChatTurn(sessionId.value, text, chatMode.value)
    turnJobId.value = turn.job_id
    notice.value = ''
  } catch (err) {
    echo.value = ''
    const failure = err as ApiError
    notice.value = failure.status === 409
      ? '上一轮还在跑,先等它结束或点停止。'
      : `发送失败:${failure.message}`
  }
}

async function stop(): Promise<void> {
  if (!sessionId.value) return
  try {
    await stopChatTurn(sessionId.value)
    notice.value = ''
  } catch (err) {
    notice.value = `停止失败:${(err as Error).message}`
  }
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Enter' || event.shiftKey) return
  event.preventDefault()
  void send()
}

onMounted(async () => {
  await loadChatModes()
  const remembered = recallSession()
  if (remembered) await attach(remembered)
  else await startNewSession()
  loading.value = false
})
</script>

<template>
  <section class="chat">
    <header class="chat-bar">
      <span class="chat-session">{{ sessionId || '未建立会话' }}</span>
      <span class="chat-spacer" />
      <span v-if="reconnecting" class="chat-state chat-state--warn">重连中…</span>
      <span v-else-if="connected" class="chat-state">已连接</span>
      <n-button v-if="running" size="small" quaternary type="error" @click="stop">停止本轮</n-button>
      <n-button size="small" quaternary :disabled="running" @click="startNewSession">新会话</n-button>
    </header>

    <p v-if="notice" class="chat-notice">{{ notice }}</p>
    <p v-if="streamError" class="chat-notice chat-notice--soft">{{ streamError }}</p>

    <n-spin v-if="loading" class="chat-loading" size="small" />
    <ChatStream v-else :events="events" :modes="chatModes" :busy="running" :echo="echo" @stop="stop" />

    <footer class="chat-composer">
      <n-input
        v-model:value="draft"
        type="textarea"
        :autosize="{ minRows: 2, maxRows: 6 }"
        :disabled="blocked"
        :placeholder="blocked ? '有待确认的动作,先处理它' : 'Enter 发送,Shift+Enter 换行'"
        @keydown="onKeydown"
      />
      <div class="chat-actions">
        <n-button type="primary" :disabled="!draft.trim() || running || blocked" @click="send">
          发送
        </n-button>
      </div>
    </footer>
  </section>
</template>

<style scoped>
.chat {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  background: var(--pa-bg);
}

.chat-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px var(--pa-gap);
  border-bottom: 1px solid var(--pa-border);
  background: var(--pa-surface);
}

.chat-session {
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-3);
}

.chat-spacer {
  flex: 1;
}

.chat-state {
  font-size: var(--pa-fs-xs);
  color: var(--pa-success);
}

.chat-state--warn {
  color: var(--pa-text-3);
}

.chat-notice {
  margin: 0;
  padding: 8px var(--pa-gap);
  font-size: var(--pa-fs-xs);
  color: var(--pa-danger);
}

.chat-notice--soft {
  color: var(--pa-text-3);
}

.chat-loading {
  display: flex;
  justify-content: center;
  padding: var(--pa-gap);
}

.chat-composer {
  border-top: 1px solid var(--pa-border);
  padding: 10px var(--pa-gap) var(--pa-gap);
  background: var(--pa-surface);
}

.chat-actions {
  margin-top: 8px;
  display: flex;
  justify-content: flex-end;
}
</style>
