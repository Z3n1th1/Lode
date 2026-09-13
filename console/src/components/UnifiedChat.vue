<script setup lang="ts">
// 统一对话主视图 —— 唯一的入口。
//
// 一个回合的流程:乐观回显 → POST /chat/sessions/{id}/messages(202,持久化任务)
// → 事件从 SSE 流回来 → 按 seq 折进对话流。模式决定这一轮注入哪个技能包、
// 以及意图路由会不会把这一轮升级成一个子任务(子任务进度同样流进这条对话)。
import { computed, onMounted, ref } from 'vue'
import { NButton, NInput, NSpin, NTooltip } from 'naive-ui'
import { ArrowUp, Plus, Square } from '@lucide/vue'

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

// 空状态引导:点一下就把话填进去(顺手把模式切到位),省得对着空框发呆
const STARTERS: { label: string; text: string; mode: string }[] = [
  { label: '只读侦察一个站', text: '在授权范围内对 https://example.com 做只读侦察,先摸清资产面和端点', mode: 'src_blackbox' },
  { label: '换个 id 试试越权', text: '测一下 https://example.com 的 IDOR:先抓一个带 id 的接口做基线,再换 id 比对响应差异', mode: 'src_blackbox' },
  { label: '审源码找注入', text: '审计这个仓库:从外部输入追到危险 sink,给出可达的注入链', mode: 'code_audit' },
  { label: '解一道题', text: '这道 CTF 题先做文件指纹,再按题型决定方向', mode: 'ctf' }
]

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
const modeTitle = computed(
  () => chatModes.value.find((m) => m.name === chatMode.value)?.title ?? chatMode.value
)

function rememberSession(id: string): void {
  try { localStorage.setItem(STORAGE_KEY, id) } catch { /* 隐私模式下写不了,不影响功能 */ }
}

function recallSession(): string {
  try { return localStorage.getItem(STORAGE_KEY) || '' } catch { return '' }
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

function useStarter(starter: (typeof STARTERS)[number]): void {
  draft.value = starter.text
  chatMode.value = starter.mode
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
      <span class="mode-chip">{{ modeTitle }}</span>
      <span class="chat-session" :title="sessionId">{{ sessionId || '未建立会话' }}</span>
      <span class="chat-spacer" />
      <span class="conn" :class="{ 'conn--warn': reconnecting }">
        <span class="conn-dot" :class="{ 'is-live': connected, 'is-warn': reconnecting }" />
        {{ reconnecting ? '重连中' : connected ? '已连接' : '等待连接' }}
      </span>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button v-if="running" quaternary circle type="error" aria-label="停止本轮" @click="stop">
            <Square :size="15" />
          </n-button>
        </template>
        停止本轮
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle :disabled="running" aria-label="新会话" @click="startNewSession">
            <Plus :size="17" />
          </n-button>
        </template>
        新会话
      </n-tooltip>
    </header>

    <p v-if="notice" class="chat-notice">{{ notice }}</p>
    <p v-if="streamError" class="chat-notice chat-notice--soft">{{ streamError }}</p>

    <div class="chat-stage">
      <div v-if="loading" class="chat-loading"><n-spin size="small" /></div>

      <div v-else-if="!events.length" class="hero">
        <div class="hero-mark">
          <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
            <path d="M12 2 3 6v6c0 5 3.8 8.6 9 10 5.2-1.4 9-5 9-10V6l-9-4Z"
                  fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" />
            <path d="m8.6 12.2 2.3 2.3 4.5-4.6" fill="none" stroke="currentColor"
                  stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </div>
        <h1>说一句,就开跑</h1>
        <p class="hero-sub">
          选好模式后直接说目标。<strong>SRC 黑盒</strong>模式下,带 URL 和动作词的一句话会被自动
          升级成一个只读子任务,进度实时长在下面这段对话里。
        </p>
        <div class="hero-cards">
          <button
            v-for="starter in STARTERS"
            :key="starter.label"
            class="hero-card"
            type="button"
            @click="useStarter(starter)"
          >
            <span class="hero-card-label">{{ starter.label }}</span>
            <span class="hero-card-text">{{ starter.text }}</span>
          </button>
        </div>
      </div>

      <ChatStream v-else :events="events" :modes="chatModes" :busy="running" :echo="echo" @stop="stop" />
    </div>

    <footer class="composer">
      <div class="composer-box" :class="{ 'is-blocked': blocked }">
        <n-input
          v-model:value="draft"
          type="textarea"
          :bordered="false"
          :autosize="{ minRows: 1, maxRows: 8 }"
          :disabled="blocked"
          :placeholder="blocked ? '有待确认的动作,先处理它' : '描述目标,或直接说要做什么…'"
          @keydown="onKeydown"
        />
        <div class="composer-foot">
          <span class="composer-hint">
            {{ blocked ? '已阻塞:等待人工确认' : 'Enter 发送 · Shift+Enter 换行' }}
          </span>
          <n-button
            circle
            type="primary"
            :disabled="!draft.trim() || running || blocked"
            :loading="running"
            aria-label="发送"
            @click="send"
          >
            <ArrowUp :size="16" />
          </n-button>
        </div>
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
  background: var(--pa-bg-glow), var(--pa-bg);
}

.chat-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 18px;
  border-bottom: 1px solid var(--pa-border);
  background: color-mix(in srgb, var(--pa-surface) 72%, transparent);
  backdrop-filter: saturate(140%) blur(8px);
}

.mode-chip {
  padding: 3px 10px;
  border-radius: var(--pa-radius-pill);
  background: var(--pa-primary-soft);
  color: var(--pa-primary-hover);
  font-size: var(--pa-fs-sm);
  font-weight: 600;
}

.chat-session {
  max-width: 34ch;
  overflow: hidden;
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-3);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chat-spacer { flex: 1; }

.conn {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: var(--pa-fs-xs);
  color: var(--pa-text-3);
}

.conn--warn { color: var(--pa-warning); }

.conn-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--pa-text-3);
}

.conn-dot.is-live { background: var(--pa-success); box-shadow: 0 0 0 3px color-mix(in srgb, var(--pa-success) 16%, transparent); }
.conn-dot.is-warn { background: var(--pa-warning); animation: pulse 1.4s ease-in-out infinite; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: .35; }
}

.chat-notice {
  margin: 0;
  padding: 9px 18px 0;
  font-size: var(--pa-fs-sm);
  color: var(--pa-danger);
}

.chat-notice--soft { color: var(--pa-text-3); }

.chat-stage { flex: 1; min-height: 0; display: flex; }
.chat-stage > * { flex: 1; min-width: 0; }

.chat-loading { display: grid; place-items: center; }

/* ---- 空状态 ---- */
.hero {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 32px 24px 12px;
  overflow-y: auto;
}

.hero-mark {
  display: grid;
  place-items: center;
  width: 48px;
  height: 48px;
  margin-bottom: 14px;
  border-radius: 15px;
  color: var(--pa-on-brand);
  background: var(--pa-brand-grad);
  box-shadow: 0 10px 26px rgb(20 184 166 / 24%);
}

.hero h1 {
  margin: 0;
  font-size: 22px;
  font-weight: 650;
  letter-spacing: -.2px;
}

.hero-sub {
  max-width: 54ch;
  margin: 8px 0 26px;
  color: var(--pa-text-2);
  font-size: var(--pa-fs-md);
  line-height: 1.7;
  text-align: center;
}

.hero-sub strong { color: var(--pa-primary-hover); font-weight: 600; }

.hero-cards {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  width: min(100%, 700px);
}

.hero-card {
  display: grid;
  gap: 4px;
  padding: 13px 15px;
  text-align: left;
  cursor: pointer;
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius);
  background: color-mix(in srgb, var(--pa-surface) 76%, transparent);
  transition: border-color .15s, background .15s, transform .15s;
}

.hero-card:hover {
  border-color: var(--pa-primary);
  background: var(--pa-surface-2);
  transform: translateY(-1px);
}

.hero-card-label {
  color: var(--pa-text);
  font-size: var(--pa-fs-base);
  font-weight: 600;
}

.hero-card-text {
  overflow: hidden;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
  line-height: 1.5;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ---- 输入框 ---- */
.composer {
  flex: 0 0 auto;
  padding: 8px 18px 18px;
}

.composer-box {
  width: min(100%, 780px);
  margin: 0 auto;
  padding: 8px 8px 6px 14px;
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius-lg);
  background: var(--pa-surface);
  box-shadow: var(--pa-shadow-soft);
  transition: border-color .15s, box-shadow .15s;
}

.composer-box:focus-within {
  border-color: var(--pa-primary);
  box-shadow: 0 0 0 4px var(--pa-primary-ring);
}

.composer-box.is-blocked { border-color: var(--pa-warning); }

.composer-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding-top: 2px;
}

.composer-hint {
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
}

@media (max-width: 720px) {
  .hero-cards { grid-template-columns: 1fr; }
  .chat-session { display: none; }
  .composer { padding: 8px 12px 12px; }
}
</style>
