<script setup lang="ts">
// 统一对话主视图 —— 唯一的入口。
//
// 一个回合的流程:乐观回显 → POST /chat/sessions/{id}/messages(202,持久化任务)
// → 事件从 SSE 流回来 → 按 seq 折进下面这条日志。模式决定这一轮注入哪个技能包、
// 以及意图路由会不会把这一轮升级成一个子任务(子任务进度同样流进这条日志)。
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

// 空状态引导:点一下就把话填进去,顺手把模式切到位
const STARTERS: { label: string; text: string; mode: string }[] = [
  {
    label: '摸一个站的资产面',
    text: '在授权范围内对 https://example.com 做只读侦察,先摸清端点再挑高价值面',
    mode: 'src_blackbox'
  },
  {
    label: '换一个 id 试越权',
    text: '测一下 https://example.com 的越权:先抓一个带 id 的接口做基线,再换 id 比对响应差异',
    mode: 'src_blackbox'
  },
  {
    label: '审源码追注入链',
    text: '审计这个仓库:从外部输入一路追到危险 sink,给出可达的注入链和证据',
    mode: 'code_audit'
  },
  {
    label: '解一道题',
    text: '这道 CTF 题先做文件指纹,再按题型决定从哪下手',
    mode: 'ctf'
  }
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

function rememberSession(id: string): void {
  try { localStorage.setItem(STORAGE_KEY, id) } catch { /* 隐私模式写不了,不影响功能 */ }
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
      ? '上一轮还在跑,先等它结束或点停止'
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
    <header class="bar">
      <span class="session" :title="sessionId">{{ sessionId || '未建立会话' }}</span>
      <span class="grow" />
      <span class="link-state">
        <span class="pip" :class="{ 'is-live': connected, 'is-warn': reconnecting }" />
        {{ reconnecting ? '重连中' : connected ? '已连接' : '等待连接' }}
      </span>
      <!-- v-if 必须在 tooltip 上:放在 #trigger 里会让插槽在条件为假时变空,
           naive-ui 会报 "slot[trigger] should have exactly one child" -->
      <n-tooltip v-if="running" trigger="hover">
        <template #trigger>
          <n-button quaternary circle type="error" aria-label="停止本轮" @click="stop">
            <Square :size="14" />
          </n-button>
        </template>
        停止本轮
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle :disabled="running" aria-label="新会话" @click="startNewSession">
            <Plus :size="16" />
          </n-button>
        </template>
        新会话
      </n-tooltip>
    </header>

    <p v-if="notice" class="notice">{{ notice }}</p>
    <p v-if="streamError" class="notice notice--quiet">{{ streamError }}</p>

    <div class="stage">
      <div v-if="loading" class="loading"><n-spin size="small" /></div>

      <div v-else-if="!events.length" class="opening">
        <h1 class="opening-title">先说清目标,再动手</h1>
        <p class="opening-lede">
          这里是只读的。<strong>黑盒漏洞挖掘</strong>模式下,一句带目标和动作词的话会被自动升级成一个
          子任务,过程和发现都落在下面这条日志里。
        </p>
        <ul class="starters">
          <li v-for="starter in STARTERS" :key="starter.label">
            <button class="starter" type="button" @click="useStarter(starter)">
              <span class="starter-label">{{ starter.label }}</span>
              <span class="starter-text">{{ starter.text }}</span>
            </button>
          </li>
        </ul>
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
          :placeholder="blocked ? '有待确认的动作,先处理它' : '说一句话:目标,或者要做什么'"
          @keydown="onKeydown"
        />
        <div class="composer-foot">
          <span class="hint">
            <template v-if="blocked">已阻塞,等待人工确认</template>
            <template v-else>
              <kbd>Enter</kbd>&nbsp;发送<span class="hint-gap" /><kbd>Shift+Enter</kbd>&nbsp;换行
            </template>
          </span>
          <n-button
            circle
            type="primary"
            :disabled="!draft.trim() || running || blocked"
            :loading="running"
            aria-label="发送"
            @click="send"
          >
            <ArrowUp :size="15" />
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
  background: var(--pa-bg);
}

.bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 0 0 auto;
  height: 44px;
  padding: 0 18px;
  border-bottom: 1px solid var(--pa-border);
}

.session {
  max-width: 30ch;
  overflow: hidden;
  color: var(--pa-text-3);
  font-family: var(--pa-mono);
  font-size: var(--pa-fs-xs);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.grow { flex: 1; }

.link-state {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-right: 4px;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-sm);
}

.pip { width: 6px; height: 6px; border-radius: 50%; background: var(--pa-text-3); }
.pip.is-live { background: var(--pa-success); }
.pip.is-warn { background: var(--pa-warning); animation: breathe 1.5s ease-in-out infinite; }

@keyframes breathe {
  0%, 100% { opacity: 1; }
  50% { opacity: .3; }
}

.notice {
  margin: 0;
  padding: 8px 18px 0;
  color: var(--pa-danger);
  font-size: var(--pa-fs-base);
}

.notice--quiet { color: var(--pa-text-3); }

.stage { flex: 1; min-height: 0; display: flex; }
.stage > * { flex: 1; min-width: 0; }

.loading { display: grid; place-items: center; }

/* ---- 开场 ---- */
.opening {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 40px 22px 20px;
  max-width: 760px;
  margin: 0 auto;
  overflow-y: auto;
}

.opening-title {
  margin: 0;
  color: var(--pa-text);
  font-family: var(--pa-display);
  font-size: 30px;
  font-weight: 640;
  letter-spacing: -.02em;
}

.opening-lede {
  max-width: 52ch;
  margin: 12px 0 30px;
  color: var(--pa-text-2);
  font-size: var(--pa-fs-lg);
  line-height: 1.7;
}

.opening-lede strong { color: var(--pa-text); font-weight: 620; }

/* 四个入口做成左对齐的行,不是等大的卡片阵列 */
.starters {
  margin: 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--pa-border-soft);
}

.starters li { border-bottom: 1px solid var(--pa-border-soft); }

.starter {
  display: grid;
  grid-template-columns: 16ch minmax(0, 1fr);
  align-items: baseline;
  gap: 14px;
  width: 100%;
  padding: 13px 4px;
  border: 0;
  background: transparent;
  text-align: left;
  cursor: pointer;
  transition: background .12s;
}

.starter:hover { background: var(--pa-hover); }

.starter-label {
  color: var(--pa-text);
  font-size: var(--pa-fs-md);
  font-weight: 600;
}

.starter-text {
  overflow: hidden;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-base);
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ---- 输入 ---- */
.composer { flex: 0 0 auto; padding: 10px 22px 18px; }

.composer-box {
  max-width: 760px;
  margin: 0 auto;
  padding: 8px 8px 6px 14px;
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius);
  background: var(--pa-surface);
  transition: border-color .12s, box-shadow .12s;
}

.composer-box:focus-within {
  border-color: var(--pa-primary);
  box-shadow: 0 0 0 3px var(--pa-primary-ring);
}

.composer-box.is-blocked { border-color: var(--pa-warning); }

.composer-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding-top: 2px;
}

.hint {
  display: flex;
  align-items: center;
  color: var(--pa-text-3);
  font-size: var(--pa-fs-xs);
}

.hint-gap { width: 12px; }

kbd {
  font-family: var(--pa-mono);
  font-size: 10.5px;
  color: var(--pa-text-2);
}

@media (max-width: 720px) {
  .opening { padding: 24px 14px 12px; }
  .opening-title { font-size: 24px; }
  .starter { grid-template-columns: 1fr; gap: 3px; }
  .starter-text { white-space: normal; }
  .composer { padding: 8px 12px 14px; }
  .session { display: none; }
  .hint { display: none; }
}
</style>
