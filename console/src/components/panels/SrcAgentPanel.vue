<script setup lang="ts">
// SRC Agent 面板:LLM 驱动的漏洞挖掘对话台(主视图)。
// 左:会话列表(持久化,重启不丢)。右:对话流 + 工具调用可视化 + 进度统计。
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { NButton, NEmpty, NInput, NSpin, NTooltip, useMessage } from 'naive-ui'
import {
  Bot, Bug, CircleDot, Link2, Pencil, Pin, PinOff, Plus, RefreshCw, Search, Send, Terminal,
  Trash2, User, Zap
} from '@lucide/vue'
import {
  loadSrcSessionsView, loadSrcHistory, sendSrcChat, loadSrcProgress,
  renameSrcSession, pinSrcSession, deleteSrcSession, pruneSrcSessions,
  submitH1Intake, startSrcAgent,
  type SrcSession, type SrcMessage, type SrcProgress, type SrcIntakeResult
} from '../../api'

const message = useMessage()

interface ChatItem {
  role: 'user' | 'assistant' | 'event'
  content: string
  ts?: number
  tool?: string
}

const sessions = ref<SrcSession[]>([])
const activeSession = ref('')
const items = ref<ChatItem[]>([])
const progress = ref<SrcProgress | null>(null)
const input = ref('')
const busy = ref(false)
const loadingSessions = ref(false)
const loadingHistory = ref(false)
const threadRef = ref<HTMLElement | null>(null)

// ---- 会话管理:搜索 / 分组 / 重命名 / 删除 / 清理空会话 ----
const emptyCount = ref(0)
const sessionFilter = ref('')
const editingId = ref('')
const editingTitle = ref('')
const pruning = ref(false)

// ---- H1 接入:粘贴整页 / URL → 抽 scope 草稿 → 确认后开跑 ----
const intakeOpen = ref(false)
const intakeText = ref('')
const intakeUrl = ref('')
const intakeBusy = ref(false)
const intakeResult = ref<SrcIntakeResult | null>(null)
const starting = ref(false)

const totals = computed(() => progress.value?.totals || {
  targets: 0, scans: 0, urls_explored: 0, total_explores: 0, findings: 0, dead_ends: 0, errors: 0
})

// 会话显示名:优先域名(title),其次首条提问,最后回退到会话 id
const activeTitle = computed(() => {
  const s = sessions.value.find((x) => x.session_id === activeSession.value)
  return s?.title || activeSession.value || ''
})

const EXAMPLES = [
  '帮我测 www.example.com,H1 项目,scope 是 example.com',
  '全自动跑一遍 target.com 的完整流程',
  '继续深挖刚才发现的 500 端点'
]

// ---- 极简 markdown 渲染(标题/粗体/行内码/代码块/列表)----
function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
function renderMarkdown(text: string): string {
  if (!text) return ''
  let h = escapeHtml(text)
  h = h.replace(/```[\w-]*\n?([\s\S]*?)```/g, (_m, code: string) => `<pre class="md-pre">${code.replace(/\n$/, '')}</pre>`)
  h = h.replace(/`([^`\n]+)`/g, '<code class="md-code">$1</code>')
  h = h.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
  h = h.replace(/^### (.+)$/gm, '<div class="md-h3">$1</div>')
  h = h.replace(/^## (.+)$/gm, '<div class="md-h2">$1</div>')
  h = h.replace(/^# (.+)$/gm, '<div class="md-h1">$1</div>')
  h = h.replace(/^[-*] (.+)$/gm, '<div class="md-li">· $1</div>')
  h = h.replace(/\n/g, '<br>')
  return h
}

function fmtTime(ts?: number): string {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`
}
function relTime(ts?: number): string {
  if (!ts) return ''
  const diff = Date.now() / 1000 - ts
  if (diff < 60) return '刚刚'
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  return `${Math.floor(diff / 86400)} 天前`
}
function hostOf(target?: string): string {
  if (!target) return ''
  return target.replace(/^https?:\/\//, '').split('/')[0]
}

async function refreshSessions() {
  loadingSessions.value = true
  try {
    const view = await loadSrcSessionsView()
    sessions.value = view.sessions
    emptyCount.value = view.empty_count
  } catch {
    message.error('加载会话列表失败')
  } finally {
    loadingSessions.value = false
  }
}

// 时间分组(ChatGPT/Codex 式):置顶 → 今天 → 昨天 → 近 7 天 → 更早
function groupLabel(ts?: number): string {
  if (!ts) return '更早'
  const now = new Date()
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()
  const t = ts * 1000
  if (t >= startOfToday) return '今天'
  if (t >= startOfToday - 86_400_000) return '昨天'
  if (t >= startOfToday - 7 * 86_400_000) return '近 7 天'
  return '更早'
}

const filteredSessions = computed(() => {
  const q = sessionFilter.value.trim().toLowerCase()
  if (!q) return sessions.value
  return sessions.value.filter((s) =>
    (s.title || '').toLowerCase().includes(q) ||
    (s.last_user || '').toLowerCase().includes(q) ||
    (s.first_user || '').toLowerCase().includes(q) ||
    s.session_id.toLowerCase().includes(q)
  )
})

const sessionGroups = computed(() => {
  const groups: Array<{ label: string; items: SrcSession[] }> = []
  for (const s of filteredSessions.value) {
    const label = s.pinned ? '置顶' : groupLabel(s.updated_at)
    let g = groups.find((x) => x.label === label)
    if (!g) {
      g = { label, items: [] }
      groups.push(g)
    }
    g.items.push(s)
  }
  return groups
})

function startRename(s: SrcSession, e: Event) {
  e.stopPropagation()
  editingId.value = s.session_id
  editingTitle.value = s.title || ''
}

async function commitRename(s: SrcSession) {
  if (editingId.value !== s.session_id) return
  const title = editingTitle.value.trim()
  editingId.value = ''
  if (!title || title === s.title) return
  try {
    await renameSrcSession(s.session_id, title)
    s.title = title
    message.success('已重命名')
  } catch (e) {
    message.error(`重命名失败:${e instanceof Error ? e.message : String(e)}`)
  }
}

async function togglePin(s: SrcSession, e: Event) {
  e.stopPropagation()
  try {
    await pinSrcSession(s.session_id, !s.pinned)
    await refreshSessions()
  } catch (e) {
    message.error(`置顶失败:${e instanceof Error ? e.message : String(e)}`)
  }
}

async function removeSession(s: SrcSession, e: Event) {
  e.stopPropagation()
  if (!window.confirm(`删除会话「${s.title || s.session_id}」?\n它的对话和该会话的扫描记录会一起删除。`)) return
  try {
    await deleteSrcSession(s.session_id)
    if (activeSession.value === s.session_id) newSession()
    await refreshSessions()
    message.success('已删除')
  } catch (e) {
    message.error(`删除失败:${e instanceof Error ? e.message : String(e)}`)
  }
}

async function pruneEmpty() {
  if (!emptyCount.value || pruning.value) return
  if (!window.confirm(`清理 ${emptyCount.value} 个空会话?\n（只删没有对话、也没有扫描记录的)`) ) return
  pruning.value = true
  try {
    const r = await pruneSrcSessions()
    await refreshSessions()
    message.success(`已清理 ${r.removed} 个空会话`)
  } catch (e) {
    message.error(`清理失败:${e instanceof Error ? e.message : String(e)}`)
  } finally {
    pruning.value = false
  }
}

async function runIntake() {
  const text = intakeText.value.trim()
  const url = intakeUrl.value.trim()
  if (!text && !url) {
    message.warning('粘贴 H1 页面内容,或填一个 URL')
    return
  }
  intakeBusy.value = true
  intakeResult.value = null
  try {
    intakeResult.value = await submitH1Intake(text ? { text } : { url })
    message.success('已解析出范围草稿,确认后再开跑')
  } catch (e) {
    message.error(`解析失败:${e instanceof Error ? e.message : String(e)}`)
  } finally {
    intakeBusy.value = false
  }
}

async function startFromIntake() {
  const d = intakeResult.value?.extracted
  if (!d || starting.value) return
  const target = d.candidate_targets[0] || d.in_scope.urls[0] || ''
  if (!target) {
    message.warning('没解析出可探测的目标 URL —— 手动并入对话更稳')
    return
  }
  starting.value = true
  try {
    await startSrcAgent({
      target_url: target,
      authorization: `H1 ${d.program || 'program'} — operator-confirmed scope`,
      allowed_domains: d.in_scope.domains,
      allowed_hosts: d.in_scope.hosts,
      reasoner_prefer: '',
      explorer_prefer: ''
    })
    intakeOpen.value = false
    message.success('已按确认的范围开跑,进度见本会话')
  } catch (e) {
    message.error(`开跑失败:${e instanceof Error ? e.message : String(e)}`)
  } finally {
    starting.value = false
  }
}

function fillIntakeToChat() {
  const d = intakeResult.value?.extracted
  if (!d) return
  const target = d.candidate_targets[0] || d.in_scope.urls[0] || d.in_scope.hosts[0] || ''
  input.value = `扫描 ${target},scope 是 ${d.in_scope.domains.join(', ') || d.in_scope.hosts.join(', ')}` +
    (d.program ? `,H1 项目 ${d.program}` : '')
  intakeOpen.value = false
}

async function openSession(sid: string) {
  if (busy.value) return
  activeSession.value = sid
  loadingHistory.value = true
  items.value = []
  try {
    const [hist, prog] = await Promise.all([loadSrcHistory(sid), loadSrcProgress(sid)])
    items.value = (hist.messages || []).map((m: SrcMessage) => ({
      role: m.role === 'user' ? 'user' : 'assistant',
      content: m.content,
    }))
    progress.value = prog
    await scrollToBottom()
  } catch {
    message.error('读取会话失败')
  } finally {
    loadingHistory.value = false
  }
}

function newSession() {
  if (busy.value) return
  activeSession.value = ''
  items.value = []
  progress.value = null
  nextTick(() => input.value = '')
}

async function scrollToBottom() {
  await nextTick()
  if (threadRef.value) threadRef.value.scrollTop = threadRef.value.scrollHeight
}

async function send() {
  const text = input.value.trim()
  if (!text || busy.value) return
  input.value = ''
  items.value.push({ role: 'user', content: text, ts: Date.now() / 1000 })
  busy.value = true
  await scrollToBottom()
  try {
    const res = await sendSrcChat(text, activeSession.value)
    activeSession.value = res.session_id
    for (const ev of (res.events || [])) {
      if (ev.kind === 'tool_call') {
        items.value.push({ role: 'event', content: `调用 ${ev.tool}`, tool: ev.tool })
      } else if (ev.kind === 'scan_complete') {
        items.value.push({ role: 'event', content: `扫描完成 · ${(ev as Record<string, unknown>).paths ?? 0} 路径 / ${(ev as Record<string, unknown>).intents ?? 0} 候选` })
      } else if (ev.kind === 'analysis_complete') {
        items.value.push({ role: 'event', content: '分析完成' })
      }
    }
    items.value.push({ role: 'assistant', content: res.reply, ts: Date.now() / 1000 })
    void refreshProgress()
    void refreshSessions()
  } catch (e) {
    items.value.push({
      role: 'event',
      content: '请求失败: ' + (e instanceof Error ? e.message : '未知错误'),
    })
  } finally {
    busy.value = false
    await scrollToBottom()
  }
}

async function refreshProgress() {
  try {
    progress.value = await loadSrcProgress(activeSession.value)
  } catch { /* ignore */ }
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
    e.preventDefault()
    void send()
  }
}

const totalFindings = computed(() =>
  sessions.value.reduce((a, s) => a + (s.hints || 0), 0))
const totalQueued = computed(() =>
  sessions.value.reduce((a, s) => a + (s.intents_queued || 0), 0))

let pollTimer: number | undefined
onMounted(() => {
  void refreshSessions()
  pollTimer = window.setInterval(() => { if (!busy.value) void refreshSessions() }, 15000)
})
onBeforeUnmount(() => { if (pollTimer) window.clearInterval(pollTimer) })
</script>

<template>
  <div class="src-agent">
    <!-- 左侧:会话列表 -->
    <aside class="sa-side">
      <div class="sa-side-head">
        <div class="sa-brand">
          <div class="sa-brand-icon"><Bug :size="16" /></div>
          <div>
            <div class="sa-brand-title">SRC Agent</div>
            <div class="sa-brand-sub">LLM 驱动漏洞挖掘</div>
          </div>
        </div>
        <div class="sa-side-actions">
          <n-button size="small" type="primary" ghost @click="newSession" :disabled="busy">
            <template #icon><Plus :size="14" /></template>新会话
          </n-button>
          <n-button size="small" quaternary aria-label="刷新会话" @click="refreshSessions" :loading="loadingSessions">
            <template #icon><RefreshCw :size="14" /></template>
          </n-button>
        </div>
        <div class="sa-search">
          <Search :size="13" class="sa-search-icon" />
          <n-input v-model:value="sessionFilter" size="small" clearable placeholder="搜索会话" />
        </div>
      </div>

      <div class="sa-side-stats">
        <div class="sa-stat"><span>会话</span><b>{{ sessions.length }}</b></div>
        <div class="sa-stat"><span>发现</span><b class="ok">{{ totalFindings }}</b></div>
        <div class="sa-stat"><span>待挖</span><b class="warn">{{ totalQueued }}</b></div>
      </div>

      <div v-if="emptyCount" class="sa-prune">
        <n-button size="tiny" quaternary :loading="pruning" @click="pruneEmpty">
          <template #icon><Trash2 :size="12" /></template>清理 {{ emptyCount }} 个空会话
        </n-button>
      </div>

      <div class="sa-session-list">
        <n-spin v-if="loadingSessions && !sessions.length" size="small" class="sa-list-spin" />
        <n-empty v-else-if="!sessions.length" size="small" description="还没有会话" class="sa-empty" />
        <n-empty v-else-if="!filteredSessions.length" size="small" description="没有匹配的会话" class="sa-empty" />
        <template v-else>
          <div v-for="g in sessionGroups" :key="g.label" class="sa-group">
            <div class="sa-group-label">{{ g.label }}</div>
            <div
              v-for="s in g.items"
              :key="s.session_id"
              class="sa-session"
              :class="{ active: s.session_id === activeSession, isempty: s.empty }"
              role="button"
              tabindex="0"
              @click="openSession(s.session_id)"
            >
              <div class="sa-session-top">
                <span class="sa-session-dot" :class="{ live: s.session_id === activeSession }" />
                <n-input
                  v-if="editingId === s.session_id"
                  v-model:value="editingTitle"
                  size="tiny"
                  autofocus
                  @click.stop
                  @keydown.enter.prevent="commitRename(s)"
                  @keydown.esc.prevent="editingId = ''"
                  @blur="commitRename(s)"
                />
                <template v-else>
                  <span class="sa-session-name" :title="s.session_id">{{ s.title || s.session_id }}</span>
                  <span class="sa-session-time">{{ relTime(s.updated_at) }}</span>
                </template>
              </div>
              <div class="sa-session-preview">{{ s.last_user || s.first_user || '（无对话）' }}</div>
              <div class="sa-session-meta">
                <span v-if="s.empty" class="sa-chip empty">空</span>
                <span v-if="s.pinned" class="sa-chip pin">置顶</span>
                <span class="sa-chip">{{ s.turns || 0 }} 轮</span>
                <span v-if="hostOf(s.targets?.[0])" class="sa-chip target">{{ hostOf(s.targets?.[0]) }}</span>
                <span v-if="s.hints" class="sa-chip ok">{{ s.hints }} 发现</span>
                <span v-if="s.intents_queued" class="sa-chip warn">{{ s.intents_queued }} 待挖</span>
              </div>
              <div class="sa-session-tools" @click.stop>
                <button class="sa-tool" :title="s.pinned ? '取消置顶' : '置顶'" @click="togglePin(s, $event)">
                  <PinOff v-if="s.pinned" :size="12" /><Pin v-else :size="12" />
                </button>
                <button class="sa-tool" title="重命名" @click="startRename(s, $event)"><Pencil :size="12" /></button>
                <button class="sa-tool danger" title="删除" @click="removeSession(s, $event)"><Trash2 :size="12" /></button>
              </div>
            </div>
          </div>
        </template>
      </div>

      <div class="sa-side-foot">
        <span class="status-dot success"></span> 仅 scope 内 GET/HEAD
      </div>
    </aside>

    <!-- 右侧:对话 -->
    <section class="sa-main">
      <header class="sa-topbar">
        <div class="sa-topbar-left">
          <CircleDot :size="12" :class="{ live: !!activeSession }" />
          <span class="sa-topbar-title">{{ activeTitle || '新会话' }}</span>
          <span v-if="busy" class="sa-running">运行中</span>
          <n-button
            size="tiny" quaternary class="sa-intake-toggle"
            :class="{ active: intakeOpen }"
            @click="intakeOpen = !intakeOpen"
          >
            <template #icon><Link2 :size="12" /></template>H1 接入
          </n-button>
        </div>
        <div class="sa-metrics">
          <n-tooltip><template #trigger>
            <span class="sa-metric"><span class="lbl">目标</span><b>{{ totals.targets }}</b></span>
          </template>已扫描的目标数</n-tooltip>
          <n-tooltip><template #trigger>
            <span class="sa-metric"><span class="lbl">探索</span><b>{{ totals.total_explores }}</b></span>
          </template>已探索的 URL 数</n-tooltip>
          <n-tooltip><template #trigger>
            <span class="sa-metric ok"><span class="lbl">发现</span><b>{{ totals.findings }}</b></span>
          </template>记录的发现/线索</n-tooltip>
          <n-tooltip><template #trigger>
            <span class="sa-metric"><span class="lbl">死路</span><b>{{ totals.dead_ends }}</b></span>
          </template>已排除的方向</n-tooltip>
        </div>
      </header>

      <div v-if="intakeOpen" class="sa-intake">
        <div class="sa-intake-head">
          <Link2 :size="13" />
          <b>H1 接入</b>
          <span>粘贴项目页面内容或给一个 URL,LLM 抽成 scope 草稿 —— 确认后才开跑</span>
          <span class="spacer" />
          <n-button size="tiny" quaternary @click="intakeOpen = false">收起</n-button>
        </div>
        <n-input
          v-model:value="intakeText"
          type="textarea"
          :autosize="{ minRows: 3, maxRows: 8 }"
          placeholder="把 HackerOne 项目页整页粘到这里(范围、资产列表、排除项)…"
        />
        <div class="sa-intake-row">
          <n-input v-model:value="intakeUrl" size="small" placeholder="…或者只给一个公开 URL" />
          <n-button size="small" type="primary" :loading="intakeBusy" @click="runIntake">解析</n-button>
        </div>

        <div v-if="intakeResult" class="sa-intake-result">
          <div class="sa-intake-line">
            <b>{{ intakeResult.extracted.program || '(未识别项目名)' }}</b>
            <span v-if="intakeResult.warnings.length" class="sa-warn">· {{ intakeResult.warnings.join(', ') }}</span>
          </div>
          <div v-if="intakeResult.extracted.in_scope.domains.length || intakeResult.extracted.in_scope.hosts.length" class="sa-chips">
            <span v-for="d in intakeResult.extracted.in_scope.domains" :key="'d' + d" class="sa-chip target">{{ d }}</span>
            <span v-for="h in intakeResult.extracted.in_scope.hosts" :key="'h' + h" class="sa-chip">{{ h }}</span>
          </div>
          <div v-if="intakeResult.extracted.candidate_targets.length" class="sa-chips">
            <span v-for="t in intakeResult.extracted.candidate_targets" :key="t" class="sa-chip">{{ t }}</span>
          </div>
          <div v-if="intakeResult.extracted.out_of_scope.length" class="sa-intake-oos">
            排除:{{ intakeResult.extracted.out_of_scope.join('、') }}
          </div>
          <div class="sa-intake-actions">
            <n-button size="small" type="primary" :loading="starting" @click="startFromIntake">按这个范围开跑</n-button>
            <n-button size="small" quaternary @click="fillIntakeToChat">填入对话</n-button>
          </div>
        </div>
      </div>

      <div ref="threadRef" class="sa-thread">
        <n-spin v-if="loadingHistory" size="small" class="sa-thread-spin" />

        <div v-else-if="!items.length" class="sa-welcome">
          <div class="sa-welcome-icon"><Zap :size="30" /></div>
          <h2>跟 Agent 对话,开始挖洞</h2>
          <p>Agent 会自动扫描表面、提取 JS 端点、分析响应,并在人机决策点找你确认。</p>
          <div class="sa-examples">
            <button
              v-for="ex in EXAMPLES"
              :key="ex"
              class="sa-example"
              @click="input = ex"
            >
              <span class="sa-example-arrow">→</span>{{ ex }}
            </button>
          </div>
        </div>

        <template v-else>
          <div v-for="(it, i) in items" :key="i" class="sa-row" :class="it.role">
            <!-- 工具/事件:居中胶囊 -->
            <div v-if="it.role === 'event'" class="sa-event">
              <Terminal :size="12" /> <span>{{ it.content }}</span>
            </div>

            <!-- 消息:头像 + 气泡 -->
            <template v-else>
              <div class="sa-avatar" :class="it.role">
                <User v-if="it.role === 'user'" :size="15" />
                <Bot v-else :size="16" />
              </div>
              <div class="sa-msg">
                <div class="sa-msg-head">
                  <span class="sa-who">{{ it.role === 'user' ? '你' : 'Agent' }}</span>
                  <span class="sa-when">{{ fmtTime(it.ts) }}</span>
                </div>
                <div class="sa-bubble" v-html="renderMarkdown(it.content)" />
              </div>
            </template>
          </div>

          <div v-if="busy" class="sa-row assistant">
            <div class="sa-avatar assistant"><Bot :size="16" /></div>
            <div class="sa-msg">
              <div class="sa-msg-head"><span class="sa-who">Agent</span></div>
              <div class="sa-bubble typing"><i /><i /><i /></div>
            </div>
          </div>
        </template>
      </div>

      <footer class="sa-composer">
        <div class="sa-composer-box">
          <n-input
            v-model:value="input"
            type="textarea"
            :autosize="{ minRows: 1, maxRows: 6 }"
            placeholder="输入指令… (Enter 发送,Shift+Enter 换行)"
            :disabled="busy"
            @keydown="onKeydown"
          />
          <n-button class="sa-send" type="primary" :loading="busy" :disabled="!input.trim()" @click="send">
            <template #icon><Send :size="15" /></template>
          </n-button>
        </div>
        <div class="sa-foot-note">Agent 只发 scope 内的 GET/HEAD,不修改目标数据</div>
      </footer>
    </section>
  </div>
</template>

<style scoped>
.src-agent {
  display: grid;
  grid-template-columns: 300px 1fr;
  height: 100%;
  min-height: 0;
  background: var(--pa-bg);
}

/* ---------- 左侧:会话列表 ---------- */
.sa-side {
  display: flex;
  flex-direction: column;
  min-height: 0;
  border-right: 1px solid var(--pa-border);
  background: var(--pa-surface);
}
.sa-side-head { padding: 16px 16px 14px; border-bottom: 1px solid var(--pa-border-soft); }
.sa-brand { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
.sa-brand-icon {
  width: 34px; height: 34px; display: grid; place-items: center;
  border-radius: 10px; background: linear-gradient(135deg, var(--pa-primary), #26c4bf);
  color: #fff; box-shadow: 0 3px 10px rgb(23 142 139 / 28%);
}
.sa-brand-title { font-weight: 650; font-size: 14px; color: var(--pa-text); letter-spacing: .2px; }
.sa-brand-sub { font-size: 11px; color: var(--pa-text-3); margin-top: 1px; }
.sa-side-actions { display: flex; gap: 6px; }
.sa-side-actions :deep(.n-button) { flex: 1; }

.sa-side-stats {
  display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 1px; background: var(--pa-border-soft);
  border-bottom: 1px solid var(--pa-border-soft);
}
.sa-stat {
  background: var(--pa-surface); padding: 10px 12px;
  display: flex; flex-direction: column; gap: 2px;
}
.sa-stat span { font-size: 11px; color: var(--pa-text-3); }
.sa-stat b { font-size: 17px; font-weight: 650; color: var(--pa-text); line-height: 1.1; }
.sa-stat b.ok { color: var(--pa-success); }
.sa-stat b.warn { color: #c98a12; }

.sa-session-list { flex: 1; overflow-y: auto; padding: 8px; min-height: 0; }
.sa-list-spin { display: block; margin: 32px auto; }
.sa-empty { margin-top: 40px; }
.sa-session {
  display: block; width: 100%; text-align: left; cursor: pointer;
  background: transparent; border: 1px solid transparent; border-radius: 10px;
  padding: 10px 12px; margin-bottom: 3px; font: inherit; transition: all .14s;
}
.sa-session:hover { background: var(--pa-bg); }
.sa-session.active {
  background: color-mix(in srgb, var(--pa-primary) 8%, transparent);
  border-color: color-mix(in srgb, var(--pa-primary) 35%, transparent);
}
.sa-session-top { display: flex; align-items: center; gap: 6px; }
.sa-session-dot {
  width: 6px; height: 6px; border-radius: 50%; flex: 0 0 auto;
  background: var(--pa-border); transition: background .14s;
}
.sa-session-dot.live { background: var(--pa-success); box-shadow: 0 0 0 3px color-mix(in srgb, var(--pa-success) 20%, transparent); }
.sa-session-name {
  flex: 1; font-size: 13px; font-weight: 600; color: var(--pa-text);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.sa-session-time { font-size: 10px; color: var(--pa-text-3); flex: 0 0 auto; }
.sa-session-preview {
  font-size: 12px; color: var(--pa-text); margin: 5px 0 6px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.sa-session-meta { display: flex; flex-wrap: wrap; gap: 4px; }
.sa-chip {
  font-size: 10px; padding: 1px 7px; border-radius: 20px;
  background: var(--pa-bg); color: var(--pa-text-3); border: 1px solid var(--pa-border-soft);
}
.sa-chip.ok { color: var(--pa-success); border-color: color-mix(in srgb, var(--pa-success) 30%, transparent); }
.sa-chip.warn { color: #c98a12; border-color: color-mix(in srgb, #c98a12 30%, transparent); }
.sa-chip.target { color: var(--pa-primary); border-color: color-mix(in srgb, var(--pa-primary) 30%, transparent); }

.sa-side-foot {
  display: flex; align-items: center; gap: 6px;
  padding: 10px 16px; border-top: 1px solid var(--pa-border-soft);
  font-size: 11px; color: var(--pa-text-3);
}

/* ---------- 右侧:对话 ---------- */
.sa-main { display: flex; flex-direction: column; min-height: 0; min-width: 0; }
.sa-topbar {
  display: flex; align-items: center; gap: 14px;
  padding: 12px 24px; border-bottom: 1px solid var(--pa-border-soft);
  background: var(--pa-surface);
}
.sa-topbar-left { display: flex; align-items: center; gap: 7px; min-width: 0; }
.sa-topbar-left svg { color: var(--pa-text-3); }
.sa-topbar-left svg.live { color: var(--pa-success); }
.sa-topbar-title {
  font-weight: 600; font-size: 13px; color: var(--pa-text);
  font-family: var(--pa-mono, ui-monospace, monospace);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.sa-running {
  margin-left: 6px; font-size: 11px; color: var(--pa-primary);
  background: color-mix(in srgb, var(--pa-primary) 10%, transparent);
  padding: 1px 8px; border-radius: 20px;
}
.sa-metrics { margin-left: auto; display: flex; gap: 18px; }
.sa-metric { display: flex; align-items: baseline; gap: 5px; font-size: 12px; }
.sa-metric .lbl { color: var(--pa-text-3); }
.sa-metric b { font-size: 14px; color: var(--pa-text); font-weight: 650; }
.sa-metric.ok b { color: var(--pa-success); }

.sa-thread { flex: 1; overflow-y: auto; padding: 24px 28px; min-height: 0; }
.sa-thread-spin { display: block; margin: 48px auto; }

.sa-welcome {
  max-width: 540px; margin: 56px auto 0; text-align: center;
  display: flex; flex-direction: column; align-items: center;
}
.sa-welcome-icon {
  width: 60px; height: 60px; display: grid; place-items: center; border-radius: 18px;
  background: linear-gradient(135deg, color-mix(in srgb, var(--pa-primary) 14%, transparent), color-mix(in srgb, var(--pa-primary) 6%, transparent));
  color: var(--pa-primary); margin-bottom: 18px;
}
.sa-welcome h2 { margin: 0 0 8px; font-size: 18px; color: var(--pa-text); }
.sa-welcome p { margin: 0 0 24px; font-size: 13px; color: var(--pa-text-2); line-height: 1.65; }
.sa-examples { display: flex; flex-direction: column; gap: 8px; width: 100%; }
.sa-example {
  display: flex; align-items: center; gap: 8px;
  text-align: left; font: inherit; font-size: 12.5px; cursor: pointer;
  padding: 11px 15px; border-radius: 10px; border: 1px solid var(--pa-border);
  background: var(--pa-surface); color: var(--pa-text-2); transition: all .14s;
}
.sa-example-arrow { color: var(--pa-primary); opacity: .5; transition: all .14s; }
.sa-example:hover {
  border-color: var(--pa-primary); color: var(--pa-text);
  background: color-mix(in srgb, var(--pa-primary) 5%, transparent);
  transform: translateX(2px);
}
.sa-example:hover .sa-example-arrow { opacity: 1; }

.sa-row { max-width: 880px; margin: 0 auto 18px; display: flex; gap: 11px; animation: sa-in .22s ease both; }
.sa-row.assistant { flex-direction: row; }
.sa-row.user { flex-direction: row-reverse; }
@keyframes sa-in { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: none; } }
.sa-avatar {
  flex: 0 0 auto; width: 30px; height: 30px; border-radius: 9px;
  display: grid; place-items: center; margin-top: 2px;
}
.sa-avatar.user { background: color-mix(in srgb, #2f6fed 12%, transparent); color: #2f6fed; }
.sa-avatar.assistant {
  background: linear-gradient(135deg, var(--pa-primary), #26c4bf); color: #fff;
  box-shadow: 0 2px 8px rgb(23 142 139 / 25%);
}
.sa-msg { min-width: 0; max-width: 78%; }
.sa-row.user .sa-msg { display: flex; flex-direction: column; align-items: flex-end; }
.sa-msg-head { display: flex; align-items: baseline; gap: 8px; margin-bottom: 5px; }
.sa-who { font-size: 11px; font-weight: 600; color: var(--pa-text-3); letter-spacing: .3px; }
.sa-when { font-size: 10px; color: var(--pa-text-3); }
.sa-bubble {
  padding: 11px 15px; border-radius: 12px; font-size: 13.5px; line-height: 1.68;
  word-break: break-word;
}
.sa-row.user .sa-bubble {
  background: color-mix(in srgb, #2f6fed 9%, transparent);
  border: 1px solid color-mix(in srgb, #2f6fed 18%, transparent);
  color: var(--pa-text); border-top-right-radius: 4px;
}
.sa-row.assistant .sa-bubble {
  background: var(--pa-surface); border: 1px solid var(--pa-border-soft);
  color: var(--pa-text); border-top-left-radius: 4px;
  box-shadow: var(--pa-shadow-soft, 0 1px 3px rgb(0 0 0 / 4%));
}
.sa-bubble :deep(.md-h1) { font-size: 15px; font-weight: 700; margin: 10px 0 6px; }
.sa-bubble :deep(.md-h2) { font-size: 14px; font-weight: 650; margin: 10px 0 5px; }
.sa-bubble :deep(.md-h3) { font-size: 13px; font-weight: 650; margin: 8px 0 4px; color: var(--pa-text-2); }
.sa-bubble :deep(.md-code) {
  background: var(--pa-bg); padding: 1px 5px; border-radius: 4px;
  font-family: var(--pa-mono, ui-monospace, monospace); font-size: 12px; color: #b3502b;
}
.sa-bubble :deep(.md-pre) {
  background: #1f2d36; color: #e6edf3; padding: 12px 14px; border-radius: 8px;
  overflow-x: auto; font-size: 12px; line-height: 1.55; margin: 8px 0;
  font-family: var(--pa-mono, ui-monospace, monospace);
}
.sa-bubble :deep(.md-li) { padding-left: 4px; }

/* typing 指示 */
.sa-bubble.typing { display: inline-flex; gap: 5px; padding: 13px 16px; }
.sa-bubble.typing i {
  width: 6px; height: 6px; border-radius: 50%; background: var(--pa-primary);
  opacity: .4; animation: sa-blink 1.2s infinite ease-in-out;
}
.sa-bubble.typing i:nth-child(2) { animation-delay: .2s; }
.sa-bubble.typing i:nth-child(3) { animation-delay: .4s; }
@keyframes sa-blink { 0%, 60%, 100% { opacity: .3; transform: translateY(0); } 30% { opacity: 1; transform: translateY(-2px); } }

.sa-event {
  margin: 0 auto; display: inline-flex; align-items: center; gap: 6px;
  font-size: 11.5px; color: var(--pa-text-3); background: var(--pa-bg);
  border: 1px solid var(--pa-border-soft); border-radius: 20px; padding: 4px 12px;
  font-family: var(--pa-mono, ui-monospace, monospace);
}
.sa-row.event { justify-content: center; }

.sa-composer {
  padding: 14px 28px 10px; border-top: 1px solid var(--pa-border-soft);
  background: var(--pa-surface);
}
.sa-composer-box {
  display: flex; align-items: flex-end; gap: 10px;
  border: 1px solid var(--pa-border); border-radius: 12px; padding: 7px 7px 7px 12px;
  background: var(--pa-surface); transition: border-color .14s, box-shadow .14s;
}
.sa-composer-box:focus-within {
  border-color: var(--pa-primary);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--pa-primary) 12%, transparent);
}
.sa-composer-box :deep(.n-input) { flex: 1; }
.sa-composer-box :deep(.n-input__border),
.sa-composer-box :deep(.n-input__state-border) { display: none; }
.sa-send { border-radius: 9px; }
.sa-foot-note {
  text-align: center; font-size: 11px; color: var(--pa-text-3);
  padding: 8px 0 2px;
}

/* ---------- 会话管理:搜索 / 分组 / 行内操作 ---------- */
.sa-search { position: relative; margin-top: 10px; }
.sa-search-icon {
  position: absolute; left: 9px; top: 50%; transform: translateY(-50%);
  color: var(--pa-text-3); pointer-events: none; z-index: 1;
}
.sa-search :deep(.n-input__input-el) { padding-left: 22px; }

.sa-prune {
  padding: 7px 10px; border-bottom: 1px solid var(--pa-border-soft);
  display: flex; justify-content: center;
}
.sa-prune :deep(.n-button) { font-size: 11.5px; }

.sa-group { margin-bottom: 8px; }
.sa-group-label {
  font-size: 10.5px; color: var(--pa-text-3); font-weight: 600;
  letter-spacing: .4px; padding: 6px 8px 4px; text-transform: uppercase;
}
.sa-session { position: relative; }
.sa-session.isempty .sa-session-name { color: var(--pa-text-2); font-weight: 500; }
.sa-session-tools {
  position: absolute; top: 8px; right: 8px;
  display: none; gap: 2px; background: var(--pa-surface);
  border: 1px solid var(--pa-border-soft); border-radius: 7px; padding: 1px;
  box-shadow: var(--pa-shadow-soft, 0 1px 3px rgb(0 0 0 / 6%));
}
.sa-session:hover .sa-session-tools,
.sa-session:focus-within .sa-session-tools { display: flex; }
.sa-tool {
  display: grid; place-items: center; width: 22px; height: 22px;
  border: none; background: transparent; cursor: pointer;
  color: var(--pa-text-3); border-radius: 5px; transition: all .12s;
}
.sa-tool:hover { background: var(--pa-bg); color: var(--pa-text); }
.sa-tool.danger:hover { color: #c0392b; background: color-mix(in srgb, #c0392b 10%, transparent); }
.sa-session:hover .sa-session-time { visibility: hidden; }
.sa-chip.empty { color: var(--pa-text-3); border-style: dashed; }
.sa-chip.pin { color: var(--pa-primary); border-color: color-mix(in srgb, var(--pa-primary) 30%, transparent); }

/* ---------- H1 接入 ---------- */
.sa-intake-toggle.active { color: var(--pa-primary); }
.sa-intake {
  border-bottom: 1px solid var(--pa-border-soft);
  background: var(--pa-surface); padding: 12px 24px 14px;
  display: flex; flex-direction: column; gap: 9px;
}
.sa-intake-head { display: flex; align-items: center; gap: 7px; font-size: 12px; color: var(--pa-text-2); }
.sa-intake-head b { color: var(--pa-text); font-weight: 650; }
.sa-intake-head svg { color: var(--pa-primary); }
.sa-intake-head .spacer { flex: 1; }
.sa-intake-row { display: flex; gap: 8px; }
.sa-intake-row :deep(.n-input) { flex: 1; }
.sa-intake-result {
  border: 1px solid var(--pa-border); border-radius: 10px;
  padding: 11px 13px; background: var(--pa-bg); display: flex; flex-direction: column; gap: 8px;
}
.sa-intake-line { font-size: 12.5px; color: var(--pa-text); }
.sa-warn { color: #c98a12; font-size: 11.5px; }
.sa-chips { display: flex; flex-wrap: wrap; gap: 4px; }
.sa-intake-oos { font-size: 11.5px; color: var(--pa-text-3); }
.sa-intake-actions { display: flex; gap: 8px; margin-top: 2px; }
</style>
