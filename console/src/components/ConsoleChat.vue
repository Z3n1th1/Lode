<script setup lang="ts">
// 对话式 agent 控制台:项目→会话→对话 一体(缝合 Element-Plus-X Conversations 侧栏 + x-markdown),
// 中间渲染 F1 的 Strix 真实多智能体对话(可靠手绘气泡,避免第三方组件渲染坑)。
// F3 SSE 实时冒(Element-Plus-X useXStream)· F4 agent 树过滤 + 运行控制
// · F5 确认门一等事件(approval_required INTERRUPT 阻断气泡,就地 approve/reject)。
// R1 丝滑化:消息流窗口化渲染(顶部哨兵 IntersectionObserver 懒加载)+ 工具三段渲染
// (参数 kv/结果摘要/折叠原文浅色高亮)+ SSE 断线重连状态条 + 乐观回声被真实回复替换后消除。
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Conversations, useXStream } from 'vue-element-plus-x'
import { NCollapse, NCollapseItem, NDrawer, NDrawerContent } from 'naive-ui'
import {
  loadProjects, loadProject, loadConversation, submitSessionGuidance, submitProjectIntake,
  loadPocPending, confirmPoc, loadFingerprintCorrections, decideFingerprintCorrection,
  loadEvolve, decideEvolve,
  type ProjectCard, type Conversation, type ConvMessage
} from '../api'
import { openProjectResults, agentCnName, resolveIntakeProfile } from '../store'   // F6 成果侧联动 + 热修:中文名映射/策略档解析
import { highlightJson, parseReasoningText, parseResultMeta, parseToolArgs, sliceRecent, summarizeToolResult, toolCallHasMore, toolCallSummary, toolResultHasMore, type ToolKv } from '../chatTools'

type SessItem = { key: string; label: string; group: string }

const convItems = ref<SessItem[]>([])
const activeKey = ref('')
const conv = ref<Conversation | null>(null)
const loading = ref(false)
const errMsg = ref('')
const targetOf = ref<Record<string, string>>({})
const profileOf = ref<Record<string, string>>({})
const projectOf = ref<Record<string, string>>({})   // session_id → project_id(成果联动)
const streamRows = ref<ConvMessage[]>([])       // SSE 实时增量
const agentFilter = ref('')                     // agent 树过滤(空=全部)
const composer = ref('')
const sending = ref(false)
const sendMsg = ref('')
const streamRef = ref<HTMLElement | null>(null)
const topSentinelRef = ref<HTMLElement | null>(null)

// ---- R1 长列表窗口化:只挂载最近 PAGE 条,顶部哨兵/按钮向前翻页(与消息总数解耦)----
const PAGE_SIZE = 60
const renderCount = ref(PAGE_SIZE)
const stickBottom = ref(true)                   // 用户贴底时才自动跟随滚动

// ---- F5 确认门:类型 + gate → 决策动作(执行仍走服务端 gate 端点)----
type ApprovalItem = { id: string; kind: string; text: string; act: (ok: boolean) => Promise<void> }
const GATE_LABEL: Record<string, string> = { poc: 'PoC', fingerprint: '指纹', evolve: '反思' }
function actFor(gate: string, rawId: string): (ok: boolean) => Promise<void> {
  if (gate === 'poc') return async (ok) => { await confirmPoc(rawId, ok) }
  if (gate === 'fingerprint') return async (ok) => { await decideFingerprintCorrection(rawId, ok ? 'approve' : 'reject') }
  return async (ok) => { await decideEvolve(rawId, ok ? 'approve' : 'reject') }
}

// ---- 侧栏:项目→会话(分组)----
async function loadSidebar() {
  try {
    const projects: ProjectCard[] = await loadProjects()
    const items: SessItem[] = []
    for (const p of projects) {
      try {
        const det = await loadProject(p.project_id)
        for (const s of det.sessions) {
          items.push({ key: s.session_id, label: s.session_id + (s.profile_name ? ' · ' + s.profile_name : ''), group: det.target })
          targetOf.value[s.session_id] = det.target
          profileOf.value[s.session_id] = s.profile_name || 'recon'
          projectOf.value[s.session_id] = p.project_id
        }
      } catch { /* skip */ }
    }
    convItems.value = items
    if (!activeKey.value && items.length) pick(items[0].key)
  } catch (e) { errMsg.value = '加载会话列表失败' }
}

// ---- 选会话 → 读历史对话 + 起 SSE ----
async function pick(key: string) {
  if (!key) return
  activeKey.value = key
  agentFilter.value = ''
  loading.value = true; errMsg.value = ''; conv.value = null; streamRows.value = []
  echoes.value = []
  renderCount.value = PAGE_SIZE; stickBottom.value = true
  try {
    conv.value = await loadConversation(key)
    if (!conv.value || !conv.value.messages) errMsg.value = '该会话无对话记录'
  } catch (e) {
    errMsg.value = '读取对话失败(' + (e instanceof Error ? e.message : '未知') + ')'
    conv.value = null
  } finally {
    loading.value = false
    scrollBottom(true)
    startStream(key)
  }
}
function onConvChange(item: { key?: string } | string) {
  const k = typeof item === 'string' ? item : (item?.key || '')
  if (k) pick(k)
}

// ---- F3 SSE 实时:Element-Plus-X useXStream 接 /conversation/stream(替轮询/裸 EventSource)----
const { startStream: xsStart, cancel: xsCancel, data: xsData } = useXStream()
let streamStop = true
let streamTimer: number | undefined
let consumed = 0
// R1:断线显式提示 + 自动重连状态条
const streamState = ref<'idle' | 'live' | 'reconnecting'>('idle')

function startStream(key: string) {
  stopStream()
  streamStop = false
  const run = async () => {
    if (streamStop || activeKey.value !== key) return
    consumed = 0
    try {
      const resp = await fetch(`/api/v1/conversation/stream?id=${encodeURIComponent(key)}`,
        { headers: { Accept: 'text/event-stream' } })
      if (!resp.ok || !resp.body) throw new Error('http ' + resp.status)
      streamState.value = 'live'
      await xsStart({ readableStream: resp.body })   // 流持续到断开/取消
    } catch { /* 取消或失败 → 走重连 */ }
    if (!streamStop && activeKey.value === key) {
      streamState.value = 'reconnecting'
      streamTimer = window.setTimeout(run, 3000)
    }
  }
  void run()
}
function stopStream() {
  streamStop = true
  streamState.value = 'idle'
  if (streamTimer) { clearTimeout(streamTimer); streamTimer = undefined }
  xsCancel()
}
function retryStream() {
  if (activeKey.value) startStream(activeKey.value)
}
// 消费 SSE 项:会话增量消息 + F5 确认门一等事件(approval_required/approval_resolved)
watch(xsData, (rows) => {
  for (; consumed < rows.length; consumed++) {
    const raw = rows[consumed]?.data
    if (typeof raw !== 'string' || !raw.trim()) continue
    let m: Record<string, unknown> | null = null
    try { m = JSON.parse(raw) } catch { continue }
    if (!m || typeof m !== 'object') continue
    if (m.kind === 'approval_required') { upsertApproval(m); continue }
    if (m.kind === 'approval_resolved') {
      approvals.value = approvals.value.filter(a => a.id !== m.approval_id); continue
    }
    if (m.seq) {
      // R1 衔接顺滑:真实用户消息进流后,消除同文乐观回声(不等刷新)
      if (m.kind === 'user_message' && typeof m.text === 'string') dropEcho(m.text)
      streamRows.value.push(m as unknown as ConvMessage)
      if (stickBottom.value) scrollBottom()
    }
  }
}, { deep: true })

// ---- 合并历史 + 实时;R-A P0-3:agent 过滤按聚合组(中文名)匹配;窗口化只挂载最近 renderCount 条 ----
const mergedMessages = computed<ConvMessage[]>(() => {
  const base = conv.value?.messages || []
  const seen = new Set(base.map(m => m.seq))
  return [...base, ...streamRows.value.filter(m => !seen.has(m.seq))]
})
const allMessages = computed<ConvMessage[]>(() =>
  agentFilter.value ? mergedMessages.value.filter(m => agentCnName(m.agent_name || '') === agentFilter.value) : mergedMessages.value)
const visibleMessages = computed<ConvMessage[]>(() => sliceRecent(allMessages.value, renderCount.value))
const hiddenCount = computed(() => Math.max(0, allMessages.value.length - renderCount.value))
const agents = computed(() => conv.value?.agents || [])

// ---- R1 翻页:向前加载更早消息并保持视觉位置不跳动 ----
function loadOlder() {
  if (hiddenCount.value <= 0) return
  const el = streamRef.value
  const prevH = el ? el.scrollHeight : 0
  const prevTop = el ? el.scrollTop : 0
  renderCount.value += PAGE_SIZE
  nextTick(() => {
    const el2 = streamRef.value
    if (el2 && prevH) el2.scrollTop = prevTop + (el2.scrollHeight - prevH)
  })
}

// ---- R1 滚动:贴底检测 + rAF 合帧;仅贴底/强制时跟随 ----
let scrollRaf = 0
function onStreamScroll() {
  const el = streamRef.value
  if (!el) return
  stickBottom.value = el.scrollHeight - el.scrollTop - el.clientHeight < 80
}
function scrollBottom(force = false) {
  if (scrollRaf) cancelAnimationFrame(scrollRaf)
  scrollRaf = requestAnimationFrame(() => {
    scrollRaf = 0
    if (!force && !stickBottom.value) return
    const el = streamRef.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

// ---- F4 运行控制:续跑 / 分叉(console 直发,排队处理;触发人工门时就地出审批按钮)----
// 热修:本地乐观回声气泡——发送即渲染,不等回包;失败原地改错误气泡并带后端原因
type EchoMsg = { id: number; text: string; status: 'sending' | 'sent' | 'failed'; err?: string }
const echoes = ref<EchoMsg[]>([])
let echoSeq = 0
// R1:真实回复进流后消除同文回声(乐观气泡 → 真实气泡的顺滑替换)
function dropEcho(text: string) {
  const t = text.trim()
  if (!t) return
  const i = echoes.value.findIndex(e => e.status !== 'failed' && e.text.trim() === t)
  if (i >= 0) echoes.value.splice(i, 1)
}

async function onSend() {
  const t = composer.value.trim()
  if (!t || !activeKey.value) return
  const echo: EchoMsg = { id: ++echoSeq, text: t, status: 'sending' }
  echoes.value.push(echo)
  if (echoes.value.length > 20) echoes.value.splice(0, echoes.value.length - 20)
  composer.value = ''
  sending.value = true; sendMsg.value = ''
  stickBottom.value = true
  scrollBottom(true)
  try {
    const r = await submitSessionGuidance({ session_id: activeKey.value, target: targetOf.value[activeKey.value] || '', guidance: t })
    echo.status = 'sent'
    sendMsg.value = r.note || `已提交 ${r.id}`
  } catch (e) {
    echo.status = 'failed'
    echo.err = e instanceof Error ? e.message : '提交失败'
  } finally { sending.value = false; scrollBottom(true) }
}
async function onFork() {
  if (!activeKey.value) return
  const target = targetOf.value[activeKey.value] || ''
  if (!target) { sendMsg.value = '分叉失败:该会话无目标信息'; return }
  sending.value = true; sendMsg.value = ''
  try {
    const profile = await resolveIntakeProfile(profileOf.value[activeKey.value] || '')
    if (!profile) { sendMsg.value = '分叉失败:无可用策略档(测试策略未加载)'; return }
    const r = await submitProjectIntake({ target_url: target, name: 'fork:' + target, engagement_profile: profile, toggles: { scan_enabled: true } })
    sendMsg.value = `已提交分叉 ${r.intake_id}(console 直发,排队处理)`
  } catch (e) {
    sendMsg.value = '分叉失败:' + (e instanceof Error ? e.message : '未知错误')
  } finally { sending.value = false }
}

// ---- R-A 工具卡片:摘要一行(主参数+退出码/耗时)· 展开=完整参数 kv/完整输出 ----
// 展开无新增信息时不渲染折叠按钮(摘要与展开同源的 P0-1 修复);WeakMap 按消息缓存免重复解析
const fullKvCache = new WeakMap<ConvMessage, ToolKv[] | null>()
const callBaseCache = new WeakMap<ConvMessage, string>()
const resSumCache = new WeakMap<ConvMessage, string>()
const rawCache = new WeakMap<ConvMessage, string>()
const thinkCache = new WeakMap<ConvMessage, string>()

// call_id → 配对 tool_result 输出(给 tool_call 摘要补退出码/耗时;结果后到也能追认)
const resultByCallId = computed(() => {
  const map = new Map<string, string>()
  for (const m of mergedMessages.value) {
    if (m.kind === 'tool_result' && m.call_id) map.set(m.call_id, m.output || '')
  }
  return map
})
function callBaseOf(m: ConvMessage): string {
  if (!callBaseCache.has(m)) callBaseCache.set(m, toolCallSummary(m.tool_name, m.tool_args))
  return callBaseCache.get(m) ?? ''
}
function callSummaryOf(m: ConvMessage): string {
  const out = m.call_id ? resultByCallId.value.get(m.call_id) : undefined
  const meta = out ? parseResultMeta(out) : ''
  return meta ? `${callBaseOf(m)} · ${meta}` : callBaseOf(m)
}
function resultSummaryOf(m: ConvMessage): string {
  if (!resSumCache.has(m)) resSumCache.set(m, summarizeToolResult(m.output))
  return resSumCache.get(m) ?? ''
}
function fullArgsOf(m: ConvMessage): ToolKv[] | null {
  if (!fullKvCache.has(m)) fullKvCache.set(m, parseToolArgs(m.tool_args, Number.MAX_SAFE_INTEGER))
  return fullKvCache.get(m) ?? null
}
function rawHtml(m: ConvMessage): string {
  if (!rawCache.has(m)) rawCache.set(m, highlightJson((m.kind === 'tool_call' ? m.tool_args : m.output) || ''))
  return rawCache.get(m) ?? ''
}
function callHasMore(m: ConvMessage): boolean { return toolCallHasMore(m.tool_args) }
function resultHasMore(m: ConvMessage): boolean { return toolResultHasMore(m.output, resultSummaryOf(m)) }
function thinkTextOf(m: ConvMessage): string {
  if (!thinkCache.has(m)) thinkCache.set(m, parseReasoningText(m.text))
  return thinkCache.get(m) ?? ''
}

// ---- R-A P0-3:子代理右侧抽屉(同名聚合计数,点击跳转其首条消息;保留组级过滤)----
const agentDrawer = ref(false)
type AgentGroup = { key: string; cn: string; count: number; done: boolean; msgCount: number; firstSeq: number | null }
const agentGroups = computed<AgentGroup[]>(() => {
  const msgCount = new Map<string, number>()
  const firstSeq = new Map<string, number>()
  for (const m of mergedMessages.value) {
    if (!m.agent_id) continue
    msgCount.set(m.agent_id, (msgCount.get(m.agent_id) || 0) + 1)
    if (!firstSeq.has(m.agent_id)) firstSeq.set(m.agent_id, m.seq)
  }
  const groups = new Map<string, AgentGroup>()
  for (const a of agents.value) {
    const cn = agentCnName(a.name)
    let g = groups.get(cn)
    if (!g) { g = { key: cn, cn, count: 0, done: true, msgCount: 0, firstSeq: null }; groups.set(cn, g) }
    g.count += 1
    if (a.status !== 'completed') g.done = false
    g.msgCount += msgCount.get(a.agent_id) || 0
    const fs = firstSeq.get(a.agent_id)
    if (fs !== undefined && (g.firstSeq === null || fs < g.firstSeq)) g.firstSeq = fs
  }
  return [...groups.values()]
})
function jumpToAgent(g: AgentGroup) {
  if (g.firstSeq === null) return
  const target = g.firstSeq
  const idx = mergedMessages.value.findIndex(m => m.seq === target)
  if (idx < 0) return
  agentFilter.value = ''
  const need = mergedMessages.value.length - idx
  if (renderCount.value < need) renderCount.value = need   // 首条在窗口外时先扩窗
  agentDrawer.value = false
  stickBottom.value = false
  nextTick(() => {
    const el = streamRef.value?.querySelector(`[data-seq="${target}"]`)
    if (!el) return
    el.scrollIntoView({ block: 'center' })
    el.classList.add('cc-flash')
    window.setTimeout(() => el.classList.remove('cc-flash'), 1600)
  })
}
function filterAgentGroup(g: AgentGroup) {
  agentFilter.value = g.key
  agentDrawer.value = false
}

// ---- F5 确认门就地:SSE 一等事件驱动(30s 轮询仅作对账兜底),就地 approve/reject ----
const approvals = ref<ApprovalItem[]>([])
function upsertApproval(m: Record<string, unknown>) {
  const id = String(m.approval_id || '')
  if (!id || approvals.value.some(a => a.id === id)) return
  const gate = String(m.gate || '')
  const rawId = id.slice(id.indexOf(':') + 1)
  approvals.value.push({ id, kind: GATE_LABEL[gate] || gate || '审批',
    text: String(m.summary || rawId), act: actFor(gate, rawId) })
}
async function loadApprovals() {
  const out: ApprovalItem[] = []
  try {
    const poc = await loadPocPending()
    for (const p of poc.pending) out.push({ id: 'poc:' + p.id, kind: 'PoC', text: `${p.title || p.id} ${p.cve || ''}`.trim(),
      act: actFor('poc', p.id) })
  } catch { /* ignore */ }
  try {
    const fc = await loadFingerprintCorrections('pending')
    for (const c of fc) out.push({ id: 'fp:' + c.id, kind: '指纹', text: `${c.kind} ${c.name}`,
      act: actFor('fingerprint', c.id) })
  } catch { /* ignore */ }
  try {
    const ev = await loadEvolve('pending')
    for (const c of ev.rows) out.push({ id: 'ev:' + c.id, kind: '反思', text: c.text.slice(0, 80),
      act: actFor('evolve', c.id) })
  } catch { /* ignore */ }
  approvals.value = out
}
async function decideApproval(a: ApprovalItem, ok: boolean) {
  try { await a.act(ok); approvals.value = approvals.value.filter(x => x.id !== a.id) } catch { /* ignore */ }
}

let approvalsTimer: number | undefined
let olderObserver: IntersectionObserver | undefined
onMounted(() => {
  loadSidebar()
  loadApprovals()
  approvalsTimer = window.setInterval(loadApprovals, 30000)
  // R1:顶部哨兵进入视口(提前 240px)即向前翻页;哨兵常挂,hiddenCount 兜底
  olderObserver = new IntersectionObserver((entries) => {
    if (entries.some(e => e.isIntersecting) && hiddenCount.value > 0) loadOlder()
  }, { root: streamRef.value, rootMargin: '240px 0px 0px 0px' })
  if (topSentinelRef.value) olderObserver.observe(topSentinelRef.value)
})
onBeforeUnmount(() => {
  stopStream()
  if (approvalsTimer) clearInterval(approvalsTimer)
  olderObserver?.disconnect()
  if (scrollRaf) cancelAnimationFrame(scrollRaf)
})
watch(allMessages, () => { if (stickBottom.value) scrollBottom() })
watch(approvals, () => scrollBottom(), { deep: true })

function roleLabel(m: ConvMessage) { return m.kind === 'user_message' ? '你' : agentCnName(m.agent_name || '') }
</script>

<template>
  <div class="cc">
    <!-- 左:项目→会话 历史(缝合 Conversations)-->
    <aside class="cc-side">
      <div class="cc-side-hd">项目 / 会话</div>
      <Conversations v-if="convItems.length" v-model:active="activeKey" :items="convItems" row-key="key"
        groupable :label-max-width="220" class="cc-conv" @change="onConvChange" />
      <el-empty v-else description="暂无会话(去『目标接入』新建项目)" :image-size="54" />
    </aside>

    <!-- 中:对话流 -->
    <section class="cc-main">
      <header class="cc-main-hd">
        <div class="cc-hd-title">
          <span class="cc-title">{{ activeKey || '选择会话' }}</span>
          <span v-if="conv" class="cc-sub">{{ targetOf[activeKey] }} · {{ allMessages.length }} 步<template v-if="hiddenCount">(窗口 {{ visibleMessages.length }})</template></span>
          <el-button v-if="projectOf[activeKey]" size="small" text type="primary"
            @click="openProjectResults(projectOf[activeKey])">成果</el-button>
        </div>
        <!-- R-A P0-3:子代理不再横排在顶部,收进右侧抽屉 -->
        <div class="cc-hd-right">
          <el-tag v-if="agentFilter" size="small" type="warning" effect="light" closable
            class="cc-filter-chip" @close="agentFilter = ''">只看:{{ agentFilter }}</el-tag>
          <el-button v-if="agents.length" size="small" @click="agentDrawer = true">👥 子代理 ({{ agents.length }})</el-button>
        </div>
      </header>

      <!-- R1:SSE 断线显式提示 + 自动重连状态条 -->
      <div v-if="streamState === 'reconnecting'" class="cc-sse-bar" role="status">
        <span>实时连接已断开,每 3s 自动重连(历史消息不受影响)</span>
        <el-button size="small" text type="primary" @click="retryStream">立即重连</el-button>
      </div>

      <div ref="streamRef" v-loading="loading" class="cc-stream" @scroll.passive="onStreamScroll">
        <el-empty v-if="!allMessages.length && !loading" :description="errMsg || '选择左侧会话查看对话'" />
        <template v-else>
          <!-- R1:顶部哨兵 + 手动翻页入口 -->
          <div ref="topSentinelRef" class="cc-sentinel" aria-hidden="true"></div>
          <div v-if="hiddenCount" class="cc-older">
            <el-button size="small" text type="primary" @click="loadOlder">加载更早消息(还有 {{ hiddenCount }} 条)</el-button>
          </div>
        </template>
        <div v-for="m in visibleMessages" :key="m.seq" :data-seq="m.seq" class="cc-msg" :class="'cc-' + m.kind">
          <!-- 文本气泡 -->
          <template v-if="m.kind === 'user_message' || m.kind === 'assistant_message'">
            <!-- R-A P0-2:推理消息解析 [{"text":...}] 包装,默认折叠成"已思考"一条 -->
            <div v-if="m.reasoning" class="cc-thinkcard">
              <n-collapse v-if="thinkTextOf(m)">
                <n-collapse-item :name="'think-' + m.seq">
                  <template #header>💭 {{ roleLabel(m) }} 已思考 · {{ thinkTextOf(m).length }} 字</template>
                  <div class="cc-think-text">{{ thinkTextOf(m) }}</div>
                </n-collapse-item>
              </n-collapse>
              <div v-else class="cc-think-empty">💭 {{ roleLabel(m) }} 已思考</div>
            </div>
            <template v-else>
              <div class="cc-avatar" :class="m.kind">{{ m.kind === 'user_message' ? '你' : (roleLabel(m)[0] || 'A') }}</div>
              <div class="cc-bubble" :class="m.kind">
                <div class="cc-role">{{ roleLabel(m) }}</div>
                <div class="cc-usertext">{{ m.text }}</div>
              </div>
            </template>
          </template>
          <!-- R-A P0-1 工具卡片:摘要一行(主参数+退出码/耗时);展开=完整参数 kv / 完整输出;无新增信息不渲染折叠 -->
          <div v-else class="cc-toolcard" :class="m.kind">
            <div class="cc-tool-head">
              <el-tag size="small" :type="m.kind === 'tool_call' ? 'warning' : 'success'" effect="light">
                {{ m.kind === 'tool_call' ? '🔧 ' + (m.tool_name || 'tool') : '↩ 返回' }}
              </el-tag>
              <span class="cc-tool-agent">{{ agentCnName(m.agent_name || '') }}</span>
            </div>
            <div v-if="m.kind === 'tool_call'" class="cc-tool-summary">{{ callSummaryOf(m) }}</div>
            <div v-else-if="resultSummaryOf(m)" class="cc-tool-summary">{{ resultSummaryOf(m) }}</div>
            <n-collapse v-if="m.kind === 'tool_call' ? callHasMore(m) : resultHasMore(m)" class="cc-tool-collapse">
              <n-collapse-item :title="m.kind === 'tool_call' ? '完整参数' : '完整输出'" :name="m.seq">
                <div v-if="m.kind === 'tool_call' && fullArgsOf(m)" class="cc-tool-kv">
                  <div v-for="kv in fullArgsOf(m)" :key="kv.k" class="cc-tool-kv-row">
                    <span class="cc-tool-k">{{ kv.k }}</span>
                    <span class="cc-tool-v">{{ kv.v }}</span>
                  </div>
                </div>
                <pre v-else class="cc-raw" v-html="rawHtml(m)"></pre>
              </n-collapse-item>
            </n-collapse>
          </div>
        </div>

        <!-- 热修:本地乐观回声(发送即渲染;失败原地改错误气泡;真实回复进流后消除)-->
        <div v-for="e in echoes" :key="'echo-' + e.id" class="cc-msg cc-user_message">
          <div class="cc-avatar user_message">你</div>
          <div class="cc-bubble user_message" :class="{ 'cc-echo-failed': e.status === 'failed' }">
            <div class="cc-role">你
              <span v-if="e.status === 'sending'" class="cc-dots"><i></i><i></i><i></i></span>
              <span v-else-if="e.status === 'failed'" class="cc-echo-err"> · 发送失败:{{ e.err }}</span>
              <span v-else> · 已提交</span>
            </div>
            <div class="cc-usertext">{{ e.text }}</div>
          </div>
        </div>

        <!-- F5 阻断式审批气泡(AG-UI INTERRUPT:待批期间阻断 composer)-->
        <div v-if="approvals.length" class="cc-appr-block">
          <div class="cc-appr-hd">⚠ 人工确认门 {{ approvals.length }} 项待批 · 已阻断输入(就地批,执行仍走服务端 gate 写盘校验)</div>
          <div v-for="a in approvals" :key="a.id" class="cc-appr-bubble">
            <el-tag size="small" type="warning" effect="light">{{ a.kind }}</el-tag>
            <span class="cc-appr-text">{{ a.text }}</span>
            <el-button size="small" type="primary" @click="decideApproval(a, true)">批准</el-button>
            <el-button size="small" type="danger" plain @click="decideApproval(a, false)">拒绝</el-button>
          </div>
        </div>
      </div>

      <!-- 底:composer + 运行控制(有 pending 审批时阻断)-->
      <footer class="cc-composer">
        <div class="cc-composer-row">
          <el-input v-model="composer" type="textarea" :rows="2" resize="none" :disabled="approvals.length > 0"
            :placeholder="approvals.length ? '有待批确认门,先就地批准/拒绝后再输入' : '给该会话追加指导(console 直发,排队处理;触发人工门时就地出审批按钮)。回车发送 / Shift+回车换行'"
            @keyup.enter.exact.prevent="onSend" />
          <div class="cc-composer-btns">
            <el-button type="primary" :loading="sending" :disabled="!composer.trim() || !activeKey || approvals.length > 0" @click="onSend">发送</el-button>
            <el-button :disabled="!activeKey || sending" :loading="sending && !composer.trim()" @click="onFork">分叉</el-button>
          </div>
        </div>
        <span v-if="sendMsg" class="cc-sendmsg">{{ sendMsg }}</span>
      </footer>

      <!-- R-A P0-3:子代理右侧抽屉(默认收起;同名聚合 ×N;点击跳转首条消息)-->
      <n-drawer v-model:show="agentDrawer" :width="320" placement="right">
        <n-drawer-content title="子代理" closable>
          <div v-if="agentFilter" class="cc-agdraw-filter">
            <span>当前只看「{{ agentFilter }}」</span>
            <el-button size="small" text type="primary" @click="agentFilter = ''">显示全部</el-button>
          </div>
          <div v-for="g in agentGroups" :key="g.key" class="cc-agdraw-row" @click="jumpToAgent(g)">
            <div class="cc-agdraw-main">
              <span class="cc-agdraw-name">{{ g.cn }}<span v-if="g.count > 1" class="cc-agdraw-count"> ×{{ g.count }}</span></span>
              <span class="cc-agdraw-meta">{{ g.done ? '已完成' : '运行中' }} · {{ g.msgCount }} 条消息</span>
            </div>
            <el-button size="small" text type="primary" @click.stop="filterAgentGroup(g)">只看</el-button>
          </div>
          <el-empty v-if="!agentGroups.length" description="无子代理" :image-size="48" />
        </n-drawer-content>
      </n-drawer>
    </section>
  </div>
</template>

<style scoped>
.cc { display: flex; gap: 12px; height: 100%; padding: 12px; box-sizing: border-box; background: var(--pa-bg, #f4f6f8); }
.cc-side { width: 268px; flex: none; background: #fff; border: 1px solid var(--pa-border, #e6ebee); border-radius: 12px; padding: 10px; overflow: auto; display: flex; flex-direction: column; box-shadow: var(--pa-shadow-soft, none); }
.cc-side-hd { font-size: 13px; color: #6b7280; font-weight: 700; margin: 4px 6px 10px; }
.cc-conv { flex: 1; }
.cc-main { flex: 1; min-width: 0; display: flex; flex-direction: column; background: #fff; border: 1px solid var(--pa-border, #e6ebee); border-radius: 12px; overflow: hidden; box-shadow: var(--pa-shadow-soft, none); }
.cc-main-hd { padding: 12px 18px; border-bottom: 1px solid #f1f2f4; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.cc-title { font-weight: 700; font-size: 15px; }
.cc-sub { color: #6b7280; font-size: 12px; margin-left: 10px; }
.cc-hd-right { display: flex; align-items: center; gap: 8px; flex: none; }
.cc-filter-chip { cursor: pointer; }
.cc-agdraw-filter { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 13px; color: #b45309; background: #fffbf2; border: 1px solid #fde9c8; border-radius: 8px; padding: 6px 10px; margin-bottom: 10px; }
.cc-agdraw-row { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 8px; cursor: pointer; }
.cc-agdraw-row:hover { background: #f4f6f8; }
.cc-agdraw-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.cc-agdraw-name { font-size: 14px; color: #1f2937; font-weight: 600; }
.cc-agdraw-count { color: #6366f1; }
.cc-agdraw-meta { font-size: 12px; color: #6b7280; }
.cc-flash { animation: cc-flash-bg 1.6s ease; border-radius: 10px; }
@keyframes cc-flash-bg { 0%, 60% { background: #fef3c7; } 100% { background: transparent; } }
.cc-thinkcard { flex: 1; min-width: 0; background: #fff; border: 1px solid var(--pa-border, #e6ebee); border-radius: 10px; padding: 2px 12px; }
.cc-think-text { font-size: 13px; color: #4b5563; white-space: pre-wrap; word-break: break-word; line-height: 1.6; padding-bottom: 8px; }
.cc-think-empty { font-size: 13px; color: #6b7280; padding: 6px 0; }
.cc-sse-bar { display: flex; align-items: center; justify-content: center; gap: 10px; padding: 6px 14px; background: #fffbf2; border-bottom: 1px solid #fde9c8; color: #b45309; font-size: 13px; }
.cc-sentinel { height: 1px; flex: none; }
.cc-older { display: flex; justify-content: center; flex: none; }
.cc-appr-block { align-self: stretch; border: 1px solid #f5c46b; background: #fffbf2; border-radius: 12px; padding: 10px 14px; box-shadow: 0 2px 8px rgba(245, 158, 11, .12); }
.cc-appr-hd { font-size: 12px; color: #b45309; font-weight: 700; }
.cc-appr-bubble { display: flex; align-items: center; gap: 8px; margin-top: 8px; background: #fff; border: 1px solid #fde9c8; border-radius: 10px; padding: 8px 10px; }
.cc-appr-text { flex: 1; font-size: 13px; color: #374151; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cc-stream { flex: 1; overflow: auto; padding: 18px 22px; display: flex; flex-direction: column; gap: 14px; }
.cc-msg { display: flex; gap: 10px; max-width: 900px; }
.cc-user_message { flex-direction: row-reverse; align-self: flex-end; }
.cc-assistant_message { align-self: flex-start; }
.cc-tool_call, .cc-tool_result { align-self: flex-start; max-width: 900px; width: 100%; }
.cc-avatar { flex: none; width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; font-size: 12px; font-weight: 700; color: #fff; }
.cc-avatar.user_message { background: #178e8b; }
.cc-avatar.assistant_message { background: #6366f1; }
.cc-bubble { padding: 10px 14px; border-radius: 12px; font-size: 14px; line-height: 1.6; }
.cc-bubble.user_message { background: var(--pa-primary-pressed, #12706d); color: #fff; border-bottom-right-radius: 4px; }
.cc-bubble.assistant_message { background: #f6f7f9; color: #1f2937; border: 1px solid #eef0f3; border-bottom-left-radius: 4px; }
.cc-role { font-size: 12px; opacity: .9; margin-bottom: 3px; }
.cc-usertext { white-space: pre-wrap; word-break: break-word; }
.cc-toolcard { background: #fff; border: 1px solid var(--pa-border, #e6ebee); border-radius: 10px; padding: 8px 12px; box-shadow: var(--pa-shadow-soft, none); }
.cc-tool-head { display: flex; align-items: center; gap: 8px; }
.cc-tool-agent { font-size: 12px; color: #6b7280; }
.cc-tool-kv { margin-top: 6px; display: grid; gap: 3px; }
.cc-tool-kv-row { display: flex; gap: 10px; font-size: 13px; line-height: 1.5; }
.cc-tool-k { flex: none; min-width: 96px; color: #5f7180; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.cc-tool-v { min-width: 0; color: #1f2d36; white-space: pre-wrap; word-break: break-all; }
.cc-tool-summary { margin-top: 6px; font-size: 13px; line-height: 1.5; color: #374151; white-space: pre-wrap; word-break: break-word; }
.cc-tool-collapse { margin-top: 6px; }
.cc-raw { margin: 0; padding: 10px 12px; background: #f6f8fa; border: 1px solid #eef1f4; color: #1f2937; border-radius: 8px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; line-height: 1.6; max-height: 360px; overflow: auto; white-space: pre-wrap; word-break: break-word; }
/* 浅色语法高亮(GitHub light 色系,对比度 ≥4.5:1) */
.cc-raw :deep(.tk-k) { color: #953800; }
.cc-raw :deep(.tk-s) { color: #0a3069; }
.cc-raw :deep(.tk-n) { color: #0550ae; }
.cc-raw :deep(.tk-b) { color: #cf222e; }
.cc-composer { border-top: 1px solid #f1f2f4; padding: 12px 18px; }
.cc-composer-row { display: flex; gap: 10px; align-items: stretch; }
.cc-composer-row :deep(.el-textarea) { flex: 1; }
.cc-composer-btns { display: flex; flex-direction: column; gap: 6px; justify-content: center; }
.cc-sendmsg { display: block; margin-top: 6px; font-size: 13px; color: var(--pa-primary-pressed, #12706d); }
/* 热修:乐观回声——等待三点动画 + 失败气泡 */
.cc-dots { display: inline-flex; gap: 3px; margin-left: 6px; vertical-align: middle; }
.cc-dots i { width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: cc-blink 1s infinite; }
.cc-dots i:nth-child(2) { animation-delay: .2s; }
.cc-dots i:nth-child(3) { animation-delay: .4s; }
@keyframes cc-blink { 0%, 80%, 100% { opacity: .25; } 40% { opacity: 1; } }
.cc-echo-failed { background: #b42318 !important; }
.cc-echo-err { color: #ffd9d4; }
</style>
