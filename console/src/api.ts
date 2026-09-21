import type { DashboardSnapshot } from './dashboard'
import type { ScopePreview, ScopeReject } from './scopeDocument'

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** 解析成功的响应体;409 的冲突里带 pending 预览,界面据此切到确认步。 */
    readonly body?: unknown
  ) {
    super(message)
  }
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...init.headers
    },
    ...init
  })
  if (!response.ok) {
    // 热修:尽力带出后端 detail(如 invalid_profile/invalid_target),前端可直接展示失败原因
    let detail = ''
    let body: unknown
    try {
      body = await response.clone().json() as { detail?: unknown }
      if (typeof (body as { detail?: unknown })?.detail === 'string') {
        detail = (body as { detail: string }).detail
      }
    } catch { /* 非 JSON 响应 */ }
    throw new ApiError(detail ? `${detail}(http ${response.status})` : `request_failed_${response.status}`, response.status, body)
  }
  return response
}

export async function loadDashboard(): Promise<DashboardSnapshot> {
  const response = await request('/api/v1/dashboard', { cache: 'no-store' })
  return (await response.json()) as DashboardSnapshot
}

export async function login(password: string): Promise<void> {
  await request('/api/v1/session', {
    method: 'POST',
    body: JSON.stringify({ password })
  })
}

export async function logout(): Promise<void> {
  await request('/api/v1/session', { method: 'DELETE' })
}

// ---- 只读业务面板(补回 py 仪表盘的数据) ----
export interface FindingRow { task: string; rule: string; severity: string; title: string; target?: string; ts?: number }
export interface ProfileRow {
  id: string; label: string; aliases: string[]
  default_goal: boolean; auto_continue: boolean; broadcast_level: string; stop_conditions: string[]
}
export interface SystemInfo {
  mem: { total_mb?: number; avail_mb?: number; used_pct?: number }
  services: Record<string, string>
  scheduler: { rss_last_run?: number; rss_seen?: number; rss_last_notified?: number; rss_last_new?: number; keyleak_last_run?: number; keyleak_status?: string; gh_events_last_run?: number; gh_events_status?: string; gh_events_poll?: number; socks_last_run?: number; socks_status?: string }
}
/** up=null 是"配了但没探测过"——三态,不是布尔。probed=false 时别把它画成 down。 */
export interface ModelProvider {
  name: string; model: string; host: string
  up: boolean | null; latency_ms?: number | null; probed: boolean
}
export interface ModelPool {
  checked_at?: number | null
  /** 有没有真实探测结果。false = 列表来自本机配置,不是健康检查。 */
  probed?: boolean
  /** status_file(探测过) | configured(只有配置) | none */
  source?: string
  total?: number; up?: number | null
  providers: ModelProvider[]; active?: string | null; active_model?: string | null
  active_set_at?: number
}

export interface SrcCandidate {
  candidate_id: string; intent_id: string; url: string; path: string; priority: number
  sources: string[]; phase: string; status: string; requires_human_review: boolean; updated_at: number
}
export interface SrcIntent {
  intent_id: string; candidate_id: string; target?: string; priority: number; phase: string; status: string
  requires_human_review: boolean; updated_at: number
  depends_on?: string[]; attempts?: number; max_attempts?: number; last_error?: string
}
export interface SrcClaim { intent_id: string; worker_id: string; heartbeat_at: number; lease_expires_at: number }
export interface SrcDeadEnd { intent_id: string; reason: string; detail: string; created_at: number }
export interface SrcHint { intent_id: string; hint: string; source: string; created_at: number }
export interface SrcWorkmem { goal?: string; focus?: string; todos?: { todo_id: string; text: string; status: string }[] }
export interface SrcTimelineItem { kind: string; summary: string; at: number }
export interface SrcAutopilotView {
  schema: 'SrcAutopilotView/v1'; available: boolean; revision?: number; error?: string
  run: { run_id?: string; status?: string; round?: number; max_rounds?: number; stop_reason?: string; candidate_count?: number; no_new_rounds?: number; updated_at?: number }
  candidates: SrcCandidate[]; intents: SrcIntent[]; claims: SrcClaim[]; dead_ends: SrcDeadEnd[]; hints: SrcHint[]
  workmem?: SrcWorkmem; timeline?: SrcTimelineItem[]
}

export async function loadSrcAutopilot(): Promise<SrcAutopilotView> {
  return (await (await request('/api/v1/src-autopilot', { cache: 'no-store' })).json()) as SrcAutopilotView
}
export async function loadFindings(): Promise<FindingRow[]> {
  return (await (await request('/api/v1/findings', { cache: 'no-store' })).json()) as FindingRow[]
}
export async function loadSystem(): Promise<SystemInfo> {
  return (await (await request('/api/v1/system', { cache: 'no-store' })).json()) as SystemInfo
}
export async function loadModelPool(): Promise<ModelPool> {
  return (await (await request('/api/v1/models', { cache: 'no-store' })).json()) as ModelPool
}
// R2: 切换活跃 provider(写运行时状态文件,model_client 下次调用即生效)
export async function setActiveModel(name: string): Promise<{ ok: boolean; active: string; model: string; up: boolean }> {
  return (await (await request('/api/v1/model/active', { method: 'POST', body: JSON.stringify({ name }) })).json())
}

// ---- LLM 供应商设置(界面配 key + 分层模型)。接口只回掩码,绝不回 api_key。----
export interface LlmProviderView {
  name: string
  base_url: string
  model: string
  key_set: boolean
  key_hint: string
}
export interface LlmProviderInput {
  name: string
  base_url: string
  model: string
  api_key?: string
  clear_key?: boolean
}
export interface LlmSettingsView {
  schema: string
  updated_at: number
  providers: LlmProviderView[]
  tiers: Record<string, string>
  settings_path?: string
  effective?: {
    providers_env_override: boolean
    legacy_env_override: boolean
    reasoner_prefer: string
    explorer_prefer: string
  }
}
export interface LlmTestResult {
  ok: boolean
  name: string
  model: string
  latency_ms: number
  error: string
}

export async function loadLlmSettings(): Promise<LlmSettingsView> {
  return (await (await request('/api/v1/llm/settings', { cache: 'no-store' })).json()) as LlmSettingsView
}
export async function saveLlmSettings(
  providers: LlmProviderInput[],
  tiers: Record<string, string>
): Promise<LlmSettingsView & { ok: boolean; applied_env?: string[] }> {
  return (await (await request('/api/v1/llm/settings', {
    method: 'PUT',
    body: JSON.stringify({ providers, tiers })
  })).json())
}
export async function testLlmProvider(payload: { name?: string; provider?: LlmProviderInput }): Promise<LlmTestResult> {
  return (await (await request('/api/v1/llm/test', {
    method: 'POST',
    body: JSON.stringify(payload)
  })).json()) as LlmTestResult
}
export async function loadReport(taskId: string): Promise<string> {
  return await (await request(`/api/v1/report?task_id=${encodeURIComponent(taskId)}`, { cache: 'no-store' })).text()
}
export async function loadProfiles(): Promise<ProfileRow[]> {
  return (await (await request('/api/v1/profiles', { cache: 'no-store' })).json()) as ProfileRow[]
}

// ---- P5: 项目 → 会话 → 轨迹 ----
export interface ProjectCard {
  project_id: string; target: string; profiles: string[]
  session_count: number; task_count: number; finding_count: number; verified_finding_count: number
  status: string; last_activity: number
}
export interface SessionTask { task_id: string; status: string; run_id: string }
export interface SessionCard {
  session_id: string; profile_name: string; created_at: number
  audited_endpoint_count: number; endpoint_count: number
  finding_count: number; verified_finding_count: number
  stop_condition: string | null; status: string; tasks: SessionTask[]
}
export interface ProjectDetail { project_id: string; target: string; sessions: SessionCard[] }
export interface TrajectoryEvent { seq: number; ts: number; source: string; kind: string; summary: string }

/** 项目列表是分页的:total 是全部项目数,不是本页数量。 */
export interface ProjectPage {
  projects: ProjectCard[]; total: number; offset: number; limit: number
}
export const PROJECT_PAGE_SIZE = 20
export async function loadProjects(offset = 0, limit = PROJECT_PAGE_SIZE): Promise<ProjectPage> {
  const q = `?offset=${offset}&limit=${limit}`
  return (await (await request(`/api/v1/projects${q}`, { cache: 'no-store' })).json()) as ProjectPage
}
export async function loadProject(id: string): Promise<ProjectDetail> {
  return (await (await request(`/api/v1/project?id=${encodeURIComponent(id)}`, { cache: 'no-store' })).json()) as ProjectDetail
}
export async function loadTrajectory(id: string): Promise<TrajectoryEvent[]> {
  return (await (await request(`/api/v1/trajectory?id=${encodeURIComponent(id)}`, { cache: 'no-store' })).json()) as TrajectoryEvent[]
}

// ---- P5-e 会话交互续跑指导 ----
export interface SessionGuidanceRow { id: string; session_id: string; target: string; guidance: string; status: string; created_at: number }
export async function submitSessionGuidance(p: { session_id: string; target: string; guidance: string }): Promise<{ ok: boolean; id: string; note: string }> {
  return (await (await request('/api/v1/session/guidance', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function loadSessionGuidance(id: string): Promise<SessionGuidanceRow[]> {
  return (await (await request(`/api/v1/session/guidance?id=${encodeURIComponent(id)}`, { cache: 'no-store' })).json()) as SessionGuidanceRow[]
}

// ---- P5-b 新建项目:预览 → 确认 → TargetCard ----
// 走的是 core.intake_state 那套门:提交只铸一个 digest 绑定的预览(什么都不执行),
// 确认时必须回显 intake_id + options_digest,门核对上了才落不可变的 TargetCard。
export interface ProjectIntakeToggles {
  scan_enabled?: boolean; fingerprint_precise?: boolean; nuclei?: boolean; tscan?: boolean
  asset_inventory?: boolean; subdomain_enum?: boolean; intel?: boolean; poc_research?: boolean
  proxy_route?: boolean; network_gate?: boolean; edge_human_gate?: boolean
}
export interface ProjectIntakePayload {
  target_url: string; instruction: string; engagement_profile: string; toggles: ProjectIntakeToggles
}
/** 门里的 options 单开关形态(能力型带 mode,代理路由带 profile)。 */
export interface IntakeOption { enabled?: boolean; mode?: string; profile?: string }
export interface IntakePreview {
  intake_id: string; target: string; canonical_host: string; entrypoint: string
  instruction: string; instruction_digest: string
  profile_name: string; goal_id: string
  options: Record<string, IntakeOption>
  options_digest: string; preview_digest: string; scope_digest: string
  created_at: number; expires_at: number
}
export interface IntakePreviewResult extends IntakePreview { ok: boolean; status: string }
export interface IntakeRun {
  session_id: string; job_id: string
  /** true = 这次确认的run早就在跑(重放/双击),没有第二次开跑。 */
  reused: boolean
}
export interface IntakeConfirmResult {
  ok: boolean; status: string
  intake_id: string; target: string; canonical_host: string
  profile_name: string; instruction: string; options_digest: string
  target_id: string; target_card_digest: string; target_card_ref: string; note: string
  run: IntakeRun | null
}
export interface PendingIntakeRow {
  intake_id: string; target: string; profile_name: string
  enabled_options: string[]; created_at: number; expires_at: number
}
export async function startProjectIntake(p: ProjectIntakePayload): Promise<IntakePreviewResult> {
  return (await (await request('/api/v1/project/intake', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function confirmProjectIntake(p: { intake_id: string; options_digest: string }): Promise<IntakeConfirmResult> {
  return (await (await request('/api/v1/project/intake/confirm', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function discardProjectIntake(): Promise<{ ok: boolean; discarded: boolean }> {
  return (await (await request('/api/v1/project/intake/discard', { method: 'POST' })).json())
}
export async function loadPendingIntake(): Promise<{
  preview: IntakePreview | null
  scope_preview: ScopePreview | null
  scope_rejects: ScopeReject[]
  ttl_seconds: number
}> {
  return (await (await request('/api/v1/project/intake/pending', { cache: 'no-store' })).json())
}

// ---- 授权文档:一份 scope 文件 → 一次确认 → 每台主机一个 job ----
// 和上面那条链共用同一个待确认槽,只是确认的东西从"一个目标"变成"一份授权"。
// 判定在服务端:这里不做 looksLikeScopeDocument 的镜像 —— 两份判定会互相走样。
export interface ScopeIntakePayload {
  text?: string
  document?: Record<string, unknown>
  filename?: string
  instruction?: string
}
export interface ScopeIntakePreviewResult extends ScopePreview { ok: boolean; status: string }
export interface ScopeIntakeRun {
  session_id: string
  turn_id: string
  job_ids: string[]
  launched: number
  created: number
  /** true = 这次确认的 job 早就在跑(重放/续跑),没有第二次开跑。 */
  reused: boolean
  hosts: string[]
  /** 超出文档自己写的上限、这次没起的台数。 */
  skipped: number
}
export interface ScopeIntakeConfirmResult {
  ok: boolean
  status: string
  intake_id: string
  program: string
  instruction: string
  options_digest: string
  document_digest: string
  authorization_id: string
  authorization_digest: string
  authorization_ref: string
  hosts: string[]
  max_fanout: number
  /** 这次 run 允许的动词。只列出闸门真会发的那些,声明了但恒被拒的不在其中。 */
  allowed_methods: string[]
  allow_request_body: boolean
  requests_per_second: number
  run: ScopeIntakeRun | null
  note: string
}
export async function startScopeIntake(p: ScopeIntakePayload): Promise<ScopeIntakePreviewResult> {
  return (await (await request('/api/v1/project/engagement/preview', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function confirmScopeIntake(p: { intake_id: string; options_digest: string }): Promise<ScopeIntakeConfirmResult> {
  return (await (await request('/api/v1/project/engagement/confirm', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function discardScopeIntake(): Promise<{ ok: boolean; discarded: boolean }> {
  return (await (await request('/api/v1/project/engagement/discard', { method: 'POST' })).json())
}
/** 提交队列。status 区分"确实没有待确认"和"台账文件/锁不在"——空队列有两种意思。
 *  取值与后端 _read_events 一致:available / partial / missing / unavailable。 */
export interface PendingIntakeQueue { intakes: PendingIntakeRow[]; status: string }

export async function loadProjectIntakes(): Promise<PendingIntakeQueue> {
  const body = (await (await request('/api/v1/project/intakes', { cache: 'no-store' })).json()) as
    | PendingIntakeQueue
    | PendingIntakeRow[]
  // 兼容旧形态:后端没给 status 时按"可读"处理,不把一个老响应说成故障。
  return Array.isArray(body) ? { intakes: body, status: 'available' } : body
}

// ---- P5-c 成果一键浏览 ----
export interface AttackChain {
  goal: string; value: number; status: string
  satisfied_by: string[]; missing: string[]; supporting_evidence: string[]
  need_human: boolean; need_verify: boolean; note: string
}
export interface AttackGraphSummary {
  target?: string; evidence_count?: number; artifacts?: string[]
  chains?: AttackChain[]; closed_chains?: AttackChain[]
}
export interface PttLeaf { label: string; value: number; status: string; kind: string }
export interface PttSummary { target?: string; total?: number; counts?: Record<string, number>; top_leaves?: PttLeaf[] }
export interface ProjectResults {
  project_id: string; target: string; session_count: number
  severity: Record<string, number>
  findings: FindingRow[]
  reports: Array<{ task_id: string }>
  attack_graph?: AttackGraphSummary
  ptt?: PttSummary
}
export async function loadProjectResults(id: string): Promise<ProjectResults> {
  return (await (await request(`/api/v1/project/results?id=${encodeURIComponent(id)}`, { cache: 'no-store' })).json()) as ProjectResults
}


// ---- #75 资产 hash 变化监控 ----

// ---- #76 资讯雷达数据源管理 ----

// ---- #53 指纹自修正(人工确认门) ----


// ---- #80 PoC 审批(替代 pa-poc-admin) ----

// ---- #70 免费 socks 池 ----

// ---- #21 代理订阅入口 ----

// ---- #74 出站 egress 门(被拦列表 + 放行 + mihomo 规则) ----

// ---- #60 自进化反思(卡片+人工门) ----

// ---- 统一对话:模式 / 会话 / 回合 / 事件流 ----
// 后端契约见 console/routers/chat.py;事件形状见 core/event_log.py。
// 回合是持久化任务:POST 返回 202,进度由 SSE 事件流回放。
export interface ChatMode {
  name: string; title: string; skill: string; tier: string; autonomy: string; tools: string[]
}
export interface ChatModesView { modes: ChatMode[]; default: string }
export interface ChatSession { session_id: string; mode: string }
export interface ChatTurn { session_id: string; turn_id: string; job_id: string }
export interface ChatStopResult { ok: boolean; job_ids?: string[]; reason?: string }

/** 事件载荷由后端按 `kind` 决定,这里只固定公共信封与已用到的字段。 */
export interface ChatEvent {
  seq: number; ts: number
  session_id?: string; turn_id?: string; agent_id?: string
  kind: string
  text?: string; delta?: string; reasoning?: string
  mode?: string; phase?: string; title?: string; target?: string
  job_id?: string; job_kind?: string; findings?: number
  tool?: string; args?: string; result?: string; call_id?: string
  severity?: string; endpoint?: string; confidence?: string; evidence?: string; detail?: string
  gate?: string; message?: string
  [key: string]: unknown
}
export interface ActiveJob {
  job_id: string; kind: string; target: string
}
export interface ChatEventsPage {
  events: ChatEvent[]
  max_seq: number
  /** 这条会话上还在跑的 job。attach 到一条已经在跑的运行流时,靠它认出不能往里发。 */
  active_jobs?: ActiveJob[]
}

export async function loadChatModes(): Promise<ChatModesView> {
  return (await (await request('/api/v1/modes', { cache: 'no-store' })).json()) as ChatModesView
}
export async function newChatSession(mode = ''): Promise<ChatSession> {
  return (await (await request('/api/v1/chat/sessions', {
    method: 'POST',
    body: JSON.stringify({ mode })
  })).json()) as ChatSession
}
export async function loadChatEvents(sessionId: string, since = 0, limit = 500): Promise<ChatEventsPage> {
  const q = `?since=${since}&limit=${limit}`
  return (await (await request(`/api/v1/chat/sessions/${encodeURIComponent(sessionId)}/events${q}`, { cache: 'no-store' })).json()) as ChatEventsPage
}
export async function sendChatTurn(sessionId: string, text: string, mode = ''): Promise<ChatTurn> {
  return (await (await request(`/api/v1/chat/sessions/${encodeURIComponent(sessionId)}/messages`, {
    method: 'POST',
    body: JSON.stringify({ text, mode })
  })).json()) as ChatTurn
}
export async function stopChatTurn(sessionId: string): Promise<ChatStopResult> {
  return (await (await request(`/api/v1/chat/sessions/${encodeURIComponent(sessionId)}/turn/stop`, {
    method: 'POST'
  })).json()) as ChatStopResult
}
