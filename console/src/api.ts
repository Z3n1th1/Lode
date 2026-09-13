import type { DashboardSnapshot } from './dashboard'

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number
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
    try {
      const body = await response.clone().json() as { detail?: unknown }
      if (typeof body?.detail === 'string') detail = body.detail
    } catch { /* 非 JSON 响应 */ }
    throw new ApiError(detail ? `${detail}(http ${response.status})` : `request_failed_${response.status}`, response.status)
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
export interface ModelProvider { name: string; model: string; host: string; up: boolean; latency_ms?: number }
export interface ModelPool { checked_at?: number; total?: number; up?: number; providers: ModelProvider[]; active?: string | null; active_model?: string | null; active_set_at?: number }

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

export async function loadProjects(): Promise<ProjectCard[]> {
  return (await (await request('/api/v1/projects', { cache: 'no-store' })).json()) as ProjectCard[]
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

// ---- P5-b 新建项目(受控写:只提交意图,执行仍走 agent 确认门) ----
export interface ProjectIntakeBrute {
  enabled?: boolean; path?: boolean; port?: boolean; password?: boolean
  username?: boolean; sms?: boolean; subdomain?: boolean
  max_attempts?: number; rate_limit_per_min?: number
}
export interface ProjectIntakeToggles {
  scan_enabled?: boolean; fingerprint_precise?: boolean; nuclei?: boolean; tscan?: boolean
  asset_inventory?: boolean; subdomain_enum?: boolean; intel?: boolean; poc_research?: boolean
  proxy_route?: boolean; network_gate?: boolean; edge_human_gate?: boolean
  brute?: ProjectIntakeBrute
}
export interface ProjectIntakePayload { target_url: string; name?: string; engagement_profile: string; toggles: ProjectIntakeToggles }
export interface ProjectIntakeRow {
  intake_id: string; target_url: string; name: string; engagement_profile: string
  status: string; created_at: number; toggle_on: string[]
}
export async function submitProjectIntake(p: ProjectIntakePayload): Promise<{ ok: boolean; intake_id: string; status: string; note: string }> {
  return (await (await request('/api/v1/project/intake', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function loadProjectIntakes(): Promise<ProjectIntakeRow[]> {
  return (await (await request('/api/v1/project/intakes', { cache: 'no-store' })).json()) as ProjectIntakeRow[]
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
export interface ChatEventsPage { events: ChatEvent[]; max_seq: number }

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
