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
export interface IntelRow {
  ts?: number; date: string; update_reason: string; cve: string; severity: string; cvss: string; title: string
  summary?: string; value?: string; kind?: string; source?: string; tags?: string[]; score?: number
  has_poc: boolean; poc_source: string; in_the_wild: boolean; refs: string[]
}
export interface FindingRow { task: string; rule: string; severity: string; title: string; target?: string; ts?: number }
export interface KeyRow {
  service: string; repo: string; path: string; source_url: string; usable: boolean | null; tail: string
  status: string; has_enc: boolean; key: string
  detail: string; assoc_url: string; assoc_kind: string; ts?: number
}
export interface ProfileRow {
  id: string; label: string; aliases: string[]
  default_goal: boolean; auto_continue: boolean; broadcast_level: string; stop_conditions: string[]
}
export interface TaskDetail {
  task_id: string
  coverage?: unknown; expectation?: unknown; acceptance?: unknown; scope?: unknown
  findings?: FindingRow[]
}
export interface SystemInfo {
  mem: { total_mb?: number; avail_mb?: number; used_pct?: number }
  services: Record<string, string>
  scheduler: { rss_last_run?: number; rss_seen?: number; rss_last_notified?: number; rss_last_new?: number; keyleak_last_run?: number; keyleak_status?: string; gh_events_last_run?: number; gh_events_status?: string; gh_events_poll?: number; socks_last_run?: number; socks_status?: string }
}
export interface ModelProvider { name: string; model: string; host: string; up: boolean; latency_ms?: number }
export interface ModelPool { checked_at?: number; total?: number; up?: number; providers: ModelProvider[]; active?: string | null; active_model?: string | null; active_set_at?: number }
export interface ProxyStatus { enabled: boolean; up: boolean; node: string; node_count: number; this_round_proxied: boolean; checked_at?: number; error?: string }

export interface SrcCandidate {
  candidate_id: string; intent_id: string; url: string; path: string; priority: number
  sources: string[]; phase: string; status: string; requires_human_review: boolean; updated_at: number
}
export interface SrcIntent {
  intent_id: string; candidate_id: string; priority: number; phase: string; status: string
  requires_human_review: boolean; updated_at: number
}
export interface SrcClaim { intent_id: string; worker_id: string; heartbeat_at: number; lease_expires_at: number }
export interface SrcDeadEnd { intent_id: string; reason: string; detail: string; created_at: number }
export interface SrcHint { intent_id: string; hint: string; source: string; created_at: number }
export interface SrcAutopilotView {
  schema: 'SrcAutopilotView/v1'; available: boolean; revision?: number; error?: string
  run: { run_id?: string; status?: string; round?: number; max_rounds?: number; stop_reason?: string; candidate_count?: number; no_new_rounds?: number; updated_at?: number }
  candidates: SrcCandidate[]; intents: SrcIntent[]; claims: SrcClaim[]; dead_ends: SrcDeadEnd[]; hints: SrcHint[]
}

export async function loadIntel(limit = 60): Promise<IntelRow[]> {
  return (await (await request(`/api/v1/intel?limit=${limit}`, { cache: 'no-store' })).json()) as IntelRow[]
}
export async function loadSrcAutopilot(): Promise<SrcAutopilotView> {
  return (await (await request('/api/v1/src-autopilot', { cache: 'no-store' })).json()) as SrcAutopilotView
}
export async function loadFindings(): Promise<FindingRow[]> {
  return (await (await request('/api/v1/findings', { cache: 'no-store' })).json()) as FindingRow[]
}
export async function loadKeys(): Promise<KeyRow[]> {
  return (await (await request('/api/v1/keys', { cache: 'no-store' })).json()) as KeyRow[]
}
export async function unlockKeys(password: string): Promise<{ ok: boolean; unlocked_until: number }> {
  return (await (await request('/api/v1/keys/unlock', { method: 'POST', body: JSON.stringify({ password }) })).json())
}
export async function lockKeys(): Promise<void> {
  await request('/api/v1/keys/lock', { method: 'POST' })
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
export async function loadProxy(): Promise<ProxyStatus> {
  return (await (await request('/api/v1/proxy', { cache: 'no-store' })).json()) as ProxyStatus
}
export async function loadReport(taskId: string): Promise<string> {
  return await (await request(`/api/v1/report?task_id=${encodeURIComponent(taskId)}`, { cache: 'no-store' })).text()
}
export async function loadProfiles(): Promise<ProfileRow[]> {
  return (await (await request('/api/v1/profiles', { cache: 'no-store' })).json()) as ProfileRow[]
}
export async function loadTask(id: string): Promise<TaskDetail> {
  return (await (await request(`/api/v1/task?id=${encodeURIComponent(id)}`, { cache: 'no-store' })).json()) as TaskDetail
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

// ---- F1 对话台:Strix 真实多智能体对话(agents.db) ----
export interface ConvAgent { agent_id: string; name: string; parent: string | null; status: string }
export interface ConvMessage {
  seq: number; ts?: string; agent_id: string; agent_name: string
  kind: 'user_message' | 'assistant_message' | 'tool_call' | 'tool_result'
  text?: string; status?: string; reasoning?: boolean
  call_id?: string; tool_name?: string; tool_args?: string; output?: string
}
export interface Conversation { session_id: string; agents: ConvAgent[]; messages: ConvMessage[]; counts: Record<string, number> }
export async function loadConversation(id: string, limit = 2000): Promise<Conversation> {
  return (await (await request(`/api/v1/conversation?id=${encodeURIComponent(id)}&limit=${limit}`, { cache: 'no-store' })).json()) as Conversation
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

// ---- P5-c 舰队(跨项目谁在跑) ----
export interface FleetRow {
  task_id: string; project_id: string; target: string; status: string
  run_id: string; created_at?: number; last_kind: string; last_event: string
}
export interface Fleet { count: number; running: FleetRow[] }
export async function loadFleet(): Promise<Fleet> {
  return (await (await request('/api/v1/fleet', { cache: 'no-store' })).json()) as Fleet
}

// ---- #75 资产 hash 变化监控 ----
export interface AssetChangeRow {
  ts?: number; target: string; summary: string
  new_endpoints: string[]; changed_artifacts: string[]; new_artifacts: string[]; aggregate_after: string
}
export async function loadAssetChanges(limit = 80): Promise<AssetChangeRow[]> {
  return (await (await request(`/api/v1/asset-changes?limit=${limit}`, { cache: 'no-store' })).json()) as AssetChangeRow[]
}

// ---- #76 资讯雷达数据源管理 ----
export interface IntelSourceRow {
  id: string; kind: string; name: string; url: string; enabled: boolean; trusted: boolean; tags: string[]
  status?: string; last_run?: string; last_error?: string; item_count?: number; query?: string
}
export async function loadIntelSources(): Promise<IntelSourceRow[]> {
  return (await (await request('/api/v1/intel/sources', { cache: 'no-store' })).json()) as IntelSourceRow[]
}
export async function addIntelSource(p: { kind: string; name: string; url: string; extract_hint?: string; query?: string; interval_sec?: number }): Promise<{ ok: boolean; id: string }> {
  return (await (await request('/api/v1/intel/sources', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function toggleIntelSource(id: string, enabled: boolean): Promise<void> {
  await request('/api/v1/intel/sources/toggle', { method: 'POST', body: JSON.stringify({ id, enabled }) })
}
export async function removeIntelSource(id: string): Promise<void> {
  await request(`/api/v1/intel/sources?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
}
export interface IntelWatchState {
  status: string; program?: string; started_at?: string; last_run_at?: string; stopped_at?: string
  runs_completed: number; last_run_id: string; consecutive_errors: number; last_error: string; interval_sec: number; recovered_previous?: boolean
}
export async function loadIntelWatch(): Promise<IntelWatchState> {
  return (await (await request('/api/v1/intel/watch', { cache: 'no-store' })).json()) as IntelWatchState
}

// ---- #53 指纹自修正(人工确认门) ----
export interface FingerprintCorrectionRow {
  id: string; kind: string; name: string; evidence: string; target: string; source: string
  status: string; poc_tags: string[]; risk: string
  created_at: number; decided_at: number; applied_at: number
}
export async function loadFingerprintCorrections(status = ''): Promise<FingerprintCorrectionRow[]> {
  const q = status ? `?status=${encodeURIComponent(status)}` : ''
  return (await (await request(`/api/v1/fingerprint/corrections${q}`, { cache: 'no-store' })).json()) as FingerprintCorrectionRow[]
}
export async function proposeFingerprintCorrection(p: { kind: string; name: string; evidence: string; proposed?: Record<string, unknown>; target?: string }): Promise<{ ok: boolean; id: string; status: string; note: string }> {
  return (await (await request('/api/v1/fingerprint/correction', { method: 'POST', body: JSON.stringify(p) })).json())
}
export async function decideFingerprintCorrection(id: string, decision: 'approve' | 'reject', reason = ''): Promise<{ ok: boolean; id: string; status: string }> {
  return (await (await request('/api/v1/fingerprint/correction/decision', { method: 'POST', body: JSON.stringify({ id, decision, reason }) })).json())
}

// ---- #79 sink 签名库(代码审计护城河) ----
export interface SinkKbRow {
  id: string; vuln_class: string; language: string; sink_symbol: string; source: string
  sanitizer_missing: string; cwe: string; status: string; confidence: string; example_ref: string
}
export interface SinkKbResult { stats: Record<string, number>; rows: SinkKbRow[] }
export async function loadSinkKb(status = ''): Promise<SinkKbResult> {
  const q = status ? `?status=${encodeURIComponent(status)}` : ''
  return (await (await request(`/api/v1/sink-kb${q}`, { cache: 'no-store' })).json()) as SinkKbResult
}
export async function decideSinkKb(id: string, decision: 'approve' | 'reject'): Promise<{ ok: boolean; id: string; status: string }> {
  return (await (await request('/api/v1/sink-kb/decision', { method: 'POST', body: JSON.stringify({ id, decision }) })).json())
}

// ---- #80 PoC 审批(替代 pa-poc-admin) ----
export interface PocPendingRow { id: string; ts?: number; reason: string; source: string; cve: string; title: string; url: string; severity: string }
export interface PocLogRow { ts?: number; action?: string; title?: string; cve?: string; source?: string }
export interface PocPending { pending: PocPendingRow[]; log: PocLogRow[] }
export async function loadPocPending(): Promise<PocPending> {
  return (await (await request('/api/v1/poc/pending', { cache: 'no-store' })).json()) as PocPending
}
export async function confirmPoc(id: string, approve: boolean): Promise<{ id: string; action: string }> {
  return (await (await request('/api/v1/poc/confirm', { method: 'POST', body: JSON.stringify({ id, approve }) })).json())
}

// ---- #70 免费 socks 池 ----
export interface SocksRow { addr: string; status: string; latency_ms: number; added_by: string; last_error: string; last_check: number }
export interface SocksPool { stats: Record<string, number>; rows: SocksRow[] }
export async function loadSocks(): Promise<SocksPool> {
  return (await (await request('/api/v1/socks', { cache: 'no-store' })).json()) as SocksPool
}
export async function addSocks(addr: string): Promise<{ ok: boolean; addr: string; result: string }> {
  return (await (await request('/api/v1/socks/add', { method: 'POST', body: JSON.stringify({ addr }) })).json())
}
export async function removeSocks(addr: string): Promise<void> {
  await request(`/api/v1/socks?addr=${encodeURIComponent(addr)}`, { method: 'DELETE' })
}

// ---- #21 代理订阅入口 ----
export interface ProxySubRow { id: string; name: string; url: string; enabled: boolean; added_at: number }
export interface ProxySubs { subs: ProxySubRow[]; mihomo_snippet: string }
export async function loadProxySubs(): Promise<ProxySubs> {
  return (await (await request('/api/v1/proxy/subscriptions', { cache: 'no-store' })).json()) as ProxySubs
}
export async function addProxySub(url: string, name = ''): Promise<{ ok: boolean; id: string }> {
  return (await (await request('/api/v1/proxy/subscriptions', { method: 'POST', body: JSON.stringify({ url, name }) })).json())
}
export async function toggleProxySub(id: string, enabled: boolean): Promise<void> {
  await request('/api/v1/proxy/subscriptions/toggle', { method: 'POST', body: JSON.stringify({ id, enabled }) })
}
export async function removeProxySub(id: string): Promise<void> {
  await request(`/api/v1/proxy/subscriptions?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// ---- #74 出站 egress 门(被拦列表 + 放行 + mihomo 规则) ----
export interface EgressBlockedRow { ts?: number; url: string; host: string; reason: string; context: string }
export interface EgressAllowRow { host: string; added_by: string; reason: string; added_at: number }
export interface EgressView { blocked: EgressBlockedRow[]; allowlist: EgressAllowRow[]; mihomo_rules: string[]; enforced: boolean }
export async function loadEgress(): Promise<EgressView> {
  return (await (await request('/api/v1/egress', { cache: 'no-store' })).json()) as EgressView
}
export async function allowEgress(host: string, reason = ''): Promise<{ ok: boolean; host: string; result: string }> {
  return (await (await request('/api/v1/egress/allow', { method: 'POST', body: JSON.stringify({ host, reason }) })).json())
}
export async function removeEgressAllow(host: string): Promise<void> {
  await request(`/api/v1/egress/allow?host=${encodeURIComponent(host)}`, { method: 'DELETE' })
}

// ---- #60 自进化反思(卡片+人工门) ----
export interface EvolveRow { id: string; kind: string; text: string; category: string; source: string; status: string; created_at: number }
export interface EvolveData { stats: Record<string, number>; rows: EvolveRow[] }
export async function loadEvolve(status = ''): Promise<EvolveData> {
  const q = status ? `?status=${encodeURIComponent(status)}` : ''
  return (await (await request(`/api/v1/evolve${q}`, { cache: 'no-store' })).json()) as EvolveData
}
export async function decideEvolve(id: string, decision: 'approve' | 'reject'): Promise<{ ok: boolean; id: string; status: string }> {
  return (await (await request('/api/v1/evolve/decision', { method: 'POST', body: JSON.stringify({ id, decision }) })).json())
}

// ---- SRC Agent(LLM 驱动的漏洞挖掘:对话 + 会话 + 进度) ----
export interface SrcSession {
  session_id: string
  title?: string
  updated_at: number
  turns?: number
  last_user?: string
  facts?: number
  intents_queued?: number
  intents_done?: number
  hints?: number
  targets?: string[]
}
export interface SrcChatEvent { kind: string; ts: number; tool?: string; args_preview?: string; [k: string]: unknown }
export interface SrcChatReply { session_id: string; reply: string; events: SrcChatEvent[] }
export interface SrcMessage { role: string; content: string }
export interface SrcHistory { session_id: string; messages: SrcMessage[]; events: SrcChatEvent[] }
export interface SrcProgress {
  totals: { targets: number; scans: number; urls_explored: number; total_explores: number; findings: number; dead_ends: number; errors: number }
  findings: Array<{ target?: string; url?: string; type?: string; confidence?: string; evidence?: string; detail?: string; ts?: number }>
  targets: Record<string, Record<string, unknown>>
  sessions?: number
}

export async function loadSrcSessions(): Promise<SrcSession[]> {
  const data = (await (await request('/api/v1/src-agent/sessions', { cache: 'no-store' })).json()) as { sessions: SrcSession[] }
  return data.sessions || []
}
export async function loadSrcHistory(sessionId: string): Promise<SrcHistory> {
  return (await (await request('/api/v1/src-agent/history?session_id=' + encodeURIComponent(sessionId), { cache: 'no-store' })).json()) as SrcHistory
}
export async function sendSrcChat(message: string, sessionId = ''): Promise<SrcChatReply> {
  return (await (await request('/api/v1/src-agent/chat', { method: 'POST', body: JSON.stringify({ message, session_id: sessionId }) })).json()) as SrcChatReply
}
export async function loadSrcProgress(sessionId = ''): Promise<SrcProgress> {
  const q = sessionId ? '?session_id=' + encodeURIComponent(sessionId) : ''
  return (await (await request('/api/v1/src-agent/progress' + q, { cache: 'no-store' })).json()) as SrcProgress
}
