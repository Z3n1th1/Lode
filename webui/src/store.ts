// F6 拆巨石:原 App.vue 的全部共享状态/逻辑,模块级单例(行为与原单文件一致)。
// 面板组件只import本模块的状态与动作,不各自持状态,保证 20s 轮询/loadPageData 派发不变。
import { computed, h, ref, watch } from 'vue'
import { NButton, NTag, type DataTableColumns } from 'naive-ui'

import {
  ApiError, loadDashboard, login, logout,
  loadIntel, loadFindings, loadKeys, loadSystem, loadModelPool, loadProxy, loadProfiles, loadReport, loadTask,
  loadProjects, loadProject, loadTrajectory, submitSessionGuidance, loadSessionGuidance,
  submitProjectIntake, loadProjectIntakes, loadProjectResults, loadFleet, loadAssetChanges,
  loadIntelSources, addIntelSource, toggleIntelSource, removeIntelSource, loadIntelWatch,
  loadSrcAutopilot,
  loadFingerprintCorrections, decideFingerprintCorrection, type FingerprintCorrectionRow,
  loadSinkKb, decideSinkKb as apiDecideSinkKb, type SinkKbResult,
  loadPocPending, confirmPoc, type PocPending,
  loadSocks, addSocks, removeSocks, type SocksPool,
  loadProxySubs, addProxySub, toggleProxySub, removeProxySub, type ProxySubs,
  loadEgress, allowEgress, removeEgressAllow, type EgressView,
  loadEvolve, decideEvolve as apiDecideEvolve, type EvolveData,
  unlockKeys, lockKeys,
  type IntelRow, type FindingRow, type KeyRow, type SystemInfo, type ProfileRow, type ModelProvider, type ModelPool, type ProxyStatus,
  type ProjectCard, type ProjectDetail, type SessionGuidanceRow, type TrajectoryEvent, type ProjectIntakeRow, type ProjectResults, type Fleet, type AssetChangeRow, type IntelSourceRow, type IntelWatchState, type SrcAutopilotView
} from './api'
import {
  createDashboardView,
  formatTimestamp,
  goalStopLabel,
  taskStatusLabel,
  taskTagType,
  type DashboardGoal,
  type DashboardSnapshot,
  type DashboardTask,
  type SandboxRun
} from './dashboard'

export { formatTimestamp, goalStopLabel, taskStatusLabel, taskTagType }

// ---- 热修:子代理中文短名映射(单一出处;对话气泡与 agent 过滤 chip 共用) ----
// 键为 Strix 原始 agent_name;未命中时原样返回英文名,不阻塞渲染。
const AGENT_CN: Record<string, string> = {
  'Root Agent': '主控',
  root_agent: '主控',
  'XSS Specialist': 'XSS 检测',
  'SQLi Specialist': 'SQLi 检测',
  'SSRF Specialist': 'SSRF 检测',
  'RCE Specialist': 'RCE 检测',
  'IDOR Specialist': '越权检测',
  'Auth Specialist': '认证检测',
  'Recon Agent': '侦察',
  'Report Agent': '报告',
  'Verifier Agent': '复核'
}
export function agentCnName(name: string): string {
  if (!name) return 'agent'
  return AGENT_CN[name] || name
}

// ---- 热修:intake 策略档解析(优先用户档;无效/缺失时回退第一个可用档,避免 400 invalid_profile) ----
export async function resolveIntakeProfile(preferred: string): Promise<string> {
  try {
    const ps = await loadProfiles()
    const valid = new Set<string>()
    for (const p of ps) {
      valid.add(p.id)
      for (const a of p.aliases || []) valid.add(a)
    }
    if (preferred && valid.has(preferred)) return preferred
    return ps[0]?.id || ''
  } catch {
    return preferred   // profiles 不可读时按原值提交,由后端报错带出原因
  }
}

export const pageNames: Record<string, string> = {
  workbench: '工作台',
  projects: '项目',
  trajectory: '会话/轨迹',
  intake: '目标接入',
  assets: '资产与指纹',
  runs: '目标运行',
  approvals: '人工确认',
  findings: '发现与证据',
  reports: '报告与核销',
  intelligence: '资讯雷达',
  'src-autopilot': 'SRC 自动化',
  poc: 'PoC 关联',
  secrets: '密钥状态',
  sandbox: '工具隔离',
  routes: '线路与代理',
  health: '运行健康',
  profiles: '测试策略',
  harness: 'Harness (dsh)'
}

// ---- 壳状态:主视图可在「对话台」与「SRC 挖掘」间切换,旧面板降入次级抽屉 ----
export const activePage = ref('workbench')
export const panelsOpen = ref(false)
// 主视图:src = LLM SRC 挖掘台(默认);chat = 原 Strix 对话台
export const mainView = ref<'src' | 'chat'>('src')

export const snapshot = ref<DashboardSnapshot | null>(null)
export const authenticated = ref(false)
export const loading = ref(true)
export const refreshing = ref(false)
export const transportError = ref('')
export const password = ref('')
export const loginError = ref('')
export const loggingIn = ref(false)
let refreshTimer: number | undefined

export const view = computed(() => (snapshot.value ? createDashboardView(snapshot.value) : null))
export const stateStatusLabel = computed(() => {
  const status = snapshot.value?.state_dir_status
  return { available: '状态可用', partial: '状态不完整', missing: '未发现状态', unavailable: '状态不可读' }[status ?? 'missing']
})

export const taskColumns: DataTableColumns<DashboardTask> = [
  { title: '任务', key: 'task_id', width: 96 },
  { title: '目标', key: 'target', minWidth: 180, ellipsis: { tooltip: true } },
  { title: '策略', key: 'profile_name', minWidth: 128 },
  {
    title: '状态',
    key: 'status',
    width: 96,
    render: row => h(NTag, { type: taskTagType(row.status), bordered: false, size: 'small' }, { default: () => taskStatusLabel(row.status) })
  },
  {
    title: '开始',
    key: 'created_at',
    width: 116,
    render: row => formatTimestamp(row.created_at)
  },
  {
    title: '操作',
    key: '_act',
    width: 148,
    render: row => h('div', { style: 'display:flex;gap:6px' }, [
      h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openReport(row.task_id) }, { default: () => '看报告' }),
      h(NButton, { size: 'small', quaternary: true, onClick: () => openTaskDetail(row.task_id) }, { default: () => '详情' })
    ])
  }
]

export const goalColumns: DataTableColumns<DashboardGoal> = [
  { title: '目标', key: 'target', minWidth: 178, ellipsis: { tooltip: true } },
  { title: '策略', key: 'profile_name', minWidth: 128 },
  {
    title: '接口覆盖',
    key: 'coverage',
    width: 154,
    render: row => `${row.audited_endpoint_count}/${row.endpoint_count || '—'}`
  },
  {
    title: '终态',
    key: 'stop_condition',
    width: 128,
    render: row => h(NTag, { type: row.stop_condition ? 'success' : 'info', bordered: false, size: 'small' }, { default: () => goalStopLabel(row.stop_condition) })
  }
]

// ---- 只读业务面板(补回 py 仪表盘数据) ----
export const intelRows = ref<IntelRow[]>([])
export const srcAutopilot = ref<SrcAutopilotView>({ available: false, schema: 'SrcAutopilotView/v1', run: {}, candidates: [], intents: [], claims: [], dead_ends: [], hints: [] })
export const intelSourceRows = ref<IntelSourceRow[]>([])
export const intelWatch = ref<IntelWatchState>({ status: 'unknown', runs_completed: 0, last_run_id: '', consecutive_errors: 0, last_error: '', interval_sec: 0 })
export const srcForm = ref({ kind: 'page_watch', name: '', url: '', extract_hint: '', query: '' })
export const srcErr = ref('')
export const findingRows = ref<FindingRow[]>([])
export const keyRows = ref<KeyRow[]>([])
export const keyHideInvalid = ref(true)              // 默认隐藏无效(dead)数据
export const keySearch = ref('')
export const keysUnlockedUntil = ref(0)              // 解锁到期(秒)
export const keyUnlockModal = ref(false)
export const keyUnlockPw = ref('')
export const keyUnlockErr = ref('')
export const keysUnlocked = computed(() => keyRows.value.some(r => !!r.key))
export const filteredKeyRows = computed(() => {
  const q = keySearch.value.trim().toLowerCase()
  return keyRows.value.filter(r => {
    if (keyHideInvalid.value && (r.status === 'dead' || r.usable === false)) return false
    if (!q) return true
    return [r.service, r.repo, r.path, r.assoc_url, r.tail, r.key].some(v => (v || '').toLowerCase().includes(q))
  })
})
export async function submitKeyUnlock() {
  keyUnlockErr.value = ''
  try {
    const r = await unlockKeys(keyUnlockPw.value)
    keysUnlockedUntil.value = r.unlocked_until
    keyUnlockModal.value = false
    keyUnlockPw.value = ''
    keyRows.value = await loadKeys()            // 重载:此时返回明文
  } catch (e) {
    keyUnlockErr.value = (e instanceof ApiError && e.status === 401) ? '密码错误' : '解锁失败(密钥库未就绪?)'
  }
}
export async function relockKeys() {
  try { await lockKeys() } catch { /* ignore */ }
  keysUnlockedUntil.value = 0
  keyRows.value = await loadKeys()
}
export function copyText(t: string) {
  if (t) navigator.clipboard?.writeText(t)
}
export const systemInfo = ref<SystemInfo | null>(null)
export const modelPool = ref<ModelPool | null>(null)
export const proxyStatus = ref<ProxyStatus | null>(null)
export const pageLoading = ref(false)

// ---- P5: 项目 → 会话 → 轨迹 ----
export const projectRows = ref<ProjectCard[]>([])
export const fleet = ref<Fleet | null>(null)
export const assetChangeRows = ref<AssetChangeRow[]>([])
export const selectedProjectId = ref('')
export const projectDetail = ref<ProjectDetail | null>(null)
export const selectedSessionId = ref('')
export const trajectoryEvents = ref<TrajectoryEvent[]>([])
export const selectedSession = computed(() =>
  projectDetail.value?.sessions.find(s => s.session_id === selectedSessionId.value) ?? null)

export function projectStatusType(s: string): 'success' | 'info' | 'default' {
  if (s === 'running') return 'info'
  if (s === 'done') return 'success'
  return 'default'
}
export function trajType(source: string): 'default' | 'info' | 'success' | 'warning' | 'error' {
  if (source === 'finding') return 'warning'
  if (source === 'human_gate') return 'error'
  if (source === 'verifier') return 'success'
  if (source === 'tool' || source === 'tool_call' || source === 'tool_result') return 'info'
  return 'default'
}
export const trajKindLabel: Record<string, string> = {
  goal_created: '创建目标', endpoint_audited: '接口核销', finding_recorded: '记录发现',
  task_status: '任务状态', reasoning: '推理', tool_call: '工具调用', tool_result: '工具结果',
  fingerprint: '指纹', poc: 'PoC', verifier: '复核', human_gate: '人工门', scope: 'Scope'
}
export function openProject(pid: string) {
  selectedProjectId.value = pid
  selectedSessionId.value = ''
  activePage.value = 'trajectory'
  panelsOpen.value = true       // F6:轨迹面板在次级抽屉里,跳转时一并打开
}
export async function selectSession(sid: string) {
  selectedSessionId.value = sid
  try { trajectoryEvents.value = await loadTrajectory(sid) } catch { trajectoryEvents.value = [] }
  try { guidanceRows.value = await loadSessionGuidance(sid) } catch { guidanceRows.value = [] }
}

// ---- P5-e 会话交互续跑指导 ----
export const guidanceText = ref('')
export const guidanceErr = ref('')
export const guidanceOk = ref('')
export const guidanceRows = ref<SessionGuidanceRow[]>([])
// P5-d fork:同目标+同策略复刻新建一次运行(走确认门,不自动执行);回放=上方流程轨迹时间线
export const forkMsg = ref('')
export async function forkSession() {
  forkMsg.value = ''
  const pd = projectDetail.value
  const s = selectedSession.value
  if (!pd) return
  try {
    const profile = await resolveIntakeProfile(s?.profile_name || '')
    if (!profile) { forkMsg.value = '分叉失败:无可用策略档(测试策略未加载)'; return }
    const r = await submitProjectIntake({
      target_url: pd.target,
      name: `fork:${pd.target}`,
      engagement_profile: profile,
      toggles: { scan_enabled: true }
    })
    forkMsg.value = `已提交分叉 ${r.intake_id}(webui 直发,排队处理)`
  } catch (e) {
    forkMsg.value = '分叉失败:' + (e instanceof Error ? e.message : '未知错误')
  }
}

export async function submitGuidance() {
  guidanceErr.value = ''; guidanceOk.value = ''
  const s = selectedSession.value
  if (!s || !projectDetail.value) { guidanceErr.value = '先选一个会话'; return }
  if (!guidanceText.value.trim()) { guidanceErr.value = '请输入指导'; return }
  try {
    const r = await submitSessionGuidance({ session_id: s.session_id, target: projectDetail.value.target, guidance: guidanceText.value.trim() })
    guidanceOk.value = `已提交 ${r.id}(webui 直发,排队处理)`
    guidanceText.value = ''
    try { guidanceRows.value = await loadSessionGuidance(s.session_id) } catch { /* ignore */ }
  } catch (e) {
    guidanceErr.value = (e instanceof ApiError && e.status === 400) ? '目标非法/指导为空' : '提交失败'
  }
}

// ---- P5-b 新建项目(受控写:只提交意图,不执行) ----
export const newProjectModal = ref(false)
export const intakeSubmitting = ref(false)
export const intakeErr = ref('')
export const intakeOk = ref('')
export const intakeRows = ref<ProjectIntakeRow[]>([])
export const profileOptions = ref<{ label: string; value: string }[]>([])
export const intakeForm = ref({
  target_url: '', name: '', engagement_profile: '',
  toggles: {
    scan_enabled: true, fingerprint_precise: true, nuclei: false, tscan: false,
    asset_inventory: true, subdomain_enum: false, intel: true, poc_research: true,
    proxy_route: false, network_gate: true, edge_human_gate: true,
    brute: { enabled: false, path: false, port: false, password: false, username: false, sms: false, subdomain: false, max_attempts: 100, rate_limit_per_min: 60 }
  }
})
export async function openNewProject() {
  intakeErr.value = ''; intakeOk.value = ''
  if (!profileOptions.value.length) {
    try {
      const ps = await loadProfiles()
      profileOptions.value = ps.map(p => ({ label: `${p.id} · ${p.label}`, value: p.id }))
    } catch { /* ignore */ }
  }
  if (!intakeForm.value.engagement_profile && profileOptions.value.length) {
    intakeForm.value.engagement_profile = profileOptions.value[0].value
  }
  newProjectModal.value = true
}
export async function submitIntake() {
  intakeErr.value = ''; intakeOk.value = ''
  if (!intakeForm.value.target_url.trim()) { intakeErr.value = '请填目标 URL'; return }
  if (!intakeForm.value.engagement_profile) { intakeErr.value = '请选策略档'; return }
  intakeSubmitting.value = true
  try {
    const r = await submitProjectIntake({
      target_url: intakeForm.value.target_url.trim(),
      name: intakeForm.value.name.trim(),
      engagement_profile: intakeForm.value.engagement_profile,
      toggles: intakeForm.value.toggles
    })
    intakeOk.value = `已提交 ${r.intake_id}（${r.note}）`
    intakeForm.value.target_url = ''; intakeForm.value.name = ''
    try { intakeRows.value = await loadProjectIntakes() } catch { /* ignore */ }
  } catch (e) {
    intakeErr.value = (e instanceof ApiError && e.status === 400)
      ? '目标或策略档非法(需公网 http(s) 目标 + 有效档)' : '提交失败'
  } finally { intakeSubmitting.value = false }
}

// ---- P5-c 成果一键浏览 ----
export const projectResultsModal = ref(false)
export const projectResults = ref<ProjectResults | null>(null)
export const projectResultsLoading = ref(false)
export async function openProjectResults(pid: string) {
  projectResults.value = null
  projectResultsLoading.value = true
  projectResultsModal.value = true
  try { projectResults.value = await loadProjectResults(pid) }
  catch { projectResults.value = null }
  finally { projectResultsLoading.value = false }
}

// ---- #60 自进化反思 ----
export const evolveData = ref<EvolveData>({ stats: {}, rows: [] })
export async function reloadEvolve() {
  try { evolveData.value = await loadEvolve() } catch { evolveData.value = { stats: {}, rows: [] } }
}
export async function decideEvolve(id: string, decision: 'approve' | 'reject') {
  try { await apiDecideEvolve(id, decision); await reloadEvolve() } catch { /* ignore */ }
}

// ---- #74 出站 egress 门 ----
export const egress = ref<EgressView>({ blocked: [], allowlist: [], mihomo_rules: [], enforced: false })
export const egressAllowHost = ref('')
export async function reloadEgress() {
  try { egress.value = await loadEgress() } catch { egress.value = { blocked: [], allowlist: [], mihomo_rules: [], enforced: false } }
}
export async function submitEgressAllow(host?: string) {
  const h = (typeof host === 'string' && host) ? host : egressAllowHost.value.trim()
  if (!h) return
  try { await allowEgress(h); if (!host) egressAllowHost.value = ''; await reloadEgress() } catch { /* ignore */ }
}
export async function removeEgressAllowRow(host: string) {
  try { await removeEgressAllow(host); await reloadEgress() } catch { /* ignore */ }
}

// ---- #67 DeepSeek Harness (dsh) 内嵌 ----
// dsh 与控制台同机(127.0.0.1:3080);控制台后端把 /dsh/ 反代到 dsh(剥前缀+重写绝对路径),
// 因此默认同源相对路径即可,无需第二条 SSH 隧道;旧默认值 localStorage 里的绝对地址可点 ⚙ 改回。
const HARNESS_URL_KEY = 'pa_harness_url'
const HARNESS_DEFAULT_URL = '/dsh/'
// 旧版本默认 http://127.0.0.1:3080(浏览器本地,无隧道时拒绝连接)→ 迁移到同源反代
const storedHarnessUrl = localStorage.getItem(HARNESS_URL_KEY)
if (storedHarnessUrl === 'http://127.0.0.1:3080') localStorage.setItem(HARNESS_URL_KEY, HARNESS_DEFAULT_URL)
export const harnessUrl = ref(localStorage.getItem(HARNESS_URL_KEY) || HARNESS_DEFAULT_URL)
export const harnessUrlInput = ref(harnessUrl.value)
export const harnessCfg = ref(false)
export function applyHarnessUrl() {
  const u = harnessUrlInput.value.trim()
  if (u) { harnessUrl.value = u; localStorage.setItem(HARNESS_URL_KEY, u) }
}

// ---- #21 代理订阅入口 ----
export const proxySubs = ref<ProxySubs>({ subs: [], mihomo_snippet: '' })
export const subUrl = ref('')
export const subName = ref('')
export const subMsg = ref('')
export async function reloadProxySubs() {
  try { proxySubs.value = await loadProxySubs() } catch { proxySubs.value = { subs: [], mihomo_snippet: '' } }
}
export async function submitProxySub() {
  subMsg.value = ''
  if (!subUrl.value.trim()) return
  try { await addProxySub(subUrl.value.trim(), subName.value.trim()); subUrl.value = ''; subName.value = ''; await reloadProxySubs() }
  catch (e) { subMsg.value = (e instanceof ApiError && e.status === 400) ? '订阅 URL 非法(需 http/https)' : '添加失败' }
}
export async function toggleSub(id: string, enabled: boolean) {
  try { await toggleProxySub(id, enabled); await reloadProxySubs() } catch { /* ignore */ }
}
export async function removeSub(id: string) {
  try { await removeProxySub(id); await reloadProxySubs() } catch { /* ignore */ }
}

// ---- #70 免费 socks 池 ----
export const socksPool = ref<SocksPool>({ stats: {}, rows: [] })
export const socksAddr = ref('')
export const socksMsg = ref('')
export async function reloadSocks() {
  try { socksPool.value = await loadSocks() } catch { socksPool.value = { stats: {}, rows: [] } }
}
export async function submitSocks() {
  socksMsg.value = ''
  if (!socksAddr.value.trim()) return
  try {
    const r = await addSocks(socksAddr.value.trim())
    socksMsg.value = r.result
    socksAddr.value = ''
    await reloadSocks()
  } catch (e) {
    socksMsg.value = (e instanceof ApiError && e.status === 400) ? '地址非法(需 host:port)' : '添加失败'
  }
}
export async function removeSocksRow(addr: string) {
  try { await removeSocks(addr); await reloadSocks() } catch { /* ignore */ }
}

// ---- #80 PoC 审批(替代 pa-poc-admin) ----
export const pocData = ref<PocPending>({ pending: [], log: [] })
export async function reloadPoc() {
  try { pocData.value = await loadPocPending() } catch { pocData.value = { pending: [], log: [] } }
}
export async function confirmPocRow(id: string, approve: boolean) {
  try { await confirmPoc(id, approve); await reloadPoc() } catch { /* ignore */ }
}

// ---- #79 sink 签名库(代码审计护城河) ----
export const sinkKb = ref<SinkKbResult>({ stats: {}, rows: [] })
export const sinkKbFilter = ref('')
export const sinkKbFilterOpts = [
  { label: '全部', value: '' }, { label: '待审 pending', value: 'pending' },
  { label: '生效 approved', value: 'approved' }, { label: '拒绝 rejected', value: 'rejected' }
]
export async function reloadSinkKb() {
  try { sinkKb.value = await loadSinkKb(sinkKbFilter.value) } catch { sinkKb.value = { stats: {}, rows: [] } }
}
export async function decideSinkKb(id: string, decision: 'approve' | 'reject') {
  try { await apiDecideSinkKb(id, decision); await reloadSinkKb() } catch { /* ignore */ }
}

// ---- #53 指纹自修正(人工确认门) ----
export const fpCorrRows = ref<FingerprintCorrectionRow[]>([])
export async function reloadFpCorr() {
  try { fpCorrRows.value = await loadFingerprintCorrections() } catch { fpCorrRows.value = [] }
}
export async function decideFpCorr(id: string, decision: 'approve' | 'reject') {
  try { await decideFingerprintCorrection(id, decision); await reloadFpCorr() } catch { /* ignore */ }
}

// ---- #76 情报数据源管理 ----
export async function reloadIntelSources() {
  try { intelSourceRows.value = await loadIntelSources() } catch { intelSourceRows.value = [] }
}
export async function reloadIntelWatch() {
  try { intelWatch.value = await loadIntelWatch() } catch { intelWatch.value = { status: 'unknown', runs_completed: 0, last_run_id: '', consecutive_errors: 0, last_error: '', interval_sec: 0 } }
}
export async function reloadSrcAutopilot() {
  try { srcAutopilot.value = await loadSrcAutopilot() }
  catch { srcAutopilot.value = { available: false, schema: 'SrcAutopilotView/v1', run: {}, candidates: [], intents: [], claims: [], dead_ends: [], hints: [] } }
}
export async function submitIntelSource() {
  srcErr.value = ''
  if (!srcForm.value.url.trim() && srcForm.value.kind !== 'twitter') { srcErr.value = '请填 URL'; return }
  if (srcForm.value.kind === 'twitter' && !srcForm.value.query.trim()) { srcErr.value = 'Twitter/X 需要搜索规则'; return }
  try {
    await addIntelSource({ kind: srcForm.value.kind, name: srcForm.value.name.trim(), url: srcForm.value.url.trim(), extract_hint: srcForm.value.extract_hint.trim(), query: srcForm.value.query.trim() })
    srcForm.value.url = ''; srcForm.value.name = ''; srcForm.value.extract_hint = ''; srcForm.value.query = ''
    await reloadIntelSources()
  } catch (e) {
    srcErr.value = (e instanceof ApiError && e.status === 400) ? '非法(需公网 http(s) URL,或重复/kind 错)' : '添加失败'
  }
}
export async function toggleSrc(s: IntelSourceRow) {
  try { await toggleIntelSource(s.id, !s.enabled); await reloadIntelSources() } catch { /* ignore */ }
}
export async function removeSrc(s: IntelSourceRow) {
  try { await removeIntelSource(s.id); await reloadIntelSources() } catch { /* ignore */ }
}

export function sevType(s: string): 'error' | 'warning' | 'success' | 'default' {
  const v = (s || '').toLowerCase()
  if (v === 'critical' || v === 'high') return 'error'
  if (v === 'medium') return 'warning'
  if (v === 'low') return 'success'
  return 'default'
}
const sevTag = (s: string) => h(NTag, { type: sevType(s), bordered: false, size: 'small' }, { default: () => (s || '?').toUpperCase() })
function pocShort(s: string): string {
  if (!s) return ''
  if (s.includes('GitHub')) return 'GitHub'
  if (s.includes('关键词')) return '关键词'
  if (s.includes('深读')) return '深读'
  if (s.includes('LLM')) return 'LLM'
  return s.length > 6 ? s.slice(0, 6) : s
}

export const intelColumns: DataTableColumns<IntelRow> = [
  { title: '时间', key: 'ts', width: 86, render: r => (r.ts ? formatTimestamp(r.ts) : '—') },
  { title: '首次出现', key: 'date', width: 124, render: r => h('span', {}, [r.date || '未知', r.update_reason ? h(NTag, { size: 'tiny', bordered: false, type: 'warning', style: 'margin-left:6px' }, { default: () => '↑' + r.update_reason }) : null]) },
  { title: '严重度', key: 'severity', width: 86, render: r => sevTag(r.severity) },
  { title: '危害评分', key: 'cvss', minWidth: 148, ellipsis: { tooltip: true }, render: r => r.cvss || '—' },
  { title: 'CVE', key: 'cve', width: 148 },
  { title: '类别', key: 'kind', width: 96 },
  { title: '标题', key: 'title', minWidth: 220, ellipsis: { tooltip: true } },
  { title: '来源', key: 'source', width: 150, ellipsis: { tooltip: true } },
  { title: '摘要', key: 'summary', minWidth: 240, ellipsis: { tooltip: true } },
  { title: 'PoC', key: 'has_poc', width: 116, render: r => (r.has_poc ? h(NTag, { type: 'success', bordered: false, size: 'small' }, { default: () => '是' + (pocShort(r.poc_source) ? '·' + pocShort(r.poc_source) : '') }) : h('span', { style: 'color:#9ca3af' }, '否')) },
  { title: '在野', key: 'in_the_wild', width: 66, render: r => (r.in_the_wild ? h(NTag, { type: 'error', bordered: false, size: 'small' }, { default: () => '是' }) : h('span', { style: 'color:#9ca3af' }, '否')) },
  { title: '操作', key: '_act', width: 72, render: r => h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openIntel(r) }, { default: () => '查看' }) }
]
export const findingColumns: DataTableColumns<FindingRow> = [
  { title: '严重度', key: 'severity', width: 96, render: r => sevTag(r.severity) },
  { title: '标题', key: 'title', minWidth: 240, ellipsis: { tooltip: true } },
  { title: '类型', key: 'rule', width: 140 },
  { title: '目标', key: 'target', minWidth: 160, ellipsis: { tooltip: true }, render: r => r.target || h('span', { style: 'color:#9ca3af' }, '—') },
  { title: '任务', key: 'task', width: 88 },
  { title: '时间', key: 'ts', width: 108, render: r => (r.ts ? formatTimestamp(r.ts) : '—') },
  { title: '操作', key: '_act', width: 76, render: r => h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openFinding(r) }, { default: () => '详情' }) }
]
export const keyColumns: DataTableColumns<KeyRow> = [
  { title: '服务', key: 'service', width: 126 },
  { title: '仓库', key: 'repo', minWidth: 148, ellipsis: { tooltip: true } },
  { title: '源头', key: 'source_url', minWidth: 150, ellipsis: { tooltip: true }, render: r => (r.source_url ? h('a', { href: r.source_url, target: '_blank', rel: 'noreferrer noopener', style: 'color:#2563eb' }, r.path || 'GitHub 出处') : (r.path ? h('span', { style: 'color:#6b7280' }, r.path) : h('span', { style: 'color:#9ca3af' }, '—'))) },
  { title: '状态', key: 'status', width: 82, render: r => { const m: Record<string, [string, string]> = { live: ['success', '可用'], dead: ['error', '已吊销'], retry: ['warning', '待重检'], none: ['default', '未验'] }; const mm = m[r.status] || ['default', r.status || '—']; return h(NTag, { type: mm[0] as 'success' | 'error' | 'warning' | 'default', bordered: false, size: 'small' }, { default: () => mm[1] }) } },
  { title: '密钥', key: 'key', minWidth: 160, ellipsis: { tooltip: true }, render: r => (r.key ? h('code', { style: 'font-size:12px;color:#b91c1c;cursor:pointer', title: '点击复制', onClick: () => copyText(r.key) }, r.key) : h('span', { style: 'color:#9ca3af' }, (r.has_enc ? '🔒 …' : '…') + (r.tail || ''))) },
  {
    title: '关联端点(LLM)', key: 'assoc_url', minWidth: 190, ellipsis: { tooltip: true },
    render: r => (r.assoc_url
      ? h('span', {}, [r.assoc_url, r.assoc_kind ? h(NTag, { size: 'tiny', bordered: false, type: 'warning', style: 'margin-left:6px' }, { default: () => r.assoc_kind }) : null])
      : h('span', { style: 'color:#9ca3af' }, '—'))
  },
  { title: '时间', key: 'ts', width: 108, render: r => (r.ts ? formatTimestamp(r.ts) : '—') },
  { title: '操作', key: '_act', width: 118, render: r => h('div', { style: 'display:flex;gap:4px' }, [
    h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openKey(r) }, { default: () => '查看' }),
    h(NButton, { size: 'small', quaternary: true, onClick: () => downloadKey(r) }, { default: () => '导出' })
  ]) }
]
export const profileRows = ref<ProfileRow[]>([])
export const profileColumns: DataTableColumns<ProfileRow> = [
  { title: '档', key: 'id', width: 180 },
  { title: '名称', key: 'label', minWidth: 140 },
  { title: '默认Goal', key: 'default_goal', width: 90, render: r => (r.default_goal ? '是' : '否') },
  { title: '自动续跑', key: 'auto_continue', width: 90, render: r => (r.auto_continue ? '是' : '否') },
  { title: '播报', key: 'broadcast_level', width: 84 },
  { title: '停止条件', key: 'stop_conditions', minWidth: 200, render: r => (r.stop_conditions || []).join(' / ') },
  { title: '别名', key: 'aliases', minWidth: 160, ellipsis: { tooltip: true }, render: r => (r.aliases || []).join(', ') }
]
export const sandboxColumns: DataTableColumns<SandboxRun> = [
  { title: '任务', key: 'task_id', width: 100 },
  { title: '运行', key: 'run_id', minWidth: 160, ellipsis: { tooltip: true } },
  { title: '状态', key: 'status', width: 96, render: r => h(NTag, { type: r.status === 'blocked' ? 'error' : 'success', bordered: false, size: 'small' }, { default: () => r.status }) },
  { title: '执行模式', key: 'execution_mode', width: 128 },
  { title: '网络', key: 'network', width: 92, render: r => (r.network === 'none' ? '无网络' : r.network) },
  { title: 'Rootless', key: 'rootless', width: 88, render: r => (r.rootless ? '是' : '否') }
]
export const modelColumns: DataTableColumns<ModelProvider> = [
  { title: '上游', key: 'name', width: 130 },
  { title: '模型', key: 'model', minWidth: 180, ellipsis: { tooltip: true } },
  { title: 'Host', key: 'host', minWidth: 160, ellipsis: { tooltip: true } },
  { title: '状态', key: 'up', width: 90, render: r => h(NTag, { type: r.up ? 'success' : 'error', bordered: false, size: 'small' }, { default: () => (r.up ? 'UP' : 'DOWN') }) },
  { title: '延迟', key: 'latency_ms', width: 90, render: r => (r.latency_ms != null ? r.latency_ms + 'ms' : '—') }
]

// ---- 详情/报告弹窗(共享:报告/任务详情=等宽全文,情报/发现/KEY=字段+外链) ----
export const modalOpen = ref(false)
export const modalTitle = ref('')
export const modalBody = ref('')
export const modalLinks = ref<string[]>([])
export const modalMono = ref(false)
export const modalLoading = ref(false)

export function openInfo(title: string, body: string, links: string[] = []) {
  modalTitle.value = title; modalBody.value = body; modalLinks.value = links
  modalMono.value = false; modalLoading.value = false; modalOpen.value = true
}
export async function openReport(taskId: string) {
  modalTitle.value = '报告 ' + taskId; modalBody.value = ''; modalLinks.value = []
  modalMono.value = true; modalLoading.value = true; modalOpen.value = true
  try { modalBody.value = (await loadReport(taskId)) || '（该任务暂无报告文件）' }
  catch { modalBody.value = '报告读取失败' }
  finally { modalLoading.value = false }
}
export async function openTaskDetail(taskId: string) {
  modalTitle.value = '任务详情 ' + taskId; modalBody.value = ''; modalLinks.value = []
  modalMono.value = true; modalLoading.value = true; modalOpen.value = true
  try { modalBody.value = JSON.stringify(await loadTask(taskId), null, 2) }
  catch { modalBody.value = '详情读取失败' }
  finally { modalLoading.value = false }
}
export function openIntel(r: IntelRow) {
  openInfo(r.cve || '资讯条目',
    `首次出现: ${r.date || '未知'}${r.update_reason ? '（本次更新原因: ' + r.update_reason + '）' : ''}\n严重度: ${(r.severity || '').toUpperCase()}\n危害评分: ${r.cvss || '—'}\n标题: ${r.title}\nPoC: ${r.has_poc ? '是' + (r.poc_source ? '·' + r.poc_source : '') : '否'}\n在野利用: ${r.in_the_wild ? '是' : '否'}`,
    r.refs || [])
}
export function openFinding(r: FindingRow) {
  openInfo(`${(r.severity || '').toUpperCase()} · ${r.rule || '候选发现'}`,
    `任务: ${r.task}\n目标: ${r.target || '—'}\n类型: ${r.rule}\n严重度: ${(r.severity || '').toUpperCase()}\n时间: ${r.ts ? formatTimestamp(r.ts) : '—'}\n标题: ${r.title}\n\n(候选发现,需二次确认)`)
}
export function openKey(r: KeyRow) {
  openInfo(r.service || 'KEY',
    `服务: ${r.service}\n仓库: ${r.repo}\n文件路径: ${r.path || '—'}\nGitHub 出处: ${r.source_url || '—'}\n可用: ${r.usable === true ? '可用' : r.usable === false ? '无效' : '未验证(不连接)'}\n验活详情: ${r.detail || '—'}\n尾4位: …${r.tail || ''}\n关联端点(LLM从片段推断,未探测): ${r.assoc_url || '—'}${r.assoc_kind ? ' [' + r.assoc_kind + ']' : ''}`,
    [r.source_url, r.assoc_url].filter(Boolean))
}
export function downloadKey(r: KeyRow) {
  // 纯客户端导出单条记录(不含明文 key——库里只有 fp 哈希 + 尾4位),供人工核查/责任披露归档
  const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `key-${(r.service || 'record').replace(/[^\w.-]/g, '_')}-${r.tail || 'x'}.json`
  a.click()
  URL.revokeObjectURL(url)
}

export async function loadPageData(page: string) {
  pageLoading.value = true
  try {
    if (page === 'intelligence') { intelRows.value = await loadIntel(80); await reloadIntelSources(); await reloadIntelWatch() }
    else if (page === 'src-autopilot') await reloadSrcAutopilot()
    else if (page === 'findings') { findingRows.value = await loadFindings(); await reloadSinkKb() }
    else if (page === 'poc') await reloadPoc()
    else if (page === 'approvals') await reloadEvolve()
    else if (page === 'secrets') keyRows.value = await loadKeys()
    else if (page === 'health') { systemInfo.value = await loadSystem(); modelPool.value = await loadModelPool() }
    else if (page === 'routes') { proxyStatus.value = await loadProxy(); await reloadSocks(); await reloadEgress(); await reloadProxySubs() }
    else if (page === 'profiles') profileRows.value = await loadProfiles()
    else if (page === 'assets') { assetChangeRows.value = await loadAssetChanges(80); await reloadFpCorr() }
    else if (page === 'projects') {
      projectRows.value = await loadProjects()
      try { intakeRows.value = await loadProjectIntakes() } catch { intakeRows.value = [] }
      try { fleet.value = await loadFleet() } catch { fleet.value = null }
    }
    else if (page === 'trajectory' && selectedProjectId.value) {
      projectDetail.value = await loadProject(selectedProjectId.value)
      const ids = projectDetail.value.sessions.map(s => s.session_id)
      if (!selectedSessionId.value || !ids.includes(selectedSessionId.value)) {
        selectedSessionId.value = ids[0] ?? ''
      }
      trajectoryEvents.value = selectedSessionId.value ? await loadTrajectory(selectedSessionId.value) : []
    }
  } catch {
    /* 单面板读失败不打断整体;20s 轮询会重试 */
  } finally {
    pageLoading.value = false
  }
}

watch(activePage, page => {
  if (authenticated.value) void loadPageData(page)
})

export function stopPolling() {
  if (refreshTimer !== undefined) {
    window.clearInterval(refreshTimer)
    refreshTimer = undefined
  }
}

export function startPolling() {
  stopPolling()
  refreshTimer = window.setInterval(() => {
    if (authenticated.value) {
      void refreshDashboard(false)
      void loadPageData(activePage.value)
    }
  }, 20_000)
}

export async function refreshDashboard(showSpinner = true) {
  if (showSpinner) refreshing.value = true
  try {
    snapshot.value = await loadDashboard()
    authenticated.value = true
    transportError.value = ''
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      authenticated.value = false
      snapshot.value = null
      stopPolling()
      return
    }
    transportError.value = '控制面暂时不可读'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

export async function submitLogin() {
  loginError.value = ''
  if (!password.value) {
    loginError.value = '请输入管理口令'
    return
  }
  loggingIn.value = true
  try {
    await login(password.value)
    password.value = ''
    await refreshDashboard()
    if (authenticated.value) {
      startPolling()
      void loadPageData(activePage.value)
    }
  } catch {
    loginError.value = '口令校验失败'
  } finally {
    loggingIn.value = false
  }
}

export async function signOut() {
  try {
    await logout()
  } finally {
    authenticated.value = false
    snapshot.value = null
    stopPolling()
  }
}

export function goalCoverage(goal: DashboardGoal): number {
  if (!goal.endpoint_count) return 0
  return Math.min(100, Math.round((goal.audited_endpoint_count / goal.endpoint_count) * 100))
}
