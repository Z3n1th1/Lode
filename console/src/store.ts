// F6 拆巨石:原 App.vue 的全部共享状态/逻辑,模块级单例(行为与原单文件一致)。
// 面板组件只import本模块的状态与动作,不各自持状态,保证 20s 轮询/loadPageData 派发不变。
import { computed, h, ref, watch } from 'vue'
import { NButton, NTag, type DataTableColumns } from 'naive-ui'

import {
  ApiError, loadDashboard, login, logout,
  loadFindings, loadSystem, loadModelPool, loadProfiles, loadReport,
  loadProjects, loadProject, loadTrajectory, submitSessionGuidance, loadSessionGuidance,
  submitProjectIntake, loadProjectIntakes, loadProjectResults,
  loadSrcAutopilot,
  loadChatModes as apiLoadChatModes,
  type FindingRow, type SystemInfo, type ModelProvider, type ModelPool, type ChatMode,
  type ProjectCard, type ProjectDetail, type SessionGuidanceRow, type TrajectoryEvent, type ProjectIntakeRow, type ProjectResults, type SrcAutopilotView
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
  'src-autopilot': 'SRC 黑板',
  findings: '发现与证据',
  projects: '项目',
  trajectory: '会话/轨迹',
  health: '运行健康'
}

// ---- 壳状态:统一对话是唯一主视图,挖洞设置是唯一的次级视图;旧面板降入抽屉 ----
export const activePage = ref('src-autopilot')
export const panelsOpen = ref(false)
// 主视图:chat = 统一对话(唯一入口);settings = 挖洞设置(模型/密钥)
export const mainView = ref<'chat' | 'settings'>('chat')

// 对话模式:头部模式选择器与统一对话共用同一份状态(单一出处)
export const chatMode = ref('chat')
export const chatModes = ref<ChatMode[]>([])
let chatModesLoaded = false
export async function loadChatModes(): Promise<void> {
  if (chatModesLoaded) return   // 模式来自 config/modes.yaml,进程内取一次即可
  try {
    const view = await apiLoadChatModes()
    chatModes.value = view.modes
    if (!view.modes.some((mode) => mode.name === chatMode.value)) chatMode.value = view.default
    chatModesLoaded = true
  } catch { /* 模式列表读不到时不阻塞对话,沿用默认 */ }
}

// ---- 主题:暗色默认,可切浅色(<html data-theme>),选择记在 localStorage ----
const THEME_KEY = 'lode.theme'
export const theme = ref<'dark' | 'light'>(
  (() => {
    try { return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark' } catch { return 'dark' }
  })()
)
export function applyTheme(): void {
  document.documentElement.dataset.theme = theme.value
}
export function toggleTheme(): void {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  try { localStorage.setItem(THEME_KEY, theme.value) } catch { /* 隐私模式:不记也行 */ }
  applyTheme()
}
// 模块加载就应用一次,免得选过浅色的人首屏闪一下暗色
if (typeof document !== 'undefined') applyTheme()

export const snapshot = ref<DashboardSnapshot | null>(null)
export const authenticated = ref(false)
export const loading = ref(true)
export const refreshing = ref(false)
export const password = ref('')
export const loginError = ref('')
export const loggingIn = ref(false)
let refreshTimer: number | undefined

export const view = computed(() => (snapshot.value ? createDashboardView(snapshot.value) : null))

// ---- 只读业务面板(补回 py 仪表盘数据) ----
export const srcAutopilot = ref<SrcAutopilotView>({ available: false, schema: 'SrcAutopilotView/v1', run: {}, candidates: [], intents: [], claims: [], dead_ends: [], hints: [] })
export const findingRows = ref<FindingRow[]>([])
export const systemInfo = ref<SystemInfo | null>(null)
export const modelPool = ref<ModelPool | null>(null)
export const pageLoading = ref(false)

// ---- P5: 项目 → 会话 → 轨迹 ----
export const projectRows = ref<ProjectCard[]>([])
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
    forkMsg.value = `已提交分叉 ${r.intake_id}(console 直发,排队处理)`
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
    guidanceOk.value = `已提交 ${r.id}(console 直发,排队处理)`
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


export async function reloadSrcAutopilot() {
  try { srcAutopilot.value = await loadSrcAutopilot() }
  catch { srcAutopilot.value = { available: false, schema: 'SrcAutopilotView/v1', run: {}, candidates: [], intents: [], claims: [], dead_ends: [], hints: [] } }
}
export function sevType(s: string): 'error' | 'warning' | 'success' | 'default' {
  const v = (s || '').toLowerCase()
  if (v === 'critical' || v === 'high') return 'error'
  if (v === 'medium') return 'warning'
  if (v === 'low') return 'success'
  return 'default'
}
const sevTag = (s: string) => h(NTag, { type: sevType(s), bordered: false, size: 'small' }, { default: () => (s || '?').toUpperCase() })

export const findingColumns: DataTableColumns<FindingRow> = [
  { title: '严重度', key: 'severity', width: 96, render: r => sevTag(r.severity) },
  { title: '标题', key: 'title', minWidth: 240, ellipsis: { tooltip: true } },
  { title: '类型', key: 'rule', width: 140 },
  { title: '目标', key: 'target', minWidth: 160, ellipsis: { tooltip: true }, render: r => r.target || h('span', { style: 'color:#9ca3af' }, '—') },
  { title: '任务', key: 'task', width: 88 },
  { title: '时间', key: 'ts', width: 108, render: r => (r.ts ? formatTimestamp(r.ts) : '—') },
  { title: '操作', key: '_act', width: 76, render: r => h(NButton, { size: 'small', quaternary: true, type: 'primary', onClick: () => openFinding(r) }, { default: () => '详情' }) }
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
export function openFinding(r: FindingRow) {
  openInfo(`${(r.severity || '').toUpperCase()} · ${r.rule || '候选发现'}`,
    `任务: ${r.task}\n目标: ${r.target || '—'}\n类型: ${r.rule}\n严重度: ${(r.severity || '').toUpperCase()}\n时间: ${r.ts ? formatTimestamp(r.ts) : '—'}\n标题: ${r.title}\n\n(候选发现,需二次确认)`)
}

export async function loadPageData(page: string) {
  pageLoading.value = true
  try {
    if (page === 'src-autopilot') await reloadSrcAutopilot()
    else if (page === 'findings') findingRows.value = await loadFindings()
    else if (page === 'health') { systemInfo.value = await loadSystem(); modelPool.value = await loadModelPool() }
    else if (page === 'projects') {
      projectRows.value = await loadProjects()
      try { intakeRows.value = await loadProjectIntakes() } catch { intakeRows.value = [] }
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
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      authenticated.value = false
      snapshot.value = null
      stopPolling()
      return
    }
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
