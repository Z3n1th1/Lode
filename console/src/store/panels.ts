// 次级页面的数据:SRC 黑板、发现、运行健康、项目/轨迹、成果浏览,以及共享弹窗。
// 与对话无关,所以单独一个 store —— 旧版把这两类状态塞在同一个 405 行单例里。
import { create } from 'zustand'

import {
  ApiError,
  PROJECT_PAGE_SIZE,
  confirmProjectIntake,
  confirmScopeIntake,
  discardProjectIntake,
  discardScopeIntake,
  loadFindings,
  loadModelPool,
  loadPendingIntake,
  loadProject,
  loadProjectIntakes,
  loadProjectResults,
  loadProjects,
  loadProfiles,
  loadReport,
  loadSessionGuidance,
  loadSrcAutopilot,
  loadSystem,
  loadTrajectory,
  startProjectIntake,
  startScopeIntake,
  submitSessionGuidance,
  type FindingRow,
  type IntakeConfirmResult,
  type IntakePreview,
  type ModelPool,
  type PendingIntakeRow,
  type ProjectCard,
  type ProjectDetail,
  type ProjectResults,
  type SessionGuidanceRow,
  type ScopeIntakeConfirmResult,
  type SrcAutopilotView,
  type SystemInfo,
  type TrajectoryEvent
} from '../api'
import { formatTimestamp } from '../dashboard'
import { refusalText, type ScopePreview, type ScopeReject } from '../scopeDocument'
import { useAuth, type Route } from './auth'
import { useChat } from './chat'

const EMPTY_AUTOPILOT: SrcAutopilotView = {
  schema: 'SrcAutopilotView/v1',
  available: false,
  run: {},
  candidates: [],
  intents: [],
  claims: [],
  dead_ends: [],
  hints: []
}

/** 读提交队列。空队列有两种意思——真的没有待确认,还是台账文件/锁读不到——
 *  所以状态一起带回来,由界面说清是哪种,而不是让两种都长成一张空表。 */
async function readIntakeQueue(
  fallback: PendingIntakeRow[],
  fallbackStatus: string
): Promise<{ intakes: PendingIntakeRow[]; intakeQueueStatus: string }> {
  try {
    const queue = await loadProjectIntakes()
    return { intakes: queue.intakes, intakeQueueStatus: queue.status }
  } catch {
    return { intakes: fallback, intakeQueueStatus: fallbackStatus }
  }
}

/** intake 策略档解析:优先用户档;无效/缺失时回退第一个可用档,避免 400。 */
export async function resolveIntakeProfile(preferred: string): Promise<string> {
  try {
    const profiles = await loadProfiles()
    const valid = new Set<string>()
    for (const profile of profiles) {
      valid.add(profile.id)
      for (const alias of profile.aliases || []) valid.add(alias)
    }
    if (preferred && valid.has(preferred)) return preferred
    return profiles[0]?.id || ''
  } catch {
    return preferred // 读不到就按原值提交,由后端报错带出原因
  }
}

export function projectStatusTone(status: string): 'ok' | 'accent' | 'neutral' {
  if (status === 'running') return 'accent'
  if (status === 'done') return 'ok'
  return 'neutral'
}

export const TRAJ_KIND_LABEL: Record<string, string> = {
  goal_created: '创建目标',
  endpoint_audited: '接口核销',
  finding_recorded: '记录发现',
  task_status: '任务状态',
  reasoning: '推理',
  tool_call: '工具调用',
  tool_result: '工具结果',
  fingerprint: '指纹',
  poc: 'PoC',
  verifier: '复核',
  human_gate: '人工门',
  scope: 'Scope'
}

/** 门的 options key → 界面上那个开关的名字。队列与确认步共用一份。 */
export const OPTION_LABEL: Record<string, string> = {
  asset_inventory: '资产清单',
  subdomain_enum: '子域枚举',
  fingerprint: '精确指纹',
  active_scan: '主动扫描',
  nuclei: 'Nuclei 模板',
  tscan: 'TScan',
  intelligence: '情报关联',
  poc_research: 'PoC 检索',
  proxy_route: '代理路由',
  network_gate: '出站门',
  edge_human_gate: '边界人工门',
  arl_next: 'ARL 资产'
}

/** 门返回的 options → 真开着的开关名。确认单与提交队列共用。 */
export function enabledOptionLabels(options: Record<string, { enabled?: boolean }>): string[] {
  return Object.keys(options)
    .filter((key) => options[key]?.enabled === true)
    .map((key) => OPTION_LABEL[key] ?? key)
}

/** 门的 4xx detail → 人话。后端只说英文短语,这里只翻译、不加解释。 */
const INTAKE_HINT: Record<string, string> = {
  invalid_target: '目标要是公网 http(s) 地址',
  invalid_profile: '策略档无效',
  empty_instruction: '请写一句这次要看什么',
  brute_force_out_of_scope: '爆破不在当前授权范围内',
  intake_option_unknown: '有个开关后端不认识(前后端没同步)',
  intake_confirmation_binding_mismatch: '确认单对不上号:这张单不是当前这条预览的',
  intake_receipt_invalid: '确认收据不完整,重新确认一次',
  canonical_target_card_mismatch: '落盘的卡和确认单不一致,没有开跑'
}

/** 文档那条路的原因码比目标多,所以走 refusalText 那张表,而不是再加一份。 */
function scopeErrorText(error: unknown): string {
  const api = error instanceof ApiError ? error : null
  const body = (api?.body ?? {}) as { detail?: string; items?: string }
  const detail = String(body.detail || '')
  if (!detail) return `失败:${(error as Error).message}`
  return refusalText(detail, String(body.items || ''))
}

export interface IntakeToggles {
  scan_enabled: boolean
  fingerprint_precise: boolean
  nuclei: boolean
  tscan: boolean
  asset_inventory: boolean
  subdomain_enum: boolean
  intel: boolean
  poc_research: boolean
  proxy_route: boolean
  network_gate: boolean
  edge_human_gate: boolean
}

const DEFAULT_TOGGLES: IntakeToggles = {
  scan_enabled: true,
  fingerprint_precise: true,
  nuclei: false,
  tscan: false,
  asset_inventory: true,
  subdomain_enum: false,
  intel: true,
  poc_research: true,
  proxy_route: false,
  network_gate: true,
  edge_human_gate: true
}

export interface IntakeForm {
  target_url: string
  instruction: string
  engagement_profile: string
  toggles: IntakeToggles
}

export interface ModalState {
  open: boolean
  title: string
  meta: string
  body: string
  links: string[]
  mono: boolean
  loading: boolean
}

const CLOSED_MODAL: ModalState = {
  open: false,
  title: '',
  meta: '',
  body: '',
  links: [],
  mono: false,
  loading: false
}

interface PanelState {
  loading: boolean
  srcAutopilot: SrcAutopilotView
  findings: FindingRow[]
  system: SystemInfo | null
  models: ModelPool | null
  projects: ProjectCard[]
  /** 全部项目数(不只是本页)。列表分页之后,这两个数是两件事。 */
  projectTotal: number
  /** "加载更多"失败的原因。空着 = 没出过错。 */
  projectsMoreError: string
  projectDetail: ProjectDetail | null
  selectedProjectId: string
  selectedSessionId: string
  trajectory: TrajectoryEvent[]
  guidanceRows: SessionGuidanceRow[]
  guidanceText: string
  guidanceError: string
  guidanceOk: string
  intakes: PendingIntakeRow[]
  /** 队列台账的读取状态:ok / missing / unavailable。空队列时用来区分原因。 */
  intakeQueueStatus: string
  intakeForm: IntakeForm
  profileOptions: { label: string; value: string }[]
  newProjectOpen: boolean
  intakeSubmitting: boolean
  intakeError: string
  intakeOk: string
  /** 待确认的预览。有它 = 弹窗停在确认步;确认/放弃后清空。 */
  intakePreview: IntakePreview | null
  /** 已落卡的确认结果,给操作者看 target_id 与卡文件。 */
  intakeResult: IntakeConfirmResult | null
  /** 待确认的**授权文档**。和 intakePreview 抢同一格,所以两者不会同时非空。 */
  scopePreview: ScopePreview | null
  /** 已落授权记录的确认结果。 */
  scopeResult: ScopeIntakeConfirmResult | null
  /** 拖进监听目录但没收下的文件 —— 不说出来,操作员只会看到"拖进去没反应"。 */
  scopeRejects: ScopeReject[]
  /** 粘贴框里的文本,以及这份内容来自哪个文件(上传时才有)。 */
  scopeText: string
  scopeFilename: string
  resultsOpen: boolean
  results: ProjectResults | null
  resultsLoading: boolean
  modal: ModalState

  load: (route: Route) => Promise<void>
  /** 再取一页项目追到列表尾部。已经取到底就是空操作。 */
  loadMoreProjects: () => Promise<void>
  selectProject: (id: string) => void
  selectSession: (id: string) => Promise<void>
  submitGuidance: () => Promise<void>
  forkSession: () => Promise<void>
  openNewProject: () => Promise<void>
  setNewProjectOpen: (open: boolean) => void
  patchIntakeForm: (patch: Partial<IntakeForm>) => void
  submitIntake: () => Promise<void>
  confirmIntake: () => Promise<void>
  discardIntake: () => Promise<void>
  patchScopeText: (text: string, filename?: string) => void
  submitScopeDocument: () => Promise<void>
  confirmScopeDocument: () => Promise<void>
  discardScopeDocument: () => Promise<void>
  openIntakeRun: () => Promise<void>
  openResults: (projectId: string) => Promise<void>
  setResultsOpen: (open: boolean) => void
  openInfo: (title: string, body: string, links?: string[]) => void
  openReport: (taskId: string) => Promise<void>
  openFinding: (row: FindingRow) => void
  closeModal: () => void
  clearGuidance: () => void
}

export const usePanels = create<PanelState>()((set, get) => ({
  loading: false,
  srcAutopilot: EMPTY_AUTOPILOT,
  findings: [],
  system: null,
  models: null,
  projects: [],
  projectTotal: 0,
  projectsMoreError: '',
  projectDetail: null,
  selectedProjectId: '',
  selectedSessionId: '',
  trajectory: [],
  guidanceRows: [],
  guidanceText: '',
  guidanceError: '',
  guidanceOk: '',
  intakes: [],
  intakeQueueStatus: '',
  intakeForm: { target_url: '', instruction: '', engagement_profile: '', toggles: DEFAULT_TOGGLES },
  profileOptions: [],
  newProjectOpen: false,
  intakeSubmitting: false,
  intakeError: '',
  intakeOk: '',
  intakePreview: null,
  intakeResult: null,
  scopePreview: null,
  scopeResult: null,
  scopeRejects: [],
  scopeText: '',
  scopeFilename: '',
  resultsOpen: false,
  results: null,
  resultsLoading: false,
  modal: CLOSED_MODAL,

  async load(route) {
    set({ loading: true })
    try {
      if (route === 'health') {
        const [system, models] = await Promise.all([loadSystem(), loadModelPool()])
        set({ system, models })
      } else if (route === 'findings') {
        set({ findings: await loadFindings() })
      } else if (route === 'projects') {
        // 后台轮询也走这条。按已经展开的条数去取,否则刚点开的"更多"会在下一次
        // 轮询时缩回去 —— 列表在脚底下塌掉比不加载更难受。服务端单次最多给
        // MAX_PROJECT_PAGE(200)条,展开得比这更多时会回落到 200;页头会写
        // "200 / 252",按钮也还在,所以那是看得见、点得回来的,不是静默截断。
        const want = Math.max(PROJECT_PAGE_SIZE, get().projects.length)
        const [page, queue] = await Promise.all([
          loadProjects(0, want),
          readIntakeQueue(get().intakes, get().intakeQueueStatus)
        ])
        set({ projects: page.projects, projectTotal: page.total, projectsMoreError: '', ...queue })
      } else if (route === 'settings') {
        const profiles = await loadProfiles().catch(() => [])
        set({
          profileOptions: profiles.map((p) => ({ label: `${p.id} · ${p.label}`, value: p.id }))
        })
      } else if (route === 'blackboard') {
        set({ srcAutopilot: await loadSrcAutopilot().catch(() => EMPTY_AUTOPILOT) })
      }
    } catch {
      /* 单个页面读失败不打断整体;20s 轮询会重试 */
    } finally {
      set({ loading: false })
    }
  },

  async loadMoreProjects() {
    const { projects, projectTotal } = get()
    if (projects.length >= projectTotal) return
    try {
      const page = await loadProjects(projects.length, PROJECT_PAGE_SIZE)
      // 按 project_id 去重:列表按最近活动排序,翻页期间头部插进新项目会让
      // 这一页的头几条和上一页的尾几条重叠,直接 concat 会渲染出重复行。
      const seen = new Set(projects.map((p) => p.project_id))
      set({
        projects: projects.concat(page.projects.filter((p) => !seen.has(p.project_id))),
        projectTotal: page.total,
        projectsMoreError: ''
      })
    } catch (error) {
      set({ projectsMoreError: error instanceof ApiError ? error.message : '加载失败' })
    }
  },

  selectProject(projectId) {
    void (async () => {
      set({
        selectedProjectId: projectId,
        selectedSessionId: '',
        projectDetail: null,
        trajectory: [],
        guidanceRows: []
      })
      try {
        const detail = await loadProject(projectId)
        set({ projectDetail: detail })
        const first = detail.sessions[0]?.session_id
        if (first) await get().selectSession(first)
      } catch {
        set({ projectDetail: null })
      }
    })()
  },

  async selectSession(sessionId) {
    set({ selectedSessionId: sessionId })
    const [trajectory, guidanceRows] = await Promise.all([
      loadTrajectory(sessionId).catch(() => []),
      loadSessionGuidance(sessionId).catch(() => [])
    ])
    set({ trajectory, guidanceRows })
  },

  clearGuidance() {
    set({ guidanceText: '', guidanceError: '', guidanceOk: '' })
  },

  async submitGuidance() {
    const { selectedSessionId, projectDetail, guidanceText } = get()
    set({ guidanceError: '', guidanceOk: '' })
    if (!selectedSessionId || !projectDetail) {
      set({ guidanceError: '先选一个会话' })
      return
    }
    if (!guidanceText.trim()) {
      set({ guidanceError: '请输入指导' })
      return
    }
    try {
      const result = await submitSessionGuidance({
        session_id: selectedSessionId,
        target: projectDetail.target,
        guidance: guidanceText.trim()
      })
      set({ guidanceOk: `已提交 ${result.id}`, guidanceText: '' })
      set({ guidanceRows: await loadSessionGuidance(selectedSessionId).catch(() => []) })
    } catch (error) {
      set({
        guidanceError:
          error instanceof ApiError && error.status === 400 ? '目标非法 / 指导为空' : '提交失败'
      })
    }
  },

  async forkSession() {
    const detail = get().projectDetail
    if (!detail) return
    const profile = await resolveIntakeProfile(detail.sessions[0]?.profile_name || '')
    if (!profile) {
      set({ guidanceError: '分叉失败:无可用策略档' })
      return
    }
    // 分叉走的就是新建那条路:预填 + 铸预览,确认仍然由人点。
    set({
      intakeError: '',
      guidanceError: '',
      intakeForm: {
        ...get().intakeForm,
        target_url: detail.target,
        instruction: `继续深挖 ${detail.target}`,
        engagement_profile: profile
      }
    })
    await get().openNewProject()
    await get().submitIntake()
  },

  setNewProjectOpen(newProjectOpen) {
    set({ newProjectOpen })
  },

  async openNewProject() {
    // 重开弹窗时先把"已经在等确认"的预览捞回来:15 分钟内刷新页面不该丢掉它,
    // 也不该让人重新填一遍表单 —— 那样会撞上 pending_intake_exists。
    set({ intakeError: '', intakeOk: '', intakeResult: null, scopeResult: null, newProjectOpen: true })
    if (!get().profileOptions.length) {
      const profiles = await loadProfiles().catch(() => [])
      set({
        profileOptions: profiles.map((p) => ({ label: `${p.id} · ${p.label}`, value: p.id }))
      })
    }
    const pending = await loadPendingIntake().catch(() => null)
    if (pending?.preview) {
      // 直接落在确认步:确认单本身就是"还有一个在等确认"的说明。
      set({ intakePreview: pending.preview })
    }
    // 文档那条路共用这一格;拖进监听目录但没收下的文件也从这里读回来,不让一次
    // 静默的拖放变成"产品没反应"。
    set({ scopePreview: pending?.scope_preview ?? null, scopeRejects: pending?.scope_rejects ?? [] })
    const { intakeForm, profileOptions } = get()
    if (!intakeForm.engagement_profile && profileOptions.length) {
      set({ intakeForm: { ...intakeForm, engagement_profile: profileOptions[0].value } })
    }
  },

  patchIntakeForm(patch) {
    set({ intakeForm: { ...get().intakeForm, ...patch } })
  },

  async submitIntake() {
    const form = get().intakeForm
    set({ intakeError: '', intakeOk: '' })
    if (!form.target_url.trim()) {
      set({ intakeError: '请填目标 URL' })
      return
    }
    if (!form.instruction.trim()) {
      set({ intakeError: '请写一句这次要看什么' })
      return
    }
    if (!form.engagement_profile) {
      set({ intakeError: '请选策略档' })
      return
    }
    set({ intakeSubmitting: true })
    try {
      const preview = await startProjectIntake({
        target_url: form.target_url.trim(),
        instruction: form.instruction.trim(),
        engagement_profile: form.engagement_profile,
        toggles: form.toggles
      })
      // 停在确认步:到这里为止什么都没执行,也没落任何卡。
      // 队列要一起刷 —— 预览刚进队列,不刷的话关掉弹窗看不到它。
      set({
        intakePreview: preview,
        intakeOk: '',
        ...(await readIntakeQueue(get().intakes, get().intakeQueueStatus))
      })
    } catch (error) {
      const conflict = error instanceof ApiError && error.status === 409
      const body = conflict
        ? (error.body as { pending?: IntakePreview; pending_kind?: string } | undefined)
        : undefined
      if (body?.pending_kind === 'document') {
        // 挡路的是一份授权文档。它和目标预览是两个形状,不能塞进 intakePreview ——
        // 那会让弹窗按目标的字段去渲染一份文档,渲染出来的是错的,不是空的。
        set({
          scopePreview: (body.pending as unknown as ScopePreview) ?? null,
          intakeError: '待确认队列里已经有一份授权文档,先确认或放弃它'
        })
      } else if (body?.pending) {
        // 已有待确认的预览:把它摆出来,由操作者决定确认还是放弃后重填。
        set({ intakePreview: body.pending, intakeError: '已有一个待确认的预览,先确认或放弃它' })
      } else {
        set({
          intakeError:
            error instanceof ApiError && error.status === 400
              ? INTAKE_HINT[(error.body as { detail?: string } | undefined)?.detail || ''] || '目标或策略档非法'
              : '预览失败'
        })
      }
    } finally {
      set({ intakeSubmitting: false })
    }
  },

  async confirmIntake() {
    const preview = get().intakePreview
    if (!preview) return
    set({ intakeSubmitting: true, intakeError: '' })
    try {
      // 不带 session_id:由服务端为这次确认开一个新会话,运行流就落在那里,
      // 不会混进操作者当前正在读的对话。
      const result = await confirmProjectIntake({
        intake_id: preview.intake_id,
        options_digest: preview.options_digest
      })
      set({
        intakeResult: result,
        intakePreview: null,
        intakeForm: { ...get().intakeForm, target_url: '', instruction: '' },
        ...(await readIntakeQueue(get().intakes, get().intakeQueueStatus))
      })
    } catch (error) {
      const api = error instanceof ApiError ? error : null
      const detail = String((api?.body as { detail?: string } | undefined)?.detail || '')
      const expired = api?.status === 410
      set({
        intakeError: expired
          ? '预览已失效,重新提交一次'
          : INTAKE_HINT[detail] || `确认失败:${(error as Error).message}`
      })
      if (expired) set({ intakePreview: null })
    } finally {
      set({ intakeSubmitting: false })
    }
  },

  async discardIntake() {
    set({ intakeSubmitting: true, intakeError: '', intakeOk: '' })
    try {
      await discardProjectIntake()
      set({
        intakePreview: null,
        ...(await readIntakeQueue(get().intakes, get().intakeQueueStatus))
      })
    } catch {
      set({ intakeError: '取消失败' })
    } finally {
      set({ intakeSubmitting: false })
    }
  },

  patchScopeText(text, filename) {
    set({ scopeText: text, scopeFilename: filename ?? '', intakeError: '', intakeOk: '' })
  },

  async submitScopeDocument() {
    const { scopeText, scopeFilename } = get()
    set({ intakeError: '', intakeOk: '', intakeSubmitting: true })
    if (!scopeText.trim()) {
      set({ intakeSubmitting: false, intakeError: '先粘贴一份 scope JSON,或者选一个文件' })
      return
    }
    try {
      // 上传和粘贴走同一个路由:差别只是带不带 filename(它只标来源,不参与判定)。
      const preview = await startScopeIntake(
        scopeFilename ? { text: scopeText, filename: scopeFilename } : { text: scopeText }
      )
      set({ scopePreview: preview, scopeRejects: [] })
    } catch (error) {
      set({ intakeError: scopeErrorText(error) })
    } finally {
      set({ intakeSubmitting: false })
    }
  },

  async confirmScopeDocument() {
    const preview = get().scopePreview
    if (!preview) return
    set({ intakeSubmitting: true, intakeError: '' })
    try {
      // 不带 session_id:由服务端为这次确认开会话,运行流不混进操作者正在读的对话。
      const result = await confirmScopeIntake({
        intake_id: preview.intake_id,
        options_digest: preview.options_digest
      })
      set({ scopeResult: result, scopePreview: null, scopeText: '', scopeFilename: '' })
    } catch (error) {
      const expired = error instanceof ApiError && error.status === 410
      set({ intakeError: expired ? '预览已失效,重新贴一次' : scopeErrorText(error) })
      if (expired) set({ scopePreview: null })
    } finally {
      set({ intakeSubmitting: false })
    }
  },

  async discardScopeDocument() {
    set({ intakeSubmitting: true, intakeError: '', intakeOk: '' })
    try {
      await discardScopeIntake()
      set({ scopePreview: null, scopeText: '', scopeFilename: '' })
    } catch {
      set({ intakeError: '取消失败' })
    } finally {
      set({ intakeSubmitting: false })
    }
  },

  async openIntakeRun() {
    const run = get().intakeResult?.run
    if (!run) {
      // 以前这里静默 return:按下去什么都不发生,操作者只能反复按。没起运行是
      // 有原因的(门确认了、卡落盘了,但服务端没起 run),就该把原因说出来。
      set({ intakeError: '这次确认没有起运行(卡已落盘),所以没有可跳的运行流。' })
      return
    }
    set({ intakeError: '', intakeOk: '' })
    // 切到这次运行自己的会话并跳过去 —— 运行流是 SSE,attach 之后就从 seq 0 回放。
    await useChat.getState().attach(run.session_id)
    useAuth.getState().setRoute('chat')
    set({ newProjectOpen: false })
  },

  setResultsOpen(resultsOpen) {
    set({ resultsOpen })
  },

  async openResults(projectId) {
    set({ resultsOpen: true, results: null, resultsLoading: true })
    try {
      set({ results: await loadProjectResults(projectId) })
    } catch {
      set({ results: null })
    } finally {
      set({ resultsLoading: false })
    }
  },

  openInfo(title, body, links = []) {
    set({ modal: { open: true, title, meta: '', body, links, mono: false, loading: false } })
  },

  async openReport(taskId) {
    set({
      modal: {
        open: true,
        title: `报告 ${taskId}`,
        meta: taskId,
        body: '',
        links: [],
        mono: true,
        loading: true
      }
    })
    try {
      const body = (await loadReport(taskId)) || '(该任务暂无报告文件)'
      set((state) => ({ modal: { ...state.modal, body, loading: false } }))
    } catch {
      set((state) => ({ modal: { ...state.modal, body: '报告读取失败', loading: false } }))
    }
  },

  openFinding(row) {
    get().openInfo(
      row.title || '候选发现',
      [
        `任务: ${row.task}`,
        `目标: ${row.target || '—'}`,
        `类型: ${row.rule || '—'}`,
        `严重度: ${(row.severity || '?').toUpperCase()}`,
        `时间: ${row.ts ? formatTimestamp(row.ts) : '—'}`,
        '',
        '(候选发现,需二次确认)'
      ].join('\n'),
      row.target ? [row.target] : []
    )
  },

  closeModal() {
    set({ modal: CLOSED_MODAL })
  }
}))
