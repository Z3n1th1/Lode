export type StateDirStatus = 'available' | 'missing' | 'partial' | 'unavailable'

export interface DashboardGoal {
  goal_id: string
  target: string
  profile_name: string
  created_at: number
  endpoint_count: number
  audited_endpoint_count: number
  finding_count: number
  verified_finding_count: number
  stop_condition: string | null
}

export interface DashboardTask {
  task_id: string
  target: string
  goal_id: string
  profile_name: string
  status: string
  created_at: number
  finished_at: number | null
  run_id: string
  blocked_reason: string | null
}

export interface PendingProfile {
  target: string
  goal_id: string
  profiles: string[]
  created_at: number
  expires_at: number
}

export interface PendingIntake {
  intake_id: string
  target: string
  profile_name: string
  created_at: number
  expires_at: number
  asset_inventory_enabled: boolean
  fingerprint_enabled: boolean
  intelligence_enabled: boolean
  poc_research_enabled: boolean
  proxy_route_enabled: boolean
}

export interface SandboxRun {
  task_id: string
  run_id: string
  status: string
  execution_mode: string
  network: string
  rootless: boolean
}

export interface DashboardSnapshot {
  schema: 'ControlPlaneDashboard/v1'
  generated_at: number
  state_dir_status: StateDirStatus
  profiles: Array<{ id: string; label: string }>
  goals: DashboardGoal[]
  tasks: DashboardTask[]
  pending_profiles: PendingProfile[]
  pending_intakes: PendingIntake[]
  sandbox_runs: SandboxRun[]
  capabilities: {
    target_intake: string
    approvals: string
    intelligence: string
    findings: string
    secret_broker: string
    system_health: string
    reports: string
    tool_runner: string
  }
}

export interface DashboardView {
  metrics: {
    activeGoals: number
    activeTasks: number
    blockedTasks: number
    pendingProfiles: number
    pendingIntakes: number
  }
  sandboxLabel: string
  capabilities: {
    targetIntake: string
    approvals: string
    intelligence: string
    findings: string
    secretBroker: string
    systemHealth: string
    reports: string
    toolRunner: string
  }
}

function capabilityLabel(value: string): string {
  if (value === 'synthetic_only') return '仅合成记录'
  if (value === 'not_implemented') return '未接入'
  if (value === 'preview_only') return '仅预检确认'
  if (value === 'read_only') return '只读'
  return '状态未知'
}

export function createDashboardView(snapshot: DashboardSnapshot): DashboardView {
  const activeTaskStatuses = new Set(['reserved', 'running', 'recovery_pending'])
  const activeGoals = snapshot.goals.filter(goal => goal.stop_condition === null).length
  const blockedTasks = snapshot.tasks.filter(task => task.status === 'blocked').length
  const sandboxLabel = snapshot.sandbox_runs.some(run => run.status === 'blocked')
    ? '宿主执行已阻断'
    : '暂无运行记录'

  return {
    metrics: {
      activeGoals,
      activeTasks: snapshot.tasks.filter(task => activeTaskStatuses.has(task.status)).length,
      blockedTasks,
      pendingProfiles: snapshot.pending_profiles.length,
      pendingIntakes: snapshot.pending_intakes.length
    },
    sandboxLabel,
    capabilities: {
      targetIntake: capabilityLabel(snapshot.capabilities.target_intake),
      approvals: capabilityLabel(snapshot.capabilities.approvals),
      intelligence: capabilityLabel(snapshot.capabilities.intelligence),
      findings: capabilityLabel(snapshot.capabilities.findings),
      secretBroker: capabilityLabel(snapshot.capabilities.secret_broker),
      systemHealth: capabilityLabel(snapshot.capabilities.system_health),
      reports: capabilityLabel(snapshot.capabilities.reports),
      toolRunner: capabilityLabel(snapshot.capabilities.tool_runner)
    }
  }
}

export function formatTimestamp(value: number | null): string {
  if (!value || value <= 0) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).format(new Date(value * 1000))
}

export function taskStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    reserved: '待启动',
    running: '执行中',
    recovery_pending: '等待处置',
    interrupted: '已中断',
    finished: '已完成',
    failed: '失败',
    timeout: '超时',
    blocked: '已阻断'
  }
  return labels[status] ?? '未知'
}

export function taskTagType(status: string): 'default' | 'info' | 'success' | 'warning' | 'error' {
  if (status === 'finished') return 'success'
  if (status === 'blocked' || status === 'failed') return 'error'
  if (status === 'timeout' || status === 'recovery_pending') return 'warning'
  if (status === 'running') return 'info'
  return 'default'
}

export function goalStopLabel(value: string | null): string {
  const labels: Record<string, string> = {
    rce_confirmed: '已确认 RCE',
    all_endpoints_audited: '全接口已核销',
    timebox_2h: '2 小时到期',
    timebox_elapsed: '时间盒到期'
  }
  return value ? labels[value] ?? '已结束' : '进行中'
}
