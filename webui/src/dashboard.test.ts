import { describe, expect, it } from 'vitest'

import { createDashboardView } from './dashboard'

describe('createDashboardView', () => {
  it('summarizes blocked tasks and pending profile confirmations', () => {
    const view = createDashboardView({
      schema: 'ControlPlaneDashboard/v1',
      generated_at: 1_000,
      state_dir_status: 'available',
      profiles: [{ id: 'standard-pentest', label: '标准测试' }],
      goals: [],
      tasks: [
        {
          task_id: 'T-001',
          target: 'https://example.test',
          goal_id: 'G-001',
          profile_name: 'standard-pentest',
          status: 'blocked',
          created_at: 900,
          finished_at: 901,
          run_id: 'run-001',
          blocked_reason: 'external_tool_runner_unconfigured'
        }
      ],
      pending_profiles: [
        {
          target: 'https://pending.example.test',
          goal_id: 'G-002',
          profiles: ['standard-pentest'],
          created_at: 950,
          expires_at: 1_500
        }
      ],
      pending_intakes: [
        {
          intake_id: 'I-001',
          target: 'https://intake.example.test',
          profile_name: 'standard-pentest',
          created_at: 950,
          expires_at: 1800,
          asset_inventory_enabled: false,
          fingerprint_enabled: false,
          intelligence_enabled: false,
          poc_research_enabled: false,
          proxy_route_enabled: false
        }
      ],
      sandbox_runs: [
        {
          task_id: 'T-001',
          run_id: 'run-001',
          status: 'blocked',
          execution_mode: 'synthetic',
          network: 'none',
          rootless: false
        }
      ],
      capabilities: {
        target_intake: 'preview_only',
        approvals: 'not_implemented',
        intelligence: 'read_only',
        findings: 'read_only',
        secret_broker: 'read_only',
        system_health: 'read_only',
        reports: 'read_only',
        tool_runner: 'synthetic_only'
      }
    })

    expect(view.metrics.blockedTasks).toBe(1)
    expect(view.metrics.pendingProfiles).toBe(1)
    expect(view.metrics.pendingIntakes).toBe(1)
    expect(view.sandboxLabel).toBe('宿主执行已阻断')
    expect(view.capabilities.targetIntake).toBe('仅预检确认')
    expect(view.capabilities.intelligence).toBe('只读')
    expect(view.capabilities.secretBroker).toBe('只读')
  })
})
