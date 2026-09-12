<script setup lang="ts">
// 控制面板抽屉:核心面板平铺,其余收进「更多工具」折叠组。
// 系统主体是 SRC agent,运维面板默认收起,避免首屏信息过载(功能不删,只是降噪)。
import { computed, h, type Component } from 'vue'
import { NDrawer, NDrawerContent, NIcon, NMenu, NSelect, type MenuOption } from 'naive-ui'
import {
  Activity, Archive, Bell, FileCheck2, Fingerprint, FolderKanban, Gauge,
  KeyRound, Layers, Network, Radar, ShieldCheck, SlidersHorizontal, Target, Workflow, Wrench
} from '@lucide/vue'

import { activePage, panelsOpen, pageNames } from '../store'
import WorkbenchPanel from './panels/WorkbenchPanel.vue'
import ProjectsPanel from './panels/ProjectsPanel.vue'
import TrajectoryPanel from './panels/TrajectoryPanel.vue'
import IntakePanel from './panels/IntakePanel.vue'
import AssetsPanel from './panels/AssetsPanel.vue'
import RunsPanel from './panels/RunsPanel.vue'
import ApprovalsPanel from './panels/ApprovalsPanel.vue'
import FindingsPanel from './panels/FindingsPanel.vue'
import ReportsPanel from './panels/ReportsPanel.vue'
import IntelligencePanel from './panels/IntelligencePanel.vue'
import PocPanel from './panels/PocPanel.vue'
import SecretsPanel from './panels/SecretsPanel.vue'
import SandboxPanel from './panels/SandboxPanel.vue'
import RoutesPanel from './panels/RoutesPanel.vue'
import HealthPanel from './panels/HealthPanel.vue'
import ProfilesPanel from './panels/ProfilesPanel.vue'
import HarnessPanel from './panels/HarnessPanel.vue'
import SrcAutopilotPanel from './panels/SrcAutopilotPanel.vue'

const icon = (component: Component) => () => h(NIcon, null, { default: () => h(component) })

const ICONS: Record<string, Component> = {
  workbench: Gauge,
  projects: FolderKanban,
  trajectory: Workflow,
  intake: Target,
  assets: Fingerprint,
  runs: Activity,
  approvals: ShieldCheck,
  findings: Bell,
  reports: FileCheck2,
  intelligence: Radar,
  'src-autopilot': Target,
  poc: Archive,
  secrets: KeyRound,
  sandbox: Wrench,
  routes: Network,
  health: SlidersHorizontal,
  profiles: Layers,
  harness: Wrench
}

// 核心:SRC 工作流日常真正会用到的
const CORE_KEYS = ['src-autopilot', 'findings', 'projects', 'trajectory', 'health']
// 更多:低频运维面板,折叠收纳
const MORE_KEYS = [
  'workbench', 'intake', 'assets', 'runs', 'approvals', 'reports',
  'intelligence', 'poc', 'secrets', 'sandbox', 'routes', 'profiles', 'harness'
]

const toOption = (key: string): MenuOption => ({
  label: pageNames[key] ?? key,
  key,
  icon: ICONS[key] ? icon(ICONS[key]) : undefined
})

const menuOptions: MenuOption[] = [
  { type: 'group', label: '核心', key: '__core', children: CORE_KEYS.map(toOption) },
  { label: '更多工具', key: '__more', children: MORE_KEYS.map(toOption) }
]

const selectOptions = [...CORE_KEYS, ...MORE_KEYS].map(k => ({ label: pageNames[k] ?? k, value: k }))

const panelComponents: Record<string, Component> = {
  workbench: WorkbenchPanel,
  projects: ProjectsPanel,
  trajectory: TrajectoryPanel,
  intake: IntakePanel,
  assets: AssetsPanel,
  runs: RunsPanel,
  approvals: ApprovalsPanel,
  findings: FindingsPanel,
  reports: ReportsPanel,
  intelligence: IntelligencePanel,
  poc: PocPanel,
  secrets: SecretsPanel,
  sandbox: SandboxPanel,
  routes: RoutesPanel,
  health: HealthPanel,
  profiles: ProfilesPanel,
  harness: HarnessPanel,
  'src-autopilot': SrcAutopilotPanel
}

const activePanel = computed(() => panelComponents[activePage.value] ?? WorkbenchPanel)
</script>

<template>
  <n-drawer v-model:show="panelsOpen" placement="left" width="min(1180px, 96vw)" class="panels-drawer">
    <n-drawer-content :title="pageNames[activePage] || '控制面板'" closable body-content-style="padding:0">
      <div class="pd">
        <nav class="pd-nav">
          <p class="pd-nav-label">控制面板</p>
          <n-menu v-model:value="activePage" :options="menuOptions" class="pd-menu" />
        </nav>
        <div class="pd-nav-mobile">
          <n-select v-model:value="activePage" :options="selectOptions" size="small" />
        </div>
        <section class="pd-body">
          <component :is="activePanel" />
        </section>
      </div>
    </n-drawer-content>
  </n-drawer>
</template>

<style scoped>
.pd-nav-label {
  margin: 2px 10px 10px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .6px;
  text-transform: uppercase;
  color: var(--pa-text-3);
}
.pd-menu :deep(.n-menu-item-content) { border-radius: 9px; }
.pd-menu :deep(.n-menu-item-content-header) { font-size: 13px; }
.pd-menu :deep(.n-menu-item-group-title) { font-size: 11px; }
</style>
