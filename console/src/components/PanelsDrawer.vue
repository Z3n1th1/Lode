<script setup lang="ts">
// 控制面板抽屉:只保留 SRC 工作流真正会用到的 5 个面板。
// 其余低频运维面板已删除(系统主体是 SRC agent,不做功能堆砌)。
import { computed, h, type Component } from 'vue'
import { NDrawer, NDrawerContent, NIcon, NMenu, NSelect, type MenuOption } from 'naive-ui'
import { Bell, FolderKanban, SlidersHorizontal, Target, Workflow } from '@lucide/vue'

import { activePage, panelsOpen, pageNames } from '../store'
import SrcAutopilotPanel from './panels/SrcAutopilotPanel.vue'
import FindingsPanel from './panels/FindingsPanel.vue'
import ProjectsPanel from './panels/ProjectsPanel.vue'
import TrajectoryPanel from './panels/TrajectoryPanel.vue'
import HealthPanel from './panels/HealthPanel.vue'

const icon = (component: Component) => () => h(NIcon, null, { default: () => h(component) })

const ICONS: Record<string, Component> = {
  'src-autopilot': Target,
  findings: Bell,
  projects: FolderKanban,
  trajectory: Workflow,
  health: SlidersHorizontal
}

const PANEL_KEYS = ['src-autopilot', 'findings', 'projects', 'trajectory', 'health']

const menuOptions: MenuOption[] = PANEL_KEYS.map(key => ({
  label: pageNames[key] ?? key,
  key,
  icon: ICONS[key] ? icon(ICONS[key]) : undefined
}))

const selectOptions = PANEL_KEYS.map(key => ({ label: pageNames[key] ?? key, value: key }))

const panelComponents: Record<string, Component> = {
  'src-autopilot': SrcAutopilotPanel,
  findings: FindingsPanel,
  projects: ProjectsPanel,
  trajectory: TrajectoryPanel,
  health: HealthPanel
}

const activePanel = computed(() => panelComponents[activePage.value] ?? SrcAutopilotPanel)
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
</style>
