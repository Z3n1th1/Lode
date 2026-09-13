<script setup lang="ts">
// 薄壳:登录门 → 统一对话(唯一主视图) + 挖洞设置 + 次级面板抽屉 + 共享弹窗。
// 全部业务状态/逻辑在 store.ts(单例);面板在 components/panels/*;弹窗在 components/modals/*。
import { onBeforeUnmount, onMounted } from 'vue'
import { NConfigProvider, NMessageProvider, dateZhCN, zhCN, type GlobalThemeOverrides } from 'naive-ui'

import AppLogin from './components/AppLogin.vue'
import AppHeader from './components/AppHeader.vue'
import PanelsDrawer from './components/PanelsDrawer.vue'
import UnifiedChat from './components/UnifiedChat.vue'
import SettingsPanel from './components/panels/SettingsPanel.vue'
import DetailModal from './components/modals/DetailModal.vue'
import NewProjectModal from './components/modals/NewProjectModal.vue'
import ProjectResultsModal from './components/modals/ProjectResultsModal.vue'

import { authenticated, refreshDashboard, startPolling, stopPolling, mainView } from './store'

// 审美收敛:naive-ui 单套 token(teal 主色 + 8px 圆角)
const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: '#178e8b',
    primaryColorHover: '#1ba19e',
    primaryColorPressed: '#12706d',
    primaryColorSuppl: '#178e8b',
    borderRadius: '8px',
    borderRadiusSmall: '6px'
  }
}

onMounted(async () => {
  await refreshDashboard(false)
  if (authenticated.value) startPolling()
})

onBeforeUnmount(stopPolling)
</script>

<template>
  <n-config-provider :locale="zhCN" :date-locale="dateZhCN" :theme-overrides="themeOverrides">
    <n-message-provider>
      <AppLogin v-if="!authenticated" />
      <div v-else class="shell">
        <AppHeader />
        <main class="console-main">
          <!-- 统一对话是唯一主视图;挖洞设置是唯一的次级视图。 -->
          <UnifiedChat v-if="mainView === 'chat'" />
          <SettingsPanel v-else />
        </main>
        <PanelsDrawer />
        <DetailModal />
        <NewProjectModal />
        <ProjectResultsModal />
      </div>
    </n-message-provider>
  </n-config-provider>
</template>
