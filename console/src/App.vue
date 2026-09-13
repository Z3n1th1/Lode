<script setup lang="ts">
// 薄壳:登录门 → 统一对话(唯一主视图) + 挖洞设置 + 次级面板抽屉 + 共享弹窗。
// 全部业务状态/逻辑在 store.ts(单例);面板在 components/panels/*;弹窗在 components/modals/*。
import { computed, onBeforeUnmount, onMounted } from 'vue'
import {
  NConfigProvider, NMessageProvider, darkTheme, dateZhCN, zhCN, type GlobalThemeOverrides
} from 'naive-ui'

import AppLogin from './components/AppLogin.vue'
import AppHeader from './components/AppHeader.vue'
import PanelsDrawer from './components/PanelsDrawer.vue'
import UnifiedChat from './components/UnifiedChat.vue'
import SettingsPanel from './components/panels/SettingsPanel.vue'
import DetailModal from './components/modals/DetailModal.vue'
import NewProjectModal from './components/modals/NewProjectModal.vue'
import ProjectResultsModal from './components/modals/ProjectResultsModal.vue'

import {
  applyTheme, authenticated, refreshDashboard, startPolling, stopPolling, mainView, theme
} from './store'

// naive-ui 的 token 与 --pa-* 对齐,不然组件库和自绘部分会花
const DARK: GlobalThemeOverrides = {
  common: {
    primaryColor: '#17a8a0',
    primaryColorHover: '#22c4b9',
    primaryColorPressed: '#0e837d',
    primaryColorSuppl: '#22c4b9',
    bodyColor: '#0d1117',
    cardColor: '#151b23',
    modalColor: '#151b23',
    popoverColor: '#1b222c',
    tableColor: '#151b23',
    inputColor: '#0d1117',
    borderColor: '#2a323d',
    dividerColor: '#212832',
    textColorBase: '#e7edf3',
    textColor1: '#e7edf3',
    textColor2: '#9dabba',
    textColor3: '#7d8b99',
    borderRadius: '10px',
    borderRadiusSmall: '8px'
  }
}

const LIGHT: GlobalThemeOverrides = {
  common: {
    primaryColor: '#0f8b84',
    primaryColorHover: '#12a39b',
    primaryColorPressed: '#0b6c67',
    primaryColorSuppl: '#12a39b',
    borderColor: '#e2e7ee',
    dividerColor: '#edf1f5',
    textColorBase: '#121820',
    textColor2: '#55616d',
    textColor3: '#6b7783',
    borderRadius: '10px',
    borderRadiusSmall: '8px'
  }
}

const naiveTheme = computed(() => (theme.value === 'dark' ? darkTheme : null))
const themeOverrides = computed(() => (theme.value === 'dark' ? DARK : LIGHT))

onMounted(async () => {
  applyTheme()
  await refreshDashboard(false)
  if (authenticated.value) startPolling()
})

onBeforeUnmount(stopPolling)
</script>

<template>
  <n-config-provider
    :locale="zhCN"
    :date-locale="dateZhCN"
    :theme="naiveTheme"
    :theme-overrides="themeOverrides"
  >
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
