<script setup lang="ts">
// 薄壳:登录门 → 统一对话(唯一主视图) + 挖洞设置 + 次级面板抽屉 + 共享弹窗。
// 全部业务状态/逻辑在 store.ts(单例);面板在 components/panels/*;弹窗在 components/modals/*。
import { computed, onBeforeUnmount, onMounted } from 'vue'
import {
  NConfigProvider, NDialogProvider, NMessageProvider, darkTheme, dateZhCN, zhCN,
  type GlobalThemeOverrides
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
    primaryColor: '#3f8f88',
    primaryColorHover: '#4ea8a0',
    primaryColorPressed: '#336f6a',
    primaryColorSuppl: '#4ea8a0',
    bodyColor: '#14171b',
    cardColor: '#1a1e23',
    modalColor: '#1a1e23',
    popoverColor: '#1f242a',
    tableColor: '#1a1e23',
    inputColor: '#14171b',
    borderColor: '#2c333a',
    dividerColor: '#23282e',
    textColorBase: '#e8eaed',
    textColor1: '#e8eaed',
    textColor2: '#9aa3ad',
    textColor3: '#6f7883',
    borderRadius: '10px',
    borderRadiusSmall: '6px'
  }
}

const LIGHT: GlobalThemeOverrides = {
  common: {
    primaryColor: '#2f7d77',
    primaryColorHover: '#26665f',
    primaryColorPressed: '#1f554f',
    primaryColorSuppl: '#26665f',
    borderColor: '#dfe3e8',
    dividerColor: '#e9ecf0',
    textColorBase: '#171a1e',
    textColor2: '#5a636d',
    textColor3: '#7c848e',
    borderRadius: '10px',
    borderRadiusSmall: '6px'
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
      <n-dialog-provider>
        <AppLogin v-if="!authenticated" />
        <div v-else class="shell">
          <a class="skip-link" href="#main">跳到主内容</a>
          <AppHeader />
          <main id="main" class="console-main">
            <!-- 统一对话是唯一主视图;挖洞设置是唯一的次级视图。 -->
            <UnifiedChat v-if="mainView === 'chat'" />
            <SettingsPanel v-else />
          </main>
          <PanelsDrawer />
          <DetailModal />
          <NewProjectModal />
          <ProjectResultsModal />
        </div>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>
