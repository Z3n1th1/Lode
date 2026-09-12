<script setup lang="ts">
// F6 收敛后的薄壳:登录门 → 对话台主视图(ConsoleChat) + 次级面板抽屉 + 共享弹窗。
// 全部业务状态/逻辑在 store.ts(单例);面板在 components/panels/*;弹窗在 components/modals/*。
import { onBeforeUnmount, onMounted } from 'vue'
import { NConfigProvider, NMessageProvider, dateZhCN, zhCN, type GlobalThemeOverrides } from 'naive-ui'

import AppLogin from './components/AppLogin.vue'
import AppHeader from './components/AppHeader.vue'
import PanelsDrawer from './components/PanelsDrawer.vue'
import ConsoleChat from './components/ConsoleChat.vue'
import SrcAgentPanel from './components/panels/SrcAgentPanel.vue'
import DetailModal from './components/modals/DetailModal.vue'
import KeyUnlockModal from './components/modals/KeyUnlockModal.vue'
import NewProjectModal from './components/modals/NewProjectModal.vue'
import ProjectResultsModal from './components/modals/ProjectResultsModal.vue'

import { authenticated, refreshDashboard, startPolling, stopPolling, mainView } from './store'

// 审美收敛:naive-ui 与 Element-Plus 共用一套 token(teal 主色 + 8px 圆角)
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
          <!-- 主视图切换:SRC 挖掘台(默认) / Strix 对话台。
               ConsoleChat 常驻(v-show)以保留在途 SSE 流;SRC 面板按需挂载。 -->
          <ConsoleChat v-show="mainView === 'chat'" />
          <SrcAgentPanel v-if="mainView === 'src'" />
        </main>
        <PanelsDrawer />
        <DetailModal />
        <KeyUnlockModal />
        <NewProjectModal />
        <ProjectResultsModal />
      </div>
    </n-message-provider>
  </n-config-provider>
</template>
