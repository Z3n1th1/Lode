<script setup lang="ts">
// 壳顶栏:品牌 + 对话模式选择器 + 模型切换下拉 + 次级面板抽屉入口 + 刷新/退出。
// 统一对话是唯一主视图,原来的三个视图 tab 由模式选择器取代。
import { computed, onMounted, ref } from 'vue'
import { NAvatar, NButton, NSelect, NTooltip, useMessage } from 'naive-ui'
import { Bot, LayoutGrid, LogOut, Moon, RefreshCw, Settings, Sun } from '@lucide/vue'
import {
  refreshing, refreshDashboard, signOut, panelsOpen, mainView,
  chatMode, chatModes, loadChatModes, theme, toggleTheme
} from '../store'
import { loadModelPool, setActiveModel, type ModelPool } from '../api'
import ModeSelect from './chat/ModeSelect.vue'

const message = useMessage()

// R2 模型切换下拉:当前活跃 provider 常显;切换写运行时状态文件,model_client 下次调用即生效
const pool = ref<ModelPool | null>(null)
const switching = ref(false)

const activeName = computed(() => pool.value?.active || pool.value?.providers?.[0]?.name || '')
const activeModel = computed(() => {
  const p = pool.value?.providers?.find((x) => x.name === activeName.value)
  return p?.model || pool.value?.active_model || ''
})
const options = computed(() =>
  (pool.value?.providers || []).map((p) => ({
    label: `${p.name} · ${p.model}${p.up ? '' : '(down)'}`,
    value: p.name,
    disabled: !p.name
  }))
)

async function reloadPool() {
  try {
    pool.value = await loadModelPool()
  } catch { /* 池状态不可用时下拉保持空态,不阻断 header */ }
}

async function onSwitch(name: string) {
  if (!name || name === activeName.value || switching.value) return
  switching.value = true
  try {
    const r = await setActiveModel(name)
    message.success(`已切换活跃模型:${r.active} · ${r.model}${r.up ? '' : '(当前 down,调用将自动故障转移)'}`)
    await reloadPool()
  } catch (e) {
    message.error(`切换失败:${e instanceof Error ? e.message : String(e)}`)
    await reloadPool()
  } finally {
    switching.value = false
  }
}

onMounted(() => {
  void reloadPool()
  void loadChatModes()
})
</script>

<template>
  <header class="app-header">
    <div class="header-left">
      <div class="brand-mark"><Bot :size="18" /></div>
      <div class="brand-copy">
        <strong>LODE</strong>
        <span>对话式 SRC 控制台</span>
      </div>
    </div>
    <div class="header-actions">
      <ModeSelect v-model:value="chatMode" :modes="chatModes" />
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-select
            class="model-select"
            size="small"
            aria-label="切换活跃模型"
            :value="activeName || null"
            :options="options"
            :loading="switching"
            :disabled="!options.length"
            :consistent-menu-width="false"
            @update:value="onSwitch"
          />
        </template>
        活跃模型:{{ activeName || '未知' }} {{ activeModel ? `· ${activeModel}` : '' }}(切换后下一次对话即生效)
      </n-tooltip>
      <span class="environment-pill"><span class="status-dot success"></span>LOCAL</span>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle aria-label="挖洞设置" @click="mainView = 'settings'">
            <Settings :size="17" />
          </n-button>
        </template>
        挖洞设置(模型 / 密钥)
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle :aria-label="theme === 'dark' ? '切到浅色' : '切到暗色'" @click="toggleTheme()">
            <Sun v-if="theme === 'dark'" :size="17" />
            <Moon v-else :size="17" />
          </n-button>
        </template>
        {{ theme === 'dark' ? '切到浅色' : '切到暗色' }}
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle aria-label="控制面板" @click="panelsOpen = true">
            <LayoutGrid :size="17" />
          </n-button>
        </template>
        控制面板
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle aria-label="刷新状态" :loading="refreshing" @click="refreshDashboard()">
            <RefreshCw :size="17" />
          </n-button>
        </template>
        刷新状态
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button quaternary circle aria-label="退出控制面" @click="signOut">
            <LogOut :size="17" />
          </n-button>
        </template>
        退出控制面
      </n-tooltip>
      <n-avatar round :size="28" class="operator-avatar">OP</n-avatar>
    </div>
  </header>
</template>

<style scoped>
.model-select {
  width: 200px;
}
</style>
