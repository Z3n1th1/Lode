<script setup lang="ts">
// 挖洞设置:界面配置 LLM provider(含 api key)+ 分层模型(reasoner 聪明/贵,explorer 便宜)。
// 密钥只落到本地 lode-state/llm_settings.json;接口只回掩码,这里也绝不整串回显,不写 localStorage。
import { computed, onMounted, ref } from 'vue'
import { NAlert, NButton, NCard, NEmpty, NInput, NSelect, NSpin, NTag, useMessage } from 'naive-ui'
import {
  loadLlmSettings, saveLlmSettings, testLlmProvider,
  type LlmProviderInput, type LlmSettingsView
} from '../../api'

interface ProviderDraft {
  key: string
  name: string
  base_url: string
  model: string
  api_key: string
  key_set: boolean
  key_hint: string
  clear_key: boolean
  testing?: boolean
  result?: string
}

const message = useMessage()
const loading = ref(true)
const saving = ref(false)
const settings = ref<LlmSettingsView | null>(null)
const providers = ref<ProviderDraft[]>([])
const reasoner = ref('')
const explorer = ref('')
let rowSeq = 0

const tierOptions = computed(() => [
  { label: '（留空 = 按池故障转移）', value: '' },
  ...providers.value.filter((p) => p.name.trim()).map((p) => ({ label: p.name, value: p.name }))
])
const envNote = computed(() => {
  const e = settings.value?.effective
  return !!(e?.providers_env_override || e?.legacy_env_override)
})
const settingsPath = computed(() => settings.value?.settings_path || '')

function toDraft(p: { name: string; base_url: string; model: string; key_set: boolean; key_hint: string }): ProviderDraft {
  return {
    key: `row-${rowSeq++}`,
    name: p.name,
    base_url: p.base_url,
    model: p.model,
    api_key: '',
    key_set: p.key_set,
    key_hint: p.key_hint,
    clear_key: false
  }
}

async function load() {
  loading.value = true
  try {
    const s = await loadLlmSettings()
    settings.value = s
    providers.value = (s.providers || []).map(toDraft)
    reasoner.value = s.tiers?.reasoner || ''
    explorer.value = s.tiers?.explorer || ''
  } catch (e) {
    message.error(`读取设置失败:${e instanceof Error ? e.message : String(e)}`)
  } finally {
    loading.value = false
  }
}

function addProvider() {
  providers.value.push({
    key: `row-${rowSeq++}`,
    name: '',
    base_url: 'https://api.deepseek.com',
    model: 'deepseek-chat',
    api_key: '',
    key_set: false,
    key_hint: '',
    clear_key: false
  })
}

function removeProvider(row: ProviderDraft) {
  providers.value = providers.value.filter((r) => r !== row)
  if (reasoner.value === row.name) reasoner.value = ''
  if (explorer.value === row.name) explorer.value = ''
}

function clearKey(row: ProviderDraft) {
  row.api_key = ''
  row.key_set = false
  row.key_hint = ''
  row.clear_key = true
}

async function test(row: ProviderDraft) {
  if (!row.name.trim()) {
    message.warning('先给这个 provider 起个名字')
    return
  }
  row.testing = true
  row.result = ''
  try {
    const r = await testLlmProvider({
      provider: { name: row.name.trim(), base_url: row.base_url.trim(), model: row.model.trim(), api_key: row.api_key }
    })
    row.result = r.ok ? `连通 ${r.latency_ms}ms` : `失败 ${r.error || 'unknown'}`
    if (r.ok) message.success(`${row.name} 连通正常(${r.latency_ms}ms)`)
    else message.error(`${row.name} 连接失败:${r.error}`)
  } catch (e) {
    row.result = `失败 ${e instanceof Error ? e.message : String(e)}`
  } finally {
    row.testing = false
  }
}

async function save() {
  saving.value = true
  try {
    const payload: LlmProviderInput[] = providers.value
      .filter((p) => p.name.trim())
      .map((p) => ({
        name: p.name.trim(),
        base_url: p.base_url.trim(),
        model: p.model.trim(),
        api_key: p.api_key,
        clear_key: p.clear_key
      }))
    const s = await saveLlmSettings(payload, { reasoner: reasoner.value, explorer: explorer.value })
    settings.value = s
    providers.value = (s.providers || []).map(toDraft)
    message.success('已保存,下一次挖洞立即生效')
  } catch (e) {
    message.error(`保存失败:${e instanceof Error ? e.message : String(e)}`)
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div>
        <p class="eyebrow">LLM SETTINGS</p>
        <h1>挖洞设置</h1>
        <p>配置模型与密钥 · Reasoner 用聪明模型,Explorer 用便宜模型</p>
      </div>
      <div class="heading-actions">
        <n-button size="small" quaternary :loading="loading" @click="load">重新读取</n-button>
        <n-button size="small" type="primary" :loading="saving" @click="save">保存</n-button>
      </div>
    </section>

    <n-alert v-if="envNote" type="warning" :bordered="false" class="env-note">
      当前密钥由 <code>.env</code> / 环境变量提供且优先级更高 —— 面板保存会立即生效,但重启 Console 后仍以
      <code>.env</code> 为准。要长期用面板配置,请把 <code>.env</code> 里的 <code>LLM_API_KEY</code>(可选连同
      <code>LLM_BASE_URL</code>/<code>LLM_MODEL</code>)清空一次。
    </n-alert>

    <n-spin :show="loading">
      <n-card class="data-panel" :bordered="false">
        <div class="card-head">
          <div>
            <h2>模型与密钥</h2>
            <p class="sub">密钥只存本机 <code>{{ settingsPath || 'lode-state/llm_settings.json' }}</code>,接口只回末 4 位。</p>
          </div>
          <n-button size="small" secondary @click="addProvider">+ 添加 provider</n-button>
        </div>

        <n-empty v-if="!providers.length && !loading" size="small" description="还没有 provider —— 点「添加 provider」填一个,或让 .env 继续提供" />

        <div v-for="row in providers" :key="row.key" class="provider-row">
          <div class="pr-grid">
            <label class="field">
              <span>名称</span>
              <n-input v-model:value="row.name" size="small" placeholder="deepseek" />
            </label>
            <label class="field">
              <span>模型</span>
              <n-input v-model:value="row.model" size="small" placeholder="deepseek-chat" />
            </label>
            <label class="field">
              <span>Base URL</span>
              <n-input v-model:value="row.base_url" size="small" placeholder="https://api.deepseek.com" />
            </label>
            <label class="field">
              <span>API Key</span>
              <n-input
                v-model:value="row.api_key"
                size="small"
                type="password"
                show-password-on="click"
                :placeholder="row.key_set ? `已设置 ••••${row.key_hint}(留空=不改)` : 'sk-...'"
              />
            </label>
          </div>
          <div class="pr-actions">
            <n-tag v-if="row.key_set" size="small" type="success" :bordered="false">已配置 ••••{{ row.key_hint }}</n-tag>
            <n-tag v-else size="small" :bordered="false">未配置密钥</n-tag>
            <span v-if="row.result" class="pr-result">{{ row.result }}</span>
            <span class="pr-spacer" />
            <n-button size="tiny" quaternary :loading="row.testing" @click="test(row)">测试连通性</n-button>
            <n-button v-if="row.key_set" size="tiny" quaternary @click="clearKey(row)">清除密钥</n-button>
            <n-button size="tiny" quaternary type="error" @click="removeProvider(row)">删除</n-button>
          </div>
        </div>
      </n-card>

      <n-card class="data-panel" :bordered="false">
        <div class="card-head">
          <div>
            <h2>分层路由</h2>
            <p class="sub">Reasoner 负责选目标/出假设(用聪明模型),Explorer 负责逐个看响应(用便宜模型)。</p>
          </div>
        </div>
        <div class="tier-grid">
          <label class="field">
            <span>Reasoner(推理)</span>
            <n-select v-model:value="reasoner" size="small" :options="tierOptions" />
          </label>
          <label class="field">
            <span>Explorer(干活)</span>
            <n-select v-model:value="explorer" size="small" :options="tierOptions" />
          </label>
        </div>
        <p class="hint">
          匹配规则是「名称/模型包含该字符串」——所以填 <code>deepseek</code> 会命中所有 deepseek provider。
          留空则该角色直接用整个池,失败时自动故障转移到下一个 provider。
        </p>
      </n-card>
    </n-spin>
  </main>
</template>

<style scoped>
.heading-actions { display: inline-flex; gap: 8px; align-items: center; }
.env-note { margin-bottom: var(--pa-gap); }
.env-note code, .sub code, .hint code {
  font-family: var(--pa-mono);
  font-size: 11.5px;
  background: var(--pa-bg);
  border: 1px solid var(--pa-border-soft);
  border-radius: 5px;
  padding: 1px 5px;
}
.data-panel { margin-bottom: var(--pa-gap); }
.card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 14px; }
.card-head h2 { margin: 0 0 2px; font-size: var(--pa-fs-md); color: var(--pa-text); }
.sub { margin: 0; font-size: var(--pa-fs-sm); color: var(--pa-text-3); }

.provider-row {
  border: 1px solid var(--pa-border);
  border-radius: var(--pa-radius-sm);
  padding: 12px 14px;
  margin-bottom: 10px;
  background: var(--pa-surface);
}
.pr-grid { display: grid; grid-template-columns: 1fr 1fr 1.4fr 1.4fr; gap: 10px; }
.field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.field > span { font-size: var(--pa-fs-xs); color: var(--pa-text-3); }
.pr-actions { display: flex; align-items: center; gap: 8px; margin-top: 10px; }
.pr-result { font-size: var(--pa-fs-xs); color: var(--pa-text-3); font-family: var(--pa-mono); }
.pr-spacer { flex: 1; }
.tier-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.hint { margin: 12px 0 0; font-size: var(--pa-fs-sm); color: var(--pa-text-3); line-height: 1.6; }

@media (max-width: 900px) {
  .pr-grid { grid-template-columns: 1fr 1fr; }
  .tier-grid { grid-template-columns: 1fr; }
}
</style>
