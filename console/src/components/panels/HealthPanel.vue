<script setup lang="ts">
// 运行健康:服务状态 + 内存 + 情报调度。重点是「一眼看出哪里不对」,
// 未知/未部署状态用中性色,不一律标红(noise)。
import { computed } from 'vue'
import { NCard, NDataTable, NSpin, NTag } from 'naive-ui'
import { systemInfo, modelPool, modelColumns, formatTimestamp } from '../../store'

type TagType = 'success' | 'error' | 'warning' | 'default' | 'info'

// 语义映射:active 绿;明确 failed/down 红;未启用/未知 中性灰。
function svcType(value: unknown): TagType {
  const s = String(value ?? '').toLowerCase()
  if (['active', 'running', 'up', 'ok'].includes(s)) return 'success'
  if (['failed', 'error', 'down', 'crashed'].includes(s)) return 'error'
  if (['inactive', 'stopped'].includes(s)) return 'warning'
  return 'default'
}

function svcLabel(value: unknown): string {
  const s = String(value ?? '').trim()
  if (!s || s.toLowerCase() === 'n/a') return '未知'
  return s
}

const services = computed<Array<[string, unknown]>>(
  () => Object.entries(systemInfo.value?.services || {}),
)
const upCount = computed(
  () => services.value.filter(([, v]) => svcType(v) === 'success').length,
)
const knownCount = computed(
  () => services.value.filter(([, v]) => svcType(v) !== 'default').length,
)

const ts = (v: unknown) => (v ? formatTimestamp(v as never) : '—')
const dash = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : String(v))

function memState(pct: unknown): 'success' | 'warning' | 'error' | 'default' {
  const n = Number(pct)
  if (!Number.isFinite(n)) return 'default'
  if (n >= 90) return 'error'
  if (n >= 75) return 'warning'
  return 'success'
}
</script>

<template>
  <main class="workbench health">
    <section class="page-heading">
      <div>
        <p class="eyebrow">SYSTEM HEALTH</p>
        <h1>运行健康</h1>
        <p>服务状态 · 内存 · 情报调度</p>
      </div>
      <div v-if="systemInfo" class="health-badges">
        <span class="hb" :class="upCount === knownCount && knownCount ? 'ok' : 'warn'">
          <span class="status-dot" :class="upCount === knownCount && knownCount ? 'success' : 'blocked'"></span>
          服务 {{ upCount }}/{{ services.length }} 在线
        </span>
        <span v-if="modelPool" class="hb">
          模型 {{ modelPool.up ?? '—' }}/{{ modelPool.total ?? '—' }} 可用
        </span>
      </div>
    </section>

    <n-spin v-if="!systemInfo" size="small" class="health-spin" />

    <template v-else>
      <section class="health-grid">
        <n-card class="hstat" :bordered="false">
          <span class="hstat-lbl">内存占用</span>
          <div class="hstat-row">
            <strong>{{ dash(systemInfo.mem.used_pct) }}<em v-if="systemInfo.mem.used_pct != null">%</em></strong>
            <n-tag :type="memState(systemInfo.mem.used_pct)" size="small" :bordered="false" round>
              {{ memState(systemInfo.mem.used_pct) === 'default' ? '未知' : memState(systemInfo.mem.used_pct) === 'error' ? '偏高' : '正常' }}
            </n-tag>
          </div>
          <small>{{ dash(systemInfo.mem.avail_mb) }}MB 可用 / {{ dash(systemInfo.mem.total_mb) }}MB</small>
        </n-card>

        <n-card class="hstat" :bordered="false">
          <span class="hstat-lbl">情报已见</span>
          <div class="hstat-row"><strong>{{ dash(systemInfo.scheduler.rss_seen) }}</strong></div>
          <small>上轮播报 {{ dash(systemInfo.scheduler.rss_last_notified) }} · 新增 {{ dash(systemInfo.scheduler.rss_last_new) }}</small>
        </n-card>

        <n-card class="hstat" :bordered="false">
          <span class="hstat-lbl">KEY 收集</span>
          <div class="hstat-row"><strong>{{ dash(systemInfo.scheduler.keyleak_status) }}</strong></div>
          <small>上轮 {{ ts(systemInfo.scheduler.keyleak_last_run) }}</small>
        </n-card>

        <n-card class="hstat" :bordered="false">
          <span class="hstat-lbl">实时 Events</span>
          <div class="hstat-row"><strong>{{ dash(systemInfo.scheduler.gh_events_status) || '未启用' }}</strong></div>
          <small>{{ systemInfo.scheduler.gh_events_last_run ? ts(systemInfo.scheduler.gh_events_last_run) : '默认关(需 token + 开关)' }}</small>
        </n-card>

        <n-card class="hstat" :bordered="false">
          <span class="hstat-lbl">socks 池</span>
          <div class="hstat-row"><strong>{{ dash(systemInfo.scheduler.socks_status) }}</strong></div>
          <small>上轮 {{ ts(systemInfo.scheduler.socks_last_run) }}</small>
        </n-card>
      </section>

      <n-card class="data-panel" :bordered="false">
        <template #header>
          <div class="panel-head">
            <div><span class="panel-kicker">SERVICES</span><h2>服务状态</h2></div>
            <n-tag v-if="knownCount" size="small" :bordered="false" round :type="upCount === knownCount ? 'success' : 'warning'">
              {{ upCount }}/{{ knownCount }} 在线
            </n-tag>
          </div>
        </template>
        <div class="svc-grid">
          <div v-for="[name, value] in services" :key="name" class="svc-row">
            <span class="svc-dot" :class="svcType(value)"></span>
            <span class="svc-name">{{ name }}</span>
            <n-tag :type="svcType(value)" size="small" :bordered="false" round>{{ svcLabel(value) }}</n-tag>
          </div>
        </div>
      </n-card>

      <n-card v-if="modelPool && modelPool.providers.length" class="data-panel" :bordered="false">
        <template #header>
          <div><span class="panel-kicker">MODEL POOL · MoA</span><h2>模型池上游 {{ modelPool.up ?? '—' }}/{{ modelPool.total ?? '—' }} 可用</h2></div>
        </template>
        <n-data-table :columns="modelColumns" :data="modelPool.providers" :pagination="false" :bordered="false" :single-line="false" />
      </n-card>
    </template>
  </main>
</template>

<style scoped>
.health { display: flex; flex-direction: column; gap: var(--pa-gap); }
.health .page-heading { margin-bottom: 0; }
.health-spin { display: block; margin: 48px auto; }

.health-badges { display: flex; gap: 8px; align-items: center; }
.hb {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;
  color: var(--pa-text-2); background: var(--pa-surface); border: 1px solid var(--pa-border);
}

.health-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: var(--pa-gap);
}
.hstat { border: 1px solid var(--pa-border) !important; border-radius: var(--pa-radius) !important; background: var(--pa-surface); box-shadow: var(--pa-shadow-soft) !important; }
.hstat :deep(.n-card__content) { display: grid; align-content: start; gap: 6px; padding: 16px 18px !important; }
.hstat-lbl { color: var(--pa-text-2); font-size: var(--pa-fs-base); }
.hstat-row { display: flex; align-items: center; gap: 8px; min-height: 30px; }
.hstat-row strong { color: var(--pa-text); font-size: var(--pa-fs-2xl); line-height: 1.05; font-weight: 650; }
.hstat-row strong em { font-size: var(--pa-fs-lg); font-style: normal; color: var(--pa-text-2); margin-left: 1px; }
.hstat small { color: var(--pa-text-3); font-size: var(--pa-fs-sm); }

.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.svc-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 2px 24px;
}
.svc-row {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 0; border-top: 1px solid var(--pa-border-soft);
}
.svc-name {
  flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: var(--pa-mono); font-size: var(--pa-fs-base); color: var(--pa-text);
}
.svc-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; background: var(--pa-text-3); }
.svc-dot.success { background: var(--pa-success); box-shadow: 0 0 0 3px rgb(21 156 132 / 14%); }
.svc-dot.error { background: var(--pa-danger); box-shadow: 0 0 0 3px rgb(212 73 68 / 14%); }
.svc-dot.warning { background: var(--pa-warning); box-shadow: 0 0 0 3px var(--pa-warning-soft); }
</style>
