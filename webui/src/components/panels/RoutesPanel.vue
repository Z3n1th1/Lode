<script setup lang="ts">
import { NButton, NCard, NEmpty, NInput, NSpace, NSpin, NSwitch, NTag } from 'naive-ui'
import {
  proxyStatus, proxySubs, subUrl, subName, subMsg,
  reloadProxySubs, submitProxySub, toggleSub, removeSub,
  socksPool, socksAddr, socksMsg, reloadSocks, submitSocks, removeSocksRow,
  egress, egressAllowHost, reloadEgress, submitEgressAllow, removeEgressAllowRow,
  pageLoading, formatTimestamp
} from '../../store'
</script>

<template>
  <main class="workbench">
    <section class="page-heading">
      <div><p class="eyebrow">EGRESS ROUTES</p><h1>线路与代理</h1><p>Strix 出站代理池(换地区/绕 IP 封禁)· 与对外访问代理 49511 无关</p></div>
      <n-tag :bordered="false" :type="proxyStatus?.this_round_proxied ? 'success' : 'warning'">{{ proxyStatus?.this_round_proxied ? '本轮走代理' : '本轮直连' }}</n-tag>
    </section>
    <section v-if="proxyStatus" class="metric-grid">
      <n-card class="metric-card" :bordered="false"><span>开关 PA_USE_PROXY</span><strong>{{ proxyStatus.enabled ? '开' : '关' }}</strong><small>默认关,按目标需要开</small></n-card>
      <n-card class="metric-card" :bordered="false"><span>池健康</span><strong>{{ proxyStatus.up ? 'UP' : 'DOWN' }}</strong><small>mihomo 控制器</small></n-card>
      <n-card class="metric-card" :bordered="false"><span>可用节点</span><strong>{{ proxyStatus.node_count ?? '—' }}</strong><small>url-test 自动选最快</small></n-card>
    </section>
    <n-card v-if="proxyStatus" class="data-panel" :bordered="false">
      <template #header><div><span class="panel-kicker">CURRENT NODE</span><h2>当前出口</h2></div></template>
      <dl class="status-list">
        <div><dt>当前节点</dt><dd>{{ proxyStatus.node || '—' }}</dd></div>
        <div><dt>本轮是否走代理</dt><dd><n-tag :type="proxyStatus.this_round_proxied ? 'success' : 'warning'" size="small" :bordered="false">{{ proxyStatus.this_round_proxied ? '走代理' : '直连(关/池不可用/零节点)' }}</n-tag></dd></div>
        <div v-if="proxyStatus.error"><dt>错误</dt><dd>{{ proxyStatus.error }}</dd></div>
      </dl>
      <p style="color:#9ca3af;font-size:12.5px;margin-top:10px">凭据 / LLM / 飞书永不走代理;mihomo 是稳定付费出口,下方免费 socks 池是换地区/低敏侦察备选。</p>
    </n-card>
    <n-spin v-else size="small" />

    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header>
        <div><span class="panel-kicker">PROXY SUBSCRIPTIONS</span>
        <h2>代理订阅 <small style="color:#9ca3af">(#21 · 加机场订阅→生成 mihomo 片段;不自动改主配,用户 include 后 reload)</small></h2></div>
      </template>
      <template #header-extra><n-button size="small" quaternary @click="reloadProxySubs">刷新</n-button></template>
      <div style="display:flex;gap:8px;margin-bottom:10px">
        <n-input v-model:value="subName" size="small" style="max-width:140px" placeholder="备注名(可选)" />
        <n-input v-model:value="subUrl" size="small" placeholder="机场订阅 URL(https://…)" @keyup.enter="submitProxySub" />
        <n-button type="primary" size="small" :disabled="!subUrl.trim()" @click="submitProxySub">添加订阅</n-button>
      </div>
      <span v-if="subMsg" style="color:#dc2626;font-size:12px">{{ subMsg }}</span>
      <div v-if="proxySubs.subs.length" class="pending-list">
        <article v-for="s in proxySubs.subs" :key="s.id" class="pending-row" style="flex-direction:row;align-items:center;gap:8px;flex-wrap:wrap">
          <n-switch size="small" :value="s.enabled" @update:value="(v: boolean) => toggleSub(s.id, v)" />
          <strong>{{ s.name }}</strong>
          <small style="color:#9ca3af;max-width:340px;overflow:hidden;text-overflow:ellipsis">{{ s.url }}</small>
          <n-button size="small" quaternary type="error" @click="removeSub(s.id)">移除</n-button>
        </article>
      </div>
      <n-empty v-else size="small" description="无订阅(加机场订阅 URL,socks 池的存活节点也会一并写进片段)" />
      <details v-if="proxySubs.mihomo_snippet" style="margin-top:10px">
        <summary style="cursor:pointer;color:#6b7280;font-size:13px">mihomo 片段(include 进主配后 reload)</summary>
        <pre class="code-dark">{{ proxySubs.mihomo_snippet }}</pre>
      </details>
    </n-card>

    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header>
        <div><span class="panel-kicker">FREE SOCKS POOL</span>
        <h2>免费 socks 池 <small style="color:#9ca3af">(验活入池 · 定时重验 · 换地区/低敏侦察备选,不走敏感 API)</small></h2></div>
      </template>
      <template #header-extra>
        <n-space size="small">
          <n-tag size="small" :bordered="false" type="success">存活 {{ socksPool.stats.alive || 0 }}</n-tag>
          <n-tag size="small" :bordered="false">共 {{ socksPool.stats.total || 0 }}</n-tag>
          <n-button size="small" quaternary @click="reloadSocks">刷新</n-button>
        </n-space>
      </template>
      <div style="display:flex;gap:8px;margin-bottom:10px">
        <n-input v-model:value="socksAddr" size="small" placeholder="host:port 或 socks5://host:port 或 user:pass@host:port" @keyup.enter="submitSocks" />
        <n-button type="primary" size="small" :disabled="!socksAddr.trim()" @click="submitSocks">添加+验活</n-button>
      </div>
      <span v-if="socksMsg" style="font-size:12px" :style="{ color: socksMsg.startsWith('alive') ? '#159c84' : '#dc2626' }">{{ socksMsg }}</span>
      <n-empty v-if="!socksPool.rows.length && !pageLoading" size="small" description="池为空(手动添加,或 VPS import ProxyAddr.txt)" />
      <div v-else class="pending-list">
        <article v-for="s in socksPool.rows" :key="s.addr" class="pending-row" style="flex-direction:row;align-items:center;gap:8px;flex-wrap:wrap">
          <n-tag size="tiny" :bordered="false" :type="s.status === 'alive' ? 'success' : 'default'">{{ s.status }}</n-tag>
          <strong>{{ s.addr }}</strong>
          <span v-if="s.status === 'alive'" style="color:#159c84">{{ s.latency_ms }}ms</span>
          <span v-else-if="s.last_error" style="color:#9ca3af">{{ s.last_error }}</span>
          <small style="color:#9ca3af">{{ s.added_by }}</small>
          <n-button size="small" quaternary type="error" @click="removeSocksRow(s.addr)">移除</n-button>
        </article>
      </div>
    </n-card>

    <n-card class="data-panel" :bordered="false" style="margin-top:16px">
      <template #header>
        <div><span class="panel-kicker">EGRESS SCOPE GATE</span>
        <h2>出站范围门 <small style="color:#9ca3af">(#74 · 越界被拦列表 + 误报放行 + mihomo 规则;网络级强制默认不激活)</small></h2></div>
      </template>
      <template #header-extra>
        <n-space size="small">
          <n-tag size="small" :bordered="false" :type="egress.enforced ? 'success' : 'default'">{{ egress.enforced ? '已强制' : '未强制(mihomo关)' }}</n-tag>
          <n-button size="small" quaternary @click="reloadEgress">刷新</n-button>
        </n-space>
      </template>
      <div style="display:flex;gap:8px;margin-bottom:10px">
        <n-input v-model:value="egressAllowHost" size="small" placeholder="放行 host(误报后允许其出站,如 cdn.partner.com)" @keyup.enter="() => submitEgressAllow()" />
        <n-button type="primary" size="small" :disabled="!egressAllowHost.trim()" @click="() => submitEgressAllow()">放行</n-button>
      </div>
      <h4 style="margin:8px 0 4px">越界被拦 ({{ egress.blocked.length }})<small style="color:#9ca3af;font-weight:400"> · 放行后自动回顾移除</small></h4>
      <n-empty v-if="!egress.blocked.length" size="small" description="无越界记录(egress 门未通电或全在 scope 内)" />
      <div v-else class="pending-list">
        <article v-for="(b, i) in egress.blocked" :key="i" class="pending-row" style="flex-direction:row;align-items:center;gap:8px;flex-wrap:wrap">
          <n-tag size="tiny" :bordered="false" type="error">{{ b.reason }}</n-tag>
          <strong>{{ b.host }}</strong>
          <small style="color:#9ca3af">{{ b.context }}{{ b.ts ? ' · ' + formatTimestamp(b.ts) : '' }}</small>
          <n-button size="small" type="primary" ghost @click="submitEgressAllow(b.host)">放行此host</n-button>
        </article>
      </div>
      <h4 style="margin:12px 0 4px">已放行 allowlist ({{ egress.allowlist.length }})</h4>
      <n-empty v-if="!egress.allowlist.length" size="small" description="无放行项" />
      <div v-else class="pending-list">
        <article v-for="a in egress.allowlist" :key="a.host" class="pending-row" style="flex-direction:row;align-items:center;gap:8px;flex-wrap:wrap">
          <n-tag size="tiny" :bordered="false" type="success">allow</n-tag>
          <strong>{{ a.host }}</strong>
          <small style="color:#9ca3af">{{ a.reason || a.added_by }}</small>
          <n-button size="small" quaternary type="error" @click="removeEgressAllowRow(a.host)">取消放行</n-button>
        </article>
      </div>
      <details style="margin-top:12px">
        <summary style="cursor:pointer;color:#6b7280;font-size:13px">mihomo allowlist 规则({{ egress.mihomo_rules.length }} 条,启用 mihomo 强制时应用)</summary>
        <pre class="code-dark">{{ egress.mihomo_rules.join('\n') }}</pre>
      </details>
    </n-card>
  </main>
</template>
