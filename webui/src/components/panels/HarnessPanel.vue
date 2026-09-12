<script setup lang="ts">
// 热修:dsh 直连探测——服务/隧道没起时给"dsh 未运行"占位+启动指引,不再留白屏。
import { onMounted, ref, watch } from 'vue'
import { NButton, NEmpty, NInput } from 'naive-ui'
import { harnessUrl, harnessUrlInput, harnessCfg, applyHarnessUrl } from '../../store'

const probe = ref<'checking' | 'up' | 'down'>('checking')

async function check() {
  probe.value = 'checking'
  const ctrl = new AbortController()
  const timer = window.setTimeout(() => ctrl.abort(), 4000)
  try {
    // 相对地址(默认 /dsh/):同源,可直接看状态码,502 也能正确判 down;
    // 绝对地址(用户自定义直连):no-cors 只探活,不读内容
    const isRelative = harnessUrl.value.startsWith('/')
    const res = await fetch(harnessUrl.value, {
      mode: isRelative ? 'same-origin' : 'no-cors',
      signal: ctrl.signal,
      cache: 'no-store',
    })
    probe.value = res.type === 'opaque' || res.ok ? 'up' : 'down'
  } catch {
    probe.value = 'down'
  } finally {
    window.clearTimeout(timer)
  }
}
onMounted(check)
watch(harnessUrl, check)
</script>

<template>
  <main class="workbench harness-full">
    <iframe v-if="probe === 'up'" :src="harnessUrl" title="DeepSeek Harness" class="harness-frame"></iframe>
    <div v-else class="harness-down">
      <n-empty :description="probe === 'checking' ? '正在探测 dsh 连接…' : 'dsh 未运行(连接被拒绝)'">
        <template v-if="probe === 'down'" #extra>
          <div class="harness-help">
            <p>dsh 面板跑在 VPS 的 <code>127.0.0.1:3080</code>,本面板经控制台后端 <code>/dsh/</code> 反代同源访问,无需额外隧道。请确认:</p>
            <ol>
              <li>VPS 上 dsh 服务已启动(监听 3080):<code>ss -tlnp | grep 3080</code></li>
              <li>控制台已加载新版 control_plane(带 /dsh/ 反代)</li>
              <li>仍失败时点右上 ⚙ 检查地址(默认 <code>/dsh/</code>)</li>
            </ol>
            <n-button size="small" type="primary" @click="check">重新探测</n-button>
          </div>
        </template>
      </n-empty>
    </div>
    <button class="harness-gear" title="dsh 地址设置" @click="harnessCfg = !harnessCfg">⚙</button>
    <div v-if="harnessCfg" class="harness-cfg">
      <p>dsh 地址(默认 <code>/dsh/</code> 经控制台反代,无需额外隧道)</p>
      <div style="display:flex;gap:8px">
        <n-input v-model:value="harnessUrlInput" size="small" placeholder="/dsh/" @keyup.enter="applyHarnessUrl" />
        <n-button size="small" type="primary" @click="applyHarnessUrl">加载</n-button>
      </div>
      <a :href="harnessUrl" target="_blank" rel="noreferrer noopener" style="font-size:12px">在新标签打开 ↗</a>
    </div>
  </main>
</template>

<style scoped>
.harness-down { display: grid; place-items: center; height: 100%; background: #fff; border-radius: var(--pa-radius, 12px); }
.harness-help { max-width: 520px; text-align: left; font-size: 13px; color: var(--pa-text-2, #5f7180); }
.harness-help code { background: #f1f4f6; padding: 1px 6px; border-radius: 4px; font-size: 12px; }
.harness-help ol { margin: 8px 0 12px; padding-left: 20px; display: grid; gap: 6px; }
</style>
