<script setup lang="ts">
import { NButton, NCollapse, NCollapseItem, NInput, NInputNumber, NModal, NSelect, NSwitch } from 'naive-ui'
import { newProjectModal, intakeForm, profileOptions, intakeSubmitting, intakeErr, intakeOk, submitIntake } from '../../store'
</script>

<template>
  <n-modal v-model:show="newProjectModal" preset="card" title="新建项目" :style="{ width: '92vw', maxWidth: '560px' }" :bordered="false">
    <div class="intake-form">
      <label>目标 URL</label>
      <n-input v-model:value="intakeForm.target_url" placeholder="https://example.com（公网 http(s) 目标）" />
      <label>项目名(可选)</label>
      <n-input v-model:value="intakeForm.name" placeholder="留空=用目标" />
      <label>策略档 EngagementProfile</label>
      <n-select v-model:value="intakeForm.engagement_profile" :options="profileOptions" placeholder="选择策略档" />
      <label>开关</label>
      <div class="toggle-grid">
        <div><n-switch v-model:value="intakeForm.toggles.scan_enabled" size="small" /><span>扫描</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.fingerprint_precise" size="small" /><span>精准指纹</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.nuclei" size="small" /><span>nuclei</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.tscan" size="small" /><span>tscan</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.asset_inventory" size="small" /><span>资产枚举</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.subdomain_enum" size="small" /><span>子域枚举</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.intel" size="small" /><span>资讯雷达</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.poc_research" size="small" /><span>PoC研究</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.proxy_route" size="small" /><span>走代理</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.network_gate" size="small" /><span>网络门</span></div>
        <div><n-switch v-model:value="intakeForm.toggles.edge_human_gate" size="small" /><span>边缘人工门</span></div>
      </div>
      <n-collapse>
        <n-collapse-item title="爆破(分点·默认全关)" name="brute">
          <div class="toggle-grid">
            <div><n-switch v-model:value="intakeForm.toggles.brute.enabled" size="small" /><span>启用</span></div>
            <div><n-switch v-model:value="intakeForm.toggles.brute.path" size="small" /><span>路径</span></div>
            <div><n-switch v-model:value="intakeForm.toggles.brute.port" size="small" /><span>端口</span></div>
            <div><n-switch v-model:value="intakeForm.toggles.brute.password" size="small" /><span>密码</span></div>
            <div><n-switch v-model:value="intakeForm.toggles.brute.username" size="small" /><span>用户名</span></div>
            <div><n-switch v-model:value="intakeForm.toggles.brute.sms" size="small" /><span>短信</span></div>
            <div><n-switch v-model:value="intakeForm.toggles.brute.subdomain" size="small" /><span>子域名</span></div>
          </div>
          <div style="display:flex;gap:14px;margin-top:10px">
            <div style="flex:1"><label>次数上限</label><n-input-number v-model:value="intakeForm.toggles.brute.max_attempts" :min="0" :max="100000" size="small" style="width:100%" /></div>
            <div style="flex:1"><label>每分钟频率</label><n-input-number v-model:value="intakeForm.toggles.brute.rate_limit_per_min" :min="0" :max="6000" size="small" style="width:100%" /></div>
          </div>
        </n-collapse-item>
      </n-collapse>
      <p style="color:#9aa8af;font-size:12.5px;margin:4px 0 0">提交只记录意图,<strong>不会自动执行</strong>——agent 侧仍走 TargetCard 人工确认门后才开跑。</p>
      <p v-if="intakeErr" style="color:#dc2626;font-size:13px;margin:2px 0 0">{{ intakeErr }}</p>
      <p v-if="intakeOk" style="color:#159c84;font-size:13px;margin:2px 0 0">{{ intakeOk }}</p>
    </div>
    <template #footer>
      <n-button type="primary" block :loading="intakeSubmitting" @click="submitIntake">提交(记录意图,不执行)</n-button>
    </template>
  </n-modal>
</template>
