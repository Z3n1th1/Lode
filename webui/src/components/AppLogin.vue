<script setup lang="ts">
import { NButton, NInput } from 'naive-ui'
import { Bot } from '@lucide/vue'
import { password, loginError, loggingIn, submitLogin } from '../store'
</script>

<template>
  <main class="login-canvas">
    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-mark" aria-hidden="true"><Bot :size="24" /></div>
      <p class="eyebrow">PENTEST AGENT</p>
      <h1 id="login-title">本地控制面</h1>
      <p class="login-subtitle">对话式 Agent 控制台 · 运行状态与人工门</p>
      <form class="login-form" @submit.prevent="submitLogin">
        <label for="control-plane-password">管理口令</label>
        <n-input
          id="control-plane-password"
          v-model:value="password"
          type="password"
          aria-label="管理口令"
          show-password-on="click"
          :disabled="loggingIn"
          placeholder="输入口令"
        />
        <p v-if="loginError" class="form-error" role="alert">{{ loginError }}</p>
        <n-button attr-type="submit" type="primary" :loading="loggingIn" block>登录</n-button>
      </form>
      <div class="login-status"><span class="status-dot neutral"></span>127.0.0.1 本地服务</div>
    </section>
  </main>
</template>
