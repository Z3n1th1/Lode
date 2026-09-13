<script setup lang="ts">
import { NButton, NInput } from 'naive-ui'
import { Bot } from '@lucide/vue'
import { password, loginError, loggingIn, submitLogin } from '../store'
</script>

<template>
  <main class="login-canvas">
    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-mark" aria-hidden="true"><Bot :size="24" /></div>
      <p class="eyebrow">LODE</p>
      <h1 id="login-title">Lode 控制台</h1>
      <p class="login-subtitle">一条对话驱动 SRC 侦察 · 只读、留痕、人工门</p>
      <form class="login-form" @submit.prevent="submitLogin">
        <label for="control-plane-password">管理口令</label>
        <n-input
          id="control-plane-password"
          v-model:value="password"
          type="password"
          name="password"
          autocomplete="current-password"
          spellcheck="false"
          aria-label="管理口令"
          show-password-on="click"
          :disabled="loggingIn"
          placeholder="输入口令…"
        />
        <p v-if="loginError" class="form-error" role="alert">{{ loginError }}</p>
        <n-button attr-type="submit" type="primary" :loading="loggingIn" block>进入控制台</n-button>
      </form>
      <div class="login-status"><span class="status-dot neutral"></span>127.0.0.1 本地服务</div>
    </section>
  </main>
</template>
