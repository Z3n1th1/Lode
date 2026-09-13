<script setup lang="ts">
import { NButton, NInput } from 'naive-ui'
import BrandMark from './BrandMark.vue'
import { password, loginError, loggingIn, submitLogin } from '../store'
</script>

<template>
  <main class="login-canvas">
    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-mark" aria-hidden="true"><BrandMark :size="22" /></div>
      
      <h1 id="login-title">Lode 控制台</h1>
      <p class="login-subtitle">一条对话驱动 SRC 侦察。只读、留痕,动手前先过人工门。</p>
      <form class="login-form" @submit.prevent="submitLogin">
        <label for="control-plane-password">管理口令</label>
        <!-- id/name/autocomplete 必须经 input-props 落到真正的 <input> 上:
             naive-ui 会把普通属性挂在外层 div,那样 <label for> 就断了 -->
        <n-input
          v-model:value="password"
          type="password"
          autofocus
          :input-props="{
            id: 'control-plane-password',
            name: 'password',
            autocomplete: 'current-password',
            spellcheck: 'false'
          }"
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
