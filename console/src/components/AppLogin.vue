<script setup lang="ts">
import { NButton, NInput } from 'naive-ui'
import BrandMark from './BrandMark.vue'
import { password, loginError, loggingIn, submitLogin } from '../store'
</script>

<template>
  <main class="login-canvas">
    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-head">
        <div class="login-mark" aria-hidden="true"><BrandMark :size="22" /></div>
        <h1 id="login-title">Lode 控制台</h1>
      </div>
      <form class="login-form" @submit.prevent="submitLogin">
        <label for="control-plane-password">口令</label>
        <!-- id/name/autocomplete 必须经 input-props 落到真正的 <input> 上:
             naive-ui 会把普通属性挂在外层 div,那样 <label for> 就断了 -->
        <n-input
          v-model:value="password"
          type="password"
          autofocus
          placeholder=""
          :input-props="{
            id: 'control-plane-password',
            name: 'password',
            autocomplete: 'current-password',
            spellcheck: 'false'
          }"
          show-password-on="click"
          :disabled="loggingIn"
        />
        <p v-if="loginError" class="form-error" role="alert">{{ loginError }}</p>
        <n-button attr-type="submit" type="primary" :loading="loggingIn">进入</n-button>
      </form>
      <p class="login-status"><span class="status-dot success"></span>127.0.0.1 本机服务</p>
    </section>

    <aside class="login-aside">
      <p class="aside-lead">动手前先过人工门</p>
      <dl class="aside-rules">
        <div><dt>只读</dt><dd>不向目标写任何东西</dd></div>
        <div><dt>留痕</dt><dd>每一轮都落进日志</dd></div>
        <div><dt>确认</dt><dd>升级子任务要你点头</dd></div>
      </dl>
    </aside>
  </main>
</template>
