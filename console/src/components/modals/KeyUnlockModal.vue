<script setup lang="ts">
import { NButton, NInput, NModal } from 'naive-ui'
import { keyUnlockModal, keyUnlockPw, keyUnlockErr, submitKeyUnlock } from '../../store'
</script>

<template>
  <n-modal v-model:show="keyUnlockModal" preset="card" title="解锁明文密钥" :style="{ width: '92vw', maxWidth: '420px' }" :bordered="false">
    <p style="color:#6b7280;font-size:13px;margin-bottom:10px">输入密钥库密码,解锁 2 小时后自动回掩。密钥全程加密封存,明文不落盘、只在此窗口内解出。</p>
    <n-input v-model:value="keyUnlockPw" type="password" show-password-on="click" placeholder="密钥库密码" @keyup.enter="submitKeyUnlock" />
    <p v-if="keyUnlockErr" style="color:#dc2626;font-size:13px;margin-top:8px">{{ keyUnlockErr }}</p>
    <template #footer>
      <n-button type="primary" block @click="submitKeyUnlock">解锁</n-button>
    </template>
  </n-modal>
</template>
