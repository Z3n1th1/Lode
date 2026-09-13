<script setup lang="ts">
// 品牌标记:Lode = 矿脉。两道成角的岩层线,粗细不同 —— 抽象,但不是盾牌/机器人那种
// 谁都能用的图标。只在这一个组件里画,登录页和顶栏共用。
defineProps<{ size?: number }>()
</script>

<template>
  <svg :width="size ?? 18" :height="size ?? 18" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M3.5 19.5 20.5 5" fill="none" stroke="currentColor"
          stroke-width="2.1" stroke-linecap="round" />
    <path d="M8 20.5 20.5 10.5" fill="none" stroke="currentColor"
          stroke-width="1.3" stroke-linecap="round" opacity=".55" />
  </svg>
</template>
