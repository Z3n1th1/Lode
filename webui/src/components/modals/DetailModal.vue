<script setup lang="ts">
import { NModal, NScrollbar, NSpin } from 'naive-ui'
import { modalOpen, modalTitle, modalBody, modalLinks, modalMono, modalLoading } from '../../store'
</script>

<template>
  <n-modal
    v-model:show="modalOpen"
    preset="card"
    :title="modalTitle"
    class="detail-modal"
    :style="{ width: '92vw', maxWidth: '880px' }"
    :bordered="false"
  >
    <n-spin v-if="modalLoading" size="large" />
    <template v-else>
      <n-scrollbar style="max-height: 62vh">
        <pre v-if="modalMono" class="modal-pre">{{ modalBody }}</pre>
        <p v-else class="modal-text">{{ modalBody }}</p>
        <div v-if="modalLinks.length" class="modal-links">
          <a v-for="(l, i) in modalLinks" :key="i" :href="l" target="_blank" rel="noreferrer noopener">{{ l }}</a>
        </div>
      </n-scrollbar>
    </template>
  </n-modal>
</template>
