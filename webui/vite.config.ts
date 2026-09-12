import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8088',
        changeOrigin: false
      }
    }
  },
  test: {
    environment: 'node'
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(moduleId) {
          const normalizedId = moduleId.replaceAll('\\', '/')
          if (normalizedId.includes('/node_modules/naive-ui/es/data-table/')) return 'naive-table'
          if (normalizedId.includes('/node_modules/naive-ui/es/menu/')) return 'naive-navigation'
          if (normalizedId.includes('/node_modules/naive-ui/')) return 'vendor-naive-ui'
          if (normalizedId.includes('/node_modules/@lucide/vue/')) return 'vendor-lucide'
          if (normalizedId.includes('/node_modules/@vue/') || normalizedId.includes('/node_modules/vue/')) {
            return 'vendor-vue'
          }
          return null
        }
      }
    }
  }
})
