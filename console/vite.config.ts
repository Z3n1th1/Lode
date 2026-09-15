import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
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
          const id = moduleId.replaceAll('\\', '/')
          if (id.includes('/node_modules/@radix-ui/')) return 'vendor-radix'
          if (id.includes('/node_modules/lucide-react/')) return 'vendor-icons'
          if (id.includes('/node_modules/react-dom/') || id.includes('/node_modules/react/')
            || id.includes('/node_modules/scheduler/')) {
            return 'vendor-react'
          }
          return null
        }
      }
    }
  }
})
