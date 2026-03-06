import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  // When served by the Go admin server the base is always /
  base: '/',
  server: {
    // Dev proxy: forward /api/* to the Go admin server on :9090
    proxy: {
      '/api': {
        target: 'https://localhost:9090',
        changeOrigin: true,
        secure: false, // accept self-signed cert in dev
      },
    },
  },
})
