import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { antdCsp } from './build/antd-csp.ts'
export default defineConfig({
  plugins: [vue(), antdCsp()],
  server: { proxy: { '/api': 'http://127.0.0.1:8080' } },
  build: { target: 'es2022', sourcemap: false },
})
