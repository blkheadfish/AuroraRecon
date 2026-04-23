import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// Prefer IPv4 loopback in dev to avoid VM/NAT localhost(::1) issues on Windows.
// 跨机部署：把 VITE_API_BASE 指向后端机 IP，例如 http://10.0.0.12:8000
const BACKEND = process.env.VITE_API_BASE || 'http://127.0.0.1:8000'

// dev proxy 默认超时只有几秒，重型接口（LLM、知识库构建等）会被截断
const PROXY_TIMEOUT_MS = Number(process.env.VITE_PROXY_TIMEOUT_MS) || 600000

export default defineConfig({
	plugins: [vue()],
	resolve: {
		alias: { '@': path.resolve(__dirname, 'src') },
	},
	server: {
		port: 3000,
		proxy: {
			'/api': {
				target: BACKEND,
				changeOrigin: true,
				rewrite: (p) => p.replace(/^\/api/, ''),
				timeout: PROXY_TIMEOUT_MS,
				proxyTimeout: PROXY_TIMEOUT_MS,
			},
			'/ws': {
				target: BACKEND.replace(/^http/, 'ws'),
				ws: true,
				changeOrigin: true,
				timeout: 0,
			},
			'/admin/terminal': {
				target: BACKEND.replace(/^http/, 'ws'),
				ws: true,
				changeOrigin: true,
				timeout: 0,
			},
			'/admin/terminal': {
				target: BACKEND.replace(/^http/, 'ws'),
				ws: true,
				changeOrigin: true,
				timeout: 0,
			},
		},
	},
})