import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// Prefer IPv4 loopback in dev to avoid VM/NAT localhost(::1) issues on Windows.
const BACKEND = process.env.VITE_API_BASE || 'http://127.0.0.1:8000'

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
			},
			'/ws': {
				target: BACKEND.replace(/^http/, 'ws'),
				ws: true,
				changeOrigin: true,
				timeout: 0,
			},
		},
	},
})