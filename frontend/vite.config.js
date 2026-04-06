import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

const BACKEND = process.env.VITE_API_BASE || 'http://localhost:8000'

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