# ===================================================
# PentestAI 前端镜像（Vue 3 + Nginx）
# 多阶段构建：Node 构建 → Nginx 静态服务
# ===================================================

# ── 构建阶段 ──────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html vite.config.js ./
COPY src/ src/

# 构建时 API 地址由 Nginx 反代，无需硬编码
RUN npm run build

# ── 运行阶段 ──────────────────────────────────────────────
FROM nginx:1.27-alpine

# 复制构建产物
COPY --from=builder /app/dist /usr/share/nginx/html

# 复制 Nginx 配置
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
