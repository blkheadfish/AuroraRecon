<template>
  <el-container class="app-layout">
    <!-- Sidebar -->
    <el-aside width="220px" class="sidebar">
      <div class="sidebar-logo">
        <el-icon class="logo-icon"><Monitor /></el-icon>
        <span class="logo-text">PentestAI</span>
      </div>

      <el-menu
          :default-active="activeMenu"
          router
          class="sidebar-menu"
      >
        <el-menu-item index="/dashboard">
          <el-icon><DataLine /></el-icon>
          <span>仪表盘</span>
        </el-menu-item>
        <el-menu-item index="/tasks">
          <el-icon><List /></el-icon>
          <span>任务列表</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer">
        <!-- Theme toggle -->
        <div class="theme-toggle" @click="toggleTheme">
          <el-icon v-if="theme === 'dark'" class="theme-icon"><Sunny /></el-icon>
          <el-icon v-else class="theme-icon"><Moon /></el-icon>
          <span class="theme-label">{{ theme === 'dark' ? '切换亮色' : '切换暗色' }}</span>
        </div>

        <span class="version-badge">v2.0.0</span>
        <span class="api-status" :class="apiOk ? 'ok' : 'err'">
          <span class="dot"></span>
          {{ apiOk ? 'API 在线' : 'API 离线' }}
        </span>
        <span v-if="dbStatus" class="db-status" :class="dbStatus === 'connected' ? 'ok' : 'warn'">
          <span class="dot"></span>
          DB {{ dbStatus === 'connected' ? '已连接' : '离线' }}
        </span>
      </div>
    </el-aside>

    <!-- Main content -->
    <el-main class="main-content">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api'
import { useTheme } from '@/composables/useTheme'

const route = useRoute()
const activeMenu = computed(() => {
  if (route.path.startsWith('/tasks/')) return '/tasks'
  return route.path === '/' ? '/dashboard' : route.path
})

const { theme, init: initTheme, toggle: toggleTheme } = useTheme()

const apiOk = ref(false)
const dbStatus = ref(null)

async function checkApi() {
  try {
    const health = await api.healthCheck()
    apiOk.value = health.status === 'ok'
    dbStatus.value = health.database
  } catch {
    apiOk.value = false
    dbStatus.value = null
  }
}

onMounted(() => {
  initTheme()
  checkApi()
  setInterval(checkApi, 30000)
})
</script>

<style scoped>
.app-layout {
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  background: var(--bg-surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  transition: background 0.2s, border-color 0.2s;
}

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 20px;
  border-bottom: 1px solid var(--border);
}

.logo-icon {
  font-size: 20px;
  color: var(--accent-blue);
}

.logo-text {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.02em;
  color: var(--text-primary);
  font-family: var(--font-mono);
}

.sidebar-menu {
  flex: 1;
  border: none !important;
  padding: 8px;
}

:deep(.el-menu-item) {
  border-radius: var(--radius-md) !important;
  margin: 2px 0 !important;
  font-size: 13px !important;
}

.sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

/* Theme toggle */
.theme-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: background 0.15s;
  color: var(--text-secondary);
  font-size: 12px;
}

.theme-toggle:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.theme-icon {
  font-size: 16px;
  color: var(--accent-yellow);
}

.theme-label {
  font-family: var(--font-sans);
}

.version-badge {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}

.api-status,
.db-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary);
}

.api-status .dot,
.db-status .dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--text-muted);
}

.api-status.ok,
.db-status.ok { color: var(--accent-green); }
.api-status.ok .dot,
.db-status.ok .dot { background: var(--accent-green); }
.api-status.err { color: var(--accent-red); }
.api-status.err .dot { background: var(--accent-red); }
.db-status.warn { color: var(--accent-yellow); }
.db-status.warn .dot { background: var(--accent-yellow); }

.main-content {
  background: var(--bg-base);
  padding: 0;
  overflow-y: auto;
  transition: background 0.2s;
}
</style>