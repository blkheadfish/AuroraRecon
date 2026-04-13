<template>
  <div v-if="hideSidebar" class="start-layout">
    <router-view />
  </div>

  <el-container v-else class="app-layout" :class="{ 'mobile-layout': isMobile }">
    <div v-if="isMobile && !sidebarCollapsed" class="mobile-overlay" @click="uiPrefs.sidebarCollapsed = true"></div>
    <el-aside :width="sidebarCollapsed ? (isMobile ? '0px' : '64px') : '220px'" class="sidebar" :class="{ collapsed: sidebarCollapsed, 'mobile-sidebar': isMobile }">
      <div class="sidebar-logo">
        <el-icon class="logo-icon"><Monitor /></el-icon>
        <transition name="fade-text">
          <span v-if="!sidebarCollapsed" class="logo-text-group">
            <span class="logo-text">Aurora</span><span class="logo-text" style="color:#7fe0bd">Recon</span>
          </span>
        </transition>
      </div>

      <div class="collapse-toggle" @click="uiPrefs.sidebarCollapsed = !uiPrefs.sidebarCollapsed">
        <el-icon><Fold v-if="!sidebarCollapsed" /><Expand v-else /></el-icon>
      </div>

      <el-menu
          :default-active="activeMenu"
          router
          :collapse="sidebarCollapsed"
          class="sidebar-menu"
      >
        <el-menu-item index="/dashboard">
          <el-icon><DataLine /></el-icon>
          <template #title><span>工作台</span></template>
        </el-menu-item>
        <el-menu-item index="/tasks">
          <el-icon><List /></el-icon>
          <template #title><span>任务列表</span></template>
        </el-menu-item>
        <el-menu-item index="/tools">
          <el-icon><Grid /></el-icon>
          <template #title><span>工具管理</span></template>
        </el-menu-item>
        <el-menu-item index="/skills">
          <el-icon><Tools /></el-icon>
          <template #title><span>Skills管理</span></template>
        </el-menu-item>
        <el-menu-item index="/knowledge">
          <el-icon><Reading /></el-icon>
          <template #title><span>知识库管理</span></template>
        </el-menu-item>
        <el-menu-item index="/prompts">
          <el-icon><ChatDotRound /></el-icon>
          <template #title><span>Prompt管理</span></template>
        </el-menu-item>
        <el-menu-item index="/profile">
          <el-icon><User /></el-icon>
          <template #title><span>个人空间</span></template>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <template #title><span>系统设置</span></template>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer">
        <div class="theme-toggle" @click="toggleTheme">
          <el-icon v-if="theme === 'dark'" class="theme-icon"><Sunny /></el-icon>
          <el-icon v-else class="theme-icon"><Moon /></el-icon>
          <span v-if="!sidebarCollapsed" class="theme-label">{{ theme === 'dark' ? '切换亮色' : '切换暗色' }}</span>
        </div>

        <template v-if="!sidebarCollapsed">
          <span class="version-badge">v2.0.0</span>
          <span class="api-status" :class="apiOk ? 'ok' : 'err'">
            <span class="dot"></span>
            {{ apiOk ? 'API 在线' : 'API 离线' }}
          </span>
          <span v-if="dbStatus" class="db-status" :class="dbStatus === 'connected' ? 'ok' : 'warn'">
            <span class="dot"></span>
            DB {{ dbStatus === 'connected' ? '已连接' : '离线' }}
          </span>
        </template>
        <template v-else>
          <span class="api-dot-only" :class="apiOk ? 'ok' : 'err'">
            <span class="dot"></span>
          </span>
        </template>
      </div>
    </el-aside>

    <el-main class="main-content">
      <div v-if="isMobile" class="mobile-topbar">
        <el-button link @click="uiPrefs.sidebarCollapsed = !uiPrefs.sidebarCollapsed" class="hamburger-btn">
          <el-icon :size="20"><Expand /></el-icon>
        </el-button>
        <span class="mobile-title">AuroraRecon</span>
      </div>
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup>
import { computed, ref, watch, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api'
import { useTheme } from '@/composables/useTheme'
import { useUiPrefsStore } from '@/stores/uiPrefs'
import { storeToRefs } from 'pinia'

const MOBILE_BREAKPOINT = 768

const route = useRoute()
const uiPrefs = useUiPrefsStore()
const { sidebarCollapsed } = storeToRefs(uiPrefs)
const isMobile = ref(window.innerWidth < MOBILE_BREAKPOINT)

function onResize() {
  const nowMobile = window.innerWidth < MOBILE_BREAKPOINT
  if (nowMobile && !isMobile.value) {
    uiPrefs.sidebarCollapsed = true
  }
  isMobile.value = nowMobile
}

watch(() => route.path, () => {
  if (isMobile.value) uiPrefs.sidebarCollapsed = true
})

const hideSidebar = computed(() =>
  ['/start', '/login', '/register'].includes(route.path)
)
const activeMenu = computed(() => {
  if (route.path.startsWith('/tasks/')) return '/tasks'
  if (route.path.startsWith('/reports/')) return '/tasks'
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

let apiCheckTimer = null

onMounted(() => {
  initTheme()
  checkApi()
  apiCheckTimer = setInterval(checkApi, 30000)
  window.addEventListener('resize', onResize)
  onResize()
})

onUnmounted(() => {
  if (apiCheckTimer) clearInterval(apiCheckTimer)
  window.removeEventListener('resize', onResize)
})
</script>

<style scoped>
.start-layout {
  height: 100vh;
  overflow: hidden;
  background: var(--bg-base);
}

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
  transition: width 0.25s cubic-bezier(0.4, 0, 0.2, 1), background 0.2s, border-color 0.2s;
}

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 20px;
  border-bottom: 1px solid var(--border);
  min-height: 56px;
  overflow: hidden;
}

.sidebar.collapsed .sidebar-logo {
  justify-content: center;
  padding: 18px 0;
}

.logo-icon {
  font-size: 20px;
  color: var(--accent-blue);
  flex-shrink: 0;
}

.logo-text-group {
  white-space: nowrap;
  overflow: hidden;
}

.logo-text {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.02em;
  color: var(--text-primary);
  font-family: var(--font-orbitron);
}

.collapse-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 6px;
  margin: 4px 8px;
  border-radius: var(--radius-md);
  cursor: pointer;
  color: var(--text-muted);
  transition: background 0.15s, color 0.15s;
}

.collapse-toggle:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.sidebar-menu {
  flex: 1;
  border: none !important;
  padding: 8px;
  overflow: hidden;
}

:deep(.el-menu-item) {
  border-radius: var(--radius-md) !important;
  margin: 2px 0 !important;
  font-size: 13px !important;
}

.sidebar.collapsed :deep(.el-menu) {
  padding: 8px 4px;
}

.sidebar.collapsed :deep(.el-menu-item) {
  padding: 0 !important;
  justify-content: center;
  margin: 2px auto !important;
}

.sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.sidebar.collapsed .sidebar-footer {
  padding: 12px 8px;
  align-items: center;
}

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

.sidebar.collapsed .theme-toggle {
  justify-content: center;
  padding: 6px;
}

.theme-toggle:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.theme-icon {
  font-size: 16px;
  color: var(--accent-yellow);
  flex-shrink: 0;
}

.theme-label {
  font-family: var(--font-sans);
  white-space: nowrap;
  overflow: hidden;
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
.db-status .dot,
.api-dot-only .dot {
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

.api-dot-only {
  display: flex;
  justify-content: center;
}
.api-dot-only.ok .dot { background: var(--accent-green); }
.api-dot-only.err .dot { background: var(--accent-red); }

.main-content {
  background: var(--bg-base);
  padding: 0;
  overflow-y: auto;
  transition: background 0.2s;
}

.fade-text-enter-active,
.fade-text-leave-active {
  transition: opacity 0.2s ease;
}
.fade-text-enter-from,
.fade-text-leave-to {
  opacity: 0;
}

/* ── Mobile ── */
.mobile-overlay {
  position: fixed;
  inset: 0;
  z-index: 999;
  background: rgba(0, 0, 0, 0.45);
}

.mobile-sidebar {
  position: fixed !important;
  top: 0;
  left: 0;
  bottom: 0;
  z-index: 1000;
}

.mobile-sidebar.collapsed {
  width: 0 !important;
  overflow: hidden;
}

.mobile-topbar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-surface);
}

.hamburger-btn {
  color: var(--text-secondary) !important;
  padding: 4px !important;
}

.mobile-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text-primary);
  font-family: var(--font-orbitron);
}

@media (max-width: 768px) {
  .summary-grid {
    grid-template-columns: repeat(2, 1fr) !important;
  }
}
</style>