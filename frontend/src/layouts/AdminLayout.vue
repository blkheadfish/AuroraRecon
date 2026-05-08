<template>
  <div class="admin-shell" :class="{ 'sidebar-collapsed': sidebarCollapsed, 'is-mobile': isMobile }">
    <div v-if="isMobile && !sidebarCollapsed" class="admin-mobile-overlay" @click="sidebarCollapsed = true" />

    <aside class="admin-sidebar" :class="{ collapsed: sidebarCollapsed }">
      <div class="admin-sidebar-brand">
        <div class="admin-brand-badge">
          <span class="brand-bar" />
          <el-icon :size="18"><Monitor /></el-icon>
          <transition name="fade-text">
            <span v-if="!sidebarCollapsed" class="brand-text">ADMIN CONSOLE</span>
          </transition>
        </div>
      </div>

      <div class="admin-collapse-toggle" @click="sidebarCollapsed = !sidebarCollapsed">
        <el-icon><Fold v-if="!sidebarCollapsed" /><Expand v-else /></el-icon>
      </div>

      <nav class="admin-nav">
        <template v-for="(group, gi) in navGroups" :key="gi">
          <div v-if="!sidebarCollapsed" class="admin-nav-group">{{ group.title }}</div>
          <div v-else class="admin-nav-divider" />
          <router-link
            v-for="item in group.items"
            :key="item.path"
            :to="item.path"
            class="admin-nav-item"
            :class="{ active: isActive(item.path) }"
            @click="isMobile && (sidebarCollapsed = true)"
          >
            <el-icon :size="16"><component :is="item.icon" /></el-icon>
            <transition name="fade-text">
              <span v-if="!sidebarCollapsed" class="nav-label">
                <span class="nav-cn">{{ item.label }}</span>
                <span class="nav-en">{{ item.sublabel }}</span>
              </span>
            </transition>
          </router-link>
        </template>
      </nav>

      <div class="admin-sidebar-footer">
        <div class="admin-health-dots">
          <span class="health-dot" :class="health.database === 'connected' ? 'ok' : 'err'" />
          <transition name="fade-text">
            <span v-if="!sidebarCollapsed" class="health-label">DB</span>
          </transition>
          <span class="health-dot" :class="health.redis === 'connected' ? 'ok' : 'err'" />
          <transition name="fade-text">
            <span v-if="!sidebarCollapsed" class="health-label">Redis</span>
          </transition>
          <span class="health-dot" :class="health.msf === 'connected' ? 'ok' : 'err'" />
          <transition name="fade-text">
            <span v-if="!sidebarCollapsed" class="health-label">MSF</span>
          </transition>
        </div>
        <div class="admin-theme-toggle" @click="toggleTheme">
          <el-icon v-if="theme === 'dark'" class="theme-icon"><Sunny /></el-icon>
          <el-icon v-else class="theme-icon"><Moon /></el-icon>
          <span v-if="!sidebarCollapsed" class="theme-label">{{ theme === 'dark' ? '亮色' : '暗色' }}</span>
        </div>
      </div>
    </aside>

    <div class="admin-body">
      <header class="admin-topbar">
        <el-button v-if="isMobile" link class="admin-hamburger" @click="sidebarCollapsed = !sidebarCollapsed">
          <el-icon :size="20"><Expand /></el-icon>
        </el-button>

        <div class="admin-breadcrumb">
          <span class="breadcrumb-console">管理控制台</span>
          <el-icon :size="12"><ArrowRight /></el-icon>
          <span class="breadcrumb-current">{{ currentPageLabel }}</span>
        </div>

        <div class="topbar-spacer" />

        <el-tooltip
          placement="bottom"
          effect="dark"
          :show-after="120"
          :hide-after="80"
          popper-class="github-tooltip"
        >
          <template #content>
            <div class="github-tip">
              <div class="github-tip-title">AuroraRecon · GitHub</div>
              <div class="github-tip-desc">查看项目源码 / 提 Issue / Star 支持一下</div>
              <div class="github-tip-url">github.com/blkheadfish/AuroraRecon</div>
            </div>
          </template>
          <a
            class="admin-github-link"
            href="https://github.com/blkheadfish/AuroraRecon"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub Repository"
          >
            <svg
              class="admin-github-icon"
              viewBox="0 0 24 24"
              width="16"
              height="16"
              aria-hidden="true"
              focusable="false"
            >
              <path
                fill="currentColor"
                d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.57.1.78-.25.78-.55 0-.27-.01-1.16-.02-2.1-3.2.7-3.87-1.36-3.87-1.36-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.25 3.34.96.1-.74.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.28 1.18-3.09-.12-.29-.51-1.46.11-3.04 0 0 .97-.31 3.18 1.18a11.06 11.06 0 0 1 5.79 0c2.21-1.49 3.18-1.18 3.18-1.18.62 1.58.23 2.75.11 3.04.74.81 1.18 1.83 1.18 3.09 0 4.42-2.69 5.4-5.25 5.68.41.36.78 1.06.78 2.13 0 1.54-.01 2.78-.01 3.16 0 .31.21.66.79.55C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z"
              />
            </svg>
            <span v-if="!isMobile" class="admin-github-label">GitHub 仓库</span>
          </a>
        </el-tooltip>

        <el-dropdown trigger="click" @command="handleUserCmd">
          <div class="admin-user-trigger" tabindex="0">
            <el-avatar :size="28" class="admin-avatar">{{ userInitial }}</el-avatar>
            <span v-if="!isMobile" class="admin-user-name">{{ displayName }}</span>
            <el-tag type="danger" size="small" effect="plain" class="admin-role-tag">admin</el-tag>
          </div>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="profile"><el-icon><User /></el-icon>个人空间</el-dropdown-item>
              <el-dropdown-item command="logout" divided><el-icon><SwitchButton /></el-icon>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </header>

      <main class="admin-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Monitor, Fold, Expand, ArrowRight,
  User, SwitchButton, Sunny, Moon,
  Odometer, UserFilled, Notebook,
  List, Briefcase, MagicStick, Reading, ChatDotSquare, Setting,
} from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { useTheme } from '@/composables/useTheme'
import { api } from '@/api'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const MOBILE_BREAKPOINT = 768
const isMobile = ref(window.innerWidth < MOBILE_BREAKPOINT)
const sidebarCollapsed = ref(isMobile.value)

const { theme, init: initTheme, toggle: toggleTheme } = useTheme()

const displayName = computed(() => auth.displayName || '管理员')
const userInitial = computed(() => (displayName.value || 'A').slice(0, 1).toUpperCase())

const navGroups = [
  {
    title: '运维',
    items: [
      { path: '/admin/dashboard', label: '仪表盘', sublabel: 'Dashboard', icon: Odometer },
      { path: '/admin/tasks', label: '任务管理', sublabel: 'Tasks', icon: List },
    ],
  },
  {
    title: '资产',
    items: [
      { path: '/admin/tools', label: '工具管理', sublabel: 'Tools', icon: Briefcase },
      { path: '/admin/skills', label: 'Skills', sublabel: 'Skills', icon: MagicStick },
      { path: '/admin/knowledge', label: '知识库', sublabel: 'Knowledge', icon: Reading },
      { path: '/admin/prompts', label: 'Prompt', sublabel: 'Prompts', icon: ChatDotSquare },
    ],
  },
  {
    title: '管控',
    items: [
      { path: '/admin/users', label: '用户管理', sublabel: 'Users', icon: UserFilled },
      { path: '/admin/settings', label: '系统设置', sublabel: 'Settings', icon: Setting },
      { path: '/admin/audit', label: '审计日志', sublabel: 'Audit', icon: Notebook },
    ],
  },
  {
    title: '运维工具',
    items: [
      { path: '/admin/terminal', label: 'SSH 终端', sublabel: 'Terminal', icon: Monitor },
      { path: '/admin/metrics', label: '性能指标', sublabel: 'Metrics', icon: Odometer },
    ],
  },
]

const navItems = navGroups.flatMap(g => g.items)

function isActive(path) {
  if (path === '/admin/tasks') {
    return route.path === '/admin/tasks' || route.path.startsWith('/admin/tasks/')
  }
  return route.path === path
}

const currentPageLabel = computed(() => {
  if (route.path.startsWith('/admin/tasks/')) return '任务详情'
  const item = navItems.find(n => route.path === n.path)
  return item ? item.label : '仪表盘'
})

const health = ref({ database: 'unknown', redis: 'unknown', msf: 'unknown' })

async function checkHealth() {
  try {
    const res = await api.healthCheck()
    health.value = {
      database: res.database || 'unknown',
      redis: res.redis || 'unknown',
      msf: res.msf || 'unknown',
    }
  } catch {
    health.value = { database: 'unknown', redis: 'unknown', msf: 'unknown' }
  }
}

function handleUserCmd(cmd) {
  if (cmd === 'profile') router.push('/profile')
  else if (cmd === 'logout') {
    auth.logout()
    ElMessage.success('已退出登录')
    router.push('/login')
  }
}

function onResize() {
  const nowMobile = window.innerWidth < MOBILE_BREAKPOINT
  if (nowMobile && !isMobile.value) sidebarCollapsed.value = true
  isMobile.value = nowMobile
}

let healthTimer = null

onMounted(() => {
  initTheme()
  checkHealth()
  healthTimer = setInterval(checkHealth, 30000)
  window.addEventListener('resize', onResize)
  onResize()
})

onUnmounted(() => {
  if (healthTimer) clearInterval(healthTimer)
  window.removeEventListener('resize', onResize)
})
</script>

<style scoped>
.admin-shell {
  --admin-accent: var(--accent-red);
  --admin-accent-soft: color-mix(in srgb, var(--accent-red) 14%, transparent);
  --admin-accent-border: color-mix(in srgb, var(--accent-red) 36%, var(--border));
  --admin-bg-base: color-mix(in srgb, var(--bg-base) 94%, #000);
  --admin-bg-sidebar: color-mix(in srgb, var(--bg-surface) 96%, #000);

  display: flex;
  height: 100vh;
  overflow: hidden;
  background: var(--admin-bg-base);
}

/* ── Sidebar ── */
.admin-sidebar {
  width: 220px;
  min-width: 220px;
  background: var(--admin-bg-sidebar);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  transition: width 0.25s cubic-bezier(0.4, 0, 0.2, 1),
              min-width 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  overflow: hidden;
  z-index: 100;
}

.admin-sidebar.collapsed {
  width: 64px;
  min-width: 64px;
}

.admin-sidebar-brand {
  padding: 16px;
  border-bottom: 1px solid var(--border);
  min-height: 56px;
  display: flex;
  align-items: center;
}

.admin-brand-badge {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--admin-accent);
  white-space: nowrap;
  overflow: hidden;
}

.brand-bar {
  width: 4px;
  height: 24px;
  border-radius: 2px;
  background: var(--admin-accent);
  flex-shrink: 0;
}

.brand-text {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: var(--admin-accent);
}

.admin-collapse-toggle {
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
.admin-collapse-toggle:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

/* ── Nav ── */
.admin-nav {
  flex: 1;
  padding: 8px;
  overflow-y: auto;
  overflow-x: hidden;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.admin-nav-group {
  font-size: 10px;
  font-family: var(--font-mono);
  font-weight: 600;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  padding: 10px 12px 4px;
  text-transform: uppercase;
  opacity: 0.7;
}
.admin-nav-group:first-child { padding-top: 4px; }

.admin-nav-divider {
  height: 1px;
  background: var(--border);
  margin: 6px 8px;
  opacity: 0.5;
}

.admin-nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 13px;
  transition: background 0.15s, color 0.15s;
  position: relative;
  white-space: nowrap;
  overflow: hidden;
}

.admin-nav-item:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.admin-nav-item.active {
  background: var(--admin-accent-soft);
  color: var(--admin-accent);
}

.admin-nav-item.active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 6px;
  bottom: 6px;
  width: 3px;
  border-radius: 0 2px 2px 0;
  background: var(--admin-accent);
}

.collapsed .admin-nav-item {
  justify-content: center;
  padding: 10px;
}
.collapsed .admin-nav-item.active::before {
  top: 8px;
  bottom: 8px;
}

.nav-label {
  display: flex;
  flex-direction: column;
  gap: 0;
  line-height: 1.2;
  overflow: hidden;
}

.nav-cn {
  font-size: 13px;
  font-weight: 600;
}

.nav-en {
  font-size: 10px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  letter-spacing: 0.03em;
}

.admin-nav-item.active .nav-en {
  color: color-mix(in srgb, var(--admin-accent) 60%, var(--text-muted));
}

/* ── Sidebar Footer ── */
.admin-sidebar-footer {
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.collapsed .admin-sidebar-footer {
  padding: 12px 8px;
  align-items: center;
}

.admin-health-dots {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.health-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--text-muted);
  flex-shrink: 0;
}
.health-dot.ok { background: var(--accent-green); }
.health-dot.err { background: var(--accent-red); }

.health-label {
  font-size: 10px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  margin-right: 4px;
}

.admin-theme-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border-radius: var(--radius-md);
  cursor: pointer;
  color: var(--text-secondary);
  font-size: 12px;
  transition: background 0.15s;
}
.admin-theme-toggle:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}
.collapsed .admin-theme-toggle {
  justify-content: center;
  padding: 6px;
}
.theme-icon {
  font-size: 16px;
  color: var(--accent-yellow);
  flex-shrink: 0;
}
.theme-label {
  font-family: var(--font-sans);
  white-space: nowrap;
}

/* ── Body ── */
.admin-body {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* ── Topbar ── */
.admin-topbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 24px;
  height: 52px;
  min-height: 52px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--admin-bg-sidebar) 90%, transparent);
  backdrop-filter: blur(6px);
  position: sticky;
  top: 0;
  z-index: 20;
}

.admin-hamburger {
  color: var(--text-secondary) !important;
  padding: 4px !important;
}

.admin-breadcrumb {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--text-muted);
}

.breadcrumb-console {
  font-weight: 600;
  color: var(--admin-accent);
}

.breadcrumb-current {
  color: var(--text-primary);
  font-weight: 500;
}

.topbar-spacer { flex: 1; }

.admin-github-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 30px;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--bg-surface);
  color: var(--text-secondary);
  text-decoration: none;
  outline: none;
  transition: border-color 0.15s, background 0.15s, color 0.15s;
}

.admin-github-link:hover,
.admin-github-link:focus-visible {
  border-color: var(--admin-accent);
  background: var(--bg-hover);
  color: var(--text-primary);
}

.admin-github-icon {
  display: block;
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.admin-github-label {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.02em;
  white-space: nowrap;
}

.admin-user-trigger {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 3px 10px 3px 4px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--bg-surface);
  cursor: pointer;
  outline: none;
  transition: border-color 0.15s, background 0.15s;
}
.admin-user-trigger:hover {
  border-color: var(--admin-accent);
  background: var(--bg-hover);
}

.admin-avatar {
  background: var(--admin-accent-soft) !important;
  color: var(--admin-accent) !important;
  font-weight: 600;
  font-size: 12px;
}

.admin-user-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  max-width: 100px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.admin-role-tag {
  font-family: var(--font-mono);
  font-size: 10px !important;
  letter-spacing: 0.04em;
  padding: 0 6px !important;
  height: 18px !important;
  line-height: 18px !important;
}

/* ── Content ── */
.admin-content {
  flex: 1;
  overflow-y: auto;
  padding: 28px 32px;
}

/* ── Animations ── */
.fade-text-enter-active,
.fade-text-leave-active {
  transition: opacity 0.2s ease;
}
.fade-text-enter-from,
.fade-text-leave-to {
  opacity: 0;
}

/* ── Mobile ── */
.admin-mobile-overlay {
  position: fixed;
  inset: 0;
  z-index: 99;
  background: rgba(0, 0, 0, 0.5);
}

.is-mobile .admin-sidebar {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  z-index: 100;
}
.is-mobile .admin-sidebar.collapsed {
  width: 0;
  min-width: 0;
  overflow: hidden;
}
.is-mobile .admin-topbar {
  padding: 0 12px;
}
.is-mobile .admin-content {
  padding: 16px;
}

@media (max-width: 768px) {
  .admin-content {
    padding: 16px;
  }
}

/* Light theme tuning: soften the red accent for less aggression */
:global([data-theme="light"]) .admin-shell {
  --admin-accent: #b85460;
  --admin-accent-soft: rgba(184, 84, 96, 0.09);
  --admin-accent-border: color-mix(in srgb, #b85460 30%, var(--border));
  --admin-bg-base: #f2f0f1;
  --admin-bg-sidebar: #eceaeb;
}
</style>
