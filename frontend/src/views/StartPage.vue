<template>
  <div ref="rootRef" class="start-page" tabindex="0" @keyup.enter="goWorkbench">
    <div class="bg-decor" aria-hidden="true">
      <span class="bg-grid"></span>
      <span class="bg-circuit"></span>
      <span class="bg-scanline"></span>
      <span class="bg-vignette"></span>
    </div>

    <div class="top-bar">
      <button class="theme-toggle" type="button" @click="toggleTheme" :aria-label="theme === 'dark' ? '切换亮色主题' : '切换暗色主题'">
        <el-icon v-if="theme === 'dark'"><Sunny /></el-icon>
        <el-icon v-else><Moon /></el-icon>
      </button>

      <el-dropdown trigger="click" @command="handleUserCommand">
        <div class="user-trigger">
          <el-avatar :size="34" :src="avatarError ? '' : profile.avatar" @error="onAvatarError">
            {{ userInitial }}
          </el-avatar>
          <span class="username">{{ profile.nickname }}</span>
          <el-icon><ArrowDown /></el-icon>
        </div>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="profile">个人空间</el-dropdown-item>
            <el-dropdown-item command="settings">系统设置</el-dropdown-item>
            <el-dropdown-item command="logout" divided>退出（预留）</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>

    <div class="hero-shell">
      <section class="hero-main">
        <div class="logo-mark">
          <span class="logo-hud logo-hud-outer" aria-hidden="true"></span>
          <span class="logo-hud logo-hud-inner" aria-hidden="true"></span>
          <span class="logo-cut logo-cut-left" aria-hidden="true"></span>
          <span class="logo-cut logo-cut-right" aria-hidden="true"></span>
          <span class="logo-etch logo-etch-top" aria-hidden="true"></span>
          <span class="logo-etch logo-etch-bottom" aria-hidden="true"></span>
          <span class="logo-monogram" aria-label="AuroraRecon Monogram">
            <span class="mono-p">A</span>
            <span class="mono-a">R</span>
          </span>
        </div>
        <h1 class="title" aria-label="AuroraRecon">
          <span class="title-aurora">Aurora</span><span class="title-recon">Recon</span>
        </h1>
        <p class="sub">自动化渗透测试工作台</p>
        <div class="title-divider" aria-hidden="true"></div>
        <div class="start-cta">
          <el-button
            size="large"
            class="start-btn"
            :class="{ 'is-hovering': startHoverActive }"
            @click="goWorkbench"
            @mouseenter="onStartHover"
            @mouseleave="onStartLeave"
            @focus="onStartHover"
            @blur="onStartLeave"
          >
            <span class="btn-frame btn-frame-tl" aria-hidden="true"></span>
            <span class="btn-frame btn-frame-tr" aria-hidden="true"></span>
            <span class="btn-frame btn-frame-bl" aria-hidden="true"></span>
            <span class="btn-frame btn-frame-br" aria-hidden="true"></span>
            <span class="btn-main">START</span>
          </el-button>
          <p v-if="startHoverActive" class="btn-terminal-line">{{ startHoverText }}</p>
        </div>
        <p class="hint"><span class="prompt">&gt;&gt;</span> 按 Enter 键也可快速开始</p>
      </section>

      <section class="board-panel" :class="{ 'is-loading': boardLoading }">
        <div class="board-head">
          <p class="board-title">SYSTEM BRIEFING</p>
          <div class="board-meta">
            <span class="source-badge" :class="metricsAvailable ? 'is-live' : 'is-fallback'">{{ sourceText }}</span>
            <span class="board-time">更新 {{ boardUpdatedAt }}</span>
          </div>
        </div>

        <div class="kpi-grid">
          <article v-for="item in boardKpis" :key="item.id" class="kpi-card">
            <p class="kpi-label">{{ item.label }}</p>
            <p class="kpi-value">{{ formatKpiValue(item.value) }}</p>
          </article>
        </div>

        <div class="status-terminal">
          <div v-for="service in boardServices" :key="service.name" class="service-row">
            <span class="state-dot" :class="`state-dot-${service.level}`" aria-hidden="true"></span>
            <span class="service-name">{{ service.name }}</span>
            <span class="service-state" :class="`service-state-${service.level}`">{{ service.state }}</span>
            <span class="service-detail">{{ service.detail }}</span>
          </div>
          <p class="status-foot">
            <span class="status-key">systemctl status</span>
            <span class="status-value" :class="metricsAvailable ? 'service-state-active' : 'service-state-warming'">
              {{ metricsAvailable ? 'live active (running)' : 'fallback active (running)' }}
            </span>
          </p>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { useTheme } from '@/composables/useTheme'

const PROFILE_LOCAL_KEY = 'profile.local.v1'
const POLL_INTERVAL_MS = 20000
const START_TERMINAL_IDLE = 'exec::dashboard_boot'
const START_TERMINAL_READY = 'exec::dashboard_ready'
const TERMINAL_GLYPHS = '01ABCDEF$#*_-'

const router = useRouter()
const rootRef = ref(null)
const avatarError = ref(false)
const boardLoading = ref(false)
const metricsAvailable = ref(false)
const startHoverActive = ref(false)
const startHoverText = ref(START_TERMINAL_IDLE)
const prefersReducedMotion = ref(false)
const boardModel = ref(createFallbackBoard())
const { theme, init: initTheme, toggle: toggleTheme } = useTheme()
const profile = ref({
  nickname: '安全研究员',
  avatar: '',
})

let boardTimer = null
let startHoverTimer = null
let startHoverResetTimer = null
let reducedMotionMedia = null
let reducedMotionHandler = null

const userInitial = computed(() => (profile.value.nickname || 'U').slice(0, 1).toUpperCase())
const boardKpis = computed(() => boardModel.value.kpis || [])
const boardServices = computed(() => boardModel.value.services || [])
const sourceText = computed(() => {
  if (boardLoading.value) return 'syncing'
  return metricsAvailable.value ? 'live data' : 'fallback data'
})
const boardUpdatedAt = computed(() => formatTime(boardModel.value.updatedAt))

function createFallbackBoard() {
  return {
    updatedAt: new Date().toISOString(),
    kpis: [
      { id: 'total_tasks', label: '任务总数', value: 128 },
      { id: 'running_tasks', label: '运行中任务', value: 12 },
      { id: 'total_calls', label: '工具调用总量', value: 3652 },
    ],
    services: [
      { name: 'orchestrator.service', state: 'active', detail: '(running)', level: 'active' },
      { name: 'netwatch.service', state: 'active', detail: '(running)', level: 'active' },
      { name: 'auditd.service', state: 'active', detail: '(running)', level: 'active' },
    ],
  }
}

function normalizeServiceState(name, raw) {
  const value = String(raw || '').toLowerCase()
  if (value === 'ok' || value === 'connected') {
    return { name, state: 'active', detail: '(running)', level: 'active' }
  }
  if (value === 'unavailable' || value === 'failed' || value === 'error') {
    return { name, state: 'failed', detail: '(dead)', level: 'failed' }
  }
  return { name, state: 'activating', detail: '(starting)', level: 'warming' }
}

function buildBoardFromMetrics(metrics) {
  const system = metrics?.system_overview || {}
  const invocation = metrics?.tool_invocation_overview || {}
  return {
    updatedAt: metrics?.generated_at || new Date().toISOString(),
    kpis: [
      { id: 'total_tasks', label: '任务总数', value: Number(system.total_tasks || 0) },
      { id: 'running_tasks', label: '运行中任务', value: Number(system.running_tasks || 0) },
      { id: 'total_calls', label: '工具调用总量', value: Number(invocation.total_calls || 0) },
    ],
    services: [
      normalizeServiceState('orchestrator.service', system.api_status),
      normalizeServiceState('database.service', system.database),
      normalizeServiceState('redis.service', system.redis),
    ],
  }
}

function formatKpiValue(value) {
  const num = Number(value)
  if (Number.isFinite(num)) return num.toLocaleString()
  return String(value || '--')
}

function formatTime(value) {
  if (!value) return '--:--:--'
  const ts = new Date(value)
  if (Number.isNaN(ts.getTime())) return '--:--:--'
  return ts.toLocaleTimeString()
}

async function loadBoard() {
  boardLoading.value = true
  try {
    const metrics = await api.getMetricsOverview(24)
    boardModel.value = buildBoardFromMetrics(metrics)
    metricsAvailable.value = true
  } catch {
    boardModel.value = createFallbackBoard()
    metricsAvailable.value = false
  } finally {
    boardLoading.value = false
  }
}

function loadProfileLocal() {
  const cached = localStorage.getItem(PROFILE_LOCAL_KEY)
  if (!cached) return
  try {
    const parsed = JSON.parse(cached)
    profile.value = {
      nickname: parsed.nickname || '安全研究员',
      avatar: parsed.avatar || '',
    }
  } catch {
    // Ignore invalid cache.
  }
}

function goWorkbench() {
  router.push('/dashboard')
}

function handleUserCommand(command) {
  if (command === 'profile') {
    router.push('/profile')
    return
  }
  if (command === 'settings') {
    router.push('/settings')
    return
  }
  ElMessage.info('退出功能预留中')
}

function onAvatarError() {
  avatarError.value = true
  return false
}

function clearStartHoverTimers() {
  if (startHoverTimer) {
    window.clearInterval(startHoverTimer)
    startHoverTimer = null
  }
  if (startHoverResetTimer) {
    window.clearTimeout(startHoverResetTimer)
    startHoverResetTimer = null
  }
}

function scrambleTerminalText(target, revealCount) {
  return target
    .split('')
    .map((char, index) => {
      if (char === ':' || char === '_' || char === ' ') return char
      if (index < revealCount) return target[index]
      const randomIndex = Math.floor(Math.random() * TERMINAL_GLYPHS.length)
      return TERMINAL_GLYPHS[randomIndex]
    })
    .join('')
}

function onStartHover() {
  clearStartHoverTimers()
  startHoverActive.value = true
  if (prefersReducedMotion.value) {
    startHoverText.value = START_TERMINAL_READY
    return
  }

  let tick = 0
  startHoverTimer = window.setInterval(() => {
    tick += 1
    const revealCount = Math.min(START_TERMINAL_READY.length, Math.floor(tick * 2.6))
    startHoverText.value = scrambleTerminalText(START_TERMINAL_READY, revealCount)
    if (revealCount >= START_TERMINAL_READY.length) {
      clearStartHoverTimers()
      startHoverText.value = START_TERMINAL_READY
      startHoverResetTimer = window.setTimeout(() => {
        if (startHoverActive.value) return
        startHoverText.value = START_TERMINAL_IDLE
      }, 320)
    }
  }, 42)
}

function onStartLeave() {
  startHoverActive.value = false
  clearStartHoverTimers()
  startHoverText.value = START_TERMINAL_IDLE
}

function initReducedMotionWatcher() {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
  reducedMotionMedia = window.matchMedia('(prefers-reduced-motion: reduce)')
  prefersReducedMotion.value = reducedMotionMedia.matches
  reducedMotionHandler = (event) => {
    prefersReducedMotion.value = Boolean(event.matches)
    if (prefersReducedMotion.value) {
      clearStartHoverTimers()
      startHoverText.value = startHoverActive.value ? START_TERMINAL_READY : START_TERMINAL_IDLE
    }
  }
  if (typeof reducedMotionMedia.addEventListener === 'function') {
    reducedMotionMedia.addEventListener('change', reducedMotionHandler)
  } else if (typeof reducedMotionMedia.addListener === 'function') {
    reducedMotionMedia.addListener(reducedMotionHandler)
  }
}

function cleanupReducedMotionWatcher() {
  if (!reducedMotionMedia || !reducedMotionHandler) return
  if (typeof reducedMotionMedia.removeEventListener === 'function') {
    reducedMotionMedia.removeEventListener('change', reducedMotionHandler)
  } else if (typeof reducedMotionMedia.removeListener === 'function') {
    reducedMotionMedia.removeListener(reducedMotionHandler)
  }
  reducedMotionHandler = null
  reducedMotionMedia = null
}

onMounted(async () => {
  initTheme()
  initReducedMotionWatcher()
  loadProfileLocal()
  rootRef.value?.focus()
  await loadBoard()
  boardTimer = window.setInterval(() => {
    loadBoard()
  }, POLL_INTERVAL_MS)
})

onUnmounted(() => {
  clearStartHoverTimers()
  cleanupReducedMotionWatcher()
  if (boardTimer) window.clearInterval(boardTimer)
})
</script>

<style scoped>
.start-page {
  position: relative;
  height: 100vh;
  width: 100%;
  background:
    linear-gradient(145deg, color-mix(in srgb, var(--bg-base) 92%, #000 8%), var(--bg-surface)),
    radial-gradient(1200px 500px at -10% -20%, color-mix(in srgb, var(--start-hacker-line) 46%, transparent), transparent);
  outline: none;
  overflow: hidden;
}

.bg-decor {
  position: absolute;
  inset: 0;
  pointer-events: none;
}

.bg-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(to right, var(--start-grid-line) 1px, transparent 1px),
    linear-gradient(to bottom, var(--start-grid-line) 1px, transparent 1px);
  background-size: 38px 38px;
  opacity: 0.26;
}

.bg-circuit {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(90deg, transparent 0%, transparent 12%, var(--start-hacker-muted-line) 12.5%, transparent 13%),
    linear-gradient(0deg, transparent 0%, transparent 68%, var(--start-hacker-muted-line) 68.5%, transparent 69%);
  background-size: 320px 160px, 220px 120px;
  opacity: 0.34;
  mask-image: linear-gradient(to bottom, transparent, #000 20%, #000 80%, transparent);
}

.bg-scanline {
  position: absolute;
  left: 0;
  right: 0;
  height: 140px;
  top: -160px;
  background: linear-gradient(to bottom, transparent 0%, var(--start-scanline) 45%, transparent 100%);
  opacity: 0.46;
  animation: scanSweep 12s linear infinite;
}

.bg-vignette {
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at center, transparent 28%, color-mix(in srgb, var(--bg-base) 72%, transparent) 100%);
}

.top-bar {
  position: absolute;
  top: 20px;
  right: 24px;
  z-index: 3;
  display: flex;
  align-items: center;
  gap: 10px;
}

.theme-toggle {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  border: 1px solid var(--start-hacker-line);
  background: color-mix(in srgb, var(--bg-surface) 86%, var(--bg-elevated));
  color: var(--text-primary);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  box-shadow: 0 6px 20px color-mix(in srgb, var(--start-panel-shadow) 60%, transparent);
  transition: transform 0.2s ease, border-color 0.2s ease, background-color 0.2s ease, box-shadow 0.2s ease;
}

.theme-toggle:hover {
  transform: translateY(-1px);
  border-color: color-mix(in srgb, var(--start-hacker-cyan) 64%, var(--border));
  box-shadow: 0 10px 24px color-mix(in srgb, var(--start-panel-shadow) 72%, transparent);
}

.theme-toggle:active {
  transform: translateY(0);
}

.user-trigger {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border: 1px solid var(--start-hacker-line);
  border-radius: 999px;
  background: var(--bg-surface);
  color: var(--text-primary);
  cursor: pointer;
  user-select: none;
  box-shadow: 0 2px 12px color-mix(in srgb, var(--bg-base) 70%, transparent);
  transition: border-color 0.2s ease, background-color 0.2s ease, transform 0.2s ease;
}

.user-trigger:hover {
  border-color: color-mix(in srgb, var(--start-hacker-cyan) 60%, var(--border));
  background: color-mix(in srgb, var(--bg-surface) 82%, var(--bg-elevated));
  transform: translateY(-1px);
}

.username {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.01em;
}

.hero-shell {
  position: relative;
  z-index: 2;
  width: min(1020px, calc(100% - 30px));
  margin: 74px auto 0;
  padding-bottom: 18px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.hero-main {
  text-align: center;
  padding: 14px 20px 4px;
}

.logo-mark {
  width: 148px;
  height: 132px;
  margin: 0 auto 18px;
  position: relative;
  clip-path: polygon(25% 4%, 75% 4%, 96% 50%, 75% 96%, 25% 96%, 4% 50%);
  background:
    radial-gradient(circle at 50% 42%, color-mix(in srgb, var(--start-hacker-cyan) 12%, transparent), transparent 64%),
    linear-gradient(140deg, color-mix(in srgb, var(--bg-surface) 88%, var(--bg-elevated)), color-mix(in srgb, var(--bg-base) 90%, #000));
  display: grid;
  place-items: center;
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--text-primary) 10%, transparent),
    0 14px 34px color-mix(in srgb, var(--start-hacker-cyan) 16%, transparent);
  animation: breathe 6s ease-in-out infinite;
}

.logo-hud {
  position: absolute;
  pointer-events: none;
  clip-path: polygon(25% 6%, 75% 6%, 95% 50%, 75% 94%, 25% 94%, 5% 50%);
}

.logo-hud-outer {
  inset: 2px;
  border: 1px solid color-mix(in srgb, var(--start-hacker-cyan) 56%, var(--border));
  background:
    linear-gradient(90deg, transparent 0 16%, color-mix(in srgb, var(--start-hacker-line) 42%, transparent) 16% 18%, transparent 18% 82%, color-mix(in srgb, var(--start-hacker-line) 42%, transparent) 82% 84%, transparent 84%),
    linear-gradient(180deg, color-mix(in srgb, var(--start-hacker-line) 18%, transparent), transparent 26%);
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent),
    0 0 16px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent);
}

.logo-hud-inner {
  inset: 18px 20px;
  border: 1px solid color-mix(in srgb, var(--start-hacker-cyan) 28%, transparent);
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--start-hacker-line) 18%, transparent), transparent 66%),
    linear-gradient(315deg, color-mix(in srgb, var(--start-hacker-muted-line) 14%, transparent), transparent 70%);
}

.logo-cut {
  position: absolute;
  top: 18px;
  width: 16px;
  height: 2px;
  background: color-mix(in srgb, var(--start-hacker-cyan) 46%, transparent);
  box-shadow: 0 0 8px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent);
}

.logo-cut-left {
  left: 30px;
  transform: rotate(-28deg);
}

.logo-cut-right {
  right: 30px;
  transform: rotate(28deg);
}

.logo-monogram {
  position: relative;
  z-index: 1;
  display: inline-flex;
  align-items: baseline;
  gap: 4px;
  font-family: var(--font-orbitron);
  font-size: 44px;
  letter-spacing: 0.06em;
  font-weight: 600;
  color: color-mix(in srgb, var(--text-primary) 72%, var(--start-hacker-cyan));
  text-shadow:
    0 0 8px color-mix(in srgb, var(--start-hacker-cyan) 18%, transparent),
    0 0 14px color-mix(in srgb, #7ca4c4 12%, transparent);
}

.mono-p {
  color: color-mix(in srgb, var(--text-primary) 78%, var(--start-hacker-cyan));
}

.mono-a {
  color: color-mix(in srgb, var(--start-hacker-cyan) 62%, #9ec0d8);
}

.logo-etch {
  position: absolute;
  width: 56px;
  height: 1px;
  background: color-mix(in srgb, var(--start-hacker-cyan) 32%, transparent);
  box-shadow: 0 0 8px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent);
}

.logo-etch-top {
  top: 42px;
}

.logo-etch-bottom {
  bottom: 42px;
}

.title {
  margin: 0;
  font-size: clamp(56px, 11vw, 104px);
  line-height: 1;
  letter-spacing: 0.04em;
  font-family: var(--font-orbitron);
  font-weight: 600;
}

.title-aurora {
  color: color-mix(in srgb, var(--text-primary) 88%, var(--start-hacker-cyan));
  text-shadow:
    0 0 14px color-mix(in srgb, var(--start-hacker-cyan) 22%, transparent),
    0 0 28px color-mix(in srgb, var(--start-hacker-green) 12%, transparent);
}

.title-recon {
  margin-left: 0.06em;
  color: color-mix(in srgb, var(--start-hacker-green) 52%, var(--text-primary));
  text-shadow:
    0 0 16px color-mix(in srgb, var(--start-hacker-green) 32%, transparent),
    0 0 28px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent);
}

.sub {
  margin: 14px 0 8px;
  color: color-mix(in srgb, var(--text-secondary) 72%, var(--start-hacker-cyan));
  font-size: 16px;
  letter-spacing: 0.08em;
}

.title-divider {
  width: min(340px, 88%);
  height: 2px;
  margin: 0 auto 20px;
  background: linear-gradient(to right, transparent, color-mix(in srgb, var(--start-hacker-green) 64%, var(--start-hacker-cyan)), transparent);
  box-shadow: 0 0 12px color-mix(in srgb, var(--start-hacker-green) 28%, transparent);
}

.start-cta {
  margin: 0 auto;
  width: fit-content;
  min-height: 84px;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.start-btn {
  position: relative;
  overflow: hidden;
  min-width: 220px;
  height: 60px;
  font-weight: 700;
  font-size: 16px;
  border-radius: 14px;
  letter-spacing: 0.12em;
  font-family: var(--font-orbitron);
  color: color-mix(in srgb, #f4fffb 92%, var(--start-hacker-green)) !important;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  box-shadow:
    0 10px 26px color-mix(in srgb, var(--start-hacker-green) 22%, transparent),
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-green) 38%, transparent),
    inset 0 -8px 16px color-mix(in srgb, #000 28%, transparent);
  transition: transform 0.2s ease, box-shadow 0.2s ease, filter 0.2s ease;
  border: 1px solid color-mix(in srgb, var(--start-hacker-green) 58%, #3d8f78);
  background: linear-gradient(
    155deg,
    color-mix(in srgb, var(--start-hacker-green) 42%, #06120e),
    color-mix(in srgb, var(--bg-base) 82%, #030806),
    color-mix(in srgb, var(--start-hacker-cyan) 18%, #050a0d)
  ) !important;
}

.start-btn::before {
  content: '';
  position: absolute;
  top: 0;
  bottom: 0;
  left: -16%;
  width: 16%;
  background: linear-gradient(to right, transparent, color-mix(in srgb, var(--start-hacker-green) 32%, transparent), transparent);
  transform: skewX(-14deg);
  animation: btnSweep 3.6s ease-in-out infinite;
}

.start-btn::after {
  content: '';
  position: absolute;
  left: 10px;
  right: 10px;
  bottom: 8px;
  height: 1px;
  background: linear-gradient(to right, transparent, color-mix(in srgb, var(--start-hacker-green) 48%, transparent), transparent);
  opacity: 0.55;
}

.start-btn:hover,
.start-btn:focus-visible {
  transform: translateY(-2px);
  color: color-mix(in srgb, #ffffff 94%, var(--start-hacker-green)) !important;
  box-shadow:
    0 14px 32px color-mix(in srgb, var(--start-hacker-green) 28%, transparent),
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-green) 52%, transparent),
    inset 0 -8px 16px color-mix(in srgb, #000 22%, transparent);
  border-color: color-mix(in srgb, var(--start-hacker-green) 72%, #6fd4b4) !important;
  background: linear-gradient(
    155deg,
    color-mix(in srgb, var(--start-hacker-green) 52%, #071a14),
    color-mix(in srgb, var(--bg-base) 78%, #030806),
    color-mix(in srgb, var(--start-hacker-cyan) 22%, #050a0d)
  ) !important;
  filter: brightness(1.04);
}

.start-btn:active {
  transform: translateY(0);
}

.btn-main {
  position: relative;
  z-index: 1;
  line-height: 1;
}

.btn-terminal-line {
  margin-top: 8px;
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.03em;
  color: color-mix(in srgb, var(--start-hacker-cyan) 70%, #8ea2b8);
  text-transform: lowercase;
  text-shadow: 0 0 8px color-mix(in srgb, var(--start-hacker-cyan) 18%, transparent);
}

.btn-frame {
  position: absolute;
  width: 12px;
  height: 12px;
  border: 1px solid color-mix(in srgb, var(--start-hacker-green) 42%, transparent);
  pointer-events: none;
}

.btn-frame-tl {
  top: 4px;
  left: 4px;
  border-right: none;
  border-bottom: none;
}

.btn-frame-tr {
  top: 4px;
  right: 4px;
  border-left: none;
  border-bottom: none;
}

.btn-frame-bl {
  bottom: 4px;
  left: 4px;
  border-right: none;
  border-top: none;
}

.btn-frame-br {
  bottom: 4px;
  right: 4px;
  border-left: none;
  border-top: none;
}

.hint {
  margin-top: 12px;
  font-size: 12px;
  color: var(--text-muted);
}

.prompt {
  color: color-mix(in srgb, var(--start-hacker-cyan) 70%, var(--text-primary));
  font-family: var(--font-mono);
  margin-right: 4px;
}

.board-panel {
  border: 1px solid color-mix(in srgb, var(--start-panel-border) 64%, var(--start-hacker-line));
  border-radius: 20px;
  background: color-mix(in srgb, var(--start-panel-bg) 86%, var(--bg-surface));
  backdrop-filter: blur(14px);
  box-shadow:
    0 20px 48px color-mix(in srgb, var(--start-panel-shadow) 82%, transparent),
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-line) 48%, transparent);
  overflow: hidden;
  padding: 16px 18px 14px;
  transition: opacity 0.2s ease;
}

.board-panel.is-loading {
  opacity: 0.9;
}

.board-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.board-title {
  font-family: var(--font-orbitron);
  font-size: 15px;
  letter-spacing: 0.08em;
  color: color-mix(in srgb, var(--start-hacker-green) 66%, var(--start-hacker-cyan));
}

.board-meta {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
  font-family: var(--font-mono);
}

.source-badge {
  border: 1px solid transparent;
  border-radius: 999px;
  padding: 2px 8px;
  letter-spacing: 0.02em;
}

.source-badge.is-live {
  color: color-mix(in srgb, var(--start-hacker-green) 74%, var(--text-primary));
  border-color: color-mix(in srgb, var(--start-hacker-green) 46%, transparent);
  background: color-mix(in srgb, var(--bg-elevated) 88%, transparent);
}

.source-badge.is-fallback {
  color: color-mix(in srgb, var(--start-hacker-green) 70%, var(--text-secondary));
  border-color: color-mix(in srgb, var(--start-hacker-green) 42%, transparent);
  background: color-mix(in srgb, var(--bg-elevated) 84%, transparent);
}

.board-time {
  color: var(--text-muted);
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 12px;
}

.kpi-card {
  border: 1px solid color-mix(in srgb, var(--start-hacker-line) 58%, var(--border));
  border-radius: 14px;
  padding: 12px 14px;
  background:
    linear-gradient(140deg, color-mix(in srgb, var(--bg-base) 70%, transparent), color-mix(in srgb, var(--bg-surface) 92%, transparent)),
    linear-gradient(0deg, color-mix(in srgb, #5b99b3 14%, transparent), transparent 60%);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-muted-line) 18%, transparent);
}

.kpi-card:nth-child(2) {
  background:
    linear-gradient(140deg, color-mix(in srgb, var(--bg-base) 70%, transparent), color-mix(in srgb, var(--bg-surface) 92%, transparent)),
    linear-gradient(0deg, color-mix(in srgb, #52b98f 20%, transparent), transparent 60%);
}

.kpi-card:nth-child(3) {
  background:
    linear-gradient(140deg, color-mix(in srgb, var(--bg-base) 70%, transparent), color-mix(in srgb, var(--bg-surface) 92%, transparent)),
    linear-gradient(0deg, color-mix(in srgb, #4db59b 19%, transparent), transparent 60%);
}

.kpi-label {
  font-size: 12px;
  letter-spacing: 0.03em;
  color: var(--text-secondary);
}

.kpi-value {
  margin-top: 8px;
  font-family: var(--font-orbitron);
  font-size: clamp(36px, 5vw, 54px);
  line-height: 1;
  color: color-mix(in srgb, var(--start-hacker-green) 58%, var(--start-hacker-cyan));
  text-shadow: 0 0 16px color-mix(in srgb, var(--start-hacker-green) 30%, transparent);
}

.kpi-card:nth-child(2) .kpi-value {
  color: color-mix(in srgb, #54c39b 82%, var(--text-primary));
  text-shadow: 0 0 16px color-mix(in srgb, #54c39b 24%, transparent);
}

.kpi-card:nth-child(3) .kpi-value {
  color: color-mix(in srgb, #56bea1 80%, var(--text-primary));
  text-shadow: 0 0 16px color-mix(in srgb, #56bea1 22%, transparent);
}

.status-terminal {
  border: 1px solid color-mix(in srgb, var(--start-hacker-line) 66%, var(--border));
  border-radius: 12px;
  padding: 10px 12px 8px;
  background: color-mix(in srgb, var(--bg-base) 56%, transparent);
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-muted-line) 28%, transparent),
    0 8px 22px color-mix(in srgb, var(--start-panel-shadow) 30%, transparent);
}

.service-row {
  display: grid;
  grid-template-columns: 10px 1fr auto auto;
  align-items: center;
  column-gap: 8px;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.5;
}

.service-row + .service-row {
  margin-top: 3px;
}

.service-name {
  color: color-mix(in srgb, var(--text-primary) 90%, var(--start-hacker-cyan));
  text-align: left;
}

.service-state {
  font-family: var(--font-mono);
  font-weight: 600;
}

.service-state-active {
  color: color-mix(in srgb, var(--start-hacker-green) 64%, var(--start-hacker-cyan));
  text-shadow:
    0 0 8px color-mix(in srgb, var(--start-hacker-green) 52%, transparent),
    0 0 14px color-mix(in srgb, var(--start-hacker-green) 30%, transparent);
}

.service-state-warming {
  color: color-mix(in srgb, #9ab3c6 76%, var(--text-primary));
}

.service-state-failed {
  color: color-mix(in srgb, #b98292 76%, var(--text-primary));
}

.service-detail {
  color: color-mix(in srgb, var(--start-hacker-cyan) 82%, var(--text-secondary));
}

.state-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.state-dot-active {
  background: color-mix(in srgb, var(--start-hacker-green) 76%, var(--start-hacker-cyan));
  box-shadow:
    0 0 0 1px color-mix(in srgb, var(--start-hacker-green) 62%, transparent),
    0 0 8px color-mix(in srgb, var(--start-hacker-green) 50%, transparent);
  animation: activePulse 2.6s ease-in-out infinite;
}

.state-dot-warming {
  background: #91aabd;
  box-shadow:
    0 0 0 1px color-mix(in srgb, #91aabd 62%, transparent),
    0 0 8px color-mix(in srgb, #91aabd 30%, transparent);
}

.state-dot-failed {
  background: #b98292;
  box-shadow:
    0 0 0 1px color-mix(in srgb, #b98292 62%, transparent),
    0 0 8px color-mix(in srgb, #b98292 30%, transparent);
}

.status-foot {
  margin-top: 8px;
  border-top: 1px solid color-mix(in srgb, var(--start-hacker-line) 46%, transparent);
  padding-top: 6px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  font-family: var(--font-mono);
  font-size: 11px;
}

.status-key {
  color: var(--text-muted);
}

.status-value {
  font-weight: 600;
}

[data-theme='light'] .start-page {
  background:
    linear-gradient(145deg, color-mix(in srgb, var(--bg-base) 88%, #eaf2ff 12%), var(--bg-surface)),
    radial-gradient(1200px 500px at -10% -20%, color-mix(in srgb, var(--start-hacker-line) 20%, transparent), transparent);
}

[data-theme='light'] .bg-grid {
  opacity: 0.18;
}

[data-theme='light'] .bg-circuit {
  opacity: 0.2;
}

[data-theme='light'] .bg-scanline {
  opacity: 0.24;
}

[data-theme='light'] .logo-mark {
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--text-primary) 7%, transparent),
    0 10px 20px color-mix(in srgb, var(--start-hacker-cyan) 12%, transparent);
}

[data-theme='light'] .logo-hud-outer {
  border-color: color-mix(in srgb, var(--start-hacker-cyan) 40%, var(--border));
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-cyan) 10%, transparent),
    0 0 12px color-mix(in srgb, var(--start-hacker-cyan) 10%, transparent);
}

[data-theme='light'] .logo-hud-inner {
  border-color: color-mix(in srgb, var(--start-hacker-cyan) 22%, transparent);
}

[data-theme='light'] .logo-cut {
  background: color-mix(in srgb, var(--start-hacker-cyan) 34%, transparent);
  box-shadow: 0 0 6px color-mix(in srgb, var(--start-hacker-cyan) 12%, transparent);
}

[data-theme='light'] .logo-monogram {
  color: color-mix(in srgb, var(--text-primary) 74%, var(--start-hacker-cyan));
  text-shadow:
    0 0 6px color-mix(in srgb, var(--start-hacker-cyan) 10%, transparent),
    0 0 10px color-mix(in srgb, #7da0bb 6%, transparent);
}

[data-theme='light'] .mono-a {
  color: color-mix(in srgb, var(--start-hacker-cyan) 56%, #6f8ea7);
}

[data-theme='light'] .title-aurora {
  color: color-mix(in srgb, #1a3d4a 72%, var(--start-hacker-cyan));
  text-shadow:
    0 0 8px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent),
    0 0 16px color-mix(in srgb, var(--start-hacker-green) 10%, transparent);
}

[data-theme='light'] .title-recon {
  color: color-mix(in srgb, var(--start-hacker-green) 48%, #1e4a42);
  text-shadow:
    0 0 10px color-mix(in srgb, var(--start-hacker-green) 20%, transparent),
    0 0 18px color-mix(in srgb, var(--start-hacker-cyan) 8%, transparent);
}

[data-theme='light'] .title-divider {
  box-shadow: 0 0 10px color-mix(in srgb, var(--start-hacker-cyan) 18%, transparent);
}

[data-theme='light'] .start-btn {
  color: #f6fffb !important;
  border-color: color-mix(in srgb, var(--start-hacker-green) 42%, #4a9d82);
  background: linear-gradient(
    155deg,
    color-mix(in srgb, var(--start-hacker-green) 58%, #1a5c4a),
    color-mix(in srgb, var(--start-hacker-green) 38%, #0d3d32)
  ) !important;
  box-shadow:
    0 8px 20px color-mix(in srgb, var(--start-hacker-green) 24%, transparent),
    inset 0 0 0 1px color-mix(in srgb, #ffffff 22%, transparent),
    inset 0 -4px 8px color-mix(in srgb, #000 12%, transparent);
}

[data-theme='light'] .start-btn:hover,
[data-theme='light'] .start-btn:focus-visible {
  color: #ffffff !important;
  border-color: color-mix(in srgb, var(--start-hacker-green) 55%, #5ec4a2) !important;
  background: linear-gradient(
    155deg,
    color-mix(in srgb, var(--start-hacker-green) 64%, #1a5c4a),
    color-mix(in srgb, var(--start-hacker-green) 44%, #0d3d32)
  ) !important;
  box-shadow:
    0 11px 24px color-mix(in srgb, var(--start-hacker-green) 30%, transparent),
    inset 0 0 0 1px color-mix(in srgb, #ffffff 28%, transparent);
}

[data-theme='light'] .start-btn::before {
  background: linear-gradient(to right, transparent, color-mix(in srgb, #ffffff 18%, transparent), transparent);
}

[data-theme='light'] .btn-terminal-line {
  color: color-mix(in srgb, var(--start-hacker-cyan) 58%, #59758a);
  text-shadow: 0 0 6px color-mix(in srgb, var(--start-hacker-cyan) 10%, transparent);
}

[data-theme='light'] .board-panel {
  background: color-mix(in srgb, var(--start-panel-bg) 95%, #ffffff);
  box-shadow:
    0 12px 28px color-mix(in srgb, var(--start-panel-shadow) 26%, transparent),
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-line) 32%, transparent);
}

[data-theme='light'] .kpi-card {
  background:
    linear-gradient(140deg, color-mix(in srgb, var(--bg-base) 40%, #ffffff), color-mix(in srgb, var(--bg-surface) 96%, #ffffff)),
    linear-gradient(0deg, color-mix(in srgb, #589eb8 12%, transparent), transparent 62%);
}

[data-theme='light'] .kpi-card:nth-child(2) {
  background:
    linear-gradient(140deg, color-mix(in srgb, var(--bg-base) 40%, #ffffff), color-mix(in srgb, var(--bg-surface) 96%, #ffffff)),
    linear-gradient(0deg, color-mix(in srgb, #54bda1 17%, transparent), transparent 62%);
}

[data-theme='light'] .kpi-card:nth-child(3) {
  background:
    linear-gradient(140deg, color-mix(in srgb, var(--bg-base) 40%, #ffffff), color-mix(in srgb, var(--bg-surface) 96%, #ffffff)),
    linear-gradient(0deg, color-mix(in srgb, #50b89f 17%, transparent), transparent 62%);
}

[data-theme='light'] .kpi-value {
  color: color-mix(in srgb, var(--start-hacker-green) 54%, var(--start-hacker-cyan));
  text-shadow: 0 0 9px color-mix(in srgb, var(--start-hacker-green) 22%, transparent);
}

[data-theme='light'] .kpi-card:nth-child(2) .kpi-value {
  color: color-mix(in srgb, #4fbc9d 74%, #223c50);
  text-shadow: 0 0 9px color-mix(in srgb, #4fbc9d 18%, transparent);
}

[data-theme='light'] .kpi-card:nth-child(3) .kpi-value {
  color: color-mix(in srgb, #50b6a0 74%, #3b4562);
  text-shadow: 0 0 9px color-mix(in srgb, #50b6a0 18%, transparent);
}

[data-theme='light'] .status-terminal {
  background: color-mix(in srgb, var(--bg-base) 32%, #ffffff);
  box-shadow:
    inset 0 0 0 1px color-mix(in srgb, var(--start-hacker-muted-line) 18%, transparent),
    0 6px 16px color-mix(in srgb, var(--start-panel-shadow) 16%, transparent);
}

[data-theme='light'] .service-state-active {
  text-shadow:
    0 0 5px color-mix(in srgb, var(--start-hacker-cyan) 30%, transparent),
    0 0 9px color-mix(in srgb, var(--start-hacker-cyan) 12%, transparent);
}

[data-theme='light'] .state-dot-active {
  box-shadow:
    0 0 0 1px color-mix(in srgb, var(--start-hacker-cyan) 42%, transparent),
    0 0 6px color-mix(in srgb, var(--start-hacker-cyan) 22%, transparent);
}

@keyframes breathe {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-4px); }
}

@keyframes scanSweep {
  0% { transform: translateY(0); }
  100% { transform: translateY(calc(100vh + 260px)); }
}

@keyframes activePulse {
  0%, 100% {
    opacity: 0.84;
    filter: saturate(1);
  }
  50% {
    opacity: 1;
    filter: saturate(1.08);
  }
}

@keyframes btnSweep {
  0% { left: -36%; }
  52% { left: 128%; }
  100% { left: 128%; }
}

@media (max-width: 860px) {
  .hero-shell {
    width: calc(100% - 20px);
    margin-top: 78px;
    gap: 14px;
  }

  .title {
    font-size: clamp(44px, 14vw, 72px);
  }

  .sub {
    font-size: 14px;
    letter-spacing: 0.05em;
  }

  .kpi-grid {
    grid-template-columns: 1fr;
  }

  .kpi-value {
    font-size: clamp(32px, 9vw, 42px);
  }
}

@media (max-width: 640px) {
  .username {
    display: none;
  }

  .board-head {
    flex-direction: column;
    align-items: flex-start;
  }
}

@media (prefers-reduced-motion: reduce) {
  .bg-scanline,
  .logo-mark,
  .state-dot-active,
  .start-btn::before {
    animation: none !important;
  }

  .theme-toggle,
  .user-trigger,
  .start-btn,
  .board-panel {
    transition: none !important;
  }
}
</style>
