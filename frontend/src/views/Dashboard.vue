<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">仪表盘</h1>
        <p class="page-sub">PentestAI 安全测试平台概览</p>
      </div>
      <el-button type="primary" @click="router.push('/tasks')" size="large">
        <el-icon><List /></el-icon>
        查看全部任务
      </el-button>
    </div>

    <!-- Health status -->
    <div class="health-bar" v-if="health">
      <div class="health-item" :class="health.status === 'ok' ? 'ok' : 'err'">
        <span class="health-dot"></span>
        API v{{ health.version }}
      </div>
      <div class="health-item" :class="health.database === 'connected' ? 'ok' : 'warn'">
        <span class="health-dot"></span>
        PostgreSQL {{ health.database }}
      </div>
      <div class="health-item" :class="health.redis === 'connected' ? 'ok' : 'warn'">
        <span class="health-dot"></span>
        Redis {{ health.redis }}
      </div>
      <div class="health-item ok" v-if="health.active_tasks > 0">
        <el-icon class="spin"><Loading /></el-icon>
        {{ health.active_tasks }} 任务运行中
      </div>
    </div>

    <!-- Stats cards -->
    <div class="stats-grid" v-loading="statsLoading">
      <div class="stat-card" v-for="item in statCards" :key="item.key">
        <div class="stat-icon-wrap" :style="{ background: item.iconBg }">
          <el-icon :size="22" :style="{ color: item.iconColor }">
            <component :is="item.icon" />
          </el-icon>
        </div>
        <div class="stat-info">
          <div class="stat-value" :style="{ color: item.valueColor }">{{ stats[item.key] ?? 0 }}</div>
          <div class="stat-label">{{ item.label }}</div>
        </div>
      </div>
    </div>

    <!-- Recent tasks -->
    <el-card class="recent-card">
      <template #header>
        <div class="card-header">
          <span class="card-title">
            <el-icon><Clock /></el-icon>
            最近任务
          </span>
          <el-button link type="primary" @click="router.push('/tasks')">查看全部 →</el-button>
        </div>
      </template>

      <el-empty v-if="!recentTasks.length" description="暂无任务" />

      <div v-else class="recent-list">
        <div
          v-for="task in recentTasks"
          :key="task.task_id"
          class="recent-item"
          @click="router.push(`/tasks/${task.task_id}`)"
        >
          <div class="recent-target">
            <code>{{ task.target }}</code>
            <StatusBadge :status="task.status" />
          </div>
          <div class="recent-meta">
            <PhaseBadge :phase="task.current_phase" />
            <span class="meta-sep">·</span>
            <span class="finding-count">
              {{ task.findings_count }} 漏洞
            </span>
            <span class="meta-sep">·</span>
            <el-icon v-if="task.got_shell" class="shell-yes"><CircleCheckFilled /></el-icon>
            <span v-if="task.got_shell" class="shell-text">Shell</span>
          </div>
        </div>
      </div>
    </el-card>

    <!-- Architecture info -->
    <el-card class="arch-card">
      <template #header>
        <div class="card-header">
          <span class="card-title">
            <el-icon><Cpu /></el-icon>
            系统架构
          </span>
        </div>
      </template>
      <div class="arch-grid">
        <div class="arch-item" v-for="comp in archComponents" :key="comp.name">
          <div class="arch-icon" :style="{ color: comp.color }">
            <el-icon :size="18"><component :is="comp.icon" /></el-icon>
          </div>
          <div class="arch-info">
            <div class="arch-name">{{ comp.name }}</div>
            <div class="arch-desc">{{ comp.desc }}</div>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api'
import { useTasksStore } from '@/stores/tasks'
import StatusBadge from '@/components/StatusBadge.vue'
import PhaseBadge from '@/components/PhaseBadge.vue'
import {
  Aim, DataLine, CircleCheckFilled, List, Clock,
  Cpu, Monitor, Connection, Warning, Lock, Document, Search,
  Loading,
} from '@element-plus/icons-vue'

const router = useRouter()
const store = useTasksStore()

const stats = ref({})
const health = ref(null)
const statsLoading = ref(true)

const recentTasks = computed(() =>
  store.tasks.slice(0, 5)
)

const statCards = [
  { key: 'total',           label: '总任务数', icon: DataLine,           iconBg: 'rgba(56,139,253,0.12)',  iconColor: '#388bfd', valueColor: '#e6edf3' },
  { key: 'running',         label: '运行中',   icon: Loading,            iconBg: 'rgba(56,139,253,0.12)',  iconColor: '#388bfd', valueColor: '#388bfd' },
  { key: 'completed',       label: '已完成',   icon: CircleCheckFilled,  iconBg: 'rgba(63,185,80,0.12)',   iconColor: '#3fb950', valueColor: '#3fb950' },
  { key: 'failed',          label: '失败',     icon: Warning,            iconBg: 'rgba(248,81,73,0.12)',   iconColor: '#f85149', valueColor: '#f85149' },
  { key: 'shells_obtained', label: '获得Shell', icon: Lock,              iconBg: 'rgba(188,140,255,0.12)', iconColor: '#bc8cff', valueColor: '#bc8cff' },
  { key: 'total_findings',  label: '总漏洞数', icon: Aim,                iconBg: 'rgba(210,153,34,0.12)',  iconColor: '#d29922', valueColor: '#d29922' },
]

const archComponents = [
  { name: 'Web 前端',        desc: 'Vue 3 + Element Plus',        icon: Monitor,    color: '#e6edf3' },
  { name: 'API 网关',        desc: 'FastAPI + WebSocket',         icon: Connection, color: '#388bfd' },
  { name: '编排 Agent',      desc: 'LangGraph 状态机',             icon: Cpu,        color: '#3fb950' },
  { name: '侦察 Agent',      desc: 'Nmap · Gobuster · DNS',       icon: Search,     color: '#388bfd' },
  { name: '漏洞 Agent',      desc: 'Nuclei · Nikto · Hydra',      icon: Warning,    color: '#d29922' },
  { name: '利用 Agent',      desc: 'Metasploit · PoC',            icon: Aim,        color: '#f85149' },
  { name: '后渗透 Agent',    desc: '提权 · 横向移动',              icon: Lock,       color: '#bc8cff' },
  { name: '报告引擎',        desc: 'Markdown · PDF',               icon: Document,   color: '#3fb950' },
]

onMounted(async () => {
  try {
    health.value = await api.healthCheck()
  } catch {
    health.value = null
  }

  try {
    stats.value = await api.getStats()
  } catch {
    stats.value = {}
  } finally {
    statsLoading.value = false
  }

  await store.fetchTasks()
})
</script>

<style scoped>
.page-wrap {
  padding: 28px 32px;
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
}

.page-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.page-sub {
  font-size: 13px;
  color: var(--text-secondary);
}

/* Health bar */
.health-bar {
  display: flex;
  gap: 16px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.health-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  padding: 5px 12px;
  border-radius: 20px;
}

.health-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--text-muted);
}

.health-item.ok { color: var(--accent-green); }
.health-item.ok .health-dot { background: var(--accent-green); }
.health-item.warn { color: var(--accent-yellow); }
.health-item.warn .health-dot { background: var(--accent-yellow); }
.health-item.err { color: var(--accent-red); }
.health-item.err .health-dot { background: var(--accent-red); }

.spin { animation: spin 1s linear infinite; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

/* Stats grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 14px;
  margin-bottom: 24px;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 18px 20px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  transition: border-color 0.2s;
}

.stat-card:hover {
  border-color: #484f58;
}

.stat-icon-wrap {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.stat-value {
  font-family: var(--font-mono);
  font-size: 26px;
  font-weight: 700;
  line-height: 1;
}

.stat-label {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 3px;
}

/* Recent tasks */
.recent-card {
  margin-bottom: 20px;
  border-radius: var(--radius-lg) !important;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.recent-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.recent-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 12px 8px;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: background 0.15s;
}

.recent-item:hover {
  background: var(--bg-hover);
}

.recent-target {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.recent-target code {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--accent-blue);
}

.recent-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-muted);
}

.meta-sep { color: var(--border); }

.finding-count {
  font-family: var(--font-mono);
  color: var(--accent-yellow);
}

.shell-yes { color: var(--accent-green); font-size: 13px; }
.shell-text { color: var(--accent-green); font-size: 12px; }

/* Architecture card */
.arch-card {
  border-radius: var(--radius-lg) !important;
}

.arch-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 12px;
}

.arch-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--bg-base);
}

.arch-icon {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: rgba(255,255,255,0.04);
  flex-shrink: 0;
}

.arch-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.arch-desc {
  font-size: 11px;
  color: var(--text-muted);
  font-family: var(--font-mono);
}
</style>
