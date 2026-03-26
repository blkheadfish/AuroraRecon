<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统设置</h1>
        <p class="page-sub">LLM 连接、工具配置、团队管理</p>
      </div>
      <el-button type="primary" @click="saveAll" :loading="saving">
        <el-icon><Check /></el-icon> 保存设置
      </el-button>
    </div>

    <el-tabs v-model="activeTab" class="settings-tabs">

      <!-- ① LLM 配置 -->
      <el-tab-pane name="llm">
        <template #label>
          <span class="tab-label"><el-icon><Cpu /></el-icon> 大模型</span>
        </template>

        <el-card class="settings-card">
          <template #header><span class="card-title">LLM 连接配置</span></template>

          <el-form :model="llm" label-width="120px" class="settings-form">
            <el-form-item label="模型提供商">
              <el-select v-model="llm.provider" @change="onProviderChange">
                <el-option label="DeepSeek" value="deepseek" />
                <el-option label="OpenAI / GPT" value="openai" />
                <el-option label="Anthropic / Claude" value="anthropic" />
                <el-option label="自定义 OpenAI 兼容" value="custom" />
              </el-select>
            </el-form-item>

            <el-form-item label="API Key">
              <el-input
                  v-model="llm.api_key"
                  type="password"
                  show-password
                  placeholder="sk-..."
                  class="mono-input"
              />
            </el-form-item>

            <el-form-item label="模型名称">
              <el-input v-model="llm.model" class="mono-input" />
            </el-form-item>

            <el-form-item label="Base URL">
              <el-input v-model="llm.base_url" class="mono-input" placeholder="https://api.deepseek.com" />
            </el-form-item>

            <el-form-item label="Max Tokens">
              <el-input-number v-model="llm.max_tokens" :min="512" :max="32768" :step="512" />
            </el-form-item>

            <el-form-item>
              <el-button @click="testLLM" :loading="testingLLM" type="info" plain>
                <el-icon><Connection /></el-icon> 测试连接
              </el-button>
              <span v-if="llmTestResult" class="test-result" :class="llmTestResult.ok ? 'ok' : 'fail'">
                {{ llmTestResult.ok ? '✓ 连接正常' : `✗ ${llmTestResult.error}` }}
              </span>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <!-- ② 系统状态 -->
      <el-tab-pane name="system">
        <template #label>
          <span class="tab-label"><el-icon><Monitor /></el-icon> 系统状态</span>
        </template>

        <el-card class="settings-card">
          <template #header>
            <div class="card-header">
              <span class="card-title">基础设施状态</span>
              <el-button link size="small" @click="refreshHealth" :loading="healthLoading">
                <el-icon><Refresh /></el-icon>
              </el-button>
            </div>
          </template>

          <div v-if="health" class="status-grid">
            <div class="status-row" v-for="item in statusItems" :key="item.label">
              <div class="status-label-wrap">
                <span class="status-dot" :class="item.cls" />
                <span class="status-label">{{ item.label }}</span>
              </div>
              <span class="status-value mono" :class="item.cls">{{ item.value }}</span>
            </div>
          </div>
          <div v-else class="loading-placeholder">
            <el-icon class="spin"><Loading /></el-icon> 加载中...
          </div>
        </el-card>

        <el-card class="settings-card">
          <template #header><span class="card-title">工具执行后端</span></template>

          <el-form :model="executor" label-width="140px" class="settings-form">
            <el-form-item label="Docker 网络">
              <el-input v-model="executor.docker_network" class="mono-input" />
            </el-form-item>
            <el-form-item label="Toolbox 镜像">
              <el-input v-model="executor.toolbox_image" class="mono-input" />
            </el-form-item>
            <el-form-item label="容器复用模式">
              <el-switch v-model="executor.persistent_container"
                         active-text="持久化容器（docker exec）"
                         inactive-text="每次新建（docker run --rm）" />
            </el-form-item>
            <el-form-item label="LHOST（反弹 Shell）">
              <el-input v-model="executor.lhost" class="mono-input" placeholder="你的公网IP" />
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <!-- ③ 流程控制 -->
      <el-tab-pane name="workflow">
        <template #label>
          <span class="tab-label"><el-icon><Setting /></el-icon> 流程</span>
        </template>

        <el-card class="settings-card">
          <template #header><span class="card-title">Agent 行为配置</span></template>

          <el-form :model="workflow" label-width="160px" class="settings-form">
            <el-form-item label="利用前人工确认">
              <el-switch v-model="workflow.require_approval"
                         active-text="开启（推荐，防止误操作）"
                         inactive-text="关闭（全自动）" />
              <div class="form-tip">开启后，Agent 在利用漏洞前暂停并等待操作员确认</div>
            </el-form-item>

            <el-form-item label="节点失败重试次数">
              <el-input-number v-model="workflow.max_retries" :min="0" :max="5" />
            </el-form-item>

            <el-form-item label="默认授权范围说明">
              <el-input
                  v-model="workflow.default_scope"
                  type="textarea"
                  :rows="2"
                  placeholder="CTF/授权靶场测试"
              />
            </el-form-item>

            <el-form-item label="报告语言">
              <el-select v-model="workflow.report_lang">
                <el-option label="中文" value="zh" />
                <el-option label="English" value="en" />
              </el-select>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <!-- ④ 团队协作（预留 UI，接口已定义） -->
      <el-tab-pane name="team">
        <template #label>
          <span class="tab-label"><el-icon><UserFilled /></el-icon> 团队</span>
        </template>

        <el-card class="settings-card">
          <template #header>
            <div class="card-header">
              <span class="card-title">团队成员</span>
              <el-tag type="info" size="small">阶段二功能</el-tag>
            </div>
          </template>

          <el-alert
              title="团队协作功能开发中"
              description="接口已预留，阶段二将实现：多人任务分配、评论协作、角色权限、独立攻击机分配（remote 执行后端）。"
              type="info"
              :closable="false"
              show-icon
              style="margin-bottom: 16px"
          />

          <!-- 成员列表占位 -->
          <div class="team-placeholder">
            <div class="member-row" v-for="m in demoMembers" :key="m.email">
              <div class="member-avatar">{{ m.name[0] }}</div>
              <div class="member-info">
                <div class="member-name">{{ m.name }}</div>
                <div class="member-email">{{ m.email }}</div>
              </div>
              <el-tag :type="m.role === 'admin' ? 'danger' : 'info'" size="small">
                {{ m.role }}
              </el-tag>
            </div>
          </div>

          <el-button disabled plain size="small" style="margin-top: 12px">
            <el-icon><Plus /></el-icon> 邀请成员（即将开放）
          </el-button>
        </el-card>

        <el-card class="settings-card">
          <template #header><span class="card-title">执行后端扩展规划</span></template>
          <div class="arch-preview">
            <div class="arch-row">
              <div class="arch-box active">local<div class="arch-sub">nmap · nuclei</div></div>
              <div class="arch-arrow">→</div>
              <div class="arch-box active">container<div class="arch-sub">MSF · JNDIExploit</div></div>
              <div class="arch-arrow">→</div>
              <div class="arch-box planned">remote SSH<div class="arch-sub">阶段二：多人独立攻击机</div></div>
            </div>
            <div class="arch-note">
              接口不变，上层 Agent 代码零改动。多人场景：按 task_id 分配容器 + 动态端口，或 SSH 到独立攻击机。
            </div>
          </div>
        </el-card>
      </el-tab-pane>

    </el-tabs>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import {
  Check, Cpu, Connection, Monitor, Refresh, Loading,
  Setting, UserFilled, Plus,
} from '@element-plus/icons-vue'

const activeTab   = ref('llm')
const saving      = ref(false)
const testingLLM  = ref(false)
const healthLoading = ref(false)
const health      = ref(null)
const llmTestResult = ref(null)

// ── 表单数据 ────────────────────────────────────────────
const PROVIDER_DEFAULTS = {
  deepseek:  { model: 'deepseek-chat',         base_url: 'https://api.deepseek.com' },
  openai:    { model: 'gpt-4o',                base_url: 'https://api.openai.com/v1' },
  anthropic: { model: 'claude-sonnet-4-6',   base_url: 'https://api.anthropic.com/v1' },
  custom:    { model: '',                       base_url: '' },
}

const llm = ref({
  provider:   'deepseek',
  api_key:    '',
  model:      'deepseek-chat',
  base_url:   'https://api.deepseek.com',
  max_tokens: 4096,
})

const executor = ref({
  docker_network:       'pentest_net',
  toolbox_image:        'pentest-toolbox:latest',
  persistent_container: true,
  lhost:                '',
})

const workflow = ref({
  require_approval: true,
  max_retries:      3,
  default_scope:    'CTF/授权靶场测试',
  report_lang:      'zh',
})

// 团队演示数据
const demoMembers = [
  { name: '当前用户', email: 'you@example.com', role: 'admin' },
]

function onProviderChange(val) {
  const d = PROVIDER_DEFAULTS[val] || {}
  llm.value.model    = d.model    || ''
  llm.value.base_url = d.base_url || ''
}

// ── API 调用 ─────────────────────────────────────────────
async function refreshHealth() {
  healthLoading.value = true
  try {
    health.value = await api.healthCheck()
  } finally {
    healthLoading.value = false
  }
}

async function testLLM() {
  testingLLM.value = true
  llmTestResult.value = null
  try {
    await api.testLLM()
    llmTestResult.value = { ok: true }
  } catch (e) {
    llmTestResult.value = { ok: false, error: e?.response?.data?.detail || '连接失败' }
  } finally {
    testingLLM.value = false
  }
}

async function saveAll() {
  saving.value = true
  try {
    await api.saveSettings({
      llm: llm.value,
      executor: executor.value,
      workflow: workflow.value,
    })
    ElMessage.success('设置已保存')
  } catch (e) {
    ElMessage.error('保存失败：' + (e?.response?.data?.detail || e.message))
  } finally {
    saving.value = false
  }
}

async function loadSettings() {
  try {
    const s = await api.getSettings()
    if (s.llm)      Object.assign(llm.value, s.llm)
    if (s.executor) Object.assign(executor.value, s.executor)
    if (s.workflow) Object.assign(workflow.value, s.workflow)
  } catch { /* 首次启动时后端可能还没有设置 */ }
}

// ── 系统状态展示 ─────────────────────────────────────────
const statusItems = computed(() => {
  if (!health.value) return []
  const h = health.value
  return [
    { label: 'API 服务',    value: `v${h.version} — ${h.status}`,           cls: h.status === 'ok' ? 'ok' : 'err' },
    { label: 'PostgreSQL', value: h.database,                               cls: h.database === 'connected' ? 'ok' : 'warn' },
    { label: 'Redis',      value: h.redis,                                  cls: h.redis === 'connected' ? 'ok' : 'warn' },
    { label: '活跃任务',   value: `${h.active_tasks} 个运行中`,              cls: h.active_tasks > 0 ? 'ok' : 'na' },
    { label: '时间戳',     value: new Date(h.timestamp).toLocaleString(),   cls: 'na' },
  ]
})

onMounted(async () => {
  await Promise.all([refreshHealth(), loadSettings()])
})
</script>

<style scoped>
.page-wrap { padding: 28px 32px; min-height: 100%; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
}
.page-title { font-size: 22px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px; }
.page-sub   { font-size: 13px; color: var(--text-secondary); }

.tab-label { display: flex; align-items: center; gap: 5px; }

.settings-card { margin-bottom: 16px; border-radius: var(--radius-lg) !important; }

.card-header { display: flex; align-items: center; justify-content: space-between; }
.card-title  { font-size: 14px; font-weight: 600; color: var(--text-primary); }

.settings-form { max-width: 560px; padding-top: 8px; }

.mono-input :deep(input), .mono-input :deep(textarea) {
  font-family: var(--font-mono);
  font-size: 13px;
}

.form-tip { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

.test-result {
  margin-left: 12px;
  font-size: 13px;
  font-family: var(--font-mono);
}
.test-result.ok   { color: var(--accent-green); }
.test-result.fail { color: var(--accent-red); }

/* 状态表格 */
.status-grid { display: flex; flex-direction: column; gap: 12px; }
.status-row  { display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border); }
.status-row:last-child { border-bottom: none; }
.status-label-wrap { display: flex; align-items: center; gap: 8px; }
.status-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--text-muted);
}
.status-dot.ok   { background: var(--accent-green); box-shadow: 0 0 5px rgba(63,185,80,.4); }
.status-dot.warn { background: var(--accent-yellow); }
.status-dot.err  { background: var(--accent-red); }
.status-label { font-size: 13px; color: var(--text-secondary); }
.status-value { font-size: 13px; color: var(--text-muted); }
.status-value.ok   { color: var(--accent-green); }
.status-value.warn { color: var(--accent-yellow); }
.status-value.err  { color: var(--accent-red); }
.mono { font-family: var(--font-mono); }

/* 团队成员 */
.team-placeholder { display: flex; flex-direction: column; gap: 10px; }
.member-row {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
}
.member-avatar {
  width: 36px; height: 36px; border-radius: 50%;
  background: rgba(56,139,253,.15);
  color: var(--accent-blue);
  display: flex; align-items: center; justify-content: center;
  font-weight: 700;
}
.member-name  { font-size: 13px; font-weight: 500; color: var(--text-primary); }
.member-email { font-size: 11px; color: var(--text-muted); }
.member-row .el-tag { margin-left: auto; }

/* 架构预览 */
.arch-preview { padding: 8px 0; }
.arch-row { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.arch-box {
  padding: 10px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
  text-align: center;
}
.arch-box.active  { border-color: var(--accent-blue); color: var(--accent-blue); background: rgba(56,139,253,.06); }
.arch-box.planned { border-color: var(--border); border-style: dashed; color: var(--text-muted); }
.arch-sub { font-size: 11px; font-weight: 400; color: var(--text-muted); font-family: var(--font-mono); margin-top: 3px; }
.arch-arrow { color: var(--text-muted); font-size: 18px; }
.arch-note  { font-size: 12px; color: var(--text-muted); line-height: 1.6; }

.loading-placeholder { display: flex; align-items: center; gap: 8px; color: var(--text-muted); padding: 12px 0; }
.spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>