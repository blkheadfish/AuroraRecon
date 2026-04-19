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
              <div class="form-tip error" v-if="validationErrors.apiKey">{{ validationErrors.apiKey }}</div>
            </el-form-item>

            <el-form-item label="模型名称">
              <el-input v-model="llm.model" class="mono-input" />
            </el-form-item>

            <el-form-item label="Base URL">
              <el-input v-model="llm.base_url" class="mono-input" placeholder="https://api.deepseek.com" />
              <div class="form-tip error" v-if="validationErrors.baseUrl">{{ validationErrors.baseUrl }}</div>
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

        <el-card class="settings-card">
          <template #header><span class="card-title">Embedding 配置</span></template>

          <el-form :model="embedding" label-width="120px" class="settings-form">
            <el-form-item label="启用语义检索">
              <el-switch
                v-model="embedding.enabled"
                active-text="开启"
                inactive-text="关闭（仅关键词检索）"
              />
            </el-form-item>

            <el-form-item label="Embedding API Key">
              <el-input
                v-model="embedding.api_key"
                type="password"
                show-password
                placeholder="jina_xxx / sk-xxx"
                class="mono-input"
              />
            </el-form-item>

            <el-form-item label="Embedding Base URL">
              <el-input
                v-model="embedding.base_url"
                class="mono-input"
                placeholder="https://api.jina.ai/v1"
              />
              <div class="form-tip error" v-if="validationErrors.embeddingBaseUrl">
                {{ validationErrors.embeddingBaseUrl }}
              </div>
            </el-form-item>

            <el-form-item label="Embedding 模型">
              <el-input
                v-model="embedding.model"
                class="mono-input"
                placeholder="jina-embeddings-v3 / text-embedding-3-small"
              />
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
              <div class="form-tip error" v-if="validationErrors.lhost">{{ validationErrors.lhost }}</div>
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
          <template #header><span class="card-title">新建任务默认值</span></template>
          <el-alert
              type="info"
              :closable="false"
              show-icon
              style="margin-bottom: 16px"
              title="workflow_mode 是 per-task 的"
              description="所有审批策略/证据门槛/轮次/Skill 阈值都在「创建任务」对话框里设置,并且只影响该任务。
                          这里只设置新建任务对话框里默认勾选哪个 mode,不再写回全局环境变量。"
          />

          <el-form :model="workflow" label-width="160px" class="settings-form">
            <el-form-item label="新建任务默认模式">
              <el-radio-group v-model="workflow.default_mode">
                <el-radio-button value="pentest_engineer">渗透工程师</el-radio-button>
                <el-radio-button value="ctf_expert">CTF 高手</el-radio-button>
              </el-radio-group>
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

        <el-card class="settings-card">
          <template #header><span class="card-title">workflow_mode 默认值矩阵(只读)</span></template>
          <el-table :data="modeMatrixRows" size="small" stripe>
            <el-table-column prop="field" label="参数" width="200" />
            <el-table-column prop="pentest_engineer" label="渗透工程师" />
            <el-table-column prop="ctf_expert" label="CTF 高手" />
          </el-table>
          <div class="form-tip" style="margin-top: 8px">
            真实下发路径 = workflow_mode 默认值 → 创建任务对话框的高级参数覆盖 → PentestState。
          </div>
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
import { trackEvent } from '@/metrics/tracker'

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

const embedding = ref({
  enabled: true,
  api_key: '',
  base_url: 'https://api.jina.ai/v1',
  model: '',
})

const executor = ref({
  docker_network:       'pentest_net',
  toolbox_image:        'pentest-toolbox:latest',
  persistent_container: true,
  lhost:                '',
})

const workflow = ref({
  default_mode:  'pentest_engineer',
  max_retries:   3,
  default_scope: 'CTF/授权靶场测试',
  report_lang:   'zh',
})

// 与后端 models._MODE_DEFAULTS 保持同步,仅供只读展示。
// 如果后端调整,这里应同步修改,否则 UI 可能误导用户。
const MODE_DEFAULTS_TABLE = {
  pentest_engineer: {
    auto_approve:       false,
    success_gate_level: 'strict',
    risk_budget:        3,
    max_react_rounds:   25,
    max_explore_rounds: 15,
    skill_min_score:    20,
    skill_weak_boost:   0,
  },
  ctf_expert: {
    auto_approve:       true,
    success_gate_level: 'lenient',
    risk_budget:        10,
    max_react_rounds:   40,
    max_explore_rounds: 25,
    skill_min_score:    5,
    skill_weak_boost:   10,
  },
}

const modeMatrixRows = computed(() => {
  const fields = [
    ['auto_approve',       '自动审批'],
    ['success_gate_level', '证据门槛'],
    ['risk_budget',        '风险预算'],
    ['max_react_rounds',   'ReAct 最大轮次'],
    ['max_explore_rounds', '自由探索最大轮次'],
    ['skill_min_score',    'Skill 匹配下限'],
    ['skill_weak_boost',   '弱信号加权'],
  ]
  return fields.map(([key, label]) => ({
    field:             label,
    pentest_engineer:  String(MODE_DEFAULTS_TABLE.pentest_engineer[key]),
    ctf_expert:        String(MODE_DEFAULTS_TABLE.ctf_expert[key]),
  }))
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
  if (
    validationErrors.value.apiKey ||
    validationErrors.value.baseUrl ||
    validationErrors.value.embeddingBaseUrl ||
    validationErrors.value.lhost
  ) {
    ElMessage.error('请先修正配置校验错误后再保存')
    return
  }
  saving.value = true
  try {
    await api.saveSettings({
      llm: llm.value,
      embedding: embedding.value,
      executor: executor.value,
      workflow: workflow.value,
    })
    trackEvent('settings.save', { provider: llm.value.provider })
    ElMessage.success('设置已保存')
  } catch (e) {
    ElMessage.error('保存失败：' + (e?.response?.data?.detail || e.message))
  } finally {
    saving.value = false
  }
}

const validationErrors = computed(() => {
  const errors = {
    apiKey: '',
    baseUrl: '',
    embeddingBaseUrl: '',
    lhost: '',
  }

  if (llm.value.api_key && !/^sk-[a-zA-Z0-9\-_]{8,}/.test(llm.value.api_key)) {
    errors.apiKey = 'API Key 格式不合法，通常应以 sk- 开头。'
  }
  if (llm.value.base_url && !/^https?:\/\/[\w.-]+(?:\/.*)?$/.test(llm.value.base_url)) {
    errors.baseUrl = 'Base URL 必须是合法的 http/https 地址。'
  }
  if (embedding.value.base_url && !/^https?:\/\/[\w.-]+(?:\/.*)?$/.test(embedding.value.base_url)) {
    errors.embeddingBaseUrl = 'Embedding Base URL 必须是合法的 http/https 地址。'
  }
  if (executor.value.lhost && !/^\d{1,3}(\.\d{1,3}){3}$/.test(executor.value.lhost)) {
    errors.lhost = 'LHOST 建议填写合法 IPv4 地址。'
  }
  return errors
})

async function loadSettings() {
  try {
    const s = await api.getSettings()
    if (s.llm)      Object.assign(llm.value, s.llm)
    if (s.embedding) Object.assign(embedding.value, s.embedding)
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
.form-tip.error { color: var(--accent-red); }

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