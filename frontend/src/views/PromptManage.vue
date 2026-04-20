<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">Prompt管理</h1>
        <p class="page-sub">维护系统 Prompt 版本并设置激活模板</p>
      </div>
      <div class="header-actions">
        <el-button @click="rollbackPrompt">回滚版本</el-button>
        <el-button type="primary" plain @click="savePrompts">保存版本</el-button>
      </div>
    </div>

    <el-card class="panel">
      <div class="prompt-layout">
        <el-menu class="prompt-menu" :default-active="selectedPromptId">
          <el-menu-item
            v-for="p in prompts"
            :key="p.id"
            :index="p.id"
            @click="selectedPromptId = p.id"
          >
            <span>{{ p.name }}</span>
            <el-tag size="small" class="version-tag">{{ p.version }}</el-tag>
            <el-tag v-if="p.active" size="small" type="success" class="active-tag">激活</el-tag>
          </el-menu-item>
        </el-menu>

        <div class="prompt-editor">
          <el-form label-width="90px">
            <el-form-item label="模板名称">
              <el-input v-model="selectedPrompt.name" />
            </el-form-item>
            <el-form-item label="版本号">
              <el-input v-model="selectedPrompt.version" />
            </el-form-item>
            <el-form-item label="内容">
              <el-input
                v-model="selectedPrompt.content"
                type="textarea"
                :rows="16"
                class="mono-input"
                placeholder="输入系统 Prompt 内容"
              />
            </el-form-item>
          </el-form>

          <div class="prompt-actions">
            <el-button type="success" @click="publishPrompt">设为激活版本</el-button>
            <el-button @click="resetCurrentPrompt">重置当前模板</el-button>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { trackEvent } from '@/metrics/tracker'
import { api } from '@/api'

const promptKey = 'prompt.manage.v1'
const snapshotKey = 'prompt.manage.snapshot'

const defaultPrompts = [
  { id: 'vuln', name: '漏洞分析 Prompt', version: 'v1.4', active: true, content: '你是漏洞分析助手，请严格基于证据输出。' },
  { id: 'exploit', name: '利用决策 Prompt', version: 'v1.7', active: true, content: '你是利用决策助手，优先输出可审计 payload。' },
  { id: 'report', name: '报告生成 Prompt', version: 'v1.2', active: true, content: '你是安全报告助手，输出结构化修复建议。' },
]

const prompts = ref(JSON.parse(JSON.stringify(defaultPrompts)))
const selectedPromptId = ref('vuln')

const selectedPrompt = computed(() => {
  const fallback = prompts.value[0]
  return prompts.value.find((item) => item.id === selectedPromptId.value) || fallback
})

function normalizeActivePrompt() {
  if (!prompts.value.some((item) => item.active) && prompts.value.length > 0) {
    prompts.value[0].active = true
  }
}

function loadPrompts() {
  api.getPrompts()
    .then((res) => {
      const parsed = res?.prompts
      if (Array.isArray(parsed) && parsed.length) {
        prompts.value = parsed
        normalizeActivePrompt()
      }
    })
    .catch(() => {
      const saved = localStorage.getItem(promptKey)
      if (!saved) return
      try {
        const parsed = JSON.parse(saved)
        if (Array.isArray(parsed) && parsed.length) {
          prompts.value = parsed
          normalizeActivePrompt()
        }
      } catch {
        ElMessage.warning('Prompt 缓存加载失败，已使用默认模板')
      }
    })
}

function savePrompts() {
  const snapshot = JSON.stringify(prompts.value)
  localStorage.setItem(snapshotKey, snapshot)
  localStorage.setItem(promptKey, snapshot)
  api.savePrompts(prompts.value).catch(() => {
    ElMessage.warning('后端保存失败，仅已保存到本地缓存')
  })
  trackEvent('prompts.save', { count: prompts.value.length })
  ElMessage.success('Prompt 版本已保存')
}

function rollbackPrompt() {
  const saved = localStorage.getItem(snapshotKey)
  if (!saved) {
    ElMessage.warning('暂无可回滚版本')
    return
  }
  try {
    prompts.value = JSON.parse(saved)
    normalizeActivePrompt()
    localStorage.setItem(promptKey, saved)
    ElMessage.success('已回滚到最近保存版本')
  } catch {
    ElMessage.error('回滚失败，版本数据损坏')
  }
}

function publishPrompt() {
  prompts.value = prompts.value.map((p) => ({ ...p, active: p.id === selectedPromptId.value }))
  localStorage.setItem(promptKey, JSON.stringify(prompts.value))
  api.savePrompts(prompts.value).catch(() => {
    ElMessage.warning('后端保存失败，仅已保存到本地缓存')
  })
  trackEvent('prompts.publish', { promptId: selectedPromptId.value })
  ElMessage.success('已设为激活版本')
}

function resetCurrentPrompt() {
  const current = selectedPrompt.value
  const defaults = defaultPrompts.find((item) => item.id === current.id)
  if (!defaults) return
  Object.assign(current, JSON.parse(JSON.stringify(defaults)))
  ElMessage.success('当前模板已重置为默认内容')
}

onMounted(() => {
  loadPrompts()
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
.page-title { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.page-sub { color: var(--text-secondary); font-size: 13px; margin-top: 4px; }
.header-actions { display: flex; gap: 8px; }

.panel { border-radius: var(--radius-lg) !important; }
.prompt-layout { display: grid; grid-template-columns: 280px 1fr; gap: 14px; min-height: 520px; }
.prompt-menu { border-right: 1px solid var(--border); }
.version-tag { margin-left: 8px; }
.active-tag { margin-left: 6px; }

.prompt-editor { padding-right: 4px; }
.prompt-actions { margin-top: 8px; display: flex; gap: 8px; }
.mono-input :deep(textarea) { font-family: var(--font-mono); font-size: 12px; line-height: 1.65; }
</style>
