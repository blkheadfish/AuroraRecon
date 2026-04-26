<template>
  <div class="admin-settings">
    <div class="section-header">
      <div>
        <h2 class="section-title">系统设置</h2>
        <p class="section-sub">LLM 配置 · 系统状态 · 流程控制 · 运行时环境</p>
      </div>
    </div>

    <!-- 原 Settings 三个 tab（LLM / 系统状态 / 流程）直接嵌入 -->
    <div class="settings-host">
      <Settings />
    </div>

    <!-- 第 4 tab：运行时环境（LLM/Embedding 环境变量只读） -->
    <el-card class="runtime-section" shadow="never">
      <template #header>
        <div class="runtime-head">
          <span class="panel-head">运行时环境（只读）</span>
          <el-button link :icon="Refresh" size="small" @click="loadRuntime" :loading="loadingRuntime" />
        </div>
      </template>

      <SkeletonBlock v-if="loadingRuntime && !runtime" :rows="4" :height="22" />

      <div v-if="runtime" class="runtime-grid">
        <div class="runtime-card">
          <div class="runtime-card-head">
            <span class="runtime-card-icon llm">LLM</span>
            <el-tag :type="runtime.llm.has_key ? 'success' : 'warning'" size="small" effect="plain" round>
              {{ runtime.llm.has_key ? 'Key 已配置' : 'Key 未配置' }}
            </el-tag>
          </div>
          <div class="runtime-fields">
            <div class="rf-row"><span class="rf-label">提供商</span><span class="rf-value">{{ runtime.llm.provider || '—' }}</span></div>
            <div class="rf-row"><span class="rf-label">模型</span><span class="rf-value mono-sm">{{ runtime.llm.model || '—' }}</span></div>
            <div class="rf-row"><span class="rf-label">Base URL</span><span class="rf-value mono-sm">{{ runtime.llm.base_url || '—' }}</span></div>
          </div>
        </div>

        <div class="runtime-card">
          <div class="runtime-card-head">
            <span class="runtime-card-icon emb">Embedding</span>
            <el-tag :type="runtime.embedding.has_key ? 'success' : 'warning'" size="small" effect="plain" round>
              {{ runtime.embedding.has_key ? 'Key 已配置' : 'Key 未配置' }}
            </el-tag>
          </div>
          <div class="runtime-fields">
            <div class="rf-row"><span class="rf-label">状态</span><span class="rf-value">{{ runtime.embedding.enabled ? '已启用' : '已禁用' }}</span></div>
            <div class="rf-row"><span class="rf-label">模型</span><span class="rf-value mono-sm">{{ runtime.embedding.model || '—' }}</span></div>
            <div class="rf-row"><span class="rf-label">Base URL</span><span class="rf-value mono-sm">{{ runtime.embedding.base_url || '—' }}</span></div>
          </div>
        </div>
      </div>

      <el-empty v-else-if="!loadingRuntime" description="无法获取运行时配置" :image-size="60" />

      <div v-if="runtime" class="note-bar">
        <el-icon><InfoFilled /></el-icon>
        <span>{{ runtime.note }}</span>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { Refresh, InfoFilled } from '@element-plus/icons-vue'
import Settings from '@/views/Settings.vue'
import { api } from '@/api'
import SkeletonBlock from '@/components/SkeletonBlock.vue'

const runtime = ref(null)
const loadingRuntime = ref(false)

async function loadRuntime() {
  loadingRuntime.value = true
  try {
    runtime.value = await api.adminGetLlmRuntime()
  } catch {
    runtime.value = null
  } finally {
    loadingRuntime.value = false
  }
}

onMounted(loadRuntime)
</script>

<style scoped>
.section-header {
  margin-bottom: 12px;
}
.section-title {
  font-size: 20px; font-weight: 700; color: var(--text-primary); margin: 0 0 4px;
}
.section-sub {
  font-size: 13px; color: var(--text-secondary); margin: 0;
}

/* 让内嵌的 Settings 不再自己撑满 padding（其 .page-wrap 自带 padding） */
.settings-host :deep(.page-wrap) {
  padding: 0 !important;
}
.settings-host :deep(.page-header) {
  display: none !important;
}

.runtime-section {
  margin-top: 20px;
  border-radius: var(--radius-lg) !important;
  border: 1px solid var(--border) !important;
}
.runtime-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.panel-head {
  font-size: 14px;
  font-weight: 700;
  color: var(--text-primary);
}

.runtime-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}
.runtime-card {
  padding: 14px 18px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg-surface);
}
.runtime-card-head {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 14px;
}
.runtime-card-icon {
  font-size: 13px; font-weight: 700; font-family: var(--font-mono);
  padding: 3px 10px; border-radius: var(--radius-md);
}
.runtime-card-icon.llm {
  background: rgba(56, 139, 253, 0.12); color: var(--accent-blue);
}
.runtime-card-icon.emb {
  background: rgba(127, 224, 189, 0.12); color: var(--accent-green);
}
.runtime-fields { display: flex; flex-direction: column; gap: 8px; }
.rf-row { display: flex; align-items: baseline; gap: 12px; }
.rf-label {
  min-width: 60px; font-size: 12px; color: var(--text-muted); flex-shrink: 0;
}
.rf-value { font-size: 13px; color: var(--text-primary); word-break: break-all; }
.mono-sm { font-family: var(--font-mono); font-size: 12px; }

.note-bar {
  margin-top: 16px;
  display: flex; align-items: center; gap: 8px;
  padding: 10px 16px;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--accent-yellow) 8%, var(--bg-surface));
  border: 1px solid color-mix(in srgb, var(--accent-yellow) 30%, var(--border));
  font-size: 12px; color: var(--text-secondary);
}
.note-bar .el-icon { color: var(--accent-yellow); flex-shrink: 0; }
</style>
