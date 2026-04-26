<template>
  <div class="admin-terminal">
    <div class="section-header">
      <div>
        <h2 class="section-title">SSH 终端</h2>
        <p class="section-sub">通过后端 WebSocket 代理连接到远端服务器 · 所有会话会被审计</p>
      </div>
      <div class="header-actions">
        <el-tag
          :type="connState === 'connected' ? 'success' : connState === 'connecting' ? 'warning' : 'info'"
          effect="plain"
          size="small"
        >
          {{
            connState === 'connected' ? '已连接'
            : connState === 'connecting' ? '连接中…'
            : connState === 'error' ? '连接失败'
            : '未连接'
          }}
        </el-tag>
        <el-button v-if="connState !== 'connected'" type="primary" size="small" @click="openConnectDialog">
          <el-icon><Link /></el-icon> 新建连接
        </el-button>
        <el-button v-else type="danger" size="small" @click="disconnect">
          <el-icon><Close /></el-icon> 断开连接
        </el-button>
      </div>
    </div>

    <el-alert
      v-if="lastError"
      type="error"
      :title="lastError"
      show-icon
      :closable="true"
      @close="lastError = ''"
      style="margin-bottom: 12px"
    />

    <div class="terminal-frame" ref="frameRef" :class="{ 'is-empty': !termRef }">
      <div v-if="connState !== 'connected' && !hasEverConnected" class="empty-hint">
        <el-icon :size="32"><Monitor /></el-icon>
        <div class="hint-title">未连接任何主机</div>
        <div class="hint-sub">点击右上角「新建连接」输入 SSH 参数</div>
      </div>
      <div ref="termContainerRef" class="xterm-container" />
    </div>

    <el-dialog v-model="dialogVisible" title="SSH 连接参数" width="520px" destroy-on-close>
      <el-form :model="form" label-width="90px" class="ssh-form">
        <el-form-item label="主机">
          <el-input v-model="form.host" placeholder="例如 10.0.0.5 或 target.lan" class="mono" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="form.port" :min="1" :max="65535" style="width: 140px" />
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="form.username" class="mono" />
        </el-form-item>
        <el-form-item label="认证方式">
          <el-radio-group v-model="form.auth_type">
            <el-radio value="password">密码</el-radio>
            <el-radio value="key">私钥</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.auth_type === 'password'" label="密码">
          <el-input v-model="form.password" type="password" show-password class="mono" />
        </el-form-item>
        <el-form-item v-else label="私钥内容">
          <el-input
            v-model="form.private_key"
            type="textarea"
            :rows="6"
            placeholder="粘贴 OpenSSH 私钥内容（-----BEGIN OPENSSH PRIVATE KEY-----）"
            class="mono"
          />
        </el-form-item>
      </el-form>
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="密码/私钥仅随首个 WebSocket 消息发送给后端建立 SSH 隧道，不会被持久化。"
      />
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="connState === 'connecting'" @click="connect">建立连接</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Link, Close, Monitor } from '@element-plus/icons-vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import { api } from '@/api'

const termContainerRef = ref(null)
const frameRef = ref(null)
const termRef = ref(null)
let fitAddon = null
let ws = null
let resizeObserver = null

const connState = ref('idle')
const hasEverConnected = ref(false)
const lastError = ref('')

const dialogVisible = ref(false)
const form = ref({
  host: '',
  port: 22,
  username: 'root',
  auth_type: 'password',
  password: '',
  private_key: '',
})

function openConnectDialog() {
  dialogVisible.value = true
}

function ensureTerminal() {
  if (termRef.value) return
  const term = new Terminal({
    fontFamily: 'var(--font-mono), Consolas, "Courier New", monospace',
    fontSize: 13,
    cursorBlink: true,
    theme: {
      background: '#0d1117',
      foreground: '#c9d1d9',
      cursor: '#7ee787',
      selectionBackground: '#33415580',
    },
    scrollback: 5000,
  })
  fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.loadAddon(new WebLinksAddon())
  term.open(termContainerRef.value)

  term.onData((data) => {
    if (ws && ws.readyState === WebSocket.OPEN && connState.value === 'connected') {
      ws.send(data)
    }
  })

  term.onResize(({ cols, rows }) => {
    if (ws && ws.readyState === WebSocket.OPEN && connState.value === 'connected') {
      ws.send(JSON.stringify({ type: 'resize', cols, rows }))
    }
  })

  termRef.value = term
  setTimeout(() => fitAddon?.fit(), 50)

  resizeObserver = new ResizeObserver(() => {
    try { fitAddon?.fit() } catch { /* ignore */ }
  })
  if (frameRef.value) resizeObserver.observe(frameRef.value)
}

function writeToTerm(text) {
  if (!termRef.value) return
  termRef.value.write(text)
}

async function connect() {
  if (!form.value.host) {
    ElMessage.warning('请输入目标主机')
    return
  }
  if (form.value.auth_type === 'password' && !form.value.password) {
    ElMessage.warning('请输入密码')
    return
  }
  if (form.value.auth_type === 'key' && !form.value.private_key.trim()) {
    ElMessage.warning('请粘贴私钥内容')
    return
  }

  lastError.value = ''
  connState.value = 'connecting'
  ensureTerminal()
  writeToTerm(`\r\n\x1b[33m>>> 正在连接 ${form.value.username}@${form.value.host}:${form.value.port} ...\x1b[0m\r\n`)

  const url = api.buildAdminTerminalWsUrl()
  try {
    ws = new WebSocket(url)
  } catch (e) {
    connState.value = 'error'
    lastError.value = `WebSocket 建立失败: ${e.message || e}`
    return
  }

  ws.onopen = () => {
    const payload = {
      host: form.value.host,
      port: form.value.port,
      username: form.value.username,
    }
    if (form.value.auth_type === 'password') payload.password = form.value.password
    else payload.private_key = form.value.private_key
    ws.send(JSON.stringify(payload))
  }

  ws.onmessage = (evt) => {
    const text = evt.data
    if (typeof text !== 'string') return
    if (text.startsWith('{') && text.endsWith('}')) {
      try {
        const msg = JSON.parse(text)
        if (msg.type === 'connected') {
          connState.value = 'connected'
          hasEverConnected.value = true
          dialogVisible.value = false
          writeToTerm(`\x1b[32m${msg.message || '已连接'}\x1b[0m\r\n`)
          setTimeout(() => fitAddon?.fit(), 100)
          return
        }
        if (msg.type === 'error') {
          lastError.value = msg.message || '未知错误'
          connState.value = 'error'
          writeToTerm(`\r\n\x1b[31m${msg.message || '连接错误'}\x1b[0m\r\n`)
          return
        }
      } catch { /* not a control message, treat as stdout */ }
    }
    writeToTerm(text)
  }

  ws.onerror = (evt) => {
    const target = evt?.target
    const wsUrl = target?.url || url
    lastError.value = `WebSocket 无法连接到 ${wsUrl}。请确认 nginx 已放行 /admin/terminal（需要 Upgrade + Connection: upgrade），且后端 admin_terminal 路由已注册。`
    connState.value = 'error'
  }

  ws.onclose = (evt) => {
    if (connState.value === 'connected') {
      writeToTerm('\r\n\x1b[33m>>> 连接已关闭\x1b[0m\r\n')
    } else if (connState.value === 'connecting' && !lastError.value) {
      const reason = evt?.reason ? `：${evt.reason}` : ''
      lastError.value = `WebSocket 在握手阶段被关闭 (code=${evt?.code ?? '?'})${reason}。常见原因：nginx 未代理 /admin/terminal、后端 token 校验失败、或当前用户非 admin。`
      connState.value = 'error'
    }
    if (connState.value !== 'error') {
      connState.value = 'idle'
    }
    ws = null
  }
}

function disconnect() {
  if (ws && ws.readyState <= WebSocket.OPEN) {
    try { ws.close() } catch { /* ignore */ }
  }
  connState.value = 'idle'
}

onMounted(() => {
  ensureTerminal()
})

onBeforeUnmount(() => {
  disconnect()
  if (resizeObserver) resizeObserver.disconnect()
  if (termRef.value) termRef.value.dispose()
})
</script>

<style scoped>
.admin-terminal { display: flex; flex-direction: column; height: 100%; min-height: 0; }
.section-header {
  display: flex; align-items: flex-start; justify-content: space-between;
  margin-bottom: 12px; gap: 12px; flex-wrap: wrap;
}
.section-title {
  font-size: 20px; font-weight: 700; color: var(--text-primary); margin: 0 0 4px;
}
.section-sub { font-size: 13px; color: var(--text-secondary); margin: 0; }
.header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

.terminal-frame {
  flex: 1;
  min-height: 460px;
  position: relative;
  background: #0d1117;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 8px;
  overflow: hidden;
}
.xterm-container { width: 100%; height: 100%; }

.empty-hint {
  position: absolute; inset: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 6px; color: #58606b; pointer-events: none; z-index: 2;
}
.hint-title { font-size: 14px; font-weight: 600; color: #8b949e; }
.hint-sub { font-size: 12px; }

.ssh-form .mono :deep(.el-input__inner),
.ssh-form .mono :deep(.el-textarea__inner) {
  font-family: var(--font-mono);
  font-size: 12px;
}

:deep(.xterm-viewport::-webkit-scrollbar) { width: 8px; }
:deep(.xterm-viewport::-webkit-scrollbar-thumb) {
  background: #30363d; border-radius: 4px;
}
</style>
