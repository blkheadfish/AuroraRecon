<template>
  <div class="auth-page" @keyup.enter="submit">
    <div class="bg-decor" aria-hidden="true">
      <span class="bg-grid"></span>
      <span class="bg-scanline"></span>
      <span class="bg-vignette"></span>
    </div>

    <div class="auth-shell">
      <div class="logo-mark-sm">
        <span class="logo-monogram"><span class="mono-p">A</span><span class="mono-a">R</span></span>
      </div>
      <h1 class="auth-title" aria-label="AuroraRecon">
        <span class="auth-title-aurora">Aurora</span><span class="auth-title-recon">Recon</span>
      </h1>
      <p class="auth-sub">创建新账号</p>

      <div class="auth-card">
        <el-form label-position="top" @submit.prevent="submit">
          <el-form-item label="用户名">
            <el-input v-model="form.username" placeholder="字母/数字/_/-，2-64位" :prefix-icon="User" autofocus />
          </el-form-item>
          <el-form-item label="昵称（可选）">
            <el-input v-model="form.nickname" placeholder="显示名称" />
          </el-form-item>
          <el-form-item label="密码">
            <el-input v-model="form.password" type="password" placeholder="至少 6 位" show-password :prefix-icon="Lock" />
          </el-form-item>
          <el-form-item label="确认密码">
            <el-input v-model="form.confirmPassword" type="password" placeholder="再次输入密码" show-password :prefix-icon="Lock" />
          </el-form-item>
          <div class="form-error" v-if="errorMsg">{{ errorMsg }}</div>
          <el-button class="auth-btn" type="primary" size="large" :loading="loading" @click="submit">
            注 册
          </el-button>
        </el-form>
        <p class="auth-link">已有账号？<router-link to="/login">登录</router-link></p>
      </div>

      <router-link to="/start" class="back-link">← 返回首页</router-link>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { User, Lock } from '@element-plus/icons-vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()
const loading = ref(false)
const errorMsg = ref('')
const form = ref({ username: '', nickname: '', password: '', confirmPassword: '' })

async function submit() {
  errorMsg.value = ''
  const u = form.value.username.trim()
  const p = form.value.password
  if (!u) { errorMsg.value = '请输入用户名'; return }
  if (p.length < 6) { errorMsg.value = '密码至少 6 位'; return }
  if (p !== form.value.confirmPassword) { errorMsg.value = '两次密码不一致'; return }

  loading.value = true
  try {
    const res = await api.authRegister(u, p, form.value.nickname.trim())
    auth.setAuth(res.token, res.user)
    router.push('/dashboard')
  } catch (e) {
    errorMsg.value = e?.response?.data?.detail || e.message || '注册失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.auth-page {
  position: relative; min-height: 100vh; width: 100%;
  display: flex; align-items: center; justify-content: center;
  background:
    linear-gradient(145deg, color-mix(in srgb, var(--bg-base) 92%, #000 8%), var(--bg-surface)),
    radial-gradient(1200px 500px at -10% -20%, color-mix(in srgb, var(--start-hacker-line) 46%, transparent), transparent);
  overflow: hidden;
}
.bg-decor { position: absolute; inset: 0; pointer-events: none; }
.bg-grid {
  position: absolute; inset: 0;
  background-image:
    linear-gradient(to right, var(--start-grid-line) 1px, transparent 1px),
    linear-gradient(to bottom, var(--start-grid-line) 1px, transparent 1px);
  background-size: 38px 38px; opacity: 0.18;
}
.bg-scanline {
  position: absolute; left: 0; right: 0; height: 140px; top: -160px;
  background: linear-gradient(to bottom, transparent 0%, var(--start-scanline) 45%, transparent 100%);
  opacity: 0.36; animation: scanSweep 12s linear infinite;
}
.bg-vignette {
  position: absolute; inset: 0;
  background: radial-gradient(ellipse at center, transparent 28%, color-mix(in srgb, var(--bg-base) 72%, transparent) 100%);
}
.auth-shell {
  position: relative; z-index: 2;
  display: flex; flex-direction: column; align-items: center;
  width: min(420px, calc(100% - 32px));
}
.logo-mark-sm {
  width: 72px; height: 64px;
  clip-path: polygon(25% 4%, 75% 4%, 96% 50%, 75% 96%, 25% 96%, 4% 50%);
  background: linear-gradient(140deg, color-mix(in srgb, var(--bg-surface) 88%, var(--bg-elevated)), color-mix(in srgb, var(--bg-base) 90%, #000));
  display: grid; place-items: center; margin-bottom: 12px;
}
.logo-monogram { font-family: var(--font-orbitron); font-size: 22px; font-weight: 600; letter-spacing: 0.06em; color: color-mix(in srgb, var(--text-primary) 72%, var(--start-hacker-cyan)); }
.mono-p { color: color-mix(in srgb, var(--text-primary) 78%, var(--start-hacker-cyan)); }
.mono-a { color: color-mix(in srgb, var(--start-hacker-cyan) 62%, #9ec0d8); }
.auth-title { font-family: var(--font-orbitron); font-size: 32px; font-weight: 600; letter-spacing: 0.04em; margin: 0 0 4px; }
.auth-title-aurora {
  color: color-mix(in srgb, var(--text-primary) 88%, var(--start-hacker-cyan));
  text-shadow:
    0 0 14px color-mix(in srgb, var(--start-hacker-cyan) 22%, transparent),
    0 0 28px color-mix(in srgb, var(--start-hacker-green) 12%, transparent);
}
.auth-title-recon {
  margin-left: 0.06em;
  color: color-mix(in srgb, var(--start-hacker-green) 52%, var(--text-primary));
  text-shadow:
    0 0 16px color-mix(in srgb, var(--start-hacker-green) 32%, transparent),
    0 0 28px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent);
}

[data-theme='light'] .auth-title-aurora {
  color: color-mix(in srgb, #1a3d4a 72%, var(--start-hacker-cyan));
  text-shadow:
    0 0 8px color-mix(in srgb, var(--start-hacker-cyan) 14%, transparent),
    0 0 16px color-mix(in srgb, var(--start-hacker-green) 10%, transparent);
}
[data-theme='light'] .auth-title-recon {
  color: color-mix(in srgb, var(--start-hacker-green) 48%, #1e4a42);
  text-shadow:
    0 0 10px color-mix(in srgb, var(--start-hacker-green) 20%, transparent),
    0 0 18px color-mix(in srgb, var(--start-hacker-cyan) 8%, transparent);
}
.auth-sub { color: var(--text-secondary); font-size: 14px; margin-bottom: 20px; }
.auth-card {
  width: 100%; padding: 28px 24px;
  border: 1px solid color-mix(in srgb, var(--start-hacker-line) 48%, var(--border));
  border-radius: 16px;
  background: color-mix(in srgb, var(--bg-surface) 86%, var(--bg-elevated));
  backdrop-filter: blur(14px);
  box-shadow: 0 20px 48px color-mix(in srgb, var(--start-panel-shadow) 60%, transparent);
}
.form-error { color: var(--accent-red); font-size: 13px; margin-bottom: 12px; }
.auth-btn { width: 100%; font-weight: 600; letter-spacing: 0.06em; }
.auth-link { margin-top: 14px; font-size: 13px; color: var(--text-secondary); text-align: center; }
.auth-link a { color: color-mix(in srgb, var(--start-hacker-cyan) 70%, var(--text-primary)); text-decoration: none; }
.auth-link a:hover { text-decoration: underline; }
.back-link { margin-top: 18px; font-size: 12px; color: var(--text-muted); text-decoration: none; }
.back-link:hover { color: var(--text-secondary); }
@keyframes scanSweep { 0% { transform: translateY(0); } 100% { transform: translateY(calc(100vh + 260px)); } }
</style>
