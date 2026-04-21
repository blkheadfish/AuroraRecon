<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">个人空间</h1>
        <p class="page-sub">维护昵称与账户安全设置</p>
      </div>
    </div>

    <el-card class="panel">
      <template #header><span class="card-title">基本资料</span></template>
      <div class="profile-grid" v-loading="profileLoading">
        <div class="avatar-col">
          <div class="profile-avatar initials-avatar">{{ nicknameInitial }}</div>
          <el-tag
            v-if="profileRoleTag"
            :type="profileRoleTag.type"
            size="small"
            effect="plain"
            class="role-badge"
          >{{ profileRoleTag.label }}</el-tag>
        </div>
        <div class="form-col">
          <el-form label-width="100px">
            <el-form-item label="用户名">
              <el-input :model-value="profile.username" disabled />
            </el-form-item>
            <el-form-item label="昵称">
              <el-input v-model="profile.nickname" maxlength="64" show-word-limit />
            </el-form-item>
            <el-form-item label="注册时间">
              <span class="muted">{{ formatTime(profile.created_at) }}</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="profileSaving" @click="saveProfile">保存资料</el-button>
            </el-form-item>
          </el-form>
        </div>
      </div>
    </el-card>

    <el-card class="panel">
      <template #header><span class="card-title">修改密码</span></template>
      <el-form label-width="100px">
        <el-form-item label="旧密码">
          <el-input v-model="passwordForm.old_password" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="passwordForm.new_password" type="password" show-password />
          <div class="hint">
            密码强度：
            <span :class="strengthClass">{{ strengthText }}</span>
          </div>
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="passwordForm.confirm_password" type="password" show-password />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="passwordSaving" @click="submitPassword">
            更新密码
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

const profileLoading = ref(false)
const profileSaving = ref(false)
const profile = ref({
  username: '',
  nickname: '',
  role: 'user',
  created_at: '',
})

const passwordSaving = ref(false)
const passwordForm = ref({
  old_password: '',
  new_password: '',
  confirm_password: '',
})

const nicknameInitial = computed(() => (profile.value.nickname || 'U').slice(0, 1).toUpperCase())
const profileRoleTag = computed(() => {
  const r = String(profile.value.role || 'user')
  if (r === 'admin') return { label: '管理员', type: 'danger' }
  return null
})

const passwordStrength = computed(() => {
  const p = passwordForm.value.new_password || ''
  let score = 0
  if (p.length >= 8) score += 1
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score += 1
  if (/\d/.test(p)) score += 1
  if (/[^A-Za-z0-9]/.test(p)) score += 1
  return score
})

const strengthText = computed(() => {
  if (passwordStrength.value <= 1) return '弱'
  if (passwordStrength.value <= 2) return '中'
  return '强'
})

const strengthClass = computed(() => {
  if (passwordStrength.value <= 1) return 'weak'
  if (passwordStrength.value <= 2) return 'medium'
  return 'strong'
})

function formatTime(raw) {
  if (!raw) return '未记录'
  const d = new Date(raw)
  if (Number.isNaN(d.getTime())) return raw
  return d.toLocaleString()
}

async function loadProfile() {
  profileLoading.value = true
  try {
    const me = await api.authMe()
    profile.value = {
      username: me.username || '',
      nickname: me.nickname || me.username || '',
      role: me.role || 'user',
      created_at: me.created_at || '',
    }
  } catch {
    if (auth.user) {
      profile.value = {
        username: auth.user.username || '',
        nickname: auth.user.nickname || '',
        role: auth.user.role || 'user',
        created_at: auth.user.created_at || '',
      }
    }
  } finally {
    profileLoading.value = false
  }
}

async function saveProfile() {
  const nickname = String(profile.value.nickname || '').trim()
  if (!nickname) {
    ElMessage.error('昵称不能为空')
    return
  }
  profileSaving.value = true
  try {
    // 头像 / OSS 字段暂时下架，后端字段保留但前端不再编辑
    const res = await api.authUpdateMe({ nickname })
    if (res?.user) {
      profile.value = {
        username: res.user.username || profile.value.username,
        nickname: res.user.nickname || nickname,
        role: res.user.role || profile.value.role,
        created_at: res.user.created_at || profile.value.created_at,
      }
      auth.updateUser({
        nickname: res.user.nickname,
      })
    }
    ElMessage.success('个人资料已保存')
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '保存失败')
  } finally {
    profileSaving.value = false
  }
}

async function submitPassword() {
  if (!passwordForm.value.old_password) {
    ElMessage.error('请输入旧密码')
    return
  }
  if (passwordForm.value.new_password.length < 6) {
    ElMessage.error('新密码至少 6 位')
    return
  }
  if (passwordForm.value.new_password !== passwordForm.value.confirm_password) {
    ElMessage.error('两次输入的新密码不一致')
    return
  }

  passwordSaving.value = true
  try {
    await api.authUpdateMe({
      old_password: passwordForm.value.old_password,
      new_password: passwordForm.value.new_password,
    })
    ElMessage.success('密码修改成功')
    passwordForm.value = { old_password: '', new_password: '', confirm_password: '' }
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || e.message || '修改密码失败')
  } finally {
    passwordSaving.value = false
  }
}

onMounted(async () => {
  await loadProfile()
})
</script>

<style scoped>
.page-wrap { padding: 24px 32px; min-height: 100%; }
.page-header { margin-bottom: 12px; }
.page-title { font-size: 24px; color: var(--text-primary); font-weight: 700; }
.page-sub { margin-top: 4px; color: var(--text-secondary); font-size: 13px; }

.panel { margin-bottom: 12px; border-radius: var(--radius-lg) !important; }
.card-title { font-weight: 600; }
.card-header { display: flex; align-items: center; justify-content: space-between; }

.profile-grid {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 16px;
}
.avatar-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}
.profile-avatar { border: 1px solid var(--border); }
.initials-avatar {
  width: 88px;
  height: 88px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 34px;
  font-weight: 700;
  color: var(--accent-blue);
  background: color-mix(in srgb, var(--accent-blue) 15%, var(--bg-surface));
  user-select: none;
}
.role-badge {
  font-family: var(--font-mono);
  letter-spacing: 0.04em;
}
.muted { color: var(--text-muted); font-size: 12px; }
.hint { font-size: 12px; color: var(--text-secondary); margin-top: 6px; }
.hint .weak { color: var(--accent-red); }
.hint .medium { color: var(--accent-yellow); }
.hint .strong { color: var(--accent-green); }
</style>
