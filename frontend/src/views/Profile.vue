<template>
  <div class="page-wrap">
    <div class="page-header">
      <div>
        <h1 class="page-title">个人空间</h1>
        <p class="page-sub">维护昵称、头像与账户安全设置</p>
      </div>
    </div>

    <el-card class="panel">
      <template #header><span class="card-title">基本资料</span></template>
      <div class="profile-grid" v-loading="profileLoading">
        <div class="avatar-col">
          <el-avatar
            :size="88"
            :src="avatarError ? '' : profile.avatar"
            class="profile-avatar"
            @error="onAvatarError"
          >
            {{ nicknameInitial }}
          </el-avatar>
          <el-button size="small" disabled>上传头像（预留）</el-button>
        </div>
        <div class="form-col">
          <el-form label-width="90px">
            <el-form-item label="昵称">
              <el-input v-model="profile.nickname" maxlength="32" show-word-limit />
            </el-form-item>
            <el-form-item label="头像链接">
              <el-input v-model="profile.avatar" placeholder="https://example.com/avatar.png" />
            </el-form-item>
            <el-form-item label="更新时间">
              <span class="muted">{{ formatTime(profile.updated_at) }}</span>
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

    <el-card class="panel">
      <template #header>
        <div class="card-header">
          <span class="card-title">团队信息（预留）</span>
          <el-button text :loading="teamLoading" @click="loadTeam">刷新</el-button>
        </div>
      </template>
      <el-alert
        v-if="teamReserved"
        title="团队接口已预留，后端尚未启用"
        type="info"
        :closable="false"
        show-icon
      />
      <el-table v-else-if="teamMembers.length" :data="teamMembers" size="small">
        <el-table-column prop="user_id" label="用户ID" min-width="180" />
        <el-table-column prop="email" label="邮箱" min-width="220" />
        <el-table-column prop="role" label="角色" width="120" />
      </el-table>
      <el-empty v-else description="暂无团队成员数据" />
      <div v-if="teamError" class="error-tip">{{ teamError }}</div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'

const PROFILE_LOCAL_KEY = 'profile.local.v1'

const profileLoading = ref(false)
const profileSaving = ref(false)
const avatarError = ref(false)
const profile = ref({
  nickname: '安全研究员',
  avatar: '',
  updated_at: '',
})

const passwordSaving = ref(false)
const passwordForm = ref({
  old_password: '',
  new_password: '',
  confirm_password: '',
})

const teamLoading = ref(false)
const teamReserved = ref(false)
const teamError = ref('')
const teamMembers = ref([])

const nicknameInitial = computed(() => (profile.value.nickname || 'U').slice(0, 1).toUpperCase())

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

function onAvatarError() {
  avatarError.value = true
  return false
}

function loadProfileLocal() {
  const cached = localStorage.getItem(PROFILE_LOCAL_KEY)
  if (!cached) return
  try {
    const parsed = JSON.parse(cached)
    profile.value = {
      nickname: parsed.nickname || '安全研究员',
      avatar: parsed.avatar || '',
      updated_at: parsed.updated_at || '',
    }
  } catch {
    // Ignore invalid cache.
  }
}

function saveProfileLocal(data) {
  localStorage.setItem(PROFILE_LOCAL_KEY, JSON.stringify(data))
}

async function loadProfile() {
  profileLoading.value = true
  loadProfileLocal()
  try {
    const remote = await api.getProfile()
    profile.value = {
      nickname: remote.nickname || profile.value.nickname || '安全研究员',
      avatar: remote.avatar || '',
      updated_at: remote.updated_at || profile.value.updated_at || '',
    }
    saveProfileLocal(profile.value)
  } catch {
    // Backend not ready: keep local profile.
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
  const payload = {
    nickname,
    avatar: String(profile.value.avatar || '').trim(),
  }
  profileSaving.value = true
  const localProfile = {
    ...payload,
    updated_at: new Date().toISOString(),
  }
  saveProfileLocal(localProfile)
  profile.value = localProfile
  avatarError.value = false

  try {
    const res = await api.updateProfile(payload)
    if (res?.profile) {
      profile.value = {
        nickname: res.profile.nickname || localProfile.nickname,
        avatar: res.profile.avatar || '',
        updated_at: res.profile.updated_at || localProfile.updated_at,
      }
      saveProfileLocal(profile.value)
    }
    ElMessage.success('个人资料已保存')
  } catch (e) {
    const status = e?.response?.status
    if (status === 404 || status === 501) {
      ElMessage.warning('后端个人资料接口未启用，已保存到本地')
    } else {
      ElMessage.warning('后端保存失败，已保存到本地')
    }
  } finally {
    profileSaving.value = false
  }
}

async function submitPassword() {
  if (!passwordForm.value.old_password) {
    ElMessage.error('请输入旧密码')
    return
  }
  if (passwordForm.value.new_password.length < 8) {
    ElMessage.error('新密码至少 8 位')
    return
  }
  if (passwordForm.value.new_password !== passwordForm.value.confirm_password) {
    ElMessage.error('两次输入的新密码不一致')
    return
  }

  passwordSaving.value = true
  try {
    await api.changePassword({
      old_password: passwordForm.value.old_password,
      new_password: passwordForm.value.new_password,
    })
    ElMessage.success('密码修改成功')
    passwordForm.value = { old_password: '', new_password: '', confirm_password: '' }
  } catch (e) {
    if (e?.response?.status === 501) {
      ElMessage.warning('后端修改密码接口未启用（预留中）')
    } else {
      ElMessage.error(e?.response?.data?.detail || e.message || '修改密码失败')
    }
  } finally {
    passwordSaving.value = false
  }
}

async function loadTeam() {
  teamLoading.value = true
  teamError.value = ''
  try {
    const members = await api.listMembers()
    teamMembers.value = Array.isArray(members) ? members : []
    teamReserved.value = false
  } catch (e) {
    teamMembers.value = []
    if (e?.response?.status === 501) {
      teamReserved.value = true
    } else {
      teamReserved.value = false
      teamError.value = e?.response?.data?.detail || e.message || '读取团队信息失败'
    }
  } finally {
    teamLoading.value = false
  }
}

onMounted(async () => {
  await loadProfile()
  await loadTeam()
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
.muted { color: var(--text-muted); font-size: 12px; }
.hint { font-size: 12px; color: var(--text-secondary); margin-top: 6px; }
.hint .weak { color: var(--accent-red); }
.hint .medium { color: var(--accent-yellow); }
.hint .strong { color: var(--accent-green); }
.error-tip { margin-top: 10px; color: var(--accent-red); font-size: 12px; }
</style>
