import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

const TOKEN_KEY = 'auth.token'
const USER_KEY = 'auth.user'

export interface AuthUser {
  id: string
  username: string
  nickname: string
  avatar_url: string
  oss_url: string
  created_at: string
}

function loadToken(): string {
  return localStorage.getItem(TOKEN_KEY) || ''
}

function loadUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref(loadToken())
  const user = ref<AuthUser | null>(loadUser())

  const isLoggedIn = computed(() => !!token.value)
  const displayName = computed(() => user.value?.nickname || user.value?.username || '')
  const avatarUrl = computed(() => user.value?.avatar_url || '')

  function setAuth(newToken: string, newUser: AuthUser) {
    token.value = newToken
    user.value = newUser
    localStorage.setItem(TOKEN_KEY, newToken)
    localStorage.setItem(USER_KEY, JSON.stringify(newUser))
  }

  function updateUser(partial: Partial<AuthUser>) {
    if (user.value) {
      user.value = { ...user.value, ...partial }
      localStorage.setItem(USER_KEY, JSON.stringify(user.value))
    }
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
  }

  return { token, user, isLoggedIn, displayName, avatarUrl, setAuth, updateUser, logout }
})
