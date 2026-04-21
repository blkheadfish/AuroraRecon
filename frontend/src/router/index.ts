import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import StartPage from '@/views/StartPage.vue'
import LoginPage from '@/views/LoginPage.vue'

const PUBLIC_ROUTES = new Set<string>(['start-page', 'login', 'register'])

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/start' },
  { path: '/start', name: 'start-page', component: StartPage },
  { path: '/login', name: 'login', component: LoginPage },
  { path: '/register', name: 'register', component: () => import('@/views/RegisterPage.vue') },
  { path: '/dashboard', name: 'dashboard', component: () => import('@/views/Dashboard.vue') },
  { path: '/tasks', name: 'tasks', component: () => import('@/views/TaskList.vue') },
  { path: '/tasks/:id', name: 'task-detail', component: () => import('@/views/TaskDetail.vue') },
  { path: '/tasks/:id/decision', name: 'decision-view', component: () => import('@/views/DecisionView.vue') },
  { path: '/reports/:id', name: 'report-center', component: () => import('@/views/ReportCenter.vue') },
  { path: '/tools', name: 'tools-manage', component: () => import('@/views/ToolsManage.vue') },
  { path: '/skills', name: 'skills-manage', component: () => import('@/views/SkillsManage.vue') },
  { path: '/knowledge', name: 'knowledge-manage', component: () => import('@/views/KnowledgeManage.vue') },
  { path: '/prompts', name: 'prompt-manage', component: () => import('@/views/PromptManage.vue') },
  { path: '/profile', name: 'profile', component: () => import('@/views/Profile.vue') },
  { path: '/settings', name: 'settings', component: () => import('@/views/Settings.vue') },
  {
    path: '/admin',
    name: 'admin',
    component: () => import('@/views/AdminPanel.vue'),
    meta: { requiresAdmin: true },
  },
  { path: '/:pathMatch(.*)*', name: 'not-found', redirect: '/dashboard' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

function currentRole(): string {
  try {
    const raw = localStorage.getItem('auth.user')
    if (!raw) return 'user'
    const u = JSON.parse(raw)
    return String(u?.role || 'user')
  } catch {
    return 'user'
  }
}

router.beforeEach((to) => {
  const token = localStorage.getItem('auth.token')
  if (!token && !PUBLIC_ROUTES.has(String(to.name ?? ''))) {
    return { name: 'login' }
  }
  if (to.meta?.requiresAdmin && currentRole() !== 'admin') {
    return { name: 'dashboard' }
  }
})

export default router
