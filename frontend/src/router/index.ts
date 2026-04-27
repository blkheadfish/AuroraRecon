import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import StartPage from '@/views/StartPage.vue'
import LoginPage from '@/views/LoginPage.vue'

const PUBLIC_ROUTES = new Set<string>(['start-page', 'login', 'register'])

// Admin 允许访问的个人向路径（仍保留用户资料页）。其他用户工作台路由都会被反向守卫重定向到 /admin/dashboard。
const ADMIN_ALLOWED_NON_ADMIN_PATHS = new Set<string>(['/profile'])

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/start' },
  { path: '/start', name: 'start-page', component: StartPage },
  { path: '/login', name: 'login', component: LoginPage },
  { path: '/register', name: 'register', component: () => import('@/views/RegisterPage.vue') },
  { path: '/dashboard', name: 'dashboard', component: () => import('@/views/Dashboard.vue') },
  { path: '/tasks', name: 'tasks', component: () => import('@/views/TaskList.vue') },
  { path: '/tasks/new', name: 'task-create', component: () => import('@/views/TaskCreateChat.vue') },
  { path: '/tasks/:id', name: 'task-detail', component: () => import('@/views/TaskDetail.vue') },
  { path: '/tasks/:id/chat', name: 'task-chat', component: () => import('@/views/TaskChat.vue') },
  { path: '/tasks/:id/decision', redirect: (to) => `/tasks/${to.params.id}/chat` },
  { path: '/reports/:id', name: 'report-center', component: () => import('@/views/ReportCenter.vue') },
  { path: '/tools', name: 'tools-manage', component: () => import('@/views/ToolsManage.vue') },
  { path: '/skills', name: 'skills-manage', component: () => import('@/views/SkillsManage.vue') },
  { path: '/knowledge', name: 'knowledge-manage', component: () => import('@/views/KnowledgeManage.vue') },
  { path: '/prompts', name: 'prompt-manage', component: () => import('@/views/PromptManage.vue') },
  { path: '/profile', name: 'profile', component: () => import('@/views/Profile.vue') },
  { path: '/settings', name: 'settings', component: () => import('@/views/Settings.vue') },
  {
    path: '/admin',
    component: () => import('@/layouts/AdminLayout.vue'),
    meta: { requiresAdmin: true, adminShell: true },
    redirect: '/admin/dashboard',
    children: [
      { path: 'dashboard', name: 'admin-dashboard', component: () => import('@/views/admin/AdminDashboard.vue') },
      { path: 'tasks', name: 'admin-tasks', component: () => import('@/views/admin/AdminTasks.vue') },
      { path: 'tasks/:id', name: 'admin-task-detail', component: () => import('@/views/TaskDetail.vue') },
      { path: 'tools', name: 'admin-tools', component: () => import('@/views/admin/AdminTools.vue') },
      { path: 'skills', name: 'admin-skills', component: () => import('@/views/admin/AdminSkills.vue') },
      { path: 'knowledge', name: 'admin-knowledge', component: () => import('@/views/admin/AdminKnowledge.vue') },
      { path: 'prompts', name: 'admin-prompts', component: () => import('@/views/PromptManage.vue') },
      { path: 'users', name: 'admin-users', component: () => import('@/views/admin/AdminUsers.vue') },
      { path: 'settings', name: 'admin-settings', component: () => import('@/views/admin/AdminSettings.vue') },
      { path: 'audit', name: 'admin-audit', component: () => import('@/views/admin/AdminAudit.vue') },
      { path: 'terminal', name: 'admin-terminal', component: () => import('@/views/admin/AdminTerminal.vue') },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    redirect: () => (currentRole() === 'admin' ? '/admin/dashboard' : '/dashboard'),
  },
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
  const name = String(to.name ?? '')
  if (!token && !PUBLIC_ROUTES.has(name)) {
    return { name: 'login' }
  }
  const role = currentRole()
  const needsAdmin = to.matched.some(r => r.meta?.requiresAdmin)
  if (needsAdmin && role !== 'admin') {
    return { name: 'dashboard' }
  }
  // 反向守卫：管理员只能看管理控制台（/admin/*），以及少量个人向路径。
  if (role === 'admin' && token) {
    const path = to.path
    const isAdminArea = path.startsWith('/admin')
    const isPublic = PUBLIC_ROUTES.has(name)
    const isPersonal = ADMIN_ALLOWED_NON_ADMIN_PATHS.has(path)
    if (!isAdminArea && !isPublic && !isPersonal) {
      return { path: '/admin/dashboard' }
    }
  }
})

export default router
