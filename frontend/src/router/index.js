import { createRouter, createWebHistory } from 'vue-router'
import StartPage from '@/views/StartPage.vue'
import LoginPage from '@/views/LoginPage.vue'
import RegisterPage from '@/views/RegisterPage.vue'
import Dashboard from '@/views/Dashboard.vue'
import TaskList from '@/views/TaskList.vue'
import TaskDetail from '@/views/TaskDetail.vue'
import DecisionView from '@/views/DecisionView.vue'
import ReportCenter from '@/views/ReportCenter.vue'
import SkillsManage from '@/views/SkillsManage.vue'
import PromptManage from '@/views/PromptManage.vue'
import ToolsManage from '@/views/ToolsManage.vue'
import KnowledgeManage from '@/views/KnowledgeManage.vue'
import Profile from '@/views/Profile.vue'
import Settings from '@/views/Settings.vue'

const PUBLIC_ROUTES = new Set(['start-page', 'login', 'register'])

const routes = [
  { path: '/', redirect: '/start' },
  { path: '/start', name: 'start-page', component: StartPage },
  { path: '/login', name: 'login', component: LoginPage },
  { path: '/register', name: 'register', component: RegisterPage },
  { path: '/dashboard', name: 'dashboard', component: Dashboard },
  { path: '/tasks', name: 'tasks', component: TaskList },
  { path: '/tasks/:id', name: 'task-detail', component: TaskDetail },
  { path: '/tasks/:id/decision', name: 'decision-view', component: DecisionView },
  { path: '/reports/:id', name: 'report-center', component: ReportCenter },
  { path: '/tools', name: 'tools-manage', component: ToolsManage },
  { path: '/skills', name: 'skills-manage', component: SkillsManage },
  { path: '/knowledge', name: 'knowledge-manage', component: KnowledgeManage },
  { path: '/prompts', name: 'prompt-manage', component: PromptManage },
  { path: '/profile', name: 'profile', component: Profile },
  { path: '/settings', name: 'settings', component: Settings },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const token = localStorage.getItem('auth.token')
  if (!token && !PUBLIC_ROUTES.has(to.name)) {
    return { name: 'login' }
  }
})

export default router
