import { createRouter, createWebHistory } from 'vue-router'
import StartPage from '@/views/StartPage.vue'
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

const routes = [
  { path: '/', redirect: '/start' },
  { path: '/start', name: 'start-page', component: StartPage },
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

export default createRouter({
  history: createWebHistory(),
  routes,
})
