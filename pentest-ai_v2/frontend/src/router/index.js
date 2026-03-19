import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '@/views/Dashboard.vue'
import TaskList from '@/views/TaskList.vue'
import TaskDetail from '@/views/TaskDetail.vue'
import Settings from '@/views/Settings.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'dashboard', component: Dashboard },
  { path: '/tasks', name: 'tasks', component: TaskList },
  { path: '/tasks/:id', name: 'task-detail', component: TaskDetail },
  { path: '/settings', name: 'settings', component: Settings },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
