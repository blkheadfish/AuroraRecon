import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api'
import type { TaskSummary } from '@/types/task'

export const useTaskListStore = defineStore('taskList', () => {
  const tasks = ref<TaskSummary[]>([])
  const loading = ref(false)

  const stats = computed(() => ({
    total: tasks.value.length,
    running: tasks.value.filter((task) => task.status === 'running' || task.status === 'pending').length,
    completed: tasks.value.filter((task) => task.status === 'completed').length,
    failed: tasks.value.filter((task) => task.status === 'failed').length,
  }))

  async function fetchTasks() {
    loading.value = true
    try {
      tasks.value = await api.listTasks()
    } finally {
      loading.value = false
    }
  }

  async function createTask(
    target: string,
    scopeNote: string,
    extraHint = '',
    userPrompt = '',
    workflowMode = 'standard',
  ) {
    const task = await api.createTask(target, scopeNote, extraHint, userPrompt, workflowMode)
    tasks.value.unshift(task)
    return task
  }

  function upsertTask(updated: Partial<TaskSummary> & { task_id: string }) {
    const idx = tasks.value.findIndex((task) => task.task_id === updated.task_id)
    if (idx >= 0) {
      tasks.value[idx] = { ...tasks.value[idx], ...updated }
    } else {
      tasks.value.unshift(updated as TaskSummary)
    }
  }

  function removeTask(taskId: string) {
    tasks.value = tasks.value.filter((task) => task.task_id !== taskId)
  }

  function getTaskById(taskId: string) {
    return tasks.value.find((task) => task.task_id === taskId) || null
  }

  return {
    tasks,
    loading,
    stats,
    fetchTasks,
    createTask,
    upsertTask,
    removeTask,
    getTaskById,
  }
})
