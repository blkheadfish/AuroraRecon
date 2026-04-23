import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api'
import type { TaskSummary, WorkflowMode } from '@/types/task'

export interface CreateTaskParams {
  target: string
  scopeNote?: string
  extraHint?: string
  userPrompt?: string
  workflowMode?: WorkflowMode
  autoApprove?: boolean | null
  successGateLevel?: 'strict' | 'medium' | 'lenient' | null
  riskBudget?: number | null
  maxReactRounds?: number | null
  maxExploreRounds?: number | null
  skillMinScore?: number | null
  skillWeakBoost?: number | null
}

export const useTaskListStore = defineStore('taskList', () => {
  const tasks = ref<TaskSummary[]>([])
  const loading = ref(false)

  const stats = computed(() => ({
    total: tasks.value.length,
    running: tasks.value.filter((task) => task.status === 'running' || task.status === 'pending').length,
    completed: tasks.value.filter((task) => task.status === 'completed').length,
    failed: tasks.value.filter((task) => task.status === 'failed').length,
    cancelled: tasks.value.filter((task) => task.status === 'cancelled').length,
  }))

  async function fetchTasks() {
    loading.value = true
    try {
      tasks.value = await api.listTasks()
    } finally {
      loading.value = false
    }
  }

  async function createTask(params: CreateTaskParams) {
    const task = await api.createTask({
      target:             params.target,
      note:               params.scopeNote,
      extraHint:          params.extraHint,
      userPrompt:         params.userPrompt,
      workflowMode:       params.workflowMode ?? 'pentest_engineer',
      autoApprove:        params.autoApprove ?? null,
      successGateLevel:   params.successGateLevel ?? null,
      riskBudget:         params.riskBudget ?? null,
      maxReactRounds:     params.maxReactRounds ?? null,
      maxExploreRounds:   params.maxExploreRounds ?? null,
      skillMinScore:      params.skillMinScore ?? null,
      skillWeakBoost:     params.skillWeakBoost ?? null,
    })
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

  async function cancelTask(taskId: string) {
    await api.cancelTask(taskId)
    const idx = tasks.value.findIndex((t) => t.task_id === taskId)
    if (idx >= 0) tasks.value[idx] = { ...tasks.value[idx], status: 'cancelled' }
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
    cancelTask,
  }
})
