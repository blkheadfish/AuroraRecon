import { defineStore } from 'pinia'
import { computed } from 'vue'
import { useTaskListStore } from '@/stores/taskList'
import { useTaskLiveStore } from '@/stores/taskLive'
import { subscribeTaskEvents } from '@/services/wsManager'
import type { WsTaskEvent } from '@/types/task'

export const useTasksStore = defineStore('tasksCompat', () => {
  const listStore = useTaskListStore()
  const liveStore = useTaskLiveStore()

  const tasks = computed(() => listStore.tasks)
  const loading = computed(() => listStore.loading)

  async function fetchTasks() {
    return listStore.fetchTasks()
  }

  async function createTask(target: string, scopeNote: string) {
    return listStore.createTask({ target, scopeNote })
  }

  function updateTask(updated: { task_id: string } & Record<string, unknown>) {
    listStore.upsertTask(updated)
  }

  function removeTask(taskId: string) {
    liveStore.clear(taskId)
    listStore.removeTask(taskId)
  }

  function subscribeTask(taskId: string, onUpdate?: (event: WsTaskEvent) => void) {
    return subscribeTaskEvents(taskId, (event) => {
      if ((event as { type?: string }).type === 'phase_update') {
        const patch = event as {
          phase?: string
          status?: string
          findings_count?: number
          got_shell?: boolean
        }
        listStore.upsertTask({
          task_id: taskId,
          current_phase: patch.phase,
          status: patch.status as never,
          findings_count: patch.findings_count,
          got_shell: patch.got_shell,
        })
      }
      if ((event as { type?: string }).type === 'approval_required') {
        listStore.upsertTask({ task_id: taskId, current_phase: 'awaiting_approval', status: 'running' as never })
      }
      onUpdate?.(event)
    })
  }

  function unsubscribeTask(taskId: string) {
    liveStore.detach(taskId)
  }

  return {
    tasks,
    loading,
    fetchTasks,
    createTask,
    updateTask,
    removeTask,
    subscribeTask,
    unsubscribeTask,
  }
})
