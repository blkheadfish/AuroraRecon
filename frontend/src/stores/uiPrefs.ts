import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export type ExecutionMode = 'auto' | 'manual'
export type DisplayMode = 'normal' | 'demo'

export const useUiPrefsStore = defineStore('uiPrefs', () => {
  const displayMode = ref<DisplayMode>((localStorage.getItem('ui.displayMode') as DisplayMode) || 'normal')
  const executionMode = ref<ExecutionMode>((localStorage.getItem('ui.executionMode') as ExecutionMode) || 'manual')
  const reportEditorEnabled = ref(localStorage.getItem('ui.reportEditorEnabled') !== 'false')

  watch(displayMode, (value) => localStorage.setItem('ui.displayMode', value))
  watch(executionMode, (value) => localStorage.setItem('ui.executionMode', value))
  watch(reportEditorEnabled, (value) => localStorage.setItem('ui.reportEditorEnabled', String(value)))

  return {
    displayMode,
    executionMode,
    reportEditorEnabled,
  }
})
