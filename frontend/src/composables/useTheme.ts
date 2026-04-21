import { ref } from 'vue'

type Theme = 'dark' | 'light'

const theme = ref<Theme>('dark')

export function useTheme() {
  function init(): void {
    const saved = localStorage.getItem('pentest-theme')
    if (saved === 'light' || saved === 'dark') {
      theme.value = saved
    }
    apply()
  }

  function toggle(): void {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
    localStorage.setItem('pentest-theme', theme.value)
    apply()
  }

  function apply(): void {
    document.documentElement.setAttribute('data-theme', theme.value)
  }

  return { theme, init, toggle }
}
