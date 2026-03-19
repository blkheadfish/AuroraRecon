import { ref, watch, onMounted } from 'vue'

const theme = ref('dark')

export function useTheme() {
	function init() {
		const saved = localStorage.getItem('pentest-theme')
		if (saved === 'light' || saved === 'dark') {
			theme.value = saved
		}
		apply()
	}

	function toggle() {
		theme.value = theme.value === 'dark' ? 'light' : 'dark'
		localStorage.setItem('pentest-theme', theme.value)
		apply()
	}

	function apply() {
		document.documentElement.setAttribute('data-theme', theme.value)
	}

	return { theme, init, toggle }
}