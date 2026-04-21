import { ref, watchEffect } from 'vue'
import { useTheme } from '@/composables/useTheme'

function getCssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

const revision = ref(0)

export interface ChartColors {
  cyan: string
  teal: string
  mint: string
  slate: string
  indigo: string
  mauve: string
  ember: string
  amber: string
  dim: string
}

export function useChartTheme() {
  const { theme } = useTheme()

  watchEffect(() => {
    void theme.value
    revision.value += 1
  })

  function colors(): ChartColors {
    void revision.value

    const isDark = theme.value === 'dark'
    return {
      cyan:   getCssVar('--accent-blue')   || (isDark ? '#58b8c9' : '#3984bf'),
      teal:   getCssVar('--accent-green')  || (isDark ? '#4a9ea8' : '#2e9472'),
      mint:   getCssVar('--accent-green')  || (isDark ? '#5cbda3' : '#2e9472'),
      slate:  getCssVar('--text-muted')    || (isDark ? '#6889a0' : '#8b949e'),
      indigo: getCssVar('--accent-purple') || (isDark ? '#7680b8' : '#7773ad'),
      mauve:  getCssVar('--accent-purple') || (isDark ? '#8878a8' : '#7773ad'),
      ember:  getCssVar('--accent-red')    || (isDark ? '#a86070' : '#c36672'),
      amber:  getCssVar('--accent-yellow') || (isDark ? '#9c8a62' : '#a68753'),
      dim:    getCssVar('--text-muted')    || (isDark ? '#4e5c68' : '#8b949e'),
    }
  }

  function palette(): string[] {
    const c = colors()
    return [c.cyan, c.teal, c.mint, c.slate, c.indigo, c.mauve, c.amber, c.dim]
  }

  function tooltipStyle() {
    const isDark = theme.value === 'dark'
    return {
      backgroundColor: isDark ? 'rgba(10,16,22,0.94)' : 'rgba(255,255,255,0.96)',
      borderColor: isDark ? 'rgba(88,184,201,0.18)' : 'rgba(0,0,0,0.08)',
      textStyle: {
        color: isDark ? '#9ab4c0' : '#333',
        fontSize: 12,
      },
    }
  }

  function textColor(): string {
    return getCssVar('--text-secondary') || '#8b949e'
  }

  function mutedTextColor(): string {
    return getCssVar('--text-muted') || '#484f58'
  }

  function bgBase(): string {
    return getCssVar('--bg-base') || '#0d1117'
  }

  return { theme, revision, colors, palette, tooltipStyle, textColor, mutedTextColor, bgBase }
}
