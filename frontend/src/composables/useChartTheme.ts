import { ref, watchEffect, watch } from 'vue'
import { useTheme } from '@/composables/useTheme'

function getCssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

const revision = ref(0)

// 缓存 getComputedStyle 结果，避免每次 computed 重算都触发强制回流
let _colorsCache: ChartColors | null = null
let _cacheRevision = -1

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
    if (_colorsCache && _cacheRevision === revision.value) return _colorsCache

    _cacheRevision = revision.value
    const isDark = theme.value === 'dark'
    _colorsCache = {
      cyan:   getCssVar('--accent-blue')   || (isDark ? '#58b8e0' : '#3d8fd4'),
      teal:   getCssVar('--accent-green')  || (isDark ? '#4ec9b0' : '#2d9d76'),
      mint:   getCssVar('--accent-green')  || (isDark ? '#56c9a4' : '#2d9d76'),
      slate:  getCssVar('--text-secondary')|| (isDark ? '#9198a9' : '#656d76'),
      indigo: getCssVar('--accent-purple') || (isDark ? '#7b8fd4' : '#7e78ba'),
      mauve:  getCssVar('--accent-purple') || (isDark ? '#aea0d6' : '#7e78ba'),
      ember:  getCssVar('--accent-red')    || (isDark ? '#e06979' : '#cf5a6a'),
      amber:  getCssVar('--accent-yellow') || (isDark ? '#d9a84e' : '#b89244'),
      dim:    getCssVar('--text-muted')    || (isDark ? '#6e7681' : '#8b949e'),
    }
    return _colorsCache
  }

  function palette(): string[] {
    const c = colors()
    return [c.cyan, c.teal, c.mint, c.slate, c.indigo, c.mauve, c.amber, c.dim]
  }

  function tooltipStyle() {
    const isDark = theme.value === 'dark'
    return {
      backgroundColor: isDark ? 'rgba(13,17,23,0.96)' : 'rgba(255,255,255,0.96)',
      borderColor: isDark ? 'rgba(88,184,224,0.22)' : 'rgba(0,0,0,0.10)',
      textStyle: {
        color: isDark ? '#c9d1d9' : '#24292f',
        fontSize: 12,
      },
      extraCssText: 'border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.25);padding:10px 14px;',
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
