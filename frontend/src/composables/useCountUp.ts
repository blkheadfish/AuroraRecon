import { onBeforeUnmount, ref, watch } from 'vue'

export function useCountUp(
  targetRef: () => number,
  options: { duration?: number; easing?: (t: number) => number } = {},
) {
  const { duration = 600, easing = easeOutCubic } = options
  const display = ref(0)
  let startVal = 0
  let startTs = 0
  let rafId = 0
  let animating = false

  function easeOutCubic(t: number): number {
    return 1 - Math.pow(1 - t, 3)
  }

  function tick(now: number) {
    if (!startTs) startTs = now
    const elapsed = now - startTs
    const progress = Math.min(elapsed / duration, 1)
    const eased = easing(progress)
    const target = targetRef()
    display.value = Math.round(startVal + (target - startVal) * eased)

    if (progress < 1) {
      rafId = requestAnimationFrame(tick)
    } else {
      display.value = target
      animating = false
    }
  }

  function start(target: number) {
    if (animating) cancelAnimationFrame(rafId)
    startVal = display.value
    startTs = 0
    animating = true
    rafId = requestAnimationFrame(tick)
  }

  watch(
    targetRef,
    (newVal) => {
      if (newVal !== display.value) {
        start(newVal)
      }
    },
    { immediate: false },
  )

  onBeforeUnmount(() => {
    cancelAnimationFrame(rafId)
  })

  return { display, start }
}
