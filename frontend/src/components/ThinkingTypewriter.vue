<!-- ThinkingTypewriter – 逐字揭示 LLM 思考文本 + 闪烁光标 -->
<template>
  <pre class="typewriter-text" ref="textRef">{{ displayedText }}<span v-if="!done" class="cursor">▋</span></pre>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps({
  text: { type: String, default: '' },
  speed: { type: Number, default: 45 },
})

const displayedLength = ref(0)
const textRef = ref<HTMLElement | null>(null)
let rafId = 0
let lastTick = 0
let charsPerFrame = 1

const displayedText = computed(() => {
  return props.text.slice(0, displayedLength.value)
})

const done = computed(() => {
  return displayedLength.value >= props.text.length
})

function tick(now: number) {
  if (!lastTick) lastTick = now
  const elapsed = now - lastTick
  const charsToAdd = Math.floor((elapsed / 1000) * props.speed)
  if (charsToAdd > 0) {
    lastTick = now
    displayedLength.value = Math.min(displayedLength.value + charsToAdd, props.text.length)
  }
  if (displayedLength.value < props.text.length) {
    rafId = requestAnimationFrame(tick)
  }
}

function start() {
  if (displayedLength.value >= props.text.length) return
  lastTick = 0
  rafId = requestAnimationFrame(tick)
}

function reset(newText: string) {
  cancelAnimationFrame(rafId)
  displayedLength.value = 0
  lastTick = 0
  if (newText) {
    rafId = requestAnimationFrame(tick)
  }
}

watch(() => props.text, (newText) => {
  if (newText.length > displayedLength.value) {
    if (!rafId) start()
  }
}, { immediate: false })

onMounted(() => {
  if (props.text) start()
})

onBeforeUnmount(() => {
  cancelAnimationFrame(rafId)
})
</script>

<style scoped>
.typewriter-text {
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 260px;
  overflow-y: auto;
  margin: 0;
  line-height: 1.65;
  padding: 8px 0;
}

.cursor {
  display: inline;
  color: var(--accent-blue);
  animation: cursor-blink 1s step-end infinite;
}

@keyframes cursor-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0; }
}

@media (prefers-reduced-motion: reduce) {
  .cursor {
    animation: none;
    opacity: 1;
  }
}
</style>
