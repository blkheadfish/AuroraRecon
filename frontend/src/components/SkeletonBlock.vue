<template>
  <div class="skeleton-block" :style="{ gap: `${gap}px` }">
    <div
      v-for="i in rows"
      :key="i"
      class="skeleton-row"
      :style="{ height: `${height}px`, width: rowWidth(i) }"
    />
  </div>
</template>

<script setup>
const props = defineProps({
  rows: { type: Number, default: 5 },
  height: { type: Number, default: 18 },
  gap: { type: Number, default: 12 },
  varyWidth: { type: Boolean, default: true },
})

const WIDTHS = ['92%', '78%', '86%', '70%', '95%', '64%', '82%']

function rowWidth(i) {
  if (!props.varyWidth) return '100%'
  return WIDTHS[(i - 1) % WIDTHS.length]
}
</script>

<style scoped>
.skeleton-block {
  display: flex;
  flex-direction: column;
  width: 100%;
  padding: 8px 4px;
}

.skeleton-row {
  border-radius: var(--radius-md);
  background: linear-gradient(
    90deg,
    color-mix(in srgb, var(--bg-hover) 70%, var(--bg-elevated)) 0%,
    color-mix(in srgb, var(--bg-hover) 40%, var(--bg-surface)) 50%,
    color-mix(in srgb, var(--bg-hover) 70%, var(--bg-elevated)) 100%
  );
  background-size: 220% 100%;
  animation: shimmer 1.4s ease-in-out infinite;
}

@keyframes shimmer {
  0%   { background-position: 220% 0; opacity: 0.85; }
  50%  { background-position: 0% 0;   opacity: 1;    }
  100% { background-position: -220% 0; opacity: 0.85; }
}
</style>
