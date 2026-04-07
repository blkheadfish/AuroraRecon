<template>
  <div class="editor-wrap">
    <textarea
      class="editor"
      :value="modelValue"
      @input="$emit('update:modelValue', $event.target.value)"
      placeholder="在这里编辑 Markdown 报告..."
    />
  </div>
</template>

<script setup>
defineProps({
  modelValue: { type: String, default: '' },
})
defineEmits(['update:modelValue'])
</script>

<style scoped>
.editor-wrap { border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-base); min-height: 540px; }
.editor { width: 100%; min-height: 540px; border: none; resize: vertical; padding: 14px; background: transparent; color: var(--text-primary); font-size: 13px; line-height: 1.7; font-family: var(--font-mono); outline: none; }
</style>
