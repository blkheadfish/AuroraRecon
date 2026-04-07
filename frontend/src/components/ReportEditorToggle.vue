<template>
  <el-button-group size="small">
    <el-button :type="modelValue === 'preview' ? 'primary' : ''" @click="$emit('update:modelValue', 'preview')">
      预览
    </el-button>
    <el-button :type="modelValue === 'edit' ? 'primary' : ''" @click="$emit('update:modelValue', 'edit')">
      编辑
    </el-button>
  </el-button-group>
</template>

<script setup>
defineProps({
  modelValue: { type: String, default: 'preview' },
})
defineEmits(['update:modelValue'])
</script>
