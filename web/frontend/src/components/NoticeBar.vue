<script setup lang="ts">
import { Alert as AAlert } from 'ant-design-vue'
withDefaults(
  defineProps<{ type?: 'info' | 'error' | 'success' | 'warning' }>(),
  { type: 'info' },
)
</script>
<template>
  <AAlert
    :class="['notice', `notice-${type}`]"
    :type="type"
    show-icon
    :role="type === 'error' ? 'alert' : 'status'"
  >
    <template #message><slot /></template>
  </AAlert>
</template>
