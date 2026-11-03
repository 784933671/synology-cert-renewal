<script setup lang="ts">
withDefaults(
  defineProps<{ type?: 'info' | 'error' | 'success' | 'warning' }>(),
  { type: 'info' },
)
</script>
<template>
  <div
    :class="['notice', `notice-${type}`]"
    :role="type === 'error' ? 'alert' : 'status'"
  >
    <slot />
  </div>
</template>
