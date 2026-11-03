<script setup lang="ts">
import { Button, Modal } from 'ant-design-vue'
defineProps<{ title: string }>()
const emit = defineEmits<{ close: [] }>()
</script>

<template>
  <Modal :open="true" :title="title" :width="820" :mask-closable="false" :destroy-on-close="true" wrap-class-name="monitoring-dialog" @cancel="emit('close')">
    <slot />
    <template #footer>
      <Button @click="emit('close')">关闭</Button>
    </template>
  </Modal>
</template>
