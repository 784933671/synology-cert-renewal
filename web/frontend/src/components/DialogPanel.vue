<script setup lang="ts">
import { onMounted, useTemplateRef } from 'vue'
import AppIcon from './AppIcon.vue'
defineProps<{ title: string }>()
const emit = defineEmits<{ close: [] }>()
const dialog = useTemplateRef<HTMLDialogElement>('dialog')
onMounted(() => dialog.value?.showModal())
</script>
<template>
  <dialog
    ref="dialog"
    class="modal"
    aria-labelledby="dialog-title"
    @cancel.prevent="emit('close')"
  >
    <header class="panel-heading">
      <h2 id="dialog-title">{{ title }}</h2>
      <button
        class="icon-button"
        aria-label="关闭对话框"
        @click="emit('close')"
      >
        <AppIcon name="close" />
      </button>
    </header>
    <div class="panel-body"><slot /></div>
    <footer class="modal-footer">
      <button class="button" @click="emit('close')">关闭</button>
    </footer>
  </dialog>
</template>
