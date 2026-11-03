import { computed, onMounted, onUnmounted, ref, shallowRef } from 'vue'
import { api, ApiError, errorText, isAborted } from '../lib/api'
import { buildPayload, makeDraft, validateDraft } from '../lib/settings'
import type { Draft, Settings } from '../types'
export function useSettingsDraft() {
  const settings = shallowRef<Settings | null>(null),
    draft = ref<Draft | null>(null),
    initial = shallowRef('')
  const loading = shallowRef(false),
    saving = shallowRef(false),
    error = shallowRef(''),
    success = shallowRef(''),
    conflict = shallowRef(false),
    validation = shallowRef<string[]>([])
  const controller = new AbortController()
  const dirty = computed(
    () => !!draft.value && JSON.stringify(draft.value) !== initial.value,
  )
  const writable = computed(
    () =>
      !!draft.value &&
      ['hourly', 'daily'].includes(draft.value.schedule.mode) &&
      draft.value.schedule.editable !== false,
  )
  function accept(value: Settings) {
    settings.value = value
    draft.value = makeDraft(value)
    initial.value = JSON.stringify(draft.value)
  }
  async function reload() {
    if (loading.value || saving.value) return
    if (
      dirty.value &&
      !window.confirm('重新读取会放弃尚未保存的修改，是否继续？')
    )
      return
    loading.value = true
    error.value = ''
    success.value = ''
    validation.value = []
    try {
      accept(
        await api<Settings>('/api/settings', { signal: controller.signal }),
      )
      conflict.value = false
    } catch (cause) {
      if (!isAborted(cause)) error.value = errorText(cause)
    } finally {
      loading.value = false
    }
  }
  async function save() {
    if (
      !draft.value ||
      !settings.value ||
      saving.value ||
      loading.value ||
      !writable.value ||
      conflict.value
    )
      return
    validation.value = validateDraft(draft.value, settings.value)
    error.value = ''
    success.value = ''
    if (validation.value.length) return
    saving.value = true
    try {
      accept(
        await api<Settings>('/api/settings', {
          method: 'PUT',
          body: buildPayload(draft.value, settings.value.revision),
          signal: controller.signal,
        }),
      )
      success.value = '配置已保存并生效。'
      conflict.value = false
    } catch (cause) {
      if (!isAborted(cause)) {
        error.value = errorText(cause)
        conflict.value = cause instanceof ApiError && cause.status === 409
      }
    } finally {
      saving.value = false
    }
  }
  function reset() {
    if (
      settings.value &&
      (!dirty.value || window.confirm('放弃尚未保存的修改？'))
    ) {
      accept(settings.value)
      validation.value = []
      success.value = ''
    }
  }
  onMounted(reload)
  onUnmounted(() => {
    controller.abort()
    if (draft.value) {
      draft.value.secret_id = ''
      draft.value.secret_key = ''
    }
  })
  return {
    settings,
    draft,
    loading,
    saving,
    error,
    success,
    conflict,
    validation,
    dirty,
    writable,
    reload,
    save,
    reset,
  }
}
