<script setup lang="ts">
import { computed, ref, useId, watch } from 'vue'
import { common as s } from '@jailops/shared/i18n/common'
import { ApiError } from '@jailops/shared/api/client'
import Modal from './Modal.vue'
import ErrorPanel from './ErrorPanel.vue'

// The one confirmation of the consoles, in two strengths (a safe action needs none, see composables/confirm.ts):
// a plain confirm that names what is affected, and with typeName a typed-name confirm for what cannot be undone.
const props = defineProps<{
  open: boolean
  title: string
  confirmLabel: string
  danger?: boolean
  run: () => Promise<unknown>
  /** One sentence on what happens. */
  text?: string
  /** What the action touches (the jails on an image, the dependants of a jail), with a heading. */
  items?: string[]
  itemsLabel?: string
  /** Tier 3: the user types this name before the button works. */
  typeName?: string
  typeLabel?: string
}>()
const emit = defineEmits<{ close: []; done: [] }>()
const busy = ref(false)
const error = ref<ApiError | null>(null)
const typed = ref('')
const tried = ref(false)
const uid = useId()
watch(() => props.open, (o) => {
  if (!o) return
  error.value = null
  typed.value = ''
  tried.value = false
})
const matches = computed(() => !props.typeName || typed.value.trim() === props.typeName)
const blocked = computed(() => (matches.value ? '' : s.confirm.typeToEnable(props.typeName ?? '', props.confirmLabel)))

async function go(): Promise<void> {
  tried.value = true
  if (!matches.value) {
    document.getElementById(`${uid}-type`)?.focus()
    return
  }
  busy.value = true
  error.value = null
  try {
    await props.run()
    emit('done')
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :open="open" :title="title" @close="emit('close')">
    <form :id="`${uid}-f`" class="stack confirm-body" data-test="confirm-dialog" :data-tier="typeName ? 3 : 2" @submit.prevent="go">
      <p v-if="text" class="confirm-text">{{ text }}</p>
      <slot />
      <div v-if="items?.length" data-test="confirm-items">
        <p class="label">{{ itemsLabel ?? s.confirm.affected }}</p>
        <ul class="confirm-items"><li v-for="i in items" :key="i" class="mono">{{ i }}</li></ul>
      </div>
      <div v-if="typeName" class="field">
        <label :for="`${uid}-type`">{{ typeLabel ?? s.confirm.typeLabel(typeName) }} <span class="req" aria-hidden="true">*</span></label>
        <input :id="`${uid}-type`" v-model="typed" class="mono" type="text" autocomplete="off" spellcheck="false" data-test="confirm-type" :aria-invalid="tried && !matches" :aria-describedby="tried && !matches ? `${uid}-err` : undefined" />
        <span v-if="tried && !matches" :id="`${uid}-err`" class="field-error" role="alert">{{ s.confirm.mismatch }}</span>
      </div>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <template #footer>
      <span v-if="blocked" class="why-disabled" data-test="confirm-why">{{ blocked }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn" :class="danger ? 'btn-danger' : 'btn-primary'" type="submit" :form="`${uid}-f`" :disabled="busy" :aria-disabled="!matches" data-test="confirm">{{ confirmLabel }}</button>
    </template>
  </Modal>
</template>

<style>
.confirm-body { gap: 10px; }
.confirm-body .field { margin-bottom: 0; }
.confirm-text { margin: 0; }
.confirm-items { margin: 4px 0 0; padding-left: 18px; max-height: 180px; overflow-y: auto; }
</style>
