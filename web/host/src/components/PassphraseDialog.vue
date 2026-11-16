<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import Modal from '@jailops/shared/components/Modal.vue'

// Change the passphrase of an encrypted volume (admin). The fields are cleared on close and after a submit.
const props = defineProps<{ open: boolean; volume: string }>()
const emit = defineEmits<{ close: []; done: [] }>()

const f = reactive({ old: '', next: '', again: '' })
const busy = ref(false)
const error = ref('')

function reset(): void {
  Object.assign(f, { old: '', next: '', again: '' })
  error.value = ''
}
watch(() => props.open, reset)

const problem = computed(() => {
  if (f.next && f.next.length < 12) return s.keys.tooShort
  if (f.again && f.next !== f.again) return s.keys.mismatch
  if (f.next && f.next === f.old) return s.keys.sameAsOld
  return ''
})
/** What is still missing, said next to the button. */
const why = computed(() => (!f.old ? s.keys.needCurrent : !f.next ? s.keys.needNew : f.next.length < 12 ? s.keys.tooShort : f.next !== f.again ? (f.again ? s.keys.mismatch : s.keys.needRepeat) : f.next === f.old ? s.keys.sameAsOld : ''))
const ready = computed(() => !!f.old && f.next.length >= 12 && f.next === f.again && !problem.value)

function close(): void {
  reset()
  emit('close')
}

async function go(): Promise<void> {
  if (!ready.value || busy.value) return
  busy.value = true
  const body = { old_passphrase: f.old, new_passphrase: f.next }
  reset()
  try {
    await runOp(s.keys.changeTitle(props.volume), () => api.volumes.passphrase(props.volume, body))
    emit('done')
    close()
  } catch (e) {
    const code = e instanceof ApiError ? e.code : ''
    error.value = code === 'bad_passphrase' ? s.keys.bad : code === 'rate_limited' ? s.keys.limited : e instanceof ApiError ? e.message : String(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :open="open" :title="s.keys.changeTitle(volume)" @close="close">
    <form id="pass-form" autocomplete="off" @submit.prevent="go">
      <p class="muted">{{ s.keys.changeLead }}</p>
      <div class="field"><label for="pc-old">{{ s.keys.current }} <span class="req" aria-hidden="true">*</span></label><input id="pc-old" v-model="f.old" type="password" autocomplete="off" /></div>
      <div class="field"><label for="pc-new">{{ s.keys.newPass }} <span class="req" aria-hidden="true">*</span></label><input id="pc-new" v-model="f.next" type="password" autocomplete="new-password" aria-describedby="pc-new-hint" /><span id="pc-new-hint" class="hint">{{ s.volumes.passphraseHint }}</span></div>
      <div class="field"><label for="pc-again">{{ s.keys.repeat }} <span class="req" aria-hidden="true">*</span></label><input id="pc-again" v-model="f.again" type="password" autocomplete="new-password" /></div>
      <p v-if="problem || error" class="field-error" role="alert" data-test="pass-error">{{ error || problem }}</p>
    </form>
    <template #footer>
      <span v-if="why && !problem" class="why-disabled" data-test="pass-why">{{ why }}</span>
      <button class="btn" type="button" @click="close">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="pass-form" :disabled="busy || !ready" data-test="pass-go">{{ s.keys.change }}</button>
    </template>
  </Modal>
</template>
