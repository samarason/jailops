<script setup lang="ts">
import { ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import Modal from '@jailops/shared/components/Modal.vue'
import Icon from '@jailops/shared/components/Icon.vue'

// The passphrase lives in this component's state only while the dialog is open: never in a store, the URL or
// browser storage, and never in an error text. One volume at a time.
const props = defineProps<{ open: boolean; volume: string }>()
const emit = defineEmits<{ close: []; done: [] }>()

const pass = ref('')
const show = ref(false)
const start = ref(false)
const busy = ref(false)
const error = ref('')
const hint = ref('')

function reset(): void {
  pass.value = ''
  show.value = false
  error.value = ''
  hint.value = ''
}
watch(() => props.open, (o) => {
  reset()
  if (o) start.value = false
})

function close(): void {
  reset()
  emit('close')
}

async function go(): Promise<void> {
  if (!pass.value || busy.value) return
  busy.value = true
  error.value = ''
  hint.value = ''
  const passphrase = pass.value
  pass.value = ''
  try {
    await runOp(s.keys.unlockTitle(props.volume), () => api.volumes.unlock(props.volume, { passphrase, ...(start.value ? { start: true } : {}) }))
    emit('done')
    close()
  } catch (e) {
    const code = e instanceof ApiError ? e.code : ''
    // the server's words, not the input: a message never repeats the passphrase
    error.value = code === 'bad_passphrase' ? s.keys.bad : code === 'rate_limited' ? s.keys.limited : e instanceof ApiError ? e.message : String(e)
    hint.value = code === 'rate_limited' && e instanceof ApiError ? e.hint : ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :open="open" :title="s.keys.unlockTitle(volume)" @close="close">
    <form id="unlock-form" autocomplete="off" data-test="unlock-form" @submit.prevent="go">
      <p class="muted">{{ s.keys.unlockLead }}</p>
      <div class="field">
        <label for="unlock-pass">{{ s.keys.passphrase }} <span class="req" aria-hidden="true">*</span></label>
        <div class="row pass-row">
          <input id="unlock-pass" v-model="pass" class="grow" :type="show ? 'text' : 'password'" autocomplete="off" spellcheck="false" autocapitalize="off" required data-test="unlock-pass" />
          <button class="btn btn-icon" type="button" :aria-label="show ? s.keys.hide : s.keys.show" :aria-pressed="show" data-test="unlock-show" @click="show = !show"><Icon :name="show ? 'eyeOff' : 'eye'" /></button>
        </div>
      </div>
      <label class="check"><input v-model="start" type="checkbox" data-test="unlock-start" /> {{ s.keys.startAfter }}</label>
      <p v-if="error" class="field-error" role="alert" data-test="unlock-error">{{ error }}<template v-if="hint"> {{ hint }}</template></p>
    </form>
    <template #footer>
      <span v-if="!pass && !error" class="why-disabled">{{ s.jails.passphraseNeeded }}</span>
      <button class="btn" type="button" @click="close">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="unlock-form" :disabled="busy || !pass" data-test="unlock-go"><Icon name="lockOpen" />{{ busy ? s.keys.unlocking : s.keys.unlock }}</button>
    </template>
  </Modal>
</template>

<style>
.pass-row { gap: 6px; flex-wrap: nowrap; }
.check { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
</style>
