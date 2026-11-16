<script setup lang="ts">
// Makes a client tunnel from a token. The token is only in this form while it is open and is cleared on close.
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import { looksLikeToken } from '@/lib/wireguard'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint } from '@jailops/shared/lib/names'
import { nameError as nameRuleError } from '@/lib/nameField'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: []; done: [] }>()
const token = ref('')
const name = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)
const tokenProblem = computed(() => (!token.value.trim() ? s.wireguard.required : !looksLikeToken(token.value) ? s.wireguard.tokenInvalid : ''))
// the name is optional; given, it names the interface wg-<name> (rule tunnel)
const check = useFormCheck(() => ({ 'wgj-token': tokenProblem.value, 'wgj-name': name.value.trim() ? nameRuleError(name.value.trim(), 'tunnel') : '' }))
const tokenError = computed(() => check.err('wgj-token') || (token.value.trim() ? tokenProblem.value : ''))
const nameError = computed(() => (name.value.trim() ? nameRuleError(name.value.trim(), 'tunnel') : ''))

function reset(): void {
  token.value = ''
  name.value = ''
  check.reset()
  error.value = null
}
watch(() => props.open, reset)

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    await runOp(s.wireguard.joinTitle, () => api.wireguard.join({ token: token.value.trim(), ...(name.value.trim() ? { name: name.value.trim() } : {}) }))
    emit('done')
    close()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
function close(): void {
  reset()
  emit('close')
}
</script>

<template>
  <Modal :open="open" :title="s.wireguard.joinTitle" wide @close="close">
    <form id="wgj" novalidate @submit.prevent="save">
      <div class="field">
        <label for="wgj-token">{{ s.wireguard.token }} <span class="req" aria-hidden="true">*</span></label>
        <textarea id="wgj-token" v-model="token" class="mono" rows="4" autocomplete="off" spellcheck="false" required :aria-invalid="!!tokenError" aria-describedby="wgj-token-h wgj-token-e"></textarea>
        <span id="wgj-token-h" class="hint">{{ s.wireguard.tokenHint }}</span>
        <span id="wgj-token-e" class="field-error" role="alert">{{ tokenError }}</span>
      </div>
      <div class="field">
        <label for="wgj-name">{{ s.wireguard.joinName }}</label>
        <input id="wgj-name" v-model="name" class="mono" type="text" autocomplete="off" :aria-invalid="!!nameError" aria-describedby="wgj-name-h wgj-name-e" />
        <span id="wgj-name-h" class="hint">{{ s.wireguard.joinNameHint }} {{ nameHint('tunnel') }}</span>
        <span id="wgj-name-e" class="field-error" role="alert">{{ nameError }}</span>
      </div>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
    </form>
    <template #footer>
      <span v-if="check.reason.value" class="why-disabled">{{ s.wireguard.fixFirst(check.firstId.value === 'wgj-name' ? s.wireguard.joinName : s.wireguard.token, check.reason.value) }}</span>
      <button class="btn" type="button" @click="close">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="wgj" :disabled="busy" :aria-disabled="!check.ok.value" data-test="wg-join-go">{{ s.wireguard.joinGo }}</button>
    </template>
  </Modal>
</template>
