<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import { detailToSetErrors, setNameError, setSpec, validateSet, type SetErrors } from '@/lib/firewall'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import type { AddressSet } from '@jailops/shared/api/types'

// Create an address set: a name and its members (addresses, CIDRs, and @name for a jail or another set). The checks are the server's (lib/firewall.ts);
// a refusal still lands on its field.
const props = defineProps<{ open: boolean; sets: AddressSet[] }>()
const emit = defineEmits<{ close: []; created: [name: string] }>()

const f = reactive({ name: '', comment: '', members: '' })
const busy = ref(false)
const error = ref<ApiError | null>(null)
const server = ref<SetErrors>({})
const others = computed(() => Object.fromEntries(props.sets.map((x) => [x.metadata.name, x.spec])))
const local = computed(() => validateSet(f.name, setSpec(f.members, f.comment), others.value, s.firewall))
const check = useFormCheck(() => ({
  'fws-name': setNameError(f.name, props.sets.map((x) => x.metadata.name), s.firewall),
  'fws-members': local.value.addresses ?? '',
}))
const labels: Record<string, string> = { 'fws-name': s.firewall.name, 'fws-members': s.firewall.addresses }
const fieldOf = { 'fws-name': 'name', 'fws-members': 'addresses' } as const
/** The message under a field: the local check, else what the server said about it. */
const err = (id: keyof typeof fieldOf) => check.err(id) || server.value[fieldOf[id]] || ''
function edited(id: keyof typeof fieldOf): void {
  check.touch(id)
  if (server.value[fieldOf[id]]) server.value = { ...server.value, [fieldOf[id]]: undefined }
}

watch(() => props.open, (o) => {
  if (!o) return
  Object.assign(f, { name: '', members: '' })
  error.value = null
  server.value = {}
  check.reset()
}, { immediate: true })

const create = () => check.submit(async () => {
  if (busy.value) return
  busy.value = true
  error.value = null
  server.value = {}
  const name = f.name
  try {
    await runOp(s.firewall.createSetOp(name), () => api.firewall.createAddressSet({ metadata: { name }, spec: setSpec(f.members, f.comment) }))
    emit('created', name)
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
    server.value = detailToSetErrors(error.value)
    const first = Object.entries(fieldOf).find(([, k]) => server.value[k])?.[0]
    if (first) document.getElementById(first)?.focus()
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal :open="open" :title="s.firewall.createSetTitle" @close="emit('close')">
    <form id="fws" novalidate data-test="set-create-form" @submit.prevent="create">
      <div class="field"><label for="fws-name">{{ s.firewall.name }} <span class="req" aria-hidden="true">*</span></label>
        <input id="fws-name" v-model="f.name" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!err('fws-name')" aria-describedby="fws-name-h fws-name-e" @input="edited('fws-name')" />
        <span id="fws-name-h" class="hint">{{ s.firewall.setNameHint }}</span>
        <span id="fws-name-e" class="field-error" role="alert">{{ err('fws-name') }}</span></div>
      <div class="field"><label for="fws-comment">{{ s.firewall.comment }}</label>
        <input id="fws-comment" v-model="f.comment" type="text" maxlength="200" autocomplete="off" :placeholder="s.firewall.setCommentHint" /></div>
      <div class="field"><label for="fws-members">{{ s.firewall.addresses }}</label>
        <textarea id="fws-members" v-model="f.members" class="mono" rows="6" spellcheck="false" :aria-invalid="!!err('fws-members')" aria-describedby="fws-members-h fws-members-e" @input="edited('fws-members')"></textarea>
        <span id="fws-members-h" class="hint">{{ s.firewall.membersHint }}</span>
        <span id="fws-members-e" class="field-error" role="alert">{{ err('fws-members') }}</span></div>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <template #footer>
      <span v-if="check.reason.value" class="why-disabled" data-test="set-create-why">{{ labels[check.firstId.value] }}: {{ check.reason.value }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="fws" :disabled="busy" :aria-disabled="!check.ok.value" data-test="set-create-go">{{ s.firewall.createSetGo }}</button>
    </template>
  </Modal>
</template>
