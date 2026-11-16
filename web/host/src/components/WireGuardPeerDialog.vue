<script setup lang="ts">
// Enrolls a peer and shows its token once. The token and the configuration live in this component only while the
// dialog is open; closing it drops them, and nothing is written to storage.
import { computed, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import CopyField from '@jailops/shared/components/CopyField.vue'
import { confFileName, splitList } from '@/lib/wireguard'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint } from '@jailops/shared/lib/names'
import { nameError as nameRuleError } from '@/lib/nameField'
import type { WireGuardPeerCreated } from '@jailops/shared/api/types'

const props = defineProps<{ open: boolean; server: string }>()
const emit = defineEmits<{ close: []; done: [] }>()
const name = ref('')
const address = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)
const created = ref<WireGuardPeerCreated | null>(null)
// a peer name follows the object rule of the server (shared lib/names.ts)
const check = useFormCheck(() => ({ 'wgp-name': nameRuleError(name.value) }))
const nameError = computed(() => check.err('wgp-name') || (name.value ? nameRuleError(name.value) : ''))

function reset(): void {
  name.value = ''
  address.value = ''
  check.reset()
  error.value = null
  created.value = null
}
watch(() => props.open, reset)

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    const r = await api.wireguard.addPeer(props.server, { name: name.value, ...(splitList(address.value).length ? { address: splitList(address.value) } : {}) })
    if (r.kind === 'sync') created.value = r.data
    emit('done')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})

function download(): void {
  if (!created.value) return
  const url = URL.createObjectURL(new Blob([created.value.config], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = confFileName(created.value.peer.name)
  a.click()
  URL.revokeObjectURL(url)
}

function close(): void {
  reset()
  emit('close')
}
</script>

<template>
  <Modal :open="open" :title="created ? s.wireguard.tokenTitle(created.peer.name) : s.wireguard.addPeerTitle(server)" wide @close="created ? () => {} : close()">
    <template v-if="created">
      <Callout tone="warn" data-test="wg-token-warning"><strong>{{ s.wireguard.tokenShownOnce }}</strong> {{ created.warning }}</Callout>
      <div class="field" style="margin-top: 12px"><span class="label">{{ s.wireguard.token }}</span><CopyField :value="created.token" :label="s.wireguard.token" /></div>
      <div class="field"><span class="label">{{ s.wireguard.joinCommand }}</span><CopyField :value="s.wireguard.tokenUse(created.token)" label="join-command" /></div>
      <p class="mono faint">{{ s.wireguard.peerAddress }}: {{ created.peer.allowed_ips.join(', ') }}</p>
      <div class="row"><button class="btn" type="button" data-test="wg-download" @click="download">{{ s.wireguard.downloadConf }}</button><span class="hint">{{ s.wireguard.confHint }}</span></div>
    </template>
    <form v-else id="wgp" novalidate @submit.prevent="save">
      <div class="field">
        <label for="wgp-name">{{ s.wireguard.peerName }} <span class="req" aria-hidden="true">*</span></label>
        <input id="wgp-name" v-model="name" class="mono" type="text" autocomplete="off" required :aria-invalid="!!nameError" aria-describedby="wgp-name-h wgp-name-e" @input="check.touch('wgp-name')" />
        <span id="wgp-name-h" class="hint">{{ nameHint() }}</span>
        <span id="wgp-name-e" class="field-error" role="alert">{{ nameError }}</span>
      </div>
      <div class="field">
        <label for="wgp-addr">{{ s.wireguard.peerAddress }}</label>
        <input id="wgp-addr" v-model="address" class="mono" type="text" autocomplete="off" aria-describedby="wgp-addr-h" />
        <span id="wgp-addr-h" class="hint">{{ s.wireguard.peerAddressHint }}</span>
      </div>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
    </form>
    <template #footer>
      <button v-if="created" class="btn btn-primary" type="button" data-test="wg-token-done" @click="close">{{ s.wireguard.done }}</button>
      <template v-else>
        <span v-if="check.reason.value" class="why-disabled">{{ s.wireguard.fixFirst(s.wireguard.peerName, check.reason.value) }}</span>
        <button class="btn" type="button" @click="close">{{ s.app.cancel }}</button>
        <button class="btn btn-primary" type="submit" form="wgp" :disabled="busy" :aria-disabled="!check.ok.value" data-test="wg-peer-go">{{ s.wireguard.addPeerGo }}</button>
      </template>
    </template>
  </Modal>
</template>
