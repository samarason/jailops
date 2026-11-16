<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint } from '@jailops/shared/lib/names'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import { blankServer, checkServer, serverBody } from '@/lib/wireguard'

const props = defineProps<{ open: boolean; networks: string[] }>()
const emit = defineEmits<{ close: []; done: [] }>()
const f = reactive(blankServer())
const busy = ref(false)
const error = ref<ApiError | null>(null)
const check = useFormCheck(() => {
  const p = checkServer(f)
  return { 'wgf-name': p.name || (!f.name ? s.wireguard.required : ''), 'wgf-port': p.port ?? '', 'wgf-addr': p.address || (!f.address ? s.wireguard.required : ''), 'wgf-ep': p.endpoint ?? '', 'wgf-dns': p.dns ?? '' }
})
const labels = computed<Record<string, string>>(() => ({ 'wgf-name': s.wireguard.name, 'wgf-port': s.wireguard.listenPort, 'wgf-addr': s.wireguard.address, 'wgf-ep': s.wireguard.endpoint, 'wgf-dns': s.wireguard.dns }))
// a mistake shows while typing; "Required." only after a try or once the field was left
const live = computed<Record<string, string | undefined>>(() => { const p = checkServer(f); return { 'wgf-name': p.name, 'wgf-port': p.port, 'wgf-addr': p.address, 'wgf-ep': p.endpoint, 'wgf-dns': p.dns } })
const msg = (id: string): string => check.err(id) || live.value[id] || ''

watch(() => props.open, (o) => {
  if (!o) return
  Object.assign(f, blankServer())
  check.reset()
  error.value = null
})

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    await runOp(s.wireguard.createTitle + ': ' + f.name, () => api.wireguard.create(serverBody(f)))
    emit('done')
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal :open="open" :title="s.wireguard.createTitle" wide @close="emit('close')">
    <form id="wgf" novalidate @submit.prevent="save">
      <div class="form-2">
        <div class="field">
          <label for="wgf-name">{{ s.wireguard.name }} <span class="req" aria-hidden="true">*</span></label>
          <input id="wgf-name" @input="check.touch('wgf-name')" v-model="f.name" class="mono" type="text" autocomplete="off" required :aria-invalid="!!msg('wgf-name')" aria-describedby="wgf-name-h wgf-name-e" />
          <span id="wgf-name-h" class="hint">{{ nameHint('tunnel') }}</span>
          <span id="wgf-name-e" class="field-error" role="alert">{{ msg('wgf-name') }}</span>
        </div>
        <div class="field">
          <label for="wgf-port">{{ s.wireguard.listenPort }} <span class="req" aria-hidden="true">*</span></label>
          <input id="wgf-port" @blur="check.touch('wgf-port')" v-model="f.port" class="mono" type="text" inputmode="numeric" autocomplete="off" :aria-invalid="!!msg('wgf-port')" aria-describedby="wgf-port-e" />
          <span id="wgf-port-e" class="field-error" role="alert">{{ msg('wgf-port') }}</span>
        </div>
      </div>
      <div class="field">
        <label for="wgf-addr">{{ s.wireguard.address }} <span class="req" aria-hidden="true">*</span></label>
        <input id="wgf-addr" @blur="check.touch('wgf-addr')" v-model="f.address" class="mono" type="text" placeholder="10.99.0.1/24" autocomplete="off" required :aria-invalid="!!msg('wgf-addr')" aria-describedby="wgf-addr-h wgf-addr-e" />
        <span id="wgf-addr-h" class="hint">{{ s.wireguard.addressHint }}</span>
        <span id="wgf-addr-e" class="field-error" role="alert">{{ msg('wgf-addr') }}</span>
      </div>
      <div class="field">
        <label for="wgf-ep">{{ s.wireguard.endpoint }}</label>
        <input id="wgf-ep" @blur="check.touch('wgf-ep')" v-model="f.endpoint" class="mono" type="text" placeholder="vpn.example.com:51820" autocomplete="off" :aria-invalid="!!msg('wgf-ep')" aria-describedby="wgf-ep-h wgf-ep-e" />
        <span id="wgf-ep-h" class="hint">{{ s.wireguard.endpointHint }}</span>
        <span id="wgf-ep-e" class="field-error" role="alert">{{ msg('wgf-ep') }}</span>
      </div>
      <fieldset v-if="networks.length" class="wgf-set">
        <legend>{{ s.wireguard.networks }}</legend>
        <label v-for="n in networks" :key="n" class="check mono"><input v-model="f.networks" type="checkbox" :value="n" :data-wg-net="n" />{{ n }}</label>
        <p class="hint">{{ s.wireguard.networksHint }}</p>
      </fieldset>
      <div class="field">
        <label for="wgf-dns">{{ s.wireguard.dns }}</label>
        <input id="wgf-dns" @blur="check.touch('wgf-dns')" v-model="f.dns" class="mono" type="text" autocomplete="off" :aria-invalid="!!msg('wgf-dns')" aria-describedby="wgf-dns-h wgf-dns-e" />
        <span id="wgf-dns-h" class="hint">{{ s.wireguard.dnsHint }}</span>
        <span id="wgf-dns-e" class="field-error" role="alert">{{ msg('wgf-dns') }}</span>
      </div>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
    </form>
    <template #footer>
      <span v-if="check.reason.value" class="why-disabled">{{ s.wireguard.fixFirst(labels[check.firstId.value] ?? '', check.reason.value) }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="wgf" :disabled="busy" :aria-disabled="!check.ok.value" data-test="wg-create-go">{{ s.wireguard.createGo }}</button>
    </template>
  </Modal>
</template>

<style scoped>
.wgf-set { border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 12px; margin: 0 0 12px; display: flex; flex-wrap: wrap; gap: 4px 16px; }
.wgf-set legend { padding: 0 4px; color: var(--text-2); }
.wgf-set .hint { flex-basis: 100%; margin: 4px 0 0; }
</style>
