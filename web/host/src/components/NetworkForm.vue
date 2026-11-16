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
import Callout from '@jailops/shared/components/Callout.vue'
import { blankNet, checkNet, formOf, netBody, suggestV4 } from '@/lib/netform'
import type { Network } from '@jailops/shared/api/types'

// Creates a network, or with `network` edits one (the name stays; PUT with the generation read).
const props = defineProps<{ open: boolean; network?: Network | null; etag?: string }>()
const emit = defineEmits<{ close: []; done: [] }>()
const f = reactive(blankNet())
const busy = ref(false)
// what the server said about the host after a save (forwarding off, a sysctl the proxy needs): the network is
// stored, and the form stays open on these until it is closed
const warnings = ref<string[]>([])
const error = ref<ApiError | null>(null)
const editing = computed(() => !!props.network)
const touched = reactive<Record<string, boolean>>({})
// field id -> problem: the plain mistakes of checkNet, then what is required and still empty
const ids: Record<string, string> = { name: 'nf-name', uplink: 'nf-up', v4subnet: 'nf-v4s', v4gateway: 'nf-v4g', v4range: 'nf-v4r', v6subnet: 'nf-v6s', v6range: 'nf-v6r', family: 'nf-v4' }
const check = useFormCheck(() => {
  const p = checkNet(f, editing.value)
  const need: Record<string, boolean> = {
    name: !f.name, v4subnet: f.v4 && !f.v4subnet, v4gateway: f.v4 && !f.v4gateway, v4range: f.v4 && !f.v4range,
    v6subnet: f.mode !== 'none' && !f.v6subnet, v6range: f.mode !== 'none' && !f.v6range,
  }
  const out: Record<string, string> = {}
  for (const k of Object.keys(ids)) out[ids[k]] = p[k] || (need[k] ? s.networks.required : '')
  return out
})
const msg = (k: string) => check.err(ids[k])
const labels: Record<string, string> = { 'nf-name': s.networks.name, 'nf-up': s.networks.uplink, 'nf-v4s': `${s.networks.ipv4} ${s.networks.subnet}`, 'nf-v4g': `${s.networks.ipv4} ${s.networks.gateway}`, 'nf-v4r': `${s.networks.ipv4} ${s.networks.range}`, 'nf-v6s': `${s.networks.ipv6} ${s.networks.subnet}`, 'nf-v6r': `${s.networks.ipv6} ${s.networks.range}`, 'nf-v4': s.networks.ipv4 }

watch(() => props.open, (o) => {
  if (!o) return
  Object.assign(f, props.network ? formOf(props.network) : blankNet())
  Object.keys(touched).forEach((k) => delete touched[k])
  check.reset()
  error.value = null
  warnings.value = []
})
// A typed subnet fills the gateway and range once, until the user has written their own.
watch(() => f.v4subnet, (v) => {
  const sug = suggestV4(v)
  if (sug && !editing.value && !touched.v4gateway && !touched.v4range) Object.assign(f, { v4gateway: sug.gateway, v4range: sug.range })
})

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  try {
    const r = props.network
      ? await runOp(s.networks.editTitle(f.name), () => api.networks.put(netBody(f, props.network!), props.etag))
      : await runOp(s.networks.createTitle + ': ' + f.name, () => api.networks.create(netBody(f)))
    emit('done')
    const w = (r.data as Network | undefined)?.status?.warnings ?? []
    if (w.length) warnings.value = w
    else emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal :open="open" :title="editing ? s.networks.editTitle(f.name) : s.networks.createTitle" wide @close="emit('close')">
    <div v-if="warnings.length" data-test="nf-warnings">
      <p>{{ editing ? s.networks.savedWarn : s.networks.createdWarn }}</p>
      <Callout v-for="x in warnings" :key="x" tone="warn">{{ x }}</Callout>
    </div>
    <form v-else id="nf" novalidate @submit.prevent="save">
      <div class="form-2">
        <div class="field">
          <label for="nf-name">{{ s.networks.name }} <span class="req" aria-hidden="true">*</span></label>
          <input id="nf-name" v-model="f.name" class="mono" type="text" autocomplete="off" required :readonly="editing" :aria-invalid="!!msg('name')" aria-describedby="nf-name-h nf-name-e" @input="check.touch('nf-name')" />
          <span id="nf-name-h" class="hint">{{ editing ? s.networks.nameFixed : nameHint('network') }}</span>
          <span id="nf-name-e" class="field-error" role="alert">{{ msg('name') }}</span>
        </div>
        <div class="field">
          <label for="nf-up">{{ s.networks.uplink }}</label>
          <input id="nf-up" v-model="f.uplink" class="mono" type="text" placeholder="em0" autocomplete="off" :aria-invalid="!!msg('uplink')" aria-describedby="nf-up-e nf-up-h" @blur="check.touch('nf-up')" />
          <span id="nf-up-h" class="hint">{{ s.networks.uplinkHint }}</span>
          <span id="nf-up-e" class="field-error" role="alert">{{ msg('uplink') }}</span>
        </div>
      </div>
      <p v-if="msg('family')" class="field-error" role="alert">{{ msg('family') }}</p>

      <fieldset class="nf-set">
        <legend><label class="check"><input id="nf-v4" v-model="f.v4" type="checkbox" data-test="nf-v4" />{{ s.networks.ipv4 }}</label></legend>
        <template v-if="f.v4">
          <div class="field">
            <label for="nf-v4s">{{ s.networks.subnet }} <span class="req" aria-hidden="true">*</span></label>
            <input id="nf-v4s" v-model="f.v4subnet" class="mono" type="text" placeholder="10.20.0.0/24" autocomplete="off" :aria-invalid="!!msg('v4subnet')" aria-describedby="nf-v4s-e" @blur="check.touch('nf-v4s')" />
            <span id="nf-v4s-e" class="field-error" role="alert">{{ msg('v4subnet') }}</span>
          </div>
          <div class="form-2">
            <div class="field">
              <label for="nf-v4g">{{ s.networks.gateway }} <span class="req" aria-hidden="true">*</span></label>
              <input id="nf-v4g" v-model="f.v4gateway" class="mono" type="text" placeholder="10.20.0.1" autocomplete="off" :aria-invalid="!!msg('v4gateway')" aria-describedby="nf-v4g-e" @input="touched.v4gateway = true" @blur="check.touch('nf-v4g')" />
              <span id="nf-v4g-e" class="field-error" role="alert">{{ msg('v4gateway') }}</span>
            </div>
            <div class="field">
              <label for="nf-v4r">{{ s.networks.range }} <span class="req" aria-hidden="true">*</span></label>
              <input id="nf-v4r" v-model="f.v4range" class="mono" type="text" placeholder="10.20.0.10-10.20.0.200" autocomplete="off" :aria-invalid="!!msg('v4range')" aria-describedby="nf-v4r-e" @input="touched.v4range = true" @blur="check.touch('nf-v4r')" />
              <span id="nf-v4r-e" class="field-error" role="alert">{{ msg('v4range') }}</span>
            </div>
          </div>
          <label class="check"><input v-model="f.nat" type="checkbox" />{{ s.networks.natHint }}</label>
        </template>
      </fieldset>

      <fieldset class="nf-set">
        <legend>{{ s.networks.ipv6 }}</legend>
        <div class="field">
          <label for="nf-mode">{{ s.networks.mode }}</label>
          <select id="nf-mode" v-model="f.mode" data-test="nf-mode">
            <option value="none">{{ s.networks.modeNone }}</option>
            <option value="routed">{{ s.networks.modeRouted }}</option>
            <option value="proxy">{{ s.networks.modeProxy }}</option>
          </select>
        </div>
        <Callout v-if="f.mode === 'routed'" tone="info" data-test="mode-help">{{ s.networks.routedHelp }}</Callout>
        <Callout v-if="f.mode === 'proxy'" tone="warn" data-test="mode-help">{{ s.networks.proxyHelp }}<br />{{ s.networks.pfNote }}</Callout>
        <template v-if="f.mode !== 'none'">
          <div class="field">
            <label for="nf-v6s">{{ s.networks.subnet }} <span class="req" aria-hidden="true">*</span></label>
            <input id="nf-v6s" v-model="f.v6subnet" class="mono" type="text" placeholder="2001:db8:20:1::/64" autocomplete="off" :aria-invalid="!!msg('v6subnet')" aria-describedby="nf-v6s-e" @blur="check.touch('nf-v6s')" />
            <span id="nf-v6s-e" class="field-error" role="alert">{{ msg('v6subnet') }}</span>
          </div>
          <div class="field">
            <label for="nf-v6r">{{ s.networks.range }} <span class="req" aria-hidden="true">*</span></label>
            <input id="nf-v6r" v-model="f.v6range" class="mono" type="text" placeholder="2001:db8:20:1::100-2001:db8:20:1::1ff" autocomplete="off" :aria-invalid="!!msg('v6range')" aria-describedby="nf-v6r-e" @blur="check.touch('nf-v6r')" />
            <span id="nf-v6r-e" class="field-error" role="alert">{{ msg('v6range') }}</span>
          </div>
        </template>
      </fieldset>
      <p class="hint">{{ s.networks.serverChecks }}</p>
      <ErrorPanel v-if="error" :error="error" />
    </form>
    <template v-if="warnings.length" #footer>
      <button class="btn btn-primary" type="button" data-test="nf-warn-close" @click="emit('close')">{{ s.app.close }}</button>
    </template>
    <template v-else #footer>
      <span v-if="check.reason.value" class="why-disabled" data-test="nf-why">{{ s.networks.fixFirst(labels[check.firstId.value] ?? '', check.reason.value) }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="nf" :disabled="busy" :aria-disabled="!check.ok.value" data-test="net-create-go">{{ editing ? s.networks.save : s.networks.create }}</button>
    </template>
  </Modal>
</template>

<style>
.nf-set { border: 1px solid var(--border); border-radius: var(--radius); margin: 12px 0; padding: 8px 12px 12px; }
.nf-set legend { padding: 0 6px; font-weight: 600; }
</style>
