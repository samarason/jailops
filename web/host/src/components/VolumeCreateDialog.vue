<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint, nameProblem } from '@jailops/shared/lib/names'
import { pathProblem } from '@/lib/volumes'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import type { Storage } from '@jailops/shared/api/types'

// A new volume. The passphrase of an encrypted one is typed twice, sent once in the body of the creation and then
// forgotten: never in a store, the URL or browser storage.
const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: []; done: [name: string] }>()

const blank = () => ({ name: '', storage: '', size: '', uid: '0', gid: '0', mode: '', comment: '', encrypted: false, pass: '', again: '', hostDir: false, path: '', watch: false, probe: 'mounted', onLoss: 'none' })
const f = reactive(blank())
const storages = ref<Storage[]>([])
const busy = ref(false)
const error = ref<ApiError | null>(null)

const idOk = (v: string) => /^[0-9]{1,10}$/.test(v) && Number(v) <= 2147483647
const modeOk = (v: string) => v === '' || (/^[0-7]{1,4}$/.test(v) && parseInt(v, 8) <= 0o777)
const check = useFormCheck(() => ({
  'vc-name': nameProblem(f.name, 'volume'),
  'vc-path': !f.hostDir ? '' : !f.path ? s.volumes.pathInvalid : pathProblem(f.path),
  'vc-uid': f.hostDir || idOk(f.uid) ? '' : s.volumes.idInvalid,
  'vc-gid': f.hostDir || idOk(f.gid) ? '' : s.volumes.idInvalid,
  'vc-mode': f.hostDir || modeOk(f.mode) ? '' : s.volumes.modeInvalid,
  'vc-pass': !f.encrypted ? '' : !f.pass ? s.volumes.passphraseNeeded : f.pass.length < 12 ? s.keys.tooShort : '',
  'vc-pass2': !f.encrypted ? '' : !f.again ? s.volumes.repeatNeeded : f.pass !== f.again ? s.keys.mismatch : '',
}))
const labels: Record<string, string> = { 'vc-name': s.volumes.name, 'vc-path': s.volumes.path, 'vc-uid': s.volumes.uid, 'vc-gid': s.volumes.gid, 'vc-mode': s.volumes.mode, 'vc-pass': s.volumes.passphrase, 'vc-pass2': s.volumes.passphraseRepeat }
const why = computed(() => (check.firstId.value ? s.form.fixFirst(`${labels[check.firstId.value]}: ${check.reason.value}`) : ''))

watch(() => props.open, (o) => {
  Object.assign(f, blank())
  error.value = null
  check.reset()
  if (o) void api.storage.list().then((l) => { storages.value = l }).catch(() => { storages.value = [] })
})
watch(() => f.encrypted, (e) => { if (!e) Object.assign(f, { pass: '', again: '' }) })
watch(() => f.hostDir, (h) => { if (h) Object.assign(f, { encrypted: false, pass: '', again: '', size: '', storage: '', mode: '', uid: '0', gid: '0' }) })

const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  const body = f.hostDir ? {
    metadata: { name: f.name },
    spec: { uid: 0, gid: 0, path: f.path, ...(f.watch ? { watch: true, probe: f.probe, on_loss: f.onLoss } : {}), ...(f.comment ? { comment: f.comment } : {}) },
  } : {
    metadata: { name: f.name },
    spec: { uid: Number(f.uid), gid: Number(f.gid), ...(f.storage ? { storage: f.storage } : {}), ...(f.size ? { size: f.size } : {}), ...(f.mode ? { mode: f.mode } : {}), ...(f.comment ? { comment: f.comment } : {}), ...(f.encrypted ? { encrypted: true } : {}) },
    ...(f.encrypted ? { passphrase: f.pass } : {}),
  }
  const name = f.name
  Object.assign(f, { pass: '', again: '' })
  try {
    await runOp(s.volumes.created(name), () => api.volumes.create(body))
    emit('done', name)
    emit('close')
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal :open="open" :title="s.volumes.createTitle" @close="emit('close')">
    <form id="vc" novalidate autocomplete="off" @submit.prevent="save">
      <p class="hint faint">{{ s.form.requiredNote }}</p>
      <div class="field">
        <label for="vc-name">{{ s.volumes.name }} <span class="req" aria-hidden="true">*</span></label>
        <input id="vc-name" v-model.trim="f.name" class="mono" type="text" autocomplete="off" spellcheck="false" data-test="vc-name" :aria-invalid="!!check.err('vc-name')" aria-describedby="vc-name-e vc-name-h" @blur="f.name && check.touch('vc-name')" />
        <span id="vc-name-e" class="field-error" role="alert">{{ check.err('vc-name') }}</span>
        <span id="vc-name-h" class="hint">{{ nameHint('volume') }}</span>
      </div>
      <label class="check"><input v-model="f.hostDir" type="checkbox" data-test="vc-hostdir" aria-describedby="vc-hd-h" /> {{ s.volumes.hostDir }}</label>
      <span id="vc-hd-h" class="hint">{{ s.volumes.hostDirHint }}</span>
      <template v-if="f.hostDir">
        <div class="field">
          <label for="vc-path">{{ s.volumes.path }} <span class="req" aria-hidden="true">*</span></label>
          <input id="vc-path" v-model.trim="f.path" class="mono" type="text" autocomplete="off" spellcheck="false" placeholder="/mnt/storagebox/backups" data-test="vc-path" :aria-invalid="!!check.err('vc-path')" aria-describedby="vc-path-e vc-path-h" @blur="f.path && check.touch('vc-path')" />
          <span id="vc-path-e" class="field-error" role="alert">{{ check.err('vc-path') }}</span>
          <span id="vc-path-h" class="hint">{{ s.volumes.pathHint }}</span>
        </div>
        <label class="check"><input v-model="f.watch" type="checkbox" data-test="vc-watch" aria-describedby="vc-watch-h" /> {{ s.volumes.watch }}</label>
        <span id="vc-watch-h" class="hint">{{ s.volumes.watchHint }}</span>
        <template v-if="f.watch">
          <div class="form-2">
            <div class="field">
              <label for="vc-probe">{{ s.volumes.probe }}</label>
              <select id="vc-probe" v-model="f.probe" data-test="vc-probe"><option value="mounted">{{ s.volumes.probeMounted }}</option><option value="write">{{ s.volumes.probeWrite }}</option></select>
            </div>
            <div class="field">
              <label for="vc-onloss">{{ s.volumes.onLoss }}</label>
              <select id="vc-onloss" v-model="f.onLoss" data-test="vc-onloss" aria-describedby="vc-onloss-h"><option value="none">{{ s.volumes.onLossNone }}</option><option value="stop">{{ s.volumes.onLossStop }}</option></select>
            </div>
          </div>
          <span id="vc-onloss-h" class="hint">{{ s.volumes.onLossHint }}</span>
        </template>
      </template>
      <template v-if="!f.hostDir">
      <div class="form-2">
        <div class="field">
          <label for="vc-uid">{{ s.volumes.uid }}</label>
          <input id="vc-uid" v-model.trim="f.uid" class="mono" type="text" inputmode="numeric" data-test="vc-uid" :aria-invalid="!!check.err('vc-uid')" aria-describedby="vc-own-h vc-uid-e" @blur="check.touch('vc-uid')" />
          <span id="vc-uid-e" class="field-error" role="alert">{{ check.err('vc-uid') }}</span>
        </div>
        <div class="field">
          <label for="vc-gid">{{ s.volumes.gid }}</label>
          <input id="vc-gid" v-model.trim="f.gid" class="mono" type="text" inputmode="numeric" data-test="vc-gid" :aria-invalid="!!check.err('vc-gid')" aria-describedby="vc-own-h vc-gid-e" @blur="check.touch('vc-gid')" />
          <span id="vc-gid-e" class="field-error" role="alert">{{ check.err('vc-gid') }}</span>
        </div>
      </div>
      <span id="vc-own-h" class="hint">{{ s.volumes.ownerHint }}</span>
      <div class="form-2">
        <div class="field">
          <label for="vc-mode">{{ s.volumes.mode }}</label>
          <input id="vc-mode" v-model.trim="f.mode" class="mono" type="text" placeholder="0755" data-test="vc-mode" :aria-invalid="!!check.err('vc-mode')" aria-describedby="vc-mode-h vc-mode-e" @blur="check.touch('vc-mode')" />
          <span id="vc-mode-e" class="field-error" role="alert">{{ check.err('vc-mode') }}</span>
          <span id="vc-mode-h" class="hint">{{ s.volumes.modeHint }}</span>
        </div>
        <div class="field">
          <label for="vc-size">{{ s.volumes.size }}</label>
          <input id="vc-size" v-model.trim="f.size" class="mono" type="text" placeholder="50G" data-test="vc-size" aria-describedby="vc-size-h" />
          <span id="vc-size-h" class="hint">{{ s.volumes.sizeHint }}</span>
        </div>
      </div>
      <div class="field">
        <label for="vc-sto">{{ s.volumes.storage }}</label>
        <select id="vc-sto" v-model="f.storage" class="mono" data-test="vc-storage" aria-describedby="vc-sto-h">
          <option value="">-</option>
          <option v-for="x in storages" :key="x.metadata.name" :value="x.metadata.name">{{ x.metadata.name }}</option>
        </select>
        <span id="vc-sto-h" class="hint">{{ s.volumes.storageHint }}</span>
      </div>
      </template>
      <div class="field">
        <label for="vc-comment">{{ s.volumes.comment }}</label>
        <input id="vc-comment" v-model="f.comment" type="text" data-test="vc-comment" aria-describedby="vc-comment-h" />
        <span id="vc-comment-h" class="hint">{{ s.volumes.commentHint }}</span>
      </div>
      <template v-if="!f.hostDir">
      <label class="check"><input v-model="f.encrypted" type="checkbox" data-test="vc-encrypted" aria-describedby="vc-enc-h" /> {{ s.volumes.encrypt }}</label>
      <span id="vc-enc-h" class="hint">{{ s.volumes.encryptHint }}</span>
      </template>
      <template v-if="f.encrypted && !f.hostDir">
        <div class="field">
          <label for="vc-pass">{{ s.volumes.passphrase }} <span class="req" aria-hidden="true">*</span></label>
          <input id="vc-pass" v-model="f.pass" type="password" autocomplete="new-password" data-test="vc-pass" :aria-invalid="!!check.err('vc-pass')" aria-describedby="vc-pass-h vc-pass-e" @blur="f.pass && check.touch('vc-pass')" />
          <span id="vc-pass-e" class="field-error" role="alert">{{ check.err('vc-pass') }}</span>
          <span id="vc-pass-h" class="hint">{{ s.volumes.passphraseHint }}</span>
        </div>
        <div class="field">
          <label for="vc-pass2">{{ s.volumes.passphraseRepeat }} <span class="req" aria-hidden="true">*</span></label>
          <input id="vc-pass2" v-model="f.again" type="password" autocomplete="new-password" data-test="vc-pass2" :aria-invalid="!!check.err('vc-pass2')" aria-describedby="vc-pass2-e" @blur="f.again && check.touch('vc-pass2')" />
          <span id="vc-pass2-e" class="field-error" role="alert">{{ check.err('vc-pass2') }}</span>
        </div>
      </template>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
    </form>
    <template #footer>
      <span v-if="why" class="why-disabled" data-test="volume-create-why">{{ why }}</span>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn btn-primary" type="submit" form="vc" :disabled="busy" :aria-disabled="!check.ok.value" data-test="volume-create-go">{{ s.volumes.save }}</button>
    </template>
  </Modal>
</template>
