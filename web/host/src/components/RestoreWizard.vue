<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { runOp } from '@jailops/shared/composables/ops'
import { buildRequest, requestKey, type RestoreForm } from '@/lib/restore'
import type { Backup, RestorePreflight } from '@jailops/shared/api/types'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'

const props = defineProps<{ open: boolean; backup: Backup | null }>()
const emit = defineEmits<{ close: []; done: [] }>()

const form = reactive<RestoreForm>({ backup: '', as: '', host: '', replace: false, keepIp: false, noVolumes: false, passphrase: '', networkMap: {} })
const report = ref<RestorePreflight | null>(null)
const reportKey = ref('')
const busy = ref(false)
const error = ref<ApiError | null>(null)

const bundle = computed(() => props.backup?.spec.bundle)
const isVolume = computed(() => props.backup?.spec.kind === 'volume')
const encrypted = computed(() => !!props.backup?.spec.volume?.encrypted)
const nets = computed(() => [...new Set((bundle.value?.spec.network ?? []).map((n) => n.network))])
const fresh = computed(() => !!report.value && reportKey.value === requestKey(form))
const step = computed(() => (!report.value ? 1 : fresh.value ? 3 : 2))

watch(() => props.open, (o) => {
  if (!o || !props.backup) return
  form.backup = props.backup.metadata.name
  form.as = ''
  form.host = ''
  form.replace = false
  form.keepIp = false
  form.noVolumes = false
  form.passphrase = ''
  form.networkMap = Object.fromEntries(nets.value.map((n) => [n, n]))
  report.value = null
  reportKey.value = ''
  error.value = null
})

async function preflight(): Promise<void> {
  busy.value = true
  error.value = null
  const key = requestKey(form)
  try {
    const r = await runOp(s.restore.title, () => api.backups.restore(buildRequest(form, true)), { silent: true })
    report.value = ((r.data ?? r.op?.metadata) as RestorePreflight | undefined) ?? { ok: false, errors: ['The server returned no preflight report.'] }
    reportKey.value = key
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}

async function restore(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await runOp(s.restore.started(form.as || props.backup?.spec.jail || ''), () => api.backups.restore(buildRequest(form, false)))
    form.passphrase = ''
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
  <Modal :open="open" :title="s.restore.title + (backup ? ': ' + backup.spec.jail : '')" wide @close="emit('close')">
    <ol class="wiz-steps" aria-label="Steps">
      <li :aria-current="step === 1 ? 'step' : undefined">{{ s.restore.step1 }}</li>
      <li :aria-current="step === 2 ? 'step' : undefined">{{ s.restore.step2 }}</li>
      <li :aria-current="step === 3 ? 'step' : undefined">{{ s.restore.step3 }}</li>
    </ol>
    <div v-if="backup" class="stack">
      <p class="mono muted">{{ backup.metadata.name }} · {{ backup.spec.snapshot }}</p>
      <div class="grid-2">
        <div class="field"><label for="rs-as">{{ s.restore.as }}</label><input id="rs-as" v-model="form.as" class="mono" type="text" /><span class="hint">{{ s.restore.asHint }}</span></div>
        <div class="field"><label for="rs-host">{{ s.restore.host }}</label><input id="rs-host" v-model="form.host" class="mono" type="text" /><span class="hint">{{ s.restore.hostHint }}</span></div>
      </div>
      <div v-if="isVolume && encrypted" class="field"><label for="rs-pass">{{ s.restore.passphrase }}</label><input id="rs-pass" v-model="form.passphrase" type="password" autocomplete="new-password" data-test="restore-passphrase" /><span class="hint">{{ s.restore.passphraseHint }}</span></div>
      <Callout v-if="isVolume" tone="info">{{ s.restore.volumeNote }}</Callout>
      <template v-else>
        <label class="check"><input v-model="form.replace" type="checkbox" />{{ s.restore.replace }}</label>
        <label class="check"><input v-model="form.keepIp" type="checkbox" />{{ s.restore.keepIp }}</label>
        <label v-if="bundle?.volumes?.length" class="check"><input v-model="form.noVolumes" type="checkbox" data-test="restore-no-volumes" />{{ s.restore.noVolumes }}</label>
      </template>
      <fieldset v-if="nets.length && !isVolume" class="netmap">
        <legend class="label">{{ s.restore.networkMap }}</legend>
        <p class="hint muted">{{ s.restore.networkMapHint }}</p>
        <div v-for="n in nets" :key="n" class="row" style="flex-wrap: nowrap; margin-bottom: 6px">
          <span class="mono" style="width: 40%">{{ n }}</span><span class="faint">to</span>
          <input v-model="form.networkMap[n]" class="mono" type="text" :aria-label="`${s.restore.mapTo}: ${n}`" />
        </div>
      </fieldset>
      <details v-if="!isVolume">
        <summary>{{ s.restore.bundle }}</summary>
        <dl class="kv">
          <dt>Image</dt><dd class="mono">{{ backup.spec.bundle.image_generation }}</dd>
          <dt>{{ s.restore.volumes }}</dt><dd class="mono">{{ backup.spec.bundle.volumes?.join(', ') || '-' }}</dd>
          <dt>{{ s.restore.secrets }}</dt><dd class="mono">{{ backup.spec.bundle.secret_refs?.join(', ') || '-' }}</dd>
        </dl>
      </details>

      <section v-if="report" data-test="preflight" aria-live="polite">
        <Callout :tone="report.ok && fresh ? 'ok' : report.ok ? 'info' : 'danger'">
          {{ !fresh ? s.restore.changedSince : report.ok ? s.restore.preflightOk : s.restore.preflightBad }}
        </Callout>
        <div class="grid-2" style="margin-top: 8px">
          <div><h3>{{ s.restore.missing }}</h3><ul class="plain"><li v-for="m in report.missing ?? []" :key="m" class="mono">{{ m }}</li><li v-if="!report.missing?.length" class="faint">{{ s.restore.nothing }}</li></ul></div>
          <div><h3>{{ s.restore.changes }}</h3><ul class="plain"><li v-for="m in report.changes ?? []" :key="m">{{ m }}</li><li v-if="!report.changes?.length" class="faint">{{ s.restore.nothing }}</li></ul></div>
        </div>
        <div v-if="report.errors?.length" style="margin-top: 8px"><h3>{{ s.restore.errors }}</h3><ul class="plain err"><li v-for="m in report.errors" :key="m">{{ m }}</li></ul></div>
      </section>
      <ErrorPanel v-if="error" :error="error" />
    </div>
    <template #footer>
      <button class="btn" type="button" @click="emit('close')">{{ s.app.cancel }}</button>
      <button class="btn" type="button" :disabled="busy" data-test="preflight-run" @click="preflight">{{ busy && !report ? s.restore.running : s.restore.runPreflight }}</button>
      <button class="btn btn-primary" type="button" :disabled="!(report?.ok && fresh) || busy" data-test="restore-go" @click="restore">{{ s.restore.go }}</button>
    </template>
  </Modal>
</template>

<style>
.wiz-steps { display: flex; gap: 16px; list-style: none; padding: 0; margin: 0 0 12px; counter-reset: s; color: var(--text-3); }
.wiz-steps li { counter-increment: s; }
.wiz-steps li::before { content: counter(s) '. '; }
.wiz-steps li[aria-current='step'] { color: var(--text); font-weight: 600; border-bottom: 2px solid var(--accent); }
.netmap { border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 12px; margin: 0; }
</style>
