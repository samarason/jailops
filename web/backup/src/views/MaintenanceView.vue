<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { bytes, sentence } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import { confirmAction } from '@jailops/shared/composables/confirm'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import { runJob } from '@/lib/jobs'
import type { Job, Mode, GCResult, VerifyResult, RetentionResult } from '@/types'

const l = useLoad(async () => {
  const [mode, jobs, quarantine] = await Promise.all([api.maintenance.get(), api.jobs.list(undefined, 30), api.quarantine.list()])
  return { mode: mode.mode, jobs, quarantine }
}, { every: 8000 })
const operate = computed(() => allows(session.role, 'backup-admin'))
const node = computed(() => session.info?.hostname ?? '')
const error = ref<ApiError | null>(null)
const busy = ref(false)
const modes: Mode[] = ['online', 'read-only', 'offline']
const newest = computed(() => [...(l.data.value?.jobs ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at)))
const stateTone = (j: Job) => ({ succeeded: 'ok', failed: 'danger', running: 'info pulse', queued: 'info', cancelled: 'warn' })[j.state]

// mode switch with typed confirmation: it stops every host's backups
function openMode(m: Mode): void {
  error.value = null
  confirmAction({
    title: s.maintenance.modeTitle(s.maintenance.modes[m]), confirmLabel: s.maintenance.setMode(s.maintenance.modes[m]), danger: m !== 'online',
    text: s.maintenance.modeText, items: s.maintenance.modeItems(m), typeName: node.value, typeLabel: s.maintenance.typeName(node.value),
    run: () => runOp(s.maintenance.modeTitle(s.maintenance.modes[m]), () => api.maintenance.set(m)), done: () => void l.reload(),
  })
}

// GC
const gc = reactive({ open: false, grace: '' })
const doGc = (dry: boolean) => runJob(dry ? s.maintenance.gcDryTitle : s.maintenance.gcTitle, () => api.jobs.gc({ dry_run: dry, ...(gc.grace.trim() ? { grace: gc.grace.trim() } : {}) }))
async function gcDry(): Promise<void> {
  error.value = null
  try {
    await doGc(true)
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
  }
}
function askGc(): void {
  confirmAction({ title: s.maintenance.gcTitle, confirmLabel: s.maintenance.runGc, danger: true, text: s.maintenance.gcConfirm, items: s.maintenance.gcItems(gc.grace.trim()), run: () => doGc(false) })
}

// verify
const ver = reactive({ open: false, mode: 'new' as 'all' | 'new' | 'stale', quarantine: true, staleDays: 30 })
async function verify(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await runJob(s.maintenance.verifyTitle(ver.mode), () => api.jobs.verify({ mode: ver.mode, quarantine: ver.quarantine, ...(ver.mode === 'stale' ? { stale_days: ver.staleDays } : {}) }))
    ver.open = false
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
async function reconcile(): Promise<void> {
  error.value = null
  try {
    await runJob(s.maintenance.reconcileTitle, () => api.jobs.reconcile())
  } catch (e) {
    error.value = e instanceof ApiError ? e : null
  }
}

function askPurge(): void {
  const healed = (l.data.value?.quarantine ?? []).filter((q) => q.healed)
  confirmAction({
    title: s.maintenance.purgeTitle, confirmLabel: s.maintenance.purge, danger: true, text: healed.length ? s.maintenance.purgeText : s.maintenance.purgeNone,
    items: healed.map((q) => `${q.id.slice(0, 16)} (${bytes(q.size)})`), run: () => runOp(s.maintenance.purgeTitle, () => api.quarantine.purge()), done: () => void l.reload(),
  })
}
const cancelJob = (j: Job) => api.jobs.cancel(j.id).then(() => l.reload()).catch((e) => (error.value = e instanceof ApiError ? e : null))

const detail = ref<Job | null>(null)
function summary(j: Job): string {
  if (j.error) return j.error
  const r = j.result as unknown
  if (!r) return '-'
  if (j.kind === 'gc') return s.maintenance.gcSummary(r as GCResult, bytes((r as GCResult).bytes_reclaimed))
  if (j.kind === 'verify') return s.maintenance.verifySummary(r as VerifyResult)
  if (j.kind === 'retention') return s.maintenance.retentionSummary(r as RetentionResult)
  return 'ok'
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.maintenance.title }}</h1></div>
    <RoleNote need="backup-admin" />
    <ErrorPanel v-if="error && !ver.open" :error="error" style="margin: 12px 0" />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div v-if="l.data.value" class="stack" style="margin-top: 12px">
        <section class="panel">
          <header><div class="row"><h2>{{ s.maintenance.mode }}</h2><span class="pill" :class="l.data.value.mode === 'online' ? 'ok' : l.data.value.mode === 'read-only' ? 'warn' : 'danger'" data-test="maint-state">{{ s.maintenance.modes[l.data.value.mode] ?? sentence(l.data.value.mode) }}</span></div></header>
          <div class="body stack">
            <p class="muted">{{ s.maintenance.modeText }}</p>
            <div class="row" role="group" :aria-label="s.maintenance.mode">
              <button v-for="m in modes" :key="m" class="btn" :class="{ 'btn-danger': m !== 'online' }" type="button" :disabled="!operate || l.data.value.mode === m" :data-mode="m" @click="openMode(m)">{{ s.maintenance.setMode(s.maintenance.modes[m]) }}</button>
            </div>
          </div>
        </section>

        <section class="panel">
          <header><h2>{{ s.maintenance.jobs }}</h2></header>
          <div class="body row">
            <div class="field" style="margin: 0; width: 180px"><label for="gc-grace">{{ s.maintenance.grace }}</label><input id="gc-grace" v-model="gc.grace" class="mono" type="text" placeholder="36h" /></div>
            <button class="btn" type="button" :disabled="!operate" data-test="gc-dry" @click="gcDry">{{ s.maintenance.dryGc }}</button>
            <button class="btn" type="button" :disabled="!operate" data-test="gc-run" @click="askGc"><Icon name="broom" />{{ s.maintenance.runGc }}</button>
            <button class="btn" type="button" :disabled="!operate" data-test="verify-open" @click="ver.open = true"><Icon name="searchCheck" />{{ s.maintenance.runVerify }}</button>
            <button class="btn" type="button" :disabled="!operate" @click="reconcile">{{ s.maintenance.runReconcile }}</button>
          </div>
          <p v-if="!newest.length" class="empty">{{ s.maintenance.noJobs }}</p>
          <div v-else class="table-wrap"><table class="rtable" data-test="jobs">
            <thead><tr><th>{{ s.maintenance.kind }}</th><th>{{ s.maintenance.state }}</th><th class="hide-sm">{{ s.maintenance.started }}</th><th class="hide-sm">{{ s.maintenance.by }}</th><th>{{ s.maintenance.result }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
            <tbody><tr v-for="j in newest" :key="j.id" :data-job="j.id">
              <td class="mono" :data-label="s.maintenance.kind">{{ j.kind }} #{{ j.id }}</td><td :data-label="s.maintenance.state"><span class="pill" :class="stateTone(j)">{{ sentence(j.state) }}</span></td>
              <td class="faint hide-sm" :data-label="s.maintenance.started"><TimeStamp :ts="j.started_at ?? j.created_at" /></td><td class="mono hide-sm" :data-label="s.maintenance.by">{{ j.created_by || '-' }}</td>
              <td :data-label="s.maintenance.result">{{ summary(j) }}</td>
              <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" :aria-label="`${s.maintenance.details} ${j.kind} #${j.id}`" @click="detail = j">{{ s.maintenance.details }}</button><button v-if="operate && (j.state === 'running' || j.state === 'queued')" class="btn btn-sm" type="button" @click="cancelJob(j)">{{ s.maintenance.cancel }}</button></div></td>
            </tr></tbody></table></div>
        </section>

        <section class="panel" data-section="quarantine">
          <header><h2>{{ s.maintenance.quarantine }} ({{ l.data.value.quarantine.length }})</h2><button class="btn btn-sm btn-danger" type="button" :disabled="!operate || !l.data.value.quarantine.length" data-test="purge" @click="askPurge">{{ s.maintenance.purge }}</button></header>
          <div class="body muted">{{ s.maintenance.quarantineText }}</div>
          <p v-if="!l.data.value.quarantine.length" class="empty">{{ s.maintenance.noQuarantine }}</p>
          <div v-else class="table-wrap"><table class="rtable">
            <thead><tr><th>{{ s.maintenance.chunk }}</th><th class="hide-sm">{{ s.maintenance.since }}</th><th class="num">{{ s.maintenance.size }}</th><th>{{ s.maintenance.state }}</th></tr></thead>
            <tbody><tr v-for="q in l.data.value.quarantine" :key="q.id"><td class="mono" :data-label="s.maintenance.chunk">{{ q.id.slice(0, 16) }}</td><td class="faint hide-sm" :data-label="s.maintenance.since"><TimeStamp :ts="q.since" /></td><td class="num mono" :data-label="s.maintenance.size">{{ bytes(q.size) }}</td><td :data-label="s.maintenance.state"><span class="pill" :class="q.healed ? 'ok' : 'danger'">{{ q.healed ? s.maintenance.healed : s.maintenance.notHealed }}</span></td></tr></tbody></table></div>
        </section>
      </div>
    </LoadState>

    

    <Modal :open="ver.open" :title="s.maintenance.verify" @close="ver.open = false">
      <form id="vf" @submit.prevent="verify">
        <div class="field"><label for="vf-mode">{{ s.maintenance.verifyMode }}</label><select id="vf-mode" v-model="ver.mode"><option v-for="(t, k) in s.maintenance.verifyModes" :key="k" :value="k">{{ t }}</option></select></div>
        <div v-if="ver.mode === 'stale'" class="field"><label for="vf-days">{{ s.maintenance.staleDays }}</label><input id="vf-days" v-model.number="ver.staleDays" type="number" min="1" /></div>
        <label class="check"><input v-model="ver.quarantine" type="checkbox" />{{ s.maintenance.quarantineFlag }}</label>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><button class="btn" type="button" @click="ver.open = false">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="vf" :disabled="busy" data-test="verify-go">{{ s.maintenance.runVerify }}</button></template>
    </Modal>

    <Modal :open="!!detail" :title="s.maintenance.jobDetail(detail?.id ?? 0)" wide @close="detail = null">
      <pre class="pre" data-test="job-json">{{ JSON.stringify(detail, null, 2) }}</pre>
      <template #footer><button class="btn" type="button" @click="detail = null">{{ s.app.close }}</button></template>
    </Modal>
  </div>
</template>
