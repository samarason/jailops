<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { ApiError } from '@jailops/shared/api/client'
import { snapshotLabel } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import CopyField from '@jailops/shared/components/CopyField.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import { isGlobalAdmin } from '@/composables/project'
import { hasExt } from '@jailops/shared/composables/session'
import HostFirewallPanel from '@/components/HostFirewallPanel.vue'
import CertificatePanel from '@/components/CertificatePanel.vue'
import { formOf, specOf, specKey, validateForm, diffLines, enableLines, RESTART, MAX_NAMESERVERS, MAX_SEARCH, MAX_NTP, type HostForm } from '@/lib/host'
import type { HostChange, HostSnapshot } from '@jailops/shared/api/types'

const l = useLoad(() => api.host.identity())
const snaps = useLoad(() => api.host.snapshots())
const admin = computed(() => isGlobalAdmin())
const managed = computed(() => !!l.data.value?.status.managed)
const canWrite = computed(() => managed.value && admin.value)
const enable = computed(() => (l.data.value ? enableLines(l.data.value) : {}))

const form = reactive<HostForm>({ hostname: '', nameservers: [], search: [], ntpServers: [], ntpEnable: false })
const dirty = ref(false)
// The form follows the host until the operator edits it.
watch(form, () => { dirty.value = true }, { deep: true, flush: 'sync' })
function fill(): void {
  if (l.data.value) Object.assign(form, formOf(l.data.value))
  dirty.value = false
}
watch(() => l.data.value, () => { if (!dirty.value) fill() }, { immediate: true })
function reset(): void {
  fill()
  preview.value = null
}

const errors = computed(() => validateForm(form))
const errOf = (f: string) => errors.value.find((e) => e.field === f)?.message
const spec = computed(() => specOf(form))

const busy = ref(false)
const error = ref<ApiError | null>(null)
const preview = ref<{ key: string; change: HostChange } | null>(null)
const previewCurrent = computed(() => !!preview.value && preview.value.key === specKey(spec.value))
const done = ref<HostChange | null>(null)
const asError = (e: unknown) => (e instanceof ApiError ? e : new ApiError({ message: String(e) }))

async function runPreview(): Promise<void> {
  busy.value = true
  error.value = null
  done.value = null
  const sent = spec.value
  try {
    const r = await api.host.apply({ spec: sent, dry_run: true })
    if (r.kind === 'sync') preview.value = { key: specKey(sent), change: r.data }
  } catch (e) {
    error.value = asError(e)
  } finally {
    busy.value = false
  }
}
async function apply(): Promise<void> {
  if (!previewCurrent.value) return
  busy.value = true
  error.value = null
  try {
    const r = await runOp(s.host.applyTitle, () => api.host.apply({ spec: spec.value }))
    done.value = r.data ?? null
    dirty.value = false
    preview.value = null
    await Promise.all([l.reload(), snaps.reload()])
    reset()
  } catch (e) {
    error.value = asError(e)
  } finally {
    busy.value = false
  }
}

const restoring = ref<HostSnapshot | null>(null)
async function restore(): Promise<void> {
  const n = restoring.value!.name
  const r = await runOp(s.host.restoreTitle(n), () => api.host.restore(n))
  done.value = r.data ?? null
  dirty.value = false
  await Promise.all([l.reload(), snaps.reload()])
  reset()
}

function addRow(list: string[], max: number): void {
  if (list.length < max) list.push('')
}
const lines = computed(() => diffLines(preview.value?.change.diff ?? ''))
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.host.title }}</h1>
      <div class="row">
        <span v-if="l.data.value" class="pill" :class="managed ? 'ok' : ''" data-test="host-managed">{{ managed ? s.host.managed : s.host.notManaged }}</span>
        <span v-if="l.data.value?.status.drift?.length" class="pill warn" data-test="host-drift">{{ s.host.drift }}</span>
      </div>
    </div>
    <p class="muted">{{ s.host.lead }}</p>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div v-if="l.data.value" class="stack" style="margin-top: 12px">
        <section class="panel" data-test="host-state">
          <div class="body stack">
            <p>{{ managed ? s.host.managedText : s.host.notManagedText }}</p>
            <ul class="plain mono host-files"><li v-for="f in s.host.files" :key="f">{{ f }}</li></ul>
            <p class="muted">{{ s.host.handEdits }}</p>
            <template v-if="!managed">
              <div v-if="enable.config" class="field"><span class="label">{{ s.host.enableConfig }}</span><pre class="mono host-snippet" data-test="enable-config">{{ enable.config }}</pre></div>
              <div v-if="enable.helper" class="field"><span class="label">{{ s.host.enableHelper }}</span><CopyField :value="enable.helper" :label="s.host.helperLine" /></div>
              <div class="field"><span class="label">{{ s.host.enableRestart }}</span><CopyField :value="RESTART" :label="s.host.restartLine" /></div>
            </template>
            <Callout v-if="l.data.value.status.drift?.length" tone="warn" data-test="drift-text">{{ s.host.driftText(l.data.value.status.drift.join(', ')) }}</Callout>
            <p v-if="managed && !admin" class="faint">{{ s.host.adminOnly }}</p>
          </div>
        </section>

        <section class="panel">
          <header><h2>{{ s.host.identity }}</h2></header>
          <form class="body" data-test="host-form" @submit.prevent="runPreview">
            <fieldset :disabled="!canWrite" class="plain-fieldset">
              <div class="field" style="max-width: 520px">
                <label for="h-name">{{ s.host.hostname }}</label>
                <input id="h-name" v-model="form.hostname" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf('hostname')" :aria-describedby="errOf('hostname') ? 'h-name-e' : 'h-name-h'" data-test="hostname" />
                <span v-if="errOf('hostname')" id="h-name-e" class="err">{{ errOf('hostname') }}</span>
                <span v-else id="h-name-h" class="hint">{{ s.host.hostnameHint }} <template v-if="l.data.value.status.rc_hostname && l.data.value.status.rc_hostname !== l.data.value.spec.hostname">{{ s.host.rcHostname(l.data.value.status.rc_hostname) }}</template></span>
              </div>

              <h3>{{ s.host.resolvers }}</h3>
              <div class="field"><span class="label" id="h-ns-l">{{ s.host.nameservers }}</span>
                <div v-for="(_, i) in form.nameservers" :key="'ns' + i" class="row host-row">
                  <input :id="`h-ns${i}`" v-model="form.nameservers[i]" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-label="s.host.nameserver(i + 1)" :aria-invalid="!!errOf(`nameserver-${i}`)" data-test="nameserver" />
                  <button class="btn btn-ghost" type="button" :aria-label="`${s.host.remove} ${s.host.nameserver(i + 1)}`" @click="form.nameservers.splice(i, 1)"><Icon name="trash" /></button>
                  <span v-if="errOf(`nameserver-${i}`)" class="err" data-test="field-error">{{ errOf(`nameserver-${i}`) }}</span>
                </div>
                <span v-if="errOf('nameservers')" class="err" data-test="field-error">{{ errOf('nameservers') }}</span>
                <div><button class="btn" type="button" :disabled="form.nameservers.length >= MAX_NAMESERVERS" data-test="add-nameserver" @click="addRow(form.nameservers, MAX_NAMESERVERS)"><Icon name="plus" />{{ s.host.addNameserver }}</button></div>
              </div>
              <div class="field"><span class="label">{{ s.host.search }}</span>
                <div v-for="(_, i) in form.search" :key="'sd' + i" class="row host-row">
                  <input :id="`h-sd${i}`" v-model="form.search[i]" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-label="s.host.searchDomain(i + 1)" :aria-invalid="!!errOf(`search-${i}`)" data-test="search" />
                  <button class="btn btn-ghost" type="button" :aria-label="`${s.host.remove} ${s.host.searchDomain(i + 1)}`" @click="form.search.splice(i, 1)"><Icon name="trash" /></button>
                  <span v-if="errOf(`search-${i}`)" class="err" data-test="field-error">{{ errOf(`search-${i}`) }}</span>
                </div>
                <span v-if="errOf('search')" class="err" data-test="field-error">{{ errOf('search') }}</span>
                <div><button class="btn" type="button" :disabled="form.search.length >= MAX_SEARCH" data-test="add-search" @click="addRow(form.search, MAX_SEARCH)"><Icon name="plus" />{{ s.host.addSearch }}</button></div>
              </div>

              <h3>{{ s.host.ntp }}</h3>
              <p v-if="l.data.value.status.ntp_sync" class="row"><span class="pill" :class="l.data.value.status.ntp_sync.synchronised ? 'ok' : 'warn'" data-test="ntp-sync">{{ l.data.value.status.ntp_sync.synchronised ? s.host.ntpSynced(l.data.value.status.ntp_sync.peer ?? '') : s.host.ntpNotSynced }}</span><span v-if="l.data.value.status.ntp_sync.detail" class="faint">{{ l.data.value.status.ntp_sync.detail }}</span></p>
              <div class="field"><span class="label">{{ s.host.ntpServers }}</span>
                <div v-for="(_, i) in form.ntpServers" :key="'ntp' + i" class="row host-row">
                  <input :id="`h-ntp${i}`" v-model="form.ntpServers[i]" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-label="s.host.ntpServer(i + 1)" :aria-invalid="!!errOf(`ntp-${i}`)" data-test="ntp-server" />
                  <button class="btn btn-ghost" type="button" :aria-label="`${s.host.remove} ${s.host.ntpServer(i + 1)}`" @click="form.ntpServers.splice(i, 1)"><Icon name="trash" /></button>
                  <span v-if="errOf(`ntp-${i}`)" class="err" data-test="field-error">{{ errOf(`ntp-${i}`) }}</span>
                </div>
                <span v-if="errOf('ntp')" class="err" data-test="field-error">{{ errOf('ntp') }}</span>
                <div><button class="btn" type="button" :disabled="form.ntpServers.length >= MAX_NTP" data-test="add-ntp" @click="addRow(form.ntpServers, MAX_NTP)"><Icon name="plus" />{{ s.host.addNtp }}</button></div>
              </div>
              <label class="check"><input v-model="form.ntpEnable" type="checkbox" data-test="ntp-enable" />{{ s.host.ntpEnable }}</label>
            </fieldset>

            <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
            <Callout v-if="done" tone="ok" style="margin-top: 12px" data-test="host-done">{{ done.snapshot ? s.host.applied(done.snapshot) : s.host.appliedNone }}</Callout>

            <div v-if="preview" class="stack host-preview" data-test="host-preview">
              <Callout v-if="!preview.change.changed" tone="info">{{ s.host.noChange }}</Callout>
              <template v-else>
                <h3>{{ s.host.diff }}</h3>
                <pre class="mono host-diff" data-test="host-diff" tabindex="0" :aria-label="s.host.diff"><span v-for="(ln, i) in lines" :key="i" :class="`d-${ln.kind}`">{{ ln.text }}
</span></pre>
                <h3>{{ s.host.actions }}</h3>
                <ol class="host-actions" data-test="host-actions"><li v-for="a in preview.change.actions" :key="a" class="mono">{{ a }}</li></ol>
              </template>
            </div>

            <div class="row" style="margin-top: 12px">
              <button class="btn" type="submit" :disabled="!canWrite || busy || errors.length > 0" data-test="host-preview-btn">{{ s.host.preview }}</button>
              <button class="btn btn-primary" type="button" :disabled="!canWrite || busy || !previewCurrent || !preview?.change.changed" data-test="host-apply" @click="apply">{{ s.host.apply }}</button>
              <button v-if="dirty" class="btn btn-ghost" type="button" @click="reset">{{ s.app.cancel }}</button>
              <span v-if="canWrite && errors.length" class="why-disabled" data-test="host-why">{{ s.form.fixFirst(errors[0].message) }}</span>
              <span v-else-if="canWrite && !previewCurrent" class="why-disabled">{{ s.host.previewFirst }}</span>
            </div>
          </form>
        </section>

        <HostFirewallPanel v-if="hasExt('host_firewall')" @applied="snaps.reload()" />

        <CertificatePanel v-if="hasExt('host_certificate')" />

        <section class="panel" data-test="host-snapshots">
          <header><h2>{{ s.host.snapshots }}</h2></header>
          <div class="body"><p class="muted">{{ s.host.snapshotsText }}</p></div>
          <LoadState :loading="snaps.loading.value" :error="snaps.error.value" :has-data="!!snaps.data.value" @retry="snaps.reload">
            <p v-if="!snaps.data.value?.length" class="empty">{{ s.host.noSnapshots }}</p>
            <div v-else class="table-wrap"><table class="rtable">
              <thead><tr><th>{{ s.host.time }}</th><th>{{ s.host.reason }}</th><th>{{ s.host.filesCol }}</th><th><span class="sr-only">{{ s.host.restore }}</span></th></tr></thead>
              <tbody><tr v-for="x in snaps.data.value" :key="x.name" :data-snapshot="x.name">
                <td :data-label="s.host.time" :title="x.name"><TimeStamp :ts="x.time" /></td>
                <td :data-label="s.host.reason">{{ s.host.reasons[x.reason ?? 'apply'] ?? x.reason }}</td>
                <td :data-label="s.host.filesCol"><span v-for="f in x.files" :key="f" class="chip mono">{{ f }}</span></td>
                <td class="actions"><button class="btn btn-sm" type="button" :disabled="!canWrite" data-test="host-restore" :aria-label="`${s.host.restore} ${snapshotLabel(x.name)}`" @click="restoring = x">{{ s.host.restore }}</button></td>
              </tr></tbody>
            </table></div>
          </LoadState>
        </section>
      </div>
    </LoadState>

    <ConfirmDialog :open="!!restoring" :title="s.host.restoreTitle(snapshotLabel(restoring?.name ?? ''))" :confirm-label="s.host.restore" danger :run="restore" @close="restoring = null">
      <p>{{ s.host.restoreText }}</p>
      <ul class="plain mono" style="margin-top: 8px"><li v-for="f in restoring?.files" :key="f">{{ f }}</li></ul>
    </ConfirmDialog>
  </div>
</template>

<style scoped>
.host-files li, .host-actions li { margin: 2px 0; overflow-wrap: anywhere; }
.host-snippet { margin: 0; padding: 8px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); white-space: pre; overflow-x: auto; }
.host-row { flex-wrap: wrap; margin-bottom: 6px; }
.host-row input { flex: 1 1 220px; min-width: 0; max-width: 420px; }
.host-row .err { flex-basis: 100%; }
.plain-fieldset { border: 0; margin: 0; padding: 0; min-width: 0; }
h3 { font-size: 14px; margin: 16px 0 8px; }
.host-preview { margin-top: 12px; }
.host-diff { margin: 0; padding: 8px 0; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); overflow-x: auto; font-size: 12px; }
.host-diff span { display: block; padding: 0 12px; white-space: pre; }
.host-diff .d-add { background: var(--ok-bg); color: var(--ok); }
.host-diff .d-del { background: var(--danger-bg); color: var(--danger); }
.host-diff .d-hunk { color: var(--info); }
.host-diff .d-file { color: var(--text-2); font-weight: 600; }
.host-actions { margin: 0; padding-left: 20px; }
</style>
