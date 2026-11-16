<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { ApiError } from '@jailops/shared/api/client'
import Icon from '@jailops/shared/components/Icon.vue'
import { sentence } from '@jailops/shared/lib/format'
import Callout from '@jailops/shared/components/Callout.vue'
import CopyField from '@jailops/shared/components/CopyField.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import { isGlobalAdmin } from '@/composables/project'
import { pendingState, refreshPending } from '@/composables/pending'
import { diffLines, RESTART } from '@/lib/host'
import { TEMPLATES, MAX_ALLOW, MAX_SETS, DEFAULT_CONFIRM, MIN_CONFIRM, MAX_CONFIRM, validateFw, fwFormOf, fwSpecOf, fwSpecKey, fwEnableLines, sshOpenToWorld, confirmWindow, type FwForm } from '@/lib/hostfw'
import type { HostChange, HostFirewallRule } from '@jailops/shared/api/types'

const emit = defineEmits<{ applied: [] }>()
const l = useLoad(() => api.host.firewall())
const admin = computed(() => isGlobalAdmin())
const managed = computed(() => !!l.data.value?.status.managed)
const canWrite = computed(() => managed.value && admin.value)
const enable = computed(() => (l.data.value ? fwEnableLines(l.data.value) : {}))
const consolePort = computed(() => l.data.value?.status.console_port ?? 0)
const openWorld = computed(() => (l.data.value ? sshOpenToWorld(l.data.value.spec) : false))

const form = reactive<FwForm>({ template: 'default', sshPorts: '22', sshFrom: '', consoleFrom: '', icmp: true, logging: false, allow: [], sets: [] })
const within = ref(DEFAULT_CONFIRM)
const dirty = ref(false)
watch(form, () => { dirty.value = true }, { deep: true, flush: 'sync' })
function fill(): void {
  if (l.data.value) Object.assign(form, fwFormOf(l.data.value))
  dirty.value = false
}
watch(() => l.data.value, () => { if (!dirty.value) fill() }, { immediate: true })
// a confirm or a revert in the banner changes what the host has
watch(() => pendingState.generation, () => { void l.reload() })
function reset(): void {
  fill()
  preview.value = null
}

const errors = computed(() => validateFw(form))
const errOf = (f: string) => errors.value.find((e) => e.field === f)?.message
const spec = computed(() => fwSpecOf(form, consolePort.value))
const windowOk = computed(() => confirmWindow(within.value) !== undefined)
const key = computed(() => fwSpecKey(spec.value, within.value))

const busy = ref(false)
const error = ref<ApiError | null>(null)
const lockout = ref(false)
const needConfirmLockout = ref(false)
const iKnow = ref(false)
const preview = ref<{ key: string; change: HostChange } | null>(null)
const previewCurrent = computed(() => !!preview.value && preview.value.key === key.value)
const done = ref<HostChange | null>(null)
const asError = (e: unknown) => (e instanceof ApiError ? e : new ApiError({ message: String(e) }))

function showError(e: unknown): void {
  const err = asError(e)
  lockout.value = err.code === 'forbidden' && err.detail.guard === 'lockout'
  if (err.code === 'invalid' && /confirm_lockout|i-know/.test(err.hint + err.message)) needConfirmLockout.value = true
  error.value = lockout.value ? null : err
}

async function runPreview(): Promise<void> {
  busy.value = true
  error.value = null
  lockout.value = false
  done.value = null
  const k = key.value
  try {
    const r = await api.host.applyFirewall({ spec: spec.value, dry_run: true, confirm_within: within.value })
    if (r.kind === 'sync' && r.data) preview.value = { key: k, change: r.data }
  } catch (e) {
    showError(e)
  } finally {
    busy.value = false
  }
}
async function apply(): Promise<void> {
  if (!previewCurrent.value) return
  busy.value = true
  error.value = null
  lockout.value = false
  try {
    const r = await api.host.applyFirewall({ spec: spec.value, confirm_within: within.value, ...(iKnow.value ? { confirm_lockout: true } : {}) })
    done.value = r.kind === 'sync' ? (r.data ?? null) : null
    preview.value = null
    needConfirmLockout.value = false
    iKnow.value = false
    await Promise.all([l.reload(), refreshPending()])
    reset()
    emit('applied')
  } catch (e) {
    showError(e)
  } finally {
    busy.value = false
  }
}

function addAllow(): void {
  if (form.allow.length < MAX_ALLOW) form.allow.push({ proto: 'tcp', ports: '', from: '', comment: '' })
}
function addSet(): void {
  if (form.sets.length < MAX_SETS) form.sets.push({ name: '', members: '' })
}
const lines = computed(() => diffLines(preview.value?.change.diff ?? ''))
const ruleFrom = (r: HostFirewallRule) => (!r.from || r.from === 'any' ? s.hostfw.any : r.from)
</script>

<template>
  <section class="panel" data-test="fw">
    <header><h2>{{ s.hostfw.title }}</h2>
      <div class="row">
        <span v-if="l.data.value" class="pill" :class="managed ? 'ok' : ''" data-test="fw-managed">{{ managed ? s.host.managed : s.host.notManaged }}</span>
        <span v-if="l.data.value?.status.drift?.length" class="pill warn" data-test="fw-drift">{{ s.host.drift }}</span>
        <span v-if="l.data.value && l.data.value.status.pf_enabled !== undefined" class="pill" :class="l.data.value.status.pf_enabled ? 'ok' : 'warn'" data-test="fw-pf">{{ l.data.value.status.pf_enabled ? s.hostfw.pfRunning : s.hostfw.pfStopped }}</span>
        <span v-if="openWorld" class="pill warn" data-test="fw-ssh-open" :title="s.hostfw.sshOpenText">{{ s.hostfw.sshOpen }}</span>
      </div>
    </header>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div v-if="l.data.value" class="panel-body stack">
        <p class="muted">{{ s.hostfw.lead }}</p>
        <p>{{ managed ? s.hostfw.managedText : s.hostfw.notManagedText }}</p>
        <template v-if="!managed">
          <div v-if="enable.config" class="field"><span class="label">{{ s.host.enableConfig }}</span><pre class="mono fw-snippet" data-test="fw-enable-config">{{ enable.config }}</pre></div>
          <div v-if="enable.helper" class="field"><span class="label">{{ s.host.enableHelper }}</span><CopyField :value="enable.helper" :label="s.host.helperLine" /></div>
          <div class="field"><span class="label">{{ s.host.enableRestart }}</span><CopyField :value="RESTART" :label="s.host.restartLine" /></div>
        </template>
        <Callout v-if="l.data.value.status.drift?.length" tone="warn" data-test="fw-drift-text">{{ s.hostfw.driftText(l.data.value.status.drift.join(', ')) }}</Callout>
        <Callout v-else-if="managed && l.data.value.status.file_exists && !l.data.value.status.file_managed" tone="info">{{ s.hostfw.fileHand }}</Callout>
        <Callout v-if="openWorld" tone="warn" data-test="fw-ssh-open-text">{{ s.hostfw.sshOpenText }}</Callout>
        <p v-if="managed && !admin" class="faint">{{ s.host.adminOnly }}</p>

        <h3>{{ s.hostfw.rules }}</h3>
        <p class="muted">{{ s.hostfw.rulesText }}</p>
        <div class="table-wrap"><table class="rtable" data-test="fw-rules">
          <thead><tr><th>{{ s.hostfw.action }}</th><th class="hide-sm">{{ s.hostfw.direction }}</th><th>{{ s.hostfw.proto }}</th><th>{{ s.hostfw.ports }}</th><th>{{ s.hostfw.from }}</th><th>{{ s.hostfw.comment }}</th></tr></thead>
          <tbody><tr v-for="(r, i) in l.data.value.status.rules" :key="i" :class="{ 'fw-fixed': r.fixed }" data-rule>
            <td :data-label="s.hostfw.action"><span class="pill" :class="r.action === 'block' ? 'danger' : 'ok'">{{ sentence(r.action) }}</span></td>
            <td class="hide-sm" :data-label="s.hostfw.direction">{{ r.direction }}</td>
            <td class="mono" :data-label="s.hostfw.proto">{{ r.proto || '-' }}</td>
            <td class="mono" :data-label="s.hostfw.ports">{{ r.ports || '-' }}</td>
            <td class="mono fw-wrap" :data-label="s.hostfw.from">{{ ruleFrom(r) }}</td>
            <td :data-label="s.hostfw.comment">{{ r.comment }} <span v-if="r.fixed" class="chip">{{ s.hostfw.fixed }}</span></td>
          </tr></tbody>
        </table></div>
      </div>
    </LoadState>
  </section>

  <section v-if="l.data.value" class="panel">
    <header><h2>{{ s.hostfw.edit }}</h2></header>
    <form class="body" data-test="fw-form" @submit.prevent="runPreview">
      <fieldset :disabled="!canWrite" class="plain-fieldset">
        <div class="field" style="max-width: 520px">
          <label for="fw-template">{{ s.hostfw.template }}</label>
          <select id="fw-template" v-model="form.template" :aria-invalid="!!errOf('template')" :aria-describedby="errOf('template') ? 'fw-template-e' : undefined" data-test="fw-template">
            <option v-for="t in TEMPLATES" :key="t" :value="t">{{ s.hostfw.templates[t] }}</option>
          </select>
          <span v-if="errOf('template')" id="fw-template-e" class="err" data-test="field-error">{{ errOf('template') }}</span>
        </div>
        <div class="fw-grid">
          <div class="field">
            <label for="fw-ssh-ports">{{ s.hostfw.sshPorts }}</label>
            <input id="fw-ssh-ports" v-model="form.sshPorts" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf('ssh-ports')" :aria-describedby="errOf('ssh-ports') ? 'fw-ssh-ports-e' : 'fw-ssh-ports-h'" data-test="fw-ssh-ports" />
            <span v-if="errOf('ssh-ports')" id="fw-ssh-ports-e" class="err" data-test="field-error">{{ errOf('ssh-ports') }}</span>
            <span v-else id="fw-ssh-ports-h" class="hint">{{ s.hostfw.sshPortsHint }}</span>
          </div>
          <div class="field">
            <label for="fw-ssh-from">{{ s.hostfw.sshFrom }}</label>
            <input id="fw-ssh-from" v-model="form.sshFrom" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf('ssh-from')" :aria-describedby="errOf('ssh-from') ? 'fw-ssh-from-e' : 'fw-ssh-from-h'" data-test="fw-ssh-from" />
            <span v-if="errOf('ssh-from')" id="fw-ssh-from-e" class="err" data-test="field-error">{{ errOf('ssh-from') }}</span>
            <span v-else id="fw-ssh-from-h" class="hint">{{ s.hostfw.sourcesHint }}</span>
          </div>
          <div class="field">
            <template v-if="consolePort">
              <label for="fw-console-from">{{ s.hostfw.consoleFrom(consolePort) }}</label>
              <input id="fw-console-from" v-model="form.consoleFrom" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf('console-from')" :aria-describedby="errOf('console-from') ? 'fw-console-from-e' : 'fw-console-from-h'" data-test="fw-console-from" />
              <span v-if="errOf('console-from')" id="fw-console-from-e" class="err" data-test="field-error">{{ errOf('console-from') }}</span>
              <span v-else id="fw-console-from-h" class="hint">{{ s.hostfw.sourcesHint }}</span>
            </template>
            <p v-else class="faint">{{ s.hostfw.consoleNone }}</p>
          </div>
        </div>
        <label class="check"><input v-model="form.icmp" type="checkbox" data-test="fw-icmp" />{{ s.hostfw.icmp }}</label>
        <label class="check"><input v-model="form.logging" type="checkbox" data-test="fw-logging" />{{ s.hostfw.logging }}</label>

        <h3>{{ s.hostfw.allow }}</h3>
        <p class="muted">{{ s.hostfw.allowText }}</p>
        <span v-if="errOf('allow')" class="err" data-test="field-error">{{ errOf('allow') }}</span>
        <p v-if="!form.allow.length" class="empty">{{ s.hostfw.noAllow }}</p>
        <div v-for="(r, i) in form.allow" :key="'a' + i" class="fw-row" role="group" :aria-label="s.hostfw.allowRow(i + 1)" data-test="fw-allow-row">
          <div class="field fw-proto">
            <label :for="`fw-a${i}-proto`">{{ s.hostfw.proto }}</label>
            <select :id="`fw-a${i}-proto`" v-model="r.proto" :aria-invalid="!!errOf(`allow-${i}-proto`)" data-test="fw-allow-proto"><option value="tcp">tcp</option><option value="udp">udp</option></select>
          </div>
          <div class="field">
            <label :for="`fw-a${i}-ports`">{{ s.hostfw.ports }}</label>
            <input :id="`fw-a${i}-ports`" v-model="r.ports" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf(`allow-${i}-ports`)" :aria-describedby="errOf(`allow-${i}-ports`) ? `fw-a${i}-ports-e` : undefined" data-test="fw-allow-ports" />
            <span v-if="errOf(`allow-${i}-ports`)" :id="`fw-a${i}-ports-e`" class="err" data-test="field-error">{{ errOf(`allow-${i}-ports`) }}</span>
          </div>
          <div class="field">
            <label :for="`fw-a${i}-from`">{{ s.hostfw.from }}</label>
            <input :id="`fw-a${i}-from`" v-model="r.from" class="mono" type="text" autocomplete="off" spellcheck="false" :placeholder="s.hostfw.any" :aria-invalid="!!errOf(`allow-${i}-from`)" :aria-describedby="errOf(`allow-${i}-from`) ? `fw-a${i}-from-e` : undefined" data-test="fw-allow-from" />
            <span v-if="errOf(`allow-${i}-from`)" :id="`fw-a${i}-from-e`" class="err" data-test="field-error">{{ errOf(`allow-${i}-from`) }}</span>
          </div>
          <div class="field">
            <label :for="`fw-a${i}-comment`">{{ s.hostfw.comment }}</label>
            <input :id="`fw-a${i}-comment`" v-model="r.comment" type="text" autocomplete="off" :aria-invalid="!!errOf(`allow-${i}-comment`)" :aria-describedby="errOf(`allow-${i}-comment`) ? `fw-a${i}-comment-e` : undefined" data-test="fw-allow-comment" />
            <span v-if="errOf(`allow-${i}-comment`)" :id="`fw-a${i}-comment-e`" class="err" data-test="field-error">{{ errOf(`allow-${i}-comment`) }}</span>
          </div>
          <button class="btn btn-ghost fw-remove" type="button" :aria-label="`${s.host.remove} ${s.hostfw.allowRow(i + 1)}`" @click="form.allow.splice(i, 1)"><Icon name="trash" /></button>
        </div>
        <div><button class="btn" type="button" :disabled="form.allow.length >= MAX_ALLOW || form.template !== 'custom-rules'" data-test="fw-add-allow" @click="addAllow"><Icon name="plus" />{{ s.hostfw.addAllow }}</button></div>

        <h3>{{ s.hostfw.sets }}</h3>
        <p class="muted">{{ s.hostfw.setsText }}</p>
        <span v-if="errOf('sets')" class="err" data-test="field-error">{{ errOf('sets') }}</span>
        <div v-for="(x, i) in form.sets" :key="'s' + i" class="fw-row" role="group" :aria-label="s.hostfw.setRow(i + 1)" data-test="fw-set-row">
          <div class="field fw-proto">
            <label :for="`fw-s${i}-name`">{{ s.hostfw.setName }}</label>
            <input :id="`fw-s${i}-name`" v-model="x.name" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf(`set-${i}-name`)" :aria-describedby="errOf(`set-${i}-name`) ? `fw-s${i}-name-e` : undefined" data-test="fw-set-name" />
            <span v-if="errOf(`set-${i}-name`)" :id="`fw-s${i}-name-e`" class="err" data-test="field-error">{{ errOf(`set-${i}-name`) }}</span>
          </div>
          <div class="field fw-wide">
            <label :for="`fw-s${i}-members`">{{ s.hostfw.setMembers }}</label>
            <input :id="`fw-s${i}-members`" v-model="x.members" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf(`set-${i}-members`)" :aria-describedby="errOf(`set-${i}-members`) ? `fw-s${i}-members-e` : undefined" data-test="fw-set-members" />
            <span v-if="errOf(`set-${i}-members`)" :id="`fw-s${i}-members-e`" class="err" data-test="field-error">{{ errOf(`set-${i}-members`) }}</span>
          </div>
          <button class="btn btn-ghost fw-remove" type="button" :aria-label="`${s.host.remove} ${s.hostfw.setRow(i + 1)}`" @click="form.sets.splice(i, 1)"><Icon name="trash" /></button>
        </div>
        <div><button class="btn" type="button" :disabled="form.sets.length >= MAX_SETS" data-test="fw-add-set" @click="addSet"><Icon name="plus" />{{ s.hostfw.addSet }}</button></div>

        <div class="field fw-within">
          <label for="fw-within">{{ s.hostfw.confirmWithin }}</label>
          <input id="fw-within" v-model.number="within" type="number" :min="MIN_CONFIRM" :max="MAX_CONFIRM" step="1" :aria-invalid="!windowOk" aria-describedby="fw-within-h" data-test="fw-within" />
          <span id="fw-within-h" :class="windowOk ? 'hint' : 'err'">{{ s.hostfw.confirmWithinHint }}</span>
        </div>
        <Callout tone="info" data-test="fw-revert-explain">{{ s.hostfw.revertExplain(windowOk ? within : DEFAULT_CONFIRM) }}</Callout>
      </fieldset>

      <Callout v-if="lockout" tone="danger" style="margin-top: 12px" data-test="fw-lockout">{{ s.hostfw.lockout }}</Callout>
      <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
      <label v-if="needConfirmLockout" class="check" style="margin-top: 12px"><input v-model="iKnow" type="checkbox" data-test="fw-i-know" />{{ s.hostfw.iKnow }}</label>
      <Callout v-if="done?.pending" tone="ok" style="margin-top: 12px" data-test="fw-done">{{ s.hostfw.applied(done.pending.confirm_within) }}</Callout>

      <div v-if="preview" class="stack fw-preview" data-test="fw-preview">
        <Callout v-if="!preview.change.changed" tone="info">{{ s.hostfw.noChange }}</Callout>
        <template v-else>
          <Callout v-for="w in preview.change.warnings ?? []" :key="w" tone="warn" data-test="fw-warning">{{ w }}</Callout>
          <h3>{{ s.hostfw.diff }}</h3>
          <pre class="mono fw-diff" data-test="fw-diff" tabindex="0" :aria-label="s.hostfw.diff"><span v-for="(ln, i) in lines" :key="i" :class="`d-${ln.kind}`">{{ ln.text }}
</span></pre>
          <h3>{{ s.hostfw.newRules }}</h3>
          <ul class="plain fw-summary" data-test="fw-preview-rules"><li v-for="(r, i) in preview.change.rules ?? []" :key="i" class="mono">{{ r.action }} {{ r.direction }} {{ r.proto ?? '' }} {{ r.ports ? 'port ' + r.ports : '' }} {{ r.from && r.from !== 'any' ? 'from ' + r.from : '' }}<span v-if="r.comment" class="faint"> ({{ r.comment }})</span></li></ul>
          <h3>{{ s.hostfw.actions }}</h3>
          <ol class="fw-actions" data-test="fw-actions"><li v-for="a in preview.change.actions" :key="a" class="mono">{{ a }}</li></ol>
        </template>
      </div>

      <div class="row" style="margin-top: 12px">
        <button class="btn" type="submit" :disabled="!canWrite || busy || errors.length > 0 || !windowOk" data-test="fw-preview-btn">{{ s.hostfw.preview }}</button>
        <button class="btn btn-primary" type="button" :disabled="!canWrite || busy || !previewCurrent || !preview?.change.changed || (needConfirmLockout && !iKnow)" data-test="fw-apply" @click="apply">{{ s.hostfw.apply }}</button>
        <button v-if="dirty" class="btn btn-ghost" type="button" @click="reset">{{ s.app.cancel }}</button>
        <span v-if="canWrite && errors.length" class="why-disabled" data-test="fw-why">{{ s.form.fixFirst(errors[0].message) }}</span>
        <span v-else-if="canWrite && !windowOk" class="why-disabled">{{ s.form.fixFirst(s.hostfw.confirmWithinHint) }}</span>
        <span v-else-if="canWrite && needConfirmLockout && !iKnow && previewCurrent" class="why-disabled">{{ s.hostfw.iKnowFirst }}</span>
        <span v-else-if="canWrite && !previewCurrent" class="why-disabled">{{ s.hostfw.previewFirst }}</span>
      </div>
    </form>
  </section>
</template>

<style scoped>
.plain-fieldset { border: 0; margin: 0; padding: 0; min-width: 0; }
h3 { font-size: 14px; margin: 16px 0 8px; }
.fw-snippet { margin: 0; padding: 8px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); white-space: pre; overflow-x: auto; }
.fw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.fw-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-start; padding: 8px 0; border-bottom: 1px solid var(--border); }
.fw-row .field { flex: 1 1 160px; min-width: 0; }
.fw-row .fw-proto { flex: 0 1 110px; }
.fw-row .fw-wide { flex: 3 1 260px; }
.fw-row input, .fw-row select { width: 100%; }
.fw-remove { align-self: flex-end; }
.fw-within { max-width: 220px; margin-top: 16px; }
.fw-wrap { overflow-wrap: anywhere; }
.fw-fixed td { color: var(--text-2); }
.fw-preview { margin-top: 12px; }
.fw-diff { margin: 0; padding: 8px 0; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); overflow-x: auto; font-size: 12px; }
.fw-diff span { display: block; padding: 0 12px; white-space: pre; }
.fw-diff .d-add { background: var(--ok-bg); color: var(--ok); }
.fw-diff .d-del { background: var(--danger-bg); color: var(--danger); }
.fw-diff .d-hunk { color: var(--info); }
.fw-diff .d-file { color: var(--text-2); font-weight: 600; }
.fw-summary li, .fw-actions li { margin: 2px 0; overflow-wrap: anywhere; }
.fw-actions { margin: 0; padding-left: 20px; }
</style>
