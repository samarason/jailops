<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { stamp } from '@jailops/shared/lib/format'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { useFormCheck } from '@jailops/shared/composables/form'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import { freeScopes, policyProblems, keepFields as fields } from '@/lib/retention'
import Icon from '@jailops/shared/components/Icon.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import { runJob } from '@/lib/jobs'
import type { RetentionPolicyRow, RetentionResult } from '@/types'
import type { RetentionPolicy } from '@jailops/shared/api/types'

const l = useLoad(async () => ({ rows: await api.retentionPolicies.list(), groups: await api.groups.list().catch(() => []) }))
const operate = computed(() => allows(session.role, 'backup-admin'))
const node = computed(() => session.info?.hostname ?? '')
const keep = (p: RetentionPolicy) => fields.filter((f) => p[f]).map((f) => `${p[f]} ${f}`).join(', ') || '-'

// policy editor: Add picks a scope that has no policy yet; Edit keeps the scope it opened with
const editing = ref<'add' | 'edit' | null>(null)
const form = reactive({ scope: '', timezone: '', values: {} as Record<string, number | undefined> })
const busy = ref(false)
const error = ref<ApiError | null>(null)
const rows = computed(() => l.data.value?.rows ?? [])
const free = computed(() => freeScopes(rows.value, l.data.value?.groups ?? []))
const check = useFormCheck(() => policyProblems(form, editing.value === 'add' ? rows.value.map((r) => r.scope) : [], editing.value === 'add', { scope: s.retention.scopeMissing, taken: s.retention.scopeTaken, count: s.retention.countRule, none: s.retention.keepNothing }))
function openEdit(r?: RetentionPolicyRow): void {
  editing.value = r ? 'edit' : 'add'
  form.scope = r?.scope ?? ''
  form.timezone = r?.timezone ?? ''
  form.values = { ...(r?.policy ?? {}) } as Record<string, number | undefined>
  error.value = null
  check.reset()
}
async function save(): Promise<void> {
  busy.value = true
  error.value = null
  const policy: Record<string, number> = {}
  for (const f of fields) if (form.values[f]) policy[f] = Number(form.values[f])
  try {
    await runOp(editing.value === 'add' ? `${s.retention.addTitle}: ${form.scope}` : s.retention.editTitle(form.scope), () => api.retentionPolicies.set(form.scope, policy as RetentionPolicy, form.timezone || undefined))
    editing.value = null
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
const scopeName = (sc: string) => (sc === 'default' ? s.retention.default : sc)
function askRemove(r: RetentionPolicyRow): void {
  confirmAction({
    title: s.retention.removeTitle(r.scope), confirmLabel: s.retention.remove, danger: true, text: s.retention.removeText(r.scope),
    run: () => runOp(s.retention.removeTitle(r.scope), () => api.retentionPolicies.remove(r.scope)), done: () => void l.reload(),
  })
}

// plan and run
const planGroup = ref('')
const plan = ref<RetentionResult | null>(null)
const planOpen = ref(false)
const planBusy = ref(false)
const planError = ref<ApiError | null>(null)
async function dryRun(): Promise<void> {
  planBusy.value = true
  planError.value = null
  try {
    const r = await runJob<RetentionResult>(s.retention.preview, () => api.jobs.retention({ dry_run: true, ...(planGroup.value ? { group: planGroup.value } : {}) }), { silent: true })
    plan.value = r.result ?? { dry_run: true, groups: [], deleted: 0 }
    planOpen.value = true
  } catch (e) {
    planError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    planBusy.value = false
  }
}
const result = ref<RetentionResult | null>(null)
function openRun(): void {
  planError.value = null
  confirmAction({
    title: s.retention.runTitle, confirmLabel: s.retention.run, danger: true, typeName: node.value, typeLabel: s.retention.typeName(node.value),
    text: `${s.retention.runText} ${s.retention.runScope(planGroup.value)}`,
    run: async () => {
      const r = await runJob<RetentionResult>(s.retention.runTitle, () => api.jobs.retention({ ...(planGroup.value ? { group: planGroup.value } : {}) }))
      result.value = r.result ?? null
    },
  })
}
const totalDelete = computed(() => (plan.value?.groups ?? []).reduce((a, g) => a + g.delete.length, 0))
const totalKeep = computed(() => (plan.value?.groups ?? []).reduce((a, g) => a + g.keep.length, 0))
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.retention.title }}</h1><button class="btn btn-primary" type="button" :disabled="!operate" data-test="add-policy" @click="openEdit()"><Icon name="plus" />{{ s.retention.add }}</button></div>
    <p class="muted">{{ s.retention.lead }}</p>
    <RoleNote need="backup-admin" />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="stack" style="margin-top: 12px">
        <section class="panel">
          <header><h2>{{ s.retention.policies }}</h2></header>
          <p v-if="!rows.length" class="empty">{{ s.retention.empty }}</p>
          <div v-else class="table-wrap"><table class="rtable">
            <thead><tr><th>{{ s.retention.scope }}</th><th>{{ s.retention.keep }}</th><th>{{ s.retention.timezone }}</th><th>{{ s.retention.updated }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
            <tbody><tr v-for="r in rows" :key="r.scope" :data-policy="r.scope">
              <td class="mono" :data-label="s.retention.scope">{{ scopeName(r.scope) }}</td><td :data-label="s.retention.keep">{{ keep(r.policy) }}</td><td class="mono" :data-label="s.retention.timezone">{{ r.timezone }}</td>
              <td class="faint" :data-label="s.retention.updated"><TimeStamp :ts="r.updated_at" /> {{ s.retention.updatedBy(r.updated_by) }}</td>
              <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" :disabled="!operate" @click="openEdit(r)" :aria-label="`${s.retention.edit} ${r.scope}`">{{ s.retention.edit }}</button><button class="btn btn-sm btn-danger" type="button" :disabled="!operate" @click="askRemove(r)" :aria-label="`${s.retention.remove} ${r.scope}`">{{ s.retention.remove }}</button></div></td>
            </tr></tbody></table></div>
        </section>
        <section class="panel">
          <header><h2>{{ s.retention.plan }}</h2></header>
          <div class="body stack">
            <div class="field" style="max-width: 360px; margin: 0"><label for="rp-group">{{ s.retention.onlyGroup }}</label>
              <select id="rp-group" v-model="planGroup"><option value="">-</option><option v-for="g in l.data.value?.groups" :key="g.group_id" :value="g.group_id">{{ g.group_id }}</option></select></div>
            <div class="row">
              <button class="btn" type="button" :disabled="planBusy" data-test="dry-run" @click="dryRun">{{ planBusy ? s.retention.previewing : s.retention.preview }}</button>
              <button class="btn btn-danger" type="button" :disabled="!operate" data-test="run" @click="openRun">{{ s.retention.run }}</button>
            </div>
            <ErrorPanel v-if="planError" :error="planError" />
            <Callout v-if="result" tone="ok" data-test="run-result">{{ s.retention.done(result.deleted) }}</Callout>
          </div>
        </section>
      </div>
    </LoadState>

    <Modal :open="planOpen" :title="s.retention.preview" wide @close="planOpen = false">
      <div v-if="plan" class="stack" data-test="plan">
        <Callout tone="info">{{ s.retention.dryRun }}</Callout>
        <p v-if="!totalDelete" class="muted">{{ s.retention.nothing }}</p>
        <p v-else><strong>{{ s.retention.wouldDelete(totalDelete) }}</strong> · {{ s.retention.kept(totalKeep) }}</p>
        <section v-for="g in plan.groups.filter((x) => x.delete.length || x.error)" :key="g.group">
          <h3 class="mono">{{ g.group }} <span class="faint">({{ s.retention.source }}: {{ g.policy_source }})</span></h3>
          <p v-if="g.error" class="err">{{ g.error }}</p>
          <div class="table-wrap"><table class="rtable">
            <thead><tr><th>{{ s.retention.snapshot }}</th><th>{{ s.retention.time }}</th><th>{{ s.retention.reasons }}</th></tr></thead>
            <tbody><tr v-for="d in g.delete" :key="d.snapshot"><td class="mono" :data-label="s.retention.snapshot">{{ d.snapshot }}</td><td class="faint" :data-label="s.retention.time"><TimeStamp :ts="d.time" /></td><td :data-label="s.retention.reasons">{{ d.reasons.join('; ') }}</td></tr></tbody></table></div>
        </section>
      </div>
      <template #footer><button class="btn" type="button" @click="planOpen = false">{{ s.app.close }}</button></template>
    </Modal>

    <Modal :open="!!editing" :title="editing === 'add' ? s.retention.addTitle : s.retention.editTitle(form.scope)" @close="editing = null">
      <form id="pe" novalidate data-test="policy-form" @submit.prevent="check.submit(save)">
        <p class="hint faint" style="margin-bottom: 8px">{{ s.form.requiredNote }}</p>
        <div v-if="editing === 'add'" class="field">
          <label for="pe-scope">{{ s.retention.scopeLabel }} <span class="req" aria-hidden="true">*</span></label>
          <select id="pe-scope" v-model="form.scope" required :aria-invalid="!!check.err('pe-scope')" aria-describedby="pe-scope-hint">
            <option value="" disabled>{{ s.retention.chooseScope }}</option>
            <option v-for="x in free" :key="x.scope" :value="x.scope">{{ x.scope === 'default' ? s.retention.default : s.retention.scopeHost(x.scope, x.host ?? '') }}</option>
          </select>
          <span id="pe-scope-hint" class="hint">{{ free.length ? s.retention.scopeHint : s.retention.noFreeScope }}</span>
          <span v-if="check.err('pe-scope')" class="field-error" role="alert" data-test="scope-error">{{ check.err('pe-scope') }}</span>
        </div>
        <div v-else class="field"><span class="label">{{ s.retention.scopeLabel }}</span><span class="mono" data-test="scope-readonly">{{ scopeName(form.scope) }}</span></div>
        <fieldset class="field keep-set">
          <legend class="label">{{ s.retention.keepLegend }} <span class="req" aria-hidden="true">*</span></legend>
          <div class="form-2"><div v-for="f in fields" :key="f" class="field"><label :for="'pe-' + f">{{ s.retention.fields[f] }}</label><input :id="'pe-' + f" v-model.number="form.values[f]" type="number" min="0" max="100000" :aria-invalid="!!check.err('pe-' + f)" @blur="form.values[f] !== undefined && check.touch('pe-' + f)" /><span v-if="check.err('pe-' + f)" class="field-error" role="alert">{{ check.err('pe-' + f) }}</span></div></div>
        </fieldset>
        <div class="field"><label for="pe-tz">{{ s.retention.timezone }}</label><input id="pe-tz" v-model="form.timezone" class="mono" type="text" placeholder="UTC" aria-describedby="pe-tz-hint" /><span id="pe-tz-hint" class="hint">{{ s.retention.timezoneHint }}</span></div>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer>
        <span v-if="check.reason.value" class="why-disabled" data-test="policy-why">{{ check.reason.value }}</span>
        <button class="btn" type="button" @click="editing = null">{{ s.app.cancel }}</button>
        <button class="btn btn-primary" type="submit" form="pe" :disabled="busy" :aria-disabled="!check.ok.value" data-test="policy-save">{{ s.retention.save }}</button>
      </template>
    </Modal>
  </div>
</template>

<style>
.keep-set { border: 1px solid var(--border); border-radius: var(--radius); padding: 8px 12px 0; }
</style>
