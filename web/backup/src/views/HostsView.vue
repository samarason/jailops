<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { sentence } from '@jailops/shared/lib/format'
import { nameHint, nameProblem } from '@jailops/shared/lib/names'
import { useFormCheck } from '@jailops/shared/composables/form'
import { confirmAction } from '@jailops/shared/composables/confirm'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import type { Host } from '@/types'

const l = useLoad(() => api.hosts.list())
const admin = computed(() => allows(session.role, 'admin'))
const scopeOptions = ['backup-push', 'backup-pull']
const stale = (h: Host) => !h.last_seen_at || Date.now() - Date.parse(h.last_seen_at) > 2 * 86400_000

const enrolling = ref(false)
const form = reactive({ name: '', fingerprint: '', certificate: '', note: '', scopes: ['backup-push', 'backup-pull'] as string[] })
const busy = ref(false)
const error = ref<ApiError | null>(null)
const check = useFormCheck(() => ({
  'en-name': form.name ? nameProblem(form.name, 'node') : s.hosts.nameMissing,
  'en-fp': form.fingerprint.trim() || form.certificate.trim() ? '' : s.hosts.keyMissing,
  'en-scope-push': form.scopes.length ? '' : s.hosts.scopeMissing,
}))
function openEnrol(): void {
  Object.assign(form, { name: '', fingerprint: '', certificate: '', note: '', scopes: ['backup-push', 'backup-pull'] })
  error.value = null
  check.reset()
  enrolling.value = true
}
async function enrol(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await runOp(s.hosts.enrolTitle + ': ' + form.name, () => api.hosts.enrol({ name: form.name, ...(form.fingerprint.trim() ? { fingerprint: form.fingerprint.trim() } : {}), ...(form.certificate.trim() ? { certificate: form.certificate } : {}), scopes: form.scopes, ...(form.note ? { note: form.note } : {}) }))
    enrolling.value = false
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}

const editing = ref<Host | null>(null)
const editScopes = ref<string[]>([])
function openEdit(h: Host): void {
  editing.value = h
  editScopes.value = [...h.scopes]
  error.value = null
}
async function saveScopes(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await runOp(s.hosts.editScopes + ': ' + editing.value!.name, () => api.hosts.setScopes(editing.value!.name, editScopes.value))
    editing.value = null
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}

function openRevoke(h: Host): void {
  confirmAction({
    title: s.hosts.revokeTitle(h.name), confirmLabel: s.hosts.revoke, danger: true, text: s.hosts.revokeText,
    items: s.hosts.revokeItems(h.scopes), typeName: h.name, typeLabel: s.hosts.typeName(h.name),
    run: () => runOp(s.hosts.revokeTitle(h.name), () => api.hosts.revoke(h.name)), done: () => void l.reload(),
  })
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.hosts.title }}</h1><button class="btn btn-primary" type="button" :disabled="!admin" data-test="enrol" @click="openEnrol"><Icon name="plus" />{{ s.hosts.enrol }}</button></div>
    <p class="muted">{{ s.hosts.lead }}</p>
    <RoleNote need="admin" />
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel" style="margin-top: 12px">
        <p v-if="!l.data.value?.length" class="empty">{{ s.hosts.empty }}</p>
        <div v-else class="table-wrap"><table class="rtable">
          <thead><tr><th>{{ s.hosts.name }}</th><th class="hide-sm">{{ s.hosts.fingerprint }}</th><th>{{ s.hosts.scopes }}</th><th>{{ s.hosts.lastSeen }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
          <tbody><tr v-for="h in l.data.value" :key="h.id" :data-host="h.name">
            <td :data-label="s.hosts.name"><span class="mono">{{ h.name }}</span><span v-if="h.revoked_at" class="pill danger" style="margin-left: 6px">{{ s.hosts.revoked }}</span><div v-if="h.note" class="faint">{{ h.note }}</div></td>
            <td class="mono faint hide-sm" :data-label="s.hosts.fingerprint" :title="h.fingerprint">{{ h.fingerprint.slice(0, 23) }}</td>
            <td :data-label="s.hosts.scopes"><div v-for="sc in h.scopes" :key="sc"><span class="mono">{{ sc }}</span> <span class="faint">{{ s.hosts.scopeText[sc] }}</span></div></td>
            <td :data-label="s.hosts.lastSeen"><TimeStamp :ts="h.last_seen_at" /><span v-if="!h.revoked_at && stale(h)" class="pill warn" style="margin-left: 6px">{{ sentence(s.hosts.stale) }}</span></td>
            <td class="actions"><div class="row-actions">
              <button class="btn btn-sm" type="button" :disabled="!admin || !!h.revoked_at" @click="openEdit(h)" :aria-label="`${s.hosts.editScopes} ${h.name}`">{{ s.hosts.editScopes }}</button>
              <button class="btn btn-sm btn-danger" type="button" :disabled="!admin || !!h.revoked_at" data-test="revoke" :aria-label="`${s.hosts.revoke} ${h.name}`" @click="openRevoke(h)">{{ s.hosts.revoke }}</button>
            </div></td>
          </tr></tbody></table></div>
      </div>
    </LoadState>

    <Modal :open="enrolling" :title="s.hosts.enrolTitle" wide @close="enrolling = false">
      <form id="en" novalidate @submit.prevent="check.submit(enrol)">
        <p class="muted">{{ s.hosts.enrolText }}</p>
        <p class="hint faint">{{ s.form.requiredNote }}</p>
        <div class="field"><label for="en-name">{{ s.hosts.name }} <span class="req" aria-hidden="true">*</span></label><input id="en-name" v-model="form.name" class="mono" type="text" required :aria-invalid="!!check.err('en-name')" aria-describedby="en-name-hint" @blur="form.name && check.touch('en-name')" /><span id="en-name-hint" class="hint">{{ nameHint('node') }}</span><span v-if="check.err('en-name')" class="field-error" role="alert">{{ check.err('en-name') }}</span></div>
        <div class="field"><label for="en-fp">{{ s.hosts.fp }} <span class="req" aria-hidden="true">*</span></label><input id="en-fp" v-model="form.fingerprint" class="mono" type="text" spellcheck="false" :aria-invalid="!!check.err('en-fp')" aria-describedby="en-fp-hint" /><span id="en-fp-hint" class="hint">{{ s.hosts.fpHint }}</span><span v-if="check.err('en-fp')" class="field-error" role="alert">{{ check.err('en-fp') }}</span></div>
        <div class="field"><label for="en-pem">{{ s.hosts.pem }}</label><textarea id="en-pem" v-model="form.certificate" rows="4" spellcheck="false"></textarea></div>
        <fieldset class="field"><legend class="label">{{ s.hosts.scopes }} <span class="req" aria-hidden="true">*</span></legend><label v-for="sc in scopeOptions" :key="sc" class="check"><input :id="sc === 'backup-push' ? 'en-scope-push' : undefined" v-model="form.scopes" type="checkbox" :value="sc" /><span class="mono">{{ sc }}</span> <span class="faint">{{ s.hosts.scopeText[sc] }}</span></label><span v-if="check.err('en-scope-push')" class="field-error" role="alert">{{ check.err('en-scope-push') }}</span></fieldset>
        <div class="field"><label for="en-note">{{ s.hosts.note }}</label><input id="en-note" v-model="form.note" type="text" /></div>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><span v-if="check.reason.value" class="why-disabled" data-test="enrol-why">{{ check.reason.value }}</span><button class="btn" type="button" @click="enrolling = false">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="en" :disabled="busy" :aria-disabled="!check.ok.value" data-test="enrol-go">{{ s.hosts.submit }}</button></template>
    </Modal>

    <Modal :open="!!editing" :title="s.hosts.editScopesTitle(editing?.name ?? '')" @close="editing = null">
      <fieldset class="field"><legend class="label">{{ s.hosts.scopes }}</legend><label v-for="sc in scopeOptions" :key="sc" class="check"><input v-model="editScopes" type="checkbox" :value="sc" /><span class="mono">{{ sc }}</span> <span class="faint">{{ s.hosts.scopeText[sc] }}</span></label></fieldset>
      <ErrorPanel v-if="error" :error="error" />
      <template #footer><span v-if="!editScopes.length" class="why-disabled">{{ s.hosts.scopeMissing }}</span><button class="btn" type="button" @click="editing = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="button" :disabled="busy || !editScopes.length" @click="saveScopes">{{ s.hosts.save }}</button></template>
    </Modal>

    
  </div>
</template>
