<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { common as s } from '../i18n/common'
import { ApiError } from '../api/client'
import { runOp } from '../composables/ops'
import { nameHint, nameProblem, type NameRule } from '../lib/names'
import { useFormCheck } from '../composables/form'
import { confirmAction } from '../composables/confirm'
import TimeStamp from './TimeStamp.vue'
import type { MutationResult } from '../api/types'
import Modal from './Modal.vue'
import Callout from './Callout.vue'
import CopyField from './CopyField.vue'
import ErrorPanel from './ErrorPanel.vue'

/** One token as a console lists it; each app maps its own wire shape to this. */
export interface TokenRow { name: string; role: string; expires_at?: string; allow_from?: string[]; projects?: string[]; global?: boolean }
export interface TokenForm { name: string; role: string; expires_at?: string; allow_from?: string[]; projects?: string[]; global?: boolean }

const props = defineProps<{
  tokens: TokenRow[]
  /** Roles a token may have, with a short description of what each may do. */
  roles: Array<{ value: string; text: string }>
  create: (f: TokenForm) => Promise<MutationResult<{ secret?: string }>>
  remove: (name: string) => Promise<MutationResult<unknown>>
  /** When given, the form asks for a scope: some of these projects, or Global. */
  projectNames?: string[]
  /** The server's rule for token names (lib/names.ts); default: identity. */
  nameRule?: NameRule
}>()
const emit = defineEmits<{ changed: [] }>()

const creating = ref(false)
const form = reactive({ name: '', role: '', expires: '', allowFrom: '', projects: [] as string[], global: false })
const scoped = computed(() => !!props.projectNames)
const scopeOk = computed(() => !scoped.value || form.global || form.projects.length > 0)
const busy = ref(false)
const error = ref<ApiError | null>(null)
const secret = ref('')
const secretFor = ref('')
const rule = computed<NameRule>(() => props.nameRule ?? 'identity')
// a date written as ISO, never in the browser's local format; the token ends at the end of that day (UTC)
const dateOk = (v: string) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v + 'T23:59:59Z')) && Date.parse(v + 'T23:59:59Z') > Date.now()
// An empty field shows its message after a submit only: one that appears on leaving the field would push the dialog's
// buttons away from under the pointer that is about to click them.
const check = useFormCheck(() => ({
  'nt-name': form.name ? nameProblem(form.name, rule.value) : s.access.nameMissing,
  'nt-scope-first': scopeOk.value ? '' : s.access.scopeRequired,
  'nt-exp': !form.expires || dateOk(form.expires) ? '' : s.access.expiresRule,
}))
const expired = (t: string | undefined) => !!t && !t.startsWith('0001') && Date.parse(t) < Date.now()
const roleText = computed(() => props.roles.find((r) => r.value === form.role)?.text ?? '')
const split = (v: string) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

defineExpose({ openCreate })
function openCreate(): void {
  Object.assign(form, { name: '', role: props.roles.find((r) => r.value === 'operator')?.value ?? props.roles[0].value, expires: '', allowFrom: '', projects: [], global: false })
  error.value = null
  check.reset()
  creating.value = true
}
async function create(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    const r = await runOp(s.access.createTitle(form.name), () =>
      props.create({
        name: form.name,
        role: form.role,
        ...(form.expires ? { expires_at: new Date(form.expires + 'T23:59:59Z').toISOString() } : {}),
        ...(form.allowFrom.trim() ? { allow_from: split(form.allowFrom) } : {}),
        ...(scoped.value ? (form.global ? { global: true } : { projects: form.projects }) : {}),
      }),
    )
    secret.value = (r.data as { secret?: string } | undefined)?.secret ?? ''
    secretFor.value = form.name
    creating.value = false
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
function askRevoke(t: TokenRow): void {
  confirmAction({
    title: s.access.revokeTitle(t.name), confirmLabel: s.access.revoke, danger: true, text: s.access.revokeText(t.name),
    run: () => runOp(s.access.revokeTitle(t.name), () => props.remove(t.name)), done: () => emit('changed'),
  })
}
function closeSecret(): void {
  secret.value = ''
  emit('changed')
}
</script>

<template>
  <div>
    <div class="panel">
      <p v-if="!tokens.length" class="empty">{{ s.access.noTokens }}</p>
      <div v-else class="table-wrap"><table class="rtable" data-test="tokens-table">
        <thead><tr><th>{{ s.access.tokenName }}</th><th>{{ s.access.permission }}</th><th>{{ s.access.expires }}</th><th>{{ s.access.scope }}</th><th class="hide-sm">{{ s.access.allowFrom }}</th><th><span class="sr-only">{{ s.access.actions }}</span></th></tr></thead>
        <tbody><tr v-for="t in tokens" :key="t.name" :data-token="t.name">
          <td class="mono" :data-label="s.access.tokenName">{{ t.name }}</td><td class="mono" :data-label="s.access.permission">{{ t.role }}</td>
          <td :data-label="s.access.expires"><span v-if="!t.expires_at || t.expires_at.startsWith('0001')" class="faint">{{ s.access.expiresNever }}</span><span v-else><TimeStamp :ts="t.expires_at" /> <span v-if="expired(t.expires_at)" class="pill danger">{{ s.access.expired }}</span></span></td>
          <td :data-label="s.access.scope"><span v-if="t.global" class="badge warn" data-test="global-badge">{{ s.access.globalBadge }}</span><template v-else><span v-for="p in t.projects ?? []" :key="p" class="chip mono">{{ p }}</span><span v-if="!t.projects?.length" class="faint">-</span></template></td>
          <td class="mono hide-sm" :data-label="s.access.allowFrom">{{ t.allow_from?.join(', ') || '-' }}</td>
          <td class="actions"><button class="btn btn-sm btn-danger" type="button" :aria-label="`${s.access.revoke} ${t.name}`" @click="askRevoke(t)">{{ s.access.revoke }}</button></td>
        </tr></tbody></table></div>
    </div>

    <Modal :open="creating" :title="s.access.newToken" @close="creating = false">
      <form id="nt" novalidate @submit.prevent="check.submit(create)">
        <p class="hint faint">{{ s.form.requiredNote }}</p>
        <div class="field"><label for="nt-name">{{ s.access.tokenName }} <span class="req" aria-hidden="true">*</span></label><input id="nt-name" v-model="form.name" class="mono" type="text" required aria-describedby="nt-name-hint" :aria-invalid="!!check.err('nt-name')" @blur="form.name && check.touch('nt-name')" /><span id="nt-name-hint" class="hint">{{ nameHint(rule) }}</span><span v-if="check.err('nt-name')" class="field-error" role="alert">{{ check.err('nt-name') }}</span></div>
        <div class="field"><label for="nt-perm">{{ s.access.permission }}</label>
          <select id="nt-perm" v-model="form.role"><option v-for="r in roles" :key="r.value" :value="r.value">{{ r.value }}</option></select><span class="hint">{{ roleText }}</span></div>
        <fieldset v-if="scoped" class="field scope-box" data-test="scope" @change="check.touch('nt-scope-first')">
          <legend class="label">{{ s.access.scope }} <span class="req" aria-hidden="true">*</span></legend>
          <label v-for="(p, i) in projectNames" :key="p" class="check"><input :id="i === 0 ? 'nt-scope-first' : undefined" v-model="form.projects" type="checkbox" :value="p" :disabled="form.global" /><span class="mono">{{ p }}</span></label>
          <label class="check"><input :id="projectNames?.length ? undefined : 'nt-scope-first'" v-model="form.global" type="checkbox" data-test="global-toggle" />{{ s.access.scopeGlobal }}</label>
          <Callout v-if="form.global" tone="warn">{{ s.access.scopeGlobalWarning }}</Callout>
          <span v-if="check.err('nt-scope-first')" class="err" role="alert" data-test="scope-required">{{ check.err('nt-scope-first') }}</span>
        </fieldset>
        <div class="field"><label for="nt-exp">{{ s.access.expires }}</label><input id="nt-exp" v-model="form.expires" class="mono" type="text" inputmode="numeric" placeholder="YYYY-MM-DD" autocomplete="off" aria-describedby="nt-exp-hint" :aria-invalid="!!check.err('nt-exp')" @blur="form.expires && check.touch('nt-exp')" /><span id="nt-exp-hint" class="hint">{{ s.access.expiresHint }}</span><span v-if="check.err('nt-exp')" class="field-error" role="alert">{{ check.err('nt-exp') }}</span></div>
        <div class="field"><label for="nt-from">{{ s.access.allowFrom }}</label><input id="nt-from" v-model="form.allowFrom" class="mono" type="text" /><span class="hint">{{ s.access.allowFromHint }}</span></div>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer>
        <span v-if="check.reason.value" class="why-disabled" data-test="token-why">{{ check.reason.value }}</span>
        <button class="btn" type="button" @click="creating = false">{{ s.app.cancel }}</button>
        <button class="btn btn-primary" type="submit" form="nt" :disabled="busy" :aria-disabled="!check.ok.value" data-test="token-create">{{ s.access.create }}</button>
      </template>
    </Modal>

    <Modal :open="!!secret" :title="s.access.createTitle(secretFor)" @close="() => {}">
      <Callout tone="warn">{{ s.access.shownOnce }}</Callout>
      <div style="margin-top: 12px"><CopyField :value="secret" :label="s.access.tokenName" /></div>
      <template #footer><button class="btn btn-primary" type="button" data-test="secret-done" @click="closeSecret">{{ s.access.done }}</button></template>
    </Modal>
  </div>
</template>
