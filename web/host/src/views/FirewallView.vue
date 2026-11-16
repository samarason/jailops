<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { blankRule, detailToRuleErrors, detailToSetErrors, setSpec, setTextOf, setUsers, splitList, validateRules, validateSet, type RuleErrors, type SetErrors } from '@/lib/firewall'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import { useFormCheck } from '@jailops/shared/composables/form'
import { nameHint } from '@jailops/shared/lib/names'
import { nameError } from '@/lib/nameField'
import TabBar from '@jailops/shared/components/TabBar.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import AddressSetCreateDialog from '@/components/AddressSetCreateDialog.vue'
import FirewallTest from '@/components/FirewallTest.vue'
import { hasFirewallTest } from '@/composables/fwtest'
import RenameDialog from '@/components/RenameDialog.vue'
import { canRename } from '@/composables/rename'
import { currentProject, isGlobalAdmin } from '@/composables/project'
import type { FirewallPolicy, AddressSet, FirewallRule } from '@jailops/shared/api/types'

const l = useLoad(async () => {
  const [policies, sets, jails] = await Promise.all([api.firewall.policies(), api.firewall.addressSets(), api.jails.list().catch(() => [])])
  return { policies, sets, jails }
})

const route = useRoute()
const { tab } = useTabQuery(() => (hasFirewallTest() ? (['policies', 'sets', 'test'] as const) : (['policies', 'sets'] as const)), 'policies')
let wantDone = false
const tabItems = computed(() => [{ key: 'policies' as const, label: s.firewall.policies }, { key: 'sets' as const, label: s.firewall.sets }, ...(hasFirewallTest() ? [{ key: 'test' as const, label: s.firewall.test }] : [])])
const selected = ref('')
const draft = ref<FirewallPolicy | null>(null)
const original = ref('')
const etag = ref<string | undefined>()
const apiError = ref<ApiError | null>(null)
const fieldErrors = ref<RuleErrors>({})
const saving = ref(false)

const setSel = ref('')
const setDraft = ref<AddressSet | null>(null)
const setOriginal = ref('')
const setEtag = ref<string | undefined>()
const setText = ref('')
const setComment = ref('')
const setError = ref<ApiError | null>(null)
const setErrors = ref<SetErrors>({})
const setSaving = ref(false)
// a pick that was overtaken by a newer one (another set, another project) drops its answer
let pickSeq = 0
let setSeq = 0

watch(() => l.data.value, (d) => {
  if (!d) return
  // ?policy=NAME (a link from the operations or a jail page) opens that policy
  const want = !wantDone && typeof route.query.policy === 'string' && d.policies.some((p) => p.metadata.name === route.query.policy) ? route.query.policy : ''
  if (want) { wantDone = true; void pick(want) }
  else if ((!selected.value || !d.policies.some((p) => p.metadata.name === selected.value)) && d.policies.length) void pick(d.policies[0].metadata.name)
  else if (!d.policies.length) { selected.value = ''; draft.value = null }
  // the selected set stays while it exists; after a delete or a project switch the first one is shown, or none
  if (!setSel.value || !d.sets.some((x) => x.metadata.name === setSel.value)) {
    if (d.sets.length) void pickSet(d.sets[0].metadata.name)
    else { setSeq++; setSel.value = ''; setDraft.value = null }
  }
}, { immediate: true })

// compared as the server would store them: an emptied comment is the same as none
const dirty = computed(() => !!draft.value && JSON.stringify(clean(draft.value)) !== JSON.stringify(clean(JSON.parse(original.value))))
const setNow = computed(() => setSpec(setText.value, setComment.value))
const setDirty = computed(() => !!setDraft.value && JSON.stringify(setNow.value) !== setOriginal.value)
const attached = computed(() => (l.data.value?.jails ?? []).filter((j) => j.spec.firewall?.policies?.includes(selected.value)).map((j) => j.metadata.name))

async function pick(n: string): Promise<void> {
  selected.value = n
  apiError.value = null
  fieldErrors.value = {}
  const mine = ++pickSeq
  try {
    const r = await api.firewall.policy(n)
    if (mine !== pickSeq) return
    r.data.spec.rules ??= []
    draft.value = structuredClone(r.data)
    original.value = JSON.stringify(r.data)
    etag.value = r.etag
  } catch (e) {
    if (mine === pickSeq) apiError.value = e instanceof ApiError ? e : null
  }
}
function revert(): void {
  if (draft.value) draft.value = JSON.parse(original.value)
  fieldErrors.value = {}
  apiError.value = null
}
const rules = computed<FirewallRule[]>(() => draft.value?.spec.rules ?? [])
function add(): void {
  draft.value?.spec.rules?.push(blankRule())
}
function remove(i: number): void {
  draft.value?.spec.rules?.splice(i, 1)
}
function move(i: number, d: number): void {
  const r = draft.value?.spec.rules
  if (!r || i + d < 0 || i + d >= r.length) return
  const [x] = r.splice(i, 1)
  r.splice(i + d, 0, x)
}
function list(r: FirewallRule, k: 'from' | 'to' | 'ports', v: string): void {
  r[k] = splitList(v)
}
// a port forward takes traffic that would reach the host: only a global administrator gives or changes one
const canForward = computed(() => isGlobalAdmin())
function toggleRedirect(r: FirewallRule, on: boolean): void {
  r.redirect = on ? { host_port: 8080, jail_port: 80 } : undefined
}
// A copy through JSON: the draft is a reactive proxy, which structuredClone refuses.
const copy = <T>(v: T): T => JSON.parse(JSON.stringify(v))
function clean(p: FirewallPolicy): FirewallPolicy {
  const c = copy(p)
  c.spec.rules = (c.spec.rules ?? []).map((r) => {
    const x = { ...r }
    if (!x.name) delete x.name
    if (!x.comment?.trim()) delete x.comment
    if (!x.proto) delete x.proto
    for (const k of ['from', 'to', 'ports'] as const) if (!x[k]?.length) delete x[k]
    if (!x.log) delete x.log
    if (!x.redirect) delete x.redirect
    return x
  })
  if (!c.spec.raw) delete c.spec.raw
  if (!c.spec.comment?.trim()) delete c.spec.comment
  return c
}
/** Why Save does nothing yet, next to the button. */
const saveWhy = computed(() => (!dirty.value ? s.firewall.noChange : Object.keys(validateRules(rules.value, s.firewall)).length ? s.firewall.fixRules : ''))
async function save(): Promise<void> {
  if (!draft.value || !dirty.value) return
  fieldErrors.value = validateRules(rules.value, s.firewall)
  if (Object.keys(fieldErrors.value).length) {
    const k = Object.keys(fieldErrors.value)[0].split('.')
    document.querySelector<HTMLElement>(`[data-rule="${k[0]}"] input, [data-rule="${k[0]}"] select`)?.focus()
  }
  apiError.value = null
  if (Object.keys(fieldErrors.value).length) return
  saving.value = true
  try {
    await runOp(s.firewall.savePolicyTitle(selected.value), () => api.firewall.putPolicy(clean(draft.value!), etag.value))
    await pick(selected.value)
  } catch (e) {
    apiError.value = e instanceof ApiError ? e : null
    fieldErrors.value = detailToRuleErrors(apiError.value?.detail)
  } finally {
    saving.value = false
  }
}

async function pickSet(n: string): Promise<void> {
  setSel.value = n
  setError.value = null
  setErrors.value = {}
  const mine = ++setSeq
  try {
    const r = await api.firewall.addressSet(n)
    if (mine !== setSeq) return
    setDraft.value = r.data
    setText.value = setTextOf(r.data.spec)
    setComment.value = r.data.spec.comment ?? ''
    setOriginal.value = JSON.stringify(setSpec(setText.value, setComment.value))
    setEtag.value = r.etag
  } catch (e) {
    if (mine === setSeq) setError.value = e instanceof ApiError ? e : null
  }
}
function revertSet(): void {
  if (!setDraft.value) return
  setText.value = setTextOf(setDraft.value.spec)
  setComment.value = setDraft.value.spec.comment ?? ''
  setErrors.value = {}
  setError.value = null
}
const setOthers = computed(() => Object.fromEntries((l.data.value?.sets ?? []).filter((x) => x.metadata.name !== setSel.value).map((x) => [x.metadata.name, x.spec])))
const setCheck = computed(() => validateSet(setSel.value, setNow.value, setOthers.value, s.firewall))
/** Why Save set does nothing yet, next to the button. */
const setWhy = computed(() => (!setDirty.value ? s.firewall.noSetChange : Object.keys(setCheck.value).length ? s.firewall.fixSet : ''))
const users = computed(() => setUsers(setSel.value, l.data.value?.policies ?? [], l.data.value?.sets ?? []))
async function saveSet(): Promise<void> {
  if (!setDraft.value || !setDirty.value || setSaving.value) return
  setErrors.value = setCheck.value
  setError.value = null
  if (setErrors.value.addresses) {
    document.getElementById('sa')?.focus()
    return
  }
  setSaving.value = true
  const name = setSel.value
  try {
    await runOp(s.firewall.saveSetTitle(name), () => api.firewall.putAddressSet({ metadata: copy(setDraft.value!.metadata), spec: setNow.value }, setEtag.value))
    await l.reload()
    await pickSet(name)
  } catch (e) {
    setError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
    setErrors.value = detailToSetErrors(setError.value)
  } finally {
    setSaving.value = false
  }
}
const creatingSet = ref(false)
async function setCreated(name: string): Promise<void> {
  creatingSet.value = false
  setSel.value = name
  await l.reload()
  await pickSet(name)
}
// Tier 2: a set holds no data of its own. While rules or other sets use it the server refuses, and the dialog
// shows the refusal; the users are listed up front.
function removeSet(): void {
  const name = setSel.value
  const u = users.value
  const items = [...u.policies.map((p) => `${s.firewall.policy} ${p}`), ...u.sets.map((x) => `set:${x}`)]
  confirmAction({
    title: s.firewall.deleteSetTitle(name), confirmLabel: s.firewall.deleteSet, danger: true,
    text: items.length ? `${s.firewall.deleteSetText} ${s.firewall.deleteSetUsed(name)}` : s.firewall.deleteSetText,
    items, itemsLabel: s.firewall.setUsers,
    run: () => runOp(s.firewall.deleteSetOp(name), () => api.firewall.deleteAddressSet(name)),
    done: () => { setSeq++; setSel.value = ''; setDraft.value = null; void l.reload() },
  })
}
const err = (i: number, f: string) => fieldErrors.value[`${i}.${f}`]

// Rename (extension rename, admin in the project; the project's mandatory policy needs a global admin). The editor's
// If-Match goes with it; afterwards the editor shows the object under its new name, and the rules that named a set
// as set:NAME name the new one.
const renamingPolicy = ref(false)
const renamingSet = ref(false)
const mayRenamePolicy = computed(() => canRename('policy', undefined, { mandatory: currentProject.value?.spec.firewall_policies?.includes(selected.value) }))
async function policyRenamed(to: string): Promise<void> {
  selected.value = to
  await l.reload()
  await pick(to)
}
async function setRenamed(to: string): Promise<void> {
  setSel.value = to
  await l.reload()
  await pickSet(to)
  if (selected.value) await pick(selected.value)
}

// create a policy: a name and the two defaults; rules are added in the editor afterwards
const creating = ref(false)
const nf = reactive({ name: '', in: 'deny', out: 'allow' })
const createError = ref<ApiError | null>(null)
const createCheck = useFormCheck(() => ({ 'fwp-name': nameError(nf.name) || ((l.data.value?.policies ?? []).some((p) => p.metadata.name === nf.name) ? s.firewall.exists : '') }))
function openCreate(): void {
  Object.assign(nf, { name: '', in: 'deny', out: 'allow' })
  createError.value = null
  createCheck.reset()
  creating.value = true
}
const create = () => createCheck.submit(async () => {
  createError.value = null
  try {
    await runOp(s.firewall.createTitle + ': ' + nf.name, () => api.firewall.createPolicy({ metadata: { name: nf.name }, spec: { default_in: nf.in, default_out: nf.out, rules: [] } }))
    creating.value = false
    selected.value = ''
    await l.reload()
    await pick(nf.name)
  } catch (e) {
    createError.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  }
})
// Tier 3 while jails use the policy (the server refuses until they are moved), tier 2 otherwise.
function removePolicy(): void {
  const name = selected.value
  const jails = attached.value
  confirmAction({
    title: s.firewall.deleteTitle(name), confirmLabel: s.firewall.delete, danger: true,
    text: jails.length ? `${s.firewall.deleteText} ${s.firewall.deleteAttached(jails.length)}` : s.firewall.deleteText,
    items: jails, itemsLabel: s.firewall.attachedJails, typeName: jails.length ? name : undefined,
    run: () => runOp(s.firewall.deleteTitle(name), () => api.firewall.deletePolicy(name)),
    done: () => { selected.value = ''; draft.value = null; void l.reload() },
  })
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.firewall.title }}</h1><button v-if="tab === 'policies'" class="btn btn-primary" type="button" data-test="new-policy" @click="openCreate"><Icon name="plus" />{{ s.firewall.create }}</button><button v-else-if="l.data.value?.sets.length" class="btn btn-primary" type="button" data-test="new-set" @click="creatingSet = true"><Icon name="plus" />{{ s.firewall.addSet }}</button></div>
    <TabBar v-model="tab" :tabs="tabItems" :label="s.firewall.sections" id="fw" />
    <div id="fw-panel" role="tabpanel" :aria-labelledby="`fw-tab-${tab}`">
    <FirewallTest v-if="tab === 'test'" />
    <LoadState v-else :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div v-if="tab === 'policies'" class="fw-layout">
        <ul class="plain picker" :aria-label="s.firewall.policies">
          <li v-for="p in l.data.value?.policies" :key="p.metadata.name">
            <button type="button" class="btn btn-ghost mono" :class="{ sel: selected === p.metadata.name }" :aria-current="selected === p.metadata.name" @click="pick(p.metadata.name)">{{ p.metadata.name }}</button>
          </li>
          <li v-if="!l.data.value?.policies.length" class="muted">{{ s.firewall.empty }}</li>
        </ul>
        <section v-if="draft" class="panel" data-test="policy-editor">
          <header>
            <div class="row"><h2 class="mono">{{ draft.metadata.name }}</h2><span v-if="dirty" class="pill warn">{{ s.firewall.unsaved }}</span></div>
            <div class="row-actions">
              <span v-if="saveWhy" class="why-disabled" data-test="save-why">{{ saveWhy }}</span>
              <button v-if="mayRenamePolicy" class="btn" type="button" data-test="rename-policy" @click="renamingPolicy = true">{{ s.rename.open(s.rename.kinds.policy) }}</button>
              <button class="btn btn-danger" type="button" data-test="delete-policy" @click="removePolicy">{{ s.firewall.delete }}</button>
              <button class="btn" type="button" :disabled="!dirty" @click="revert">{{ s.firewall.revert }}</button>
              <button class="btn btn-primary" type="button" :disabled="saving" :aria-disabled="!!saveWhy" data-test="save-policy" @click="save">{{ s.firewall.save }}</button>
            </div>
          </header>
          <div class="body stack">
            <ErrorPanel v-if="apiError" :error="apiError" />
            <p v-if="attached.length" class="muted">{{ s.firewall.usedBy }}: <template v-for="(n, i) in attached" :key="n">{{ i ? ', ' : '' }}<router-link :to="`/jails/${n}`" class="mono">{{ n }}</router-link></template></p>
            <div class="field"><label for="pc">{{ s.firewall.comment }}</label>
              <input id="pc" v-model="draft.spec.comment" type="text" maxlength="200" autocomplete="off" :placeholder="s.firewall.policyCommentHint" data-test="policy-comment" /></div>
            <div class="row">
              <div class="field" style="min-width: 160px"><label for="din">{{ s.firewall.defaultIn }}</label>
                <select id="din" v-model="draft.spec.default_in"><option>allow</option><option>deny</option></select></div>
              <div class="field" style="min-width: 160px"><label for="dout">{{ s.firewall.defaultOut }}</label>
                <select id="dout" v-model="draft.spec.default_out"><option>allow</option><option>deny</option></select></div>
            </div>
            <h3>{{ s.firewall.rules }}</h3>
            <p v-if="!rules.length" class="muted">{{ s.firewall.noRules }}</p>
            <ol class="rules">
              <li v-for="(r, i) in rules" :key="i" class="rule" :data-rule="i">
                <div class="rule-head row">
                  <span class="mono faint">{{ i + 1 }}</span>
                  <span v-if="r.disabled" class="faint" data-test="rule-off">{{ s.firewall.disabled }}</span>
                  <input v-model="r.name" type="text" :placeholder="s.firewall.ruleName" :aria-label="s.firewall.ruleName + ' ' + (i + 1)" style="max-width: 200px" />
                  <input v-model="r.comment" class="grow" type="text" maxlength="200" autocomplete="off" :placeholder="s.firewall.ruleComment" :aria-label="s.firewall.ruleComment + ' ' + (i + 1)" data-test="rule-comment" />
                  <button class="btn btn-sm btn-icon" type="button" :aria-label="s.firewall.moveUp" :disabled="i === 0" @click="move(i, -1)"><Icon name="arrowUp" /></button>
                  <button class="btn btn-sm btn-icon" type="button" :aria-label="s.firewall.moveDown" :disabled="i === rules.length - 1" @click="move(i, 1)"><Icon name="arrowDown" /></button>
                  <button class="btn btn-sm btn-icon btn-danger" type="button" :aria-label="s.firewall.removeRule" @click="remove(i)"><Icon name="trash" /></button>
                </div>
                <div class="rule-grid">
                  <div class="field"><label :for="`a${i}`">{{ s.firewall.action }}</label><select :id="`a${i}`" v-model="r.action"><option>allow</option><option>deny</option></select></div>
                  <div class="field"><label :for="`d${i}`">{{ s.firewall.direction }}</label><select :id="`d${i}`" v-model="r.direction"><option>in</option><option>out</option></select></div>
                  <div class="field"><label :for="`p${i}`">{{ s.firewall.proto }}</label><select :id="`p${i}`" v-model="r.proto"><option value="">{{ s.firewall.any }}</option><option>tcp</option><option>udp</option><option>icmp</option><option>icmp6</option></select></div>
                  <div class="field"><label :for="`f${i}`">{{ s.firewall.from }}</label><input :id="`f${i}`" class="mono" type="text" :value="(r.from ?? []).join(', ')" :placeholder="s.firewall.any" @input="list(r, 'from', ($event.target as HTMLInputElement).value)" /></div>
                  <div class="field"><label :for="`t${i}`">{{ s.firewall.to }}</label><input :id="`t${i}`" class="mono" type="text" :value="(r.to ?? []).join(', ')" :placeholder="s.firewall.any" @input="list(r, 'to', ($event.target as HTMLInputElement).value)" /></div>
                  <div class="field">
                    <label :for="`o${i}`">{{ s.firewall.ports }}</label>
                    <input :id="`o${i}`" class="mono" type="text" :class="{ invalid: err(i, 'ports') }" :value="(r.ports ?? []).join(', ')" :aria-invalid="!!err(i, 'ports')" :aria-describedby="err(i, 'ports') ? `oe${i}` : undefined" @input="list(r, 'ports', ($event.target as HTMLInputElement).value)" />
                    <span v-if="err(i, 'ports')" :id="`oe${i}`" class="err" data-test="field-error">{{ err(i, 'ports') }}</span>
                  </div>
                </div>
                <span v-for="f in (['from', 'to', 'action', 'direction', 'proto'] as const)" :key="f"><span v-if="err(i, f)" class="err" data-test="field-error">{{ f }}: {{ err(i, f) }}</span></span>
                <div class="row">
                  <label class="check"><input v-model="r.log" type="checkbox" />{{ s.firewall.log }}</label>
                  <label class="check" :title="s.firewall.disabledHint"><input v-model="r.disabled" type="checkbox" data-test="rule-disabled" />{{ s.firewall.disabled }}</label>
                  <label class="check" :title="canForward ? undefined : s.firewall.redirectGlobal"><input type="checkbox" :checked="!!r.redirect" :disabled="!canForward" data-test="rule-redirect" @change="toggleRedirect(r, ($event.target as HTMLInputElement).checked)" />{{ s.firewall.redirect }}</label>
                  <template v-if="r.redirect">
                    <input v-model.number="r.redirect.host_port" type="number" min="1" max="65535" :disabled="!canForward" :aria-label="s.firewall.hostPort" style="width: 90px" />
                    <span class="faint">{{ s.firewall.to2 }}</span>
                    <input v-model.number="r.redirect.jail_port" type="number" min="1" max="65535" :disabled="!canForward" :aria-label="s.firewall.jailPort" style="width: 90px" />
                  </template>
                  <span v-if="err(i, 'redirect')" class="err" data-test="field-error">{{ err(i, 'redirect') }}</span>
                </div>
              </li>
            </ol>
            <div><button class="btn" type="button" @click="add"><Icon name="plus" />{{ s.firewall.addRule }}</button></div>
            <div class="field">
              <label for="raw">{{ s.firewall.raw }}</label>
              <textarea id="raw" v-model="draft.spec.raw" rows="4" spellcheck="false"></textarea>
            </div>
          </div>
        </section>
      </div>

      <div v-else-if="!l.data.value?.sets.length" class="panel empty-sets" data-test="sets-empty">
        <div class="body stack">
          <h2>{{ s.firewall.emptySets }}</h2>
          <p class="muted">{{ s.firewall.emptySetsText }}</p>
          <div><button class="btn btn-primary" type="button" data-test="new-set-empty" @click="creatingSet = true"><Icon name="plus" />{{ s.firewall.addSet }}</button></div>
        </div>
      </div>
      <div v-else class="fw-layout">
        <ul class="plain picker" :aria-label="s.firewall.sets" data-test="set-list">
          <li v-for="a in l.data.value?.sets" :key="a.metadata.name"><button type="button" class="btn btn-ghost mono" :class="{ sel: setSel === a.metadata.name }" :aria-current="setSel === a.metadata.name" @click="pickSet(a.metadata.name)">set:{{ a.metadata.name }}</button></li>
        </ul>
        <section v-if="setDraft" class="panel" data-test="set-editor">
          <header>
            <div class="row"><h2 class="mono">set:{{ setDraft.metadata.name }}</h2><span v-if="setDirty" class="pill warn">{{ s.firewall.unsaved }}</span></div>
            <div class="row-actions">
              <span v-if="setWhy" class="why-disabled" data-test="set-save-why">{{ setWhy }}</span>
              <button v-if="canRename('addressSet')" class="btn" type="button" data-test="rename-set" @click="renamingSet = true">{{ s.rename.open(s.rename.kinds.addressSet) }}</button>
              <button class="btn btn-danger" type="button" data-test="delete-set" @click="removeSet">{{ s.firewall.deleteSet }}</button>
              <button class="btn" type="button" :disabled="!setDirty" @click="revertSet">{{ s.firewall.revert }}</button>
              <button class="btn btn-primary" type="button" :disabled="setSaving" :aria-disabled="!!setWhy" data-test="save-set" @click="saveSet">{{ s.firewall.saveSet }}</button>
            </div>
          </header>
          <div class="body stack">
            <ErrorPanel v-if="setError" :error="setError" />
            <p v-if="users.policies.length || users.sets.length" class="muted" data-test="set-users">{{ s.firewall.setUsedBy }}:
              <template v-for="(n, i) in users.policies" :key="'p' + n">{{ i ? ', ' : '' }}<router-link :to="`/firewall?policy=${n}`" class="mono">{{ n }}</router-link></template><template v-for="(n, i) in users.sets" :key="'s' + n">{{ i || users.policies.length ? ', ' : '' }}<span class="mono">set:{{ n }}</span></template></p>
            <div class="field"><label for="sc">{{ s.firewall.comment }}</label>
              <input id="sc" v-model="setComment" type="text" maxlength="200" autocomplete="off" :placeholder="s.firewall.setCommentHint" data-test="set-comment" /></div>
            <div class="field"><label for="sa">{{ s.firewall.addresses }}</label>
              <textarea id="sa" v-model="setText" class="mono" rows="8" spellcheck="false" :aria-invalid="!!setErrors.addresses" aria-describedby="sa-h sa-e" @input="setErrors.addresses = undefined"></textarea>
              <span id="sa-h" class="hint">{{ s.firewall.membersHint }}</span>
              <span id="sa-e" class="field-error" role="alert">{{ setErrors.addresses }}</span></div>
          </div>
        </section>
      </div>
    </LoadState>
    </div>
    <RenameDialog :open="renamingPolicy" kind="policy" :name="selected" :etag="etag" @close="renamingPolicy = false" @done="policyRenamed" />
    <RenameDialog :open="renamingSet" kind="addressSet" :name="setSel" :etag="setEtag" @close="renamingSet = false" @done="setRenamed" />
    <AddressSetCreateDialog :open="creatingSet" :sets="l.data.value?.sets ?? []" @close="creatingSet = false" @created="setCreated" />
    <Modal :open="creating" :title="s.firewall.createTitle" @close="creating = false">
      <form id="fwp" novalidate @submit.prevent="create">
        <div class="field"><label for="fwp-name">{{ s.firewall.name }} <span class="req" aria-hidden="true">*</span></label>
          <input id="fwp-name" v-model="nf.name" class="mono" type="text" autocomplete="off" :aria-invalid="!!createCheck.err('fwp-name')" aria-describedby="fwp-name-h fwp-name-e" @input="createCheck.touch('fwp-name')" />
          <span id="fwp-name-h" class="hint">{{ nameHint() }}</span>
          <span id="fwp-name-e" class="field-error" role="alert">{{ createCheck.err('fwp-name') }}</span></div>
        <div class="form-2">
          <div class="field"><label for="fwp-in">{{ s.firewall.defaultIn }}</label><select id="fwp-in" v-model="nf.in"><option>deny</option><option>allow</option></select></div>
          <div class="field"><label for="fwp-out">{{ s.firewall.defaultOut }}</label><select id="fwp-out" v-model="nf.out"><option>allow</option><option>deny</option></select></div>
        </div>
        <ErrorPanel v-if="createError" :error="createError" />
      </form>
      <template #footer>
        <span v-if="createCheck.reason.value" class="why-disabled">{{ s.firewall.name }}: {{ createCheck.reason.value }}</span>
        <button class="btn" type="button" @click="creating = false">{{ s.app.cancel }}</button>
        <button class="btn btn-primary" type="submit" form="fwp" :aria-disabled="!createCheck.ok.value" data-test="policy-create-go">{{ s.firewall.createGo }}</button>
      </template>
    </Modal>
  </div>
</template>

<style>
.fw-layout { display: grid; grid-template-columns: 220px minmax(0, 1fr); gap: 12px; align-items: start; }
.picker { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 4px; }
.picker .btn { width: 100%; justify-content: flex-start; }
.picker .btn.sel { background: var(--accent-soft); font-weight: 600; }
.rules { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
.rule { border: 1px solid var(--border); border-radius: var(--radius); padding: 8px; background: var(--surface-2); }
.rule-head { margin-bottom: 8px; }
.rule-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0 8px; }
.rule .field { margin-bottom: 8px; }
.rule .err { display: block; }
@media (max-width: 800px) { .fw-layout { grid-template-columns: minmax(0, 1fr); } }
</style>
