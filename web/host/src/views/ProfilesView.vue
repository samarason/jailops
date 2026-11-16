<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import { useFormCheck } from '@jailops/shared/composables/form'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { nameHint } from '@jailops/shared/lib/names'
import { nameError } from '@/lib/nameField'
import TabBar from '@jailops/shared/components/TabBar.vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { ApiError } from '@jailops/shared/api/client'
import Icon from '@jailops/shared/components/Icon.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import { checkProfile } from '@/lib/configKeys'
import { projectState } from '@/composables/project'
import RenameDialog from '@/components/RenameDialog.vue'
import { canRename } from '@/composables/rename'
import { ifMatch } from '@/lib/rename'
import type { Profile } from '@jailops/shared/api/types'

const { tab: scope } = useTabQuery(() => ['project', 'host'] as const, 'project')
const scopeTabs = computed(() => [{ key: 'project' as const, label: s.profiles.ofProject(projectState.current) }, { key: 'host' as const, label: s.profiles.ofHost }])
const l = useLoad(async () => ({ list: await api.profiles.list(scope.value === 'host' ? 'host' : undefined), jails: await api.jails.list().catch(() => []) }))
const usedBy = (n: string) => (l.data.value?.jails ?? []).filter((j) => (j.spec.profiles ?? []).includes(n)).map((j) => j.metadata.name)

const editing = ref<Profile | 'new' | null>(null)
const f = reactive({ name: '', comment: '', rows: [] as Array<{ key: string; value: string }> })
const busy = ref(false)
const error = ref<ApiError | null>(null)
const msgs = { int: s.config.invalidInt, size: s.config.invalidSize, rate: s.config.invalidRate, mac: s.config.invalidMac, address: s.config.invalidAddress, listen: s.config.invalidListen, bool: s.config.invalidBool, name: s.config.invalidPattern, enum: s.config.invalidEnum }
const config = computed(() => Object.fromEntries(f.rows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value])))
const issues = computed(() => checkProfile(config.value, msgs, { unknown: s.profiles.unknownKey, notAllowed: s.profiles.notAllowed }))
const issueOf = (k: string) => issues.value.find((i) => i.key === k.trim())?.message
watch(scope, () => void l.reload())
// a new profile follows the object name rule; every key must be one the registry knows
const check = useFormCheck(() => ({
  'pr-name': editing.value === 'new' ? nameError(f.name) : '',
  [`pr-key-${f.rows.findIndex((r) => !!issueOf(r.key))}`]: issues.value.length ? s.profiles.fixKeys : '',
}))

function open(p: Profile | 'new'): void {
  editing.value = p
  error.value = null
  check.reset()
  if (p === 'new') Object.assign(f, { name: '', comment: '', rows: [{ key: '', value: '' }] })
  else Object.assign(f, { name: p.metadata.name, comment: p.spec.comment ?? '', rows: Object.entries(p.spec.config ?? {}).map(([key, value]) => ({ key, value })) })
}
const save = () => check.submit(async () => {
  busy.value = true
  error.value = null
  const body: Profile = { metadata: { name: f.name }, spec: { ...(f.comment ? { comment: f.comment } : {}), config: config.value } }
  try {
    if (editing.value === 'new') await runOp(s.profiles.createTitle + ': ' + f.name, () => api.profiles.create(body))
    else await runOp(s.profiles.editTitle(f.name), () => api.profiles.put({ ...(editing.value as Profile), spec: body.spec }))
    editing.value = null
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
})
// Rename (extension rename): admin in the project, a global admin for the host profiles; the jails that list it follow
const renaming = ref<Profile | null>(null)
const scopeProject = computed(() => (scope.value === 'host' ? 'host' : projectState.current))
// tier 2: the jails that list the profile are named
function remove(p: Profile): void {
  const n = p.metadata.name
  confirmAction({
    title: s.profiles.deleteTitle(n), confirmLabel: s.profiles.delete, danger: true, text: s.profiles.deleteText, items: usedBy(n), itemsLabel: s.profiles.deleteUsed,
    run: () => runOp(s.profiles.deleteTitle(n), () => api.profiles.remove(n)),
    done: () => void l.reload(),
  })
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.profiles.title }}</h1><button class="btn btn-primary" type="button" data-test="new-profile" @click="open('new')"><Icon name="plus" />{{ s.profiles.create }}</button></div>
    <p class="muted">{{ s.profiles.lead }}</p>
    <TabBar v-model="scope" :tabs="scopeTabs" :label="s.profiles.sections" id="prof" />
    <div id="prof-panel" role="tabpanel" :aria-labelledby="`prof-tab-${scope}`">
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel">
        <p v-if="!l.data.value?.list.length" class="empty">{{ s.profiles.empty }}</p>
        <div v-else class="table-wrap"><table data-test="profiles-table" class="rtable">
          <thead><tr><th>{{ s.profiles.name }}</th><th>{{ s.profiles.keys }}</th><th>{{ s.profiles.appliedTo }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
          <tbody><tr v-for="p in l.data.value?.list" :key="p.metadata.name" :data-profile="p.metadata.name">
            <td :data-label="s.profiles.name"><span class="mono">{{ p.metadata.name }}</span><div v-if="p.spec.comment" class="faint">{{ p.spec.comment }}</div></td>
            <td class="mono" :data-label="s.profiles.keys"><div v-for="(v, k) in p.spec.config" :key="k">{{ k }}={{ v }}</div></td>
            <td :data-label="s.profiles.appliedTo"><router-link v-for="j in usedBy(p.metadata.name)" :key="j" class="mono chip" :to="`/jails/${j}`">{{ j }}</router-link></td>
            <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" @click="open(p)">{{ s.profiles.edit }}</button><button v-if="canRename('profile', scopeProject)" class="btn btn-sm" type="button" :data-test="`rename-profile-${p.metadata.name}`" @click="renaming = p">{{ s.rename.open(s.rename.kinds.profile) }}</button><button class="btn btn-sm btn-danger" type="button" @click="remove(p)">{{ s.profiles.delete }}</button></div></td>
          </tr></tbody></table></div>
      </div>
    </LoadState>
    </div>

    <RenameDialog :open="!!renaming" kind="profile" :name="renaming?.metadata.name ?? ''" :etag="ifMatch(renaming?.metadata.generation)" :project="scope === 'host' ? 'host' : undefined" @close="renaming = null" @done="l.reload" />
    <Modal :open="!!editing" :title="editing === 'new' ? s.profiles.createTitle : s.profiles.editTitle(f.name)" wide @close="editing = null">
      <form id="pr" novalidate @submit.prevent="save">
        <div class="form-2"><div class="field"><label for="pr-name">{{ s.profiles.name }} <span v-if="editing === 'new'" class="req" aria-hidden="true">*</span></label>
          <input id="pr-name" v-model="f.name" class="mono" type="text" autocomplete="off" :readonly="editing !== 'new'" :aria-invalid="!!check.err('pr-name')" aria-describedby="pr-name-h pr-name-e" @input="check.touch('pr-name')" />
          <span id="pr-name-h" class="hint">{{ editing === 'new' ? nameHint() : s.profiles.nameFixed }}</span><span id="pr-name-e" class="field-error" role="alert">{{ check.err('pr-name') }}</span></div>
          <div class="field"><label for="pr-desc">{{ s.profiles.comment }}</label><input id="pr-desc" v-model="f.comment" type="text" /></div></div>
        <h3>{{ s.profiles.keys }}</h3>
        <div v-for="(r, i) in f.rows" :key="i" class="grant-row grant-sto" :data-row="i">
          <input :id="`pr-key-${i}`" v-model="r.key" class="mono" type="text" list="profile-keys" :aria-label="s.profiles.key" :class="{ invalid: issueOf(r.key) }" />
          <input v-model="r.value" class="mono" type="text" :aria-label="s.profiles.value" />
          <button class="btn btn-sm btn-icon btn-danger" type="button" :aria-label="s.profiles.removeKey" @click="f.rows.splice(i, 1)"><Icon name="trash" /></button>
          <span v-if="issueOf(r.key)" class="err" data-test="profile-issue" style="grid-column: 1 / -1">{{ issueOf(r.key) }}</span>
        </div>
        <button class="btn btn-sm" type="button" @click="f.rows.push({ key: '', value: '' })"><Icon name="plus" />{{ s.profiles.addKey }}</button>
        <ErrorPanel v-if="error" :error="error" style="margin-top: 12px" />
      </form>
      <template #footer><span v-if="check.reason.value" class="why-disabled">{{ check.firstId.value === 'pr-name' ? `${s.profiles.name}: ${check.reason.value}` : check.reason.value }}</span><button class="btn" type="button" @click="editing = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="pr" :disabled="busy" :aria-disabled="!check.ok.value" data-test="profile-save">{{ s.profiles.save }}</button></template>
    </Modal>
  </div>
</template>
