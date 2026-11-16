<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import { useFormCheck } from '@jailops/shared/composables/form'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { nameHint, nameProblem } from '@jailops/shared/lib/names'
import Icon from '@jailops/shared/components/Icon.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import TabBar from '@jailops/shared/components/TabBar.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import TokenManager, { type TokenForm } from '@jailops/shared/components/TokenManager.vue'
import RoleNote from '@/components/RoleNote.vue'
import { allows } from '@/lib/roles'
import type { NodeRole, NodeUser } from '@/types'

const admin = computed(() => allows(session.role, 'admin'))
const l = useLoad(async () => (admin.value ? { users: await api.users.list(), tokens: await api.tokens.list() } : { users: [], tokens: [] }))
const { tab } = useTabQuery(() => ['users', 'tokens'] as const, 'users')
const tabs = computed(() => [
  { key: 'users' as const, label: s.access.users, count: l.data.value?.users.length },
  { key: 'tokens' as const, label: s.access.tokens, count: l.data.value?.tokens.length },
])
const mgr = ref<InstanceType<typeof TokenManager> | null>(null)
const roles: NodeRole[] = ['readonly', 'backup-admin', 'admin']
const roleOptions = roles.map((r) => ({ value: r, text: s.roles.text[r] }))
const rows = computed(() => (l.data.value?.tokens ?? []).map((t) => ({ name: t.name, role: t.role, expires_at: t.expires_at, allow_from: t.allow_from })))
const createToken = (f: TokenForm) => api.tokens.create({ name: f.name, role: f.role as NodeRole, ...(f.allow_from ? { allow_from: f.allow_from } : {}), ...(f.expires_at ? { expires_at: f.expires_at } : {}) })
const removeToken = (n: string) => api.tokens.remove(n)

const editing = ref<'new' | NodeUser | null>(null)
const form = reactive({ name: '', password: '', role: 'readonly' as NodeRole, disabled: false })
const busy = ref(false)
const error = ref<ApiError | null>(null)
const check = useFormCheck((): Record<string, string> => (editing.value === 'new'
  ? { 'us-name': form.name ? nameProblem(form.name, 'node') : s.access.nameMissing, 'us-pw': form.password.length >= 12 ? '' : s.access.passwordMissing }
  : { 'us-pw': !form.password || form.password.length >= 12 ? '' : s.access.passwordMissing }))
function openUser(u: 'new' | NodeUser): void {
  editing.value = u
  Object.assign(form, u === 'new' ? { name: '', password: '', role: 'readonly', disabled: false } : { name: u.name, password: '', role: u.role, disabled: u.disabled })
  error.value = null
  check.reset()
}
async function saveUser(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    if (editing.value === 'new') await runOp(s.access.userTitle(form.name), () => api.users.create({ name: form.name, password: form.password, role: form.role }))
    else await runOp(s.access.editUser(form.name), () => api.users.update(form.name, { role: form.role, disabled: form.disabled, ...(form.password ? { password: form.password } : {}) }))
    editing.value = null
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
function askDelete(u: NodeUser): void {
  confirmAction({
    title: s.access.deleteTitle(u.name), confirmLabel: s.access.deleteUser, danger: true, text: s.access.deleteText, typeName: u.name, typeLabel: s.access.typeName(u.name),
    run: () => runOp(s.access.deleteTitle(u.name), () => api.users.remove(u.name)), done: () => void l.reload(),
  })
}
</script>

<template>
  <div>
    <div class="page-head">
      <h1>{{ s.access.title }}</h1>
      <button v-if="admin && tab === 'users'" class="btn btn-primary" type="button" data-test="new-user" @click="openUser('new')"><Icon name="plus" />{{ s.access.newUser }}</button>
      <button v-if="admin && tab === 'tokens'" class="btn btn-primary" type="button" @click="mgr?.openCreate()"><Icon name="plus" />{{ s.access.newToken }}</button>
    </div>
    <RoleNote need="admin" gate />
    <section class="panel" style="margin-bottom: 12px">
      <header><h2>{{ s.access.rolesTitle }}</h2></header>
      <dl class="body kv"><template v-for="r in roles" :key="r"><dt class="mono">{{ r }}</dt><dd>{{ s.roles.text[r] }}</dd></template></dl>
    </section>
    <template v-if="admin">
      <TabBar v-model="tab" :tabs="tabs" :label="s.access.sections" id="access" />
      <div id="access-panel" role="tabpanel" :aria-labelledby="`access-tab-${tab}`">
        <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
          <div v-if="tab === 'users'" class="panel">
            <p v-if="!l.data.value?.users.length" class="empty">{{ s.access.noUsers }}</p>
            <div v-else class="table-wrap"><table class="rtable">
              <thead><tr><th>{{ s.access.userName }}</th><th>{{ s.access.role }}</th><th class="hide-sm">{{ s.access.created }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
              <tbody><tr v-for="u in l.data.value?.users" :key="u.name" :data-user="u.name"><td class="mono" :data-label="s.access.userName">{{ u.name }}<span v-if="u.disabled" class="pill warn" style="margin-left: 6px">{{ s.access.disabled }}</span></td><td class="mono" :data-label="s.access.role">{{ u.role }}</td><td class="faint hide-sm" :data-label="s.access.created"><TimeStamp :ts="u.created_at" /></td>
                <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" @click="openUser(u)" :aria-label="`${s.access.edit} ${u.name}`">{{ s.access.edit }}</button><button class="btn btn-sm btn-danger" type="button" :disabled="u.name === session.user" :title="u.name === session.user ? s.access.selfDelete : undefined" @click="askDelete(u)" :aria-label="`${s.access.deleteUser} ${u.name}`">{{ s.access.deleteUser }}</button></div></td></tr></tbody></table></div>
          </div>
          <TokenManager v-show="tab === 'tokens'" ref="mgr" :tokens="rows" :roles="roleOptions" :create="createToken" :remove="removeToken" name-rule="node" @changed="l.reload" />
        </LoadState>
      </div>
    </template>

    <Modal :open="!!editing" :title="editing === 'new' ? s.access.newUser : s.access.editUser(form.name)" @close="editing = null">
      <form id="us" novalidate @submit.prevent="check.submit(saveUser)">
        <p v-if="editing === 'new'" class="hint faint">{{ s.form.requiredNote }}</p>
        <div v-if="editing === 'new'" class="field"><label for="us-name">{{ s.access.userName }} <span class="req" aria-hidden="true">*</span></label><input id="us-name" v-model="form.name" class="mono" type="text" required aria-describedby="us-name-hint" :aria-invalid="!!check.err('us-name')" @blur="form.name && check.touch('us-name')" /><span id="us-name-hint" class="hint">{{ nameHint('node') }}</span><span v-if="check.err('us-name')" class="field-error" role="alert">{{ check.err('us-name') }}</span></div>
        <div class="field"><label for="us-pw">{{ editing === 'new' ? s.access.password : s.access.newPassword }} <span v-if="editing === 'new'" class="req" aria-hidden="true">*</span></label><input id="us-pw" v-model="form.password" type="password" autocomplete="new-password" :required="editing === 'new'" aria-describedby="us-pw-hint" :aria-invalid="!!check.err('us-pw')" @blur="form.password && check.touch('us-pw')" /><span id="us-pw-hint" class="hint">{{ s.access.passwordHint }}</span><span v-if="check.err('us-pw')" class="field-error" role="alert">{{ check.err('us-pw') }}</span></div>
        <div class="field"><label for="us-role">{{ s.access.role }}</label><select id="us-role" v-model="form.role"><option v-for="r in roles" :key="r" :value="r">{{ r }}</option></select><span class="hint">{{ s.roles.text[form.role] }}</span></div>
        <label v-if="editing !== 'new'" class="check"><input v-model="form.disabled" type="checkbox" />{{ s.access.disabled }}</label>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><span v-if="check.reason.value" class="why-disabled">{{ check.reason.value }}</span><button class="btn" type="button" @click="editing = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="us" :disabled="busy" :aria-disabled="!check.ok.value" data-test="user-save">{{ editing === 'new' ? s.access.createUser : s.access.save }}</button></template>
    </Modal>
  </div>
</template>
