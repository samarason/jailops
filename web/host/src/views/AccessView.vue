<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session, hasExt } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { stamp } from '@jailops/shared/lib/format'
import { nameHint, nameProblem } from '@jailops/shared/lib/names'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import { useFormCheck } from '@jailops/shared/composables/form'
import { confirmAction } from '@jailops/shared/composables/confirm'
import TabBar from '@jailops/shared/components/TabBar.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import CopyField from '@jailops/shared/components/CopyField.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import TokenManager, { type TokenForm } from '@jailops/shared/components/TokenManager.vue'
import ScopePicker from '@/components/ScopePicker.vue'
import { isGlobalAdmin } from '@/composables/project'
import { remoteAddCommand } from '@/lib/trust'
import { publicRemoteAddCommand } from '@/lib/setup'
import type { Certificate, Permission, TrustToken, User } from '@jailops/shared/api/types'

type Tab = 'users' | 'tokens' | 'trust' | 'certs' | 'sessions' | 'whoami'
const tabKeys: Tab[] = ['users', 'tokens', 'trust', 'certs', 'sessions', 'whoami']
// the address keeps the tab (?tab=trust); without one the page opens on Users
const { tab } = useTabQuery(() => tabKeys, 'users')
const tabs = computed(() => tabKeys.map((k) => ({ key: k, label: s.trust.tabs[k] })))
const admin = computed(() => isGlobalAdmin())
const l = useLoad(async () => {
  const [tokens, users, certs, projects, sessions, me] = await Promise.all([
    api.tokens.list().catch(() => []), api.access.users().catch(() => []), api.access.certificates().catch(() => []),
    api.projects.list().catch(() => []), api.trust.sessions().catch(() => []), api.trust.whoami().catch(() => undefined),
  ])
  return { tokens, users, certs, projects: projects.map((p) => p.metadata.name), sessions, me }
})
const names = computed(() => l.data.value?.projects ?? [])
const mgr = ref<InstanceType<typeof TokenManager> | null>(null)
const roles = (['readonly', 'operator', 'admin', 'backup-push', 'backup-pull', 'restore', 'backup-admin'] as const).map((r) => ({ value: r, text: s.access.roles[r] }))
const rows = computed(() => (l.data.value?.tokens ?? []).map((t) => ({ name: t.metadata.name, role: t.spec.permission, expires_at: t.spec.expires_at, allow_from: t.spec.allow_from, projects: t.spec.projects, global: t.spec.global })))
const createToken = (f: TokenForm) => api.tokens.create({ metadata: { name: f.name }, spec: { permission: f.role as Permission, ...(f.expires_at ? { expires_at: f.expires_at } : {}), ...(f.allow_from ? { allow_from: f.allow_from } : {}), ...(f.projects ? { projects: f.projects } : {}), ...(f.global ? { global: true } : {}) } })
const removeToken = (n: string) => api.tokens.remove(n)

// ---- trust token ----
const tf = reactive({ name: '', role: 'operator' as Permission, projects: [] as string[], global: false, ttl: 3600, expires: '' })
const scopeOk = computed(() => tf.global || tf.projects.length > 0)
const busy = ref(false)
const error = ref<ApiError | null>(null)
const issued = ref<TrustToken | null>(null)
// an ISO date (YYYY-MM-DD), never the browser's local date format
const dateOk = (v: string) => /^\d{4}-\d{2}-\d{2}$/.test(v) && Date.parse(v + 'T23:59:59Z') > Date.now()
const tcheck = useFormCheck(() => ({
  'tt-name': tf.name ? nameProblem(tf.name, 'client') : s.trust.nameMissing,
  'tt-scope': scopeOk.value ? '' : s.trust.scopeMissing,
  'tt-exp': !tf.expires || dateOk(tf.expires) ? '' : s.access.expiresRule,
}))
async function createTrust(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    const r = await runOp(s.trust.createTitle(tf.name), () => api.trust.createToken({ name: tf.name, permission: tf.role, ...(tf.global ? { global: true } : { projects: tf.projects }), ttl_seconds: tf.ttl, ...(tf.expires ? { expires_at: new Date(tf.expires + 'T23:59:59Z').toISOString() } : {}) }))
    issued.value = r.data as TrustToken
    tf.name = ''
    tcheck.reset()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
const command = computed(() => (issued.value ? remoteAddCommand(location.host, issued.value.token) : ''))
// A certificate a public CA signed is renewed every few weeks: a trust token pins the one served now, so the client
// breaks at the renewal. With such a certificate an API token and the host's trusted roots are the way in.
const cert = useLoad(async () => (hasExt('host_certificate') && admin.value ? api.host.certificate().catch(() => undefined) : undefined))
const publicCA = computed(() => !!cert.data.value?.current.public_ca)
const publicCommand = computed(() => publicRemoteAddCommand(location.hostname.split('.')[0] || 'host', location.host))

// ---- users ----
const nu = reactive({ name: '', role: 'operator' as Permission, projects: [] as string[], global: false, password: '' })
const creatingUser = ref(false)
const generated = ref<{ user: string; password: string } | null>(null)
const ucheck = useFormCheck(() => ({
  'nu-name': nu.name ? nameProblem(nu.name, 'identity') : s.trust.userNameMissing,
  'nu-scope': nu.global || nu.projects.length ? '' : s.trust.scopeMissing,
}))
function openNewUser(): void {
  Object.assign(nu, { name: '', role: 'operator', projects: [], global: false, password: '' })
  error.value = null
  ucheck.reset()
  creatingUser.value = true
}
async function createUser(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    const r = await runOp(s.trust.newUserTitle, () => api.access.createUser({ metadata: { name: nu.name }, spec: { permission: nu.role, ...(nu.global ? { global: true } : { projects: nu.projects }) }, ...(nu.password ? { password: nu.password } : {}) }))
    creatingUser.value = false
    const out = r.data as { password?: string } | undefined
    if (out?.password) generated.value = { user: nu.name, password: out.password }
    nu.password = ''
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
const pwUser = ref<User | null>(null)
const pw = ref('')
async function setPassword(): Promise<void> {
  busy.value = true
  error.value = null
  const name = pwUser.value!.metadata.name
  try {
    const r = await runOp(s.trust.passwordSet(name), () => api.access.setPassword(name, pw.value))
    pwUser.value = null
    const out = r.data as { password?: string } | undefined
    if (out?.password) generated.value = { user: name, password: out.password }
    pw.value = ''
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
const roleUser = ref<User | null>(null)
const rf = reactive({ permission: 'operator' as Permission, projects: [] as string[], global: false })
function openRole(u: User): void {
  roleUser.value = u
  Object.assign(rf, { permission: u.spec.permission, projects: [...(u.spec.projects ?? [])], global: !!u.spec.global })
  error.value = null
}
async function saveRole(): Promise<void> {
  busy.value = true
  error.value = null
  const name = roleUser.value!.metadata.name
  try {
    await runOp(s.trust.roleTitle(name), () => api.access.patchUser(name, { permission: rf.permission, global: rf.global, projects: rf.global ? (null as unknown as string[]) : rf.projects }))
    roleUser.value = null
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
function askDeleteUser(u: User): void {
  const n = u.metadata.name
  confirmAction({
    title: s.trust.deleteUserTitle(n), confirmLabel: s.trust.deleteUser, danger: true, text: s.trust.deleteUserText, items: s.trust.deleteUserItems(n),
    typeName: n, typeLabel: s.trust.typeName(n), run: () => runOp(s.trust.deleteUserTitle(n), () => api.access.deleteUser(n)), done: () => void l.reload(),
  })
}

// ---- certificates ----
const editing = ref<Certificate | null>(null)
const ef = reactive({ permission: 'operator' as Permission, projects: [] as string[], global: false })
function openEdit(c: Certificate): void {
  editing.value = c
  Object.assign(ef, { permission: c.spec.permission, projects: [...(c.spec.projects ?? [])], global: !!c.spec.global })
  error.value = null
}
async function saveCert(): Promise<void> {
  busy.value = true
  error.value = null
  const c = editing.value!
  const spec = { ...c.spec, permission: ef.permission, projects: ef.global ? undefined : ef.projects, global: ef.global || undefined }
  try {
    await runOp(s.trust.editTitle(c.metadata.name), () => api.trust.putCertificate({ ...c, spec }))
    editing.value = null
    await l.reload()
  } catch (e) {
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}
function askRevokeCert(c: Certificate): void {
  const n = c.metadata.name
  confirmAction({
    title: s.trust.revokeTitle(n), confirmLabel: s.trust.revoke, danger: true, text: s.trust.revokeText, typeName: n, typeLabel: s.trust.typeName(n),
    run: () => runOp(s.trust.revokeTitle(n), () => api.access.deleteCertificate(n)), done: () => void l.reload(),
  })
}
function askRevokeSession(x: import('@jailops/shared/api/types').Session): void {
  confirmAction({
    title: s.trust.revokeSessionTitle(x.user), confirmLabel: s.trust.revokeSession, danger: true,
    text: x.current ? s.trust.revokeCurrent : s.trust.revokeSessionText(x.user),
    run: () => runOp(s.trust.revokeSessionTitle(x.user), () => api.trust.revokeSession(x.id)), done: () => void l.reload(),
  })
}
const scopeText = (x: { projects?: string[]; global?: boolean }) => (x.global ? '' : (x.projects ?? []).join(', '))
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.access.title }}</h1><button v-if="tab === 'tokens'" class="btn btn-primary" type="button" @click="mgr?.openCreate()"><Icon name="plus" />{{ s.access.newToken }}</button><button v-if="tab === 'users'" class="btn btn-primary" type="button" :disabled="!admin" data-test="user-new" @click="openNewUser"><Icon name="plus" />{{ s.trust.newUser }}</button></div>
    <Callout v-if="!admin" style="margin-bottom: 12px">{{ s.trust.notAllowed }}</Callout>
    <TabBar v-model="tab" :tabs="tabs" :label="s.trust.sections" id="access" />
    <div id="access-panel" role="tabpanel" :aria-labelledby="`access-tab-${tab}`">
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <TokenManager v-show="tab === 'tokens'" ref="mgr" :tokens="rows" :roles="roles" :project-names="names" :create="createToken" :remove="removeToken" @changed="l.reload" />

      <section v-if="tab === 'trust'" class="panel" data-test="trust-panel">
        <header><h2>{{ s.trust.newTrust }}</h2></header>
        <form class="body" style="max-width: 520px" novalidate @submit.prevent="tcheck.submit(createTrust)">
          <p class="muted">{{ s.trust.lead }}</p>
          <p class="hint faint">{{ s.form.requiredNote }}</p>
          <div class="field"><label for="tt-name">{{ s.trust.name }} <span class="req" aria-hidden="true">*</span></label><input id="tt-name" v-model="tf.name" class="mono" type="text" required aria-describedby="tt-name-hint" :aria-invalid="!!tcheck.err('tt-name')" @blur="tf.name && tcheck.touch('tt-name')" /><span id="tt-name-hint" class="hint">{{ nameHint('client') }}</span><span v-if="tcheck.err('tt-name')" class="field-error" role="alert">{{ tcheck.err('tt-name') }}</span></div>
          <div class="field"><label for="tt-role">{{ s.trust.role }}</label><select id="tt-role" v-model="tf.role"><option v-for="r in roles" :key="r.value" :value="r.value">{{ r.value }}</option></select><span class="hint">{{ s.access.roles[tf.role] }}</span></div>
          <ScopePicker v-model:projects="tf.projects" v-model:global="tf.global" :names="names" :show-error="tcheck.tried.value" first-id="tt-scope" />
          <div class="field"><label for="tt-ttl">{{ s.trust.ttl }}</label><select id="tt-ttl" v-model.number="tf.ttl"><option v-for="(t, sec) in s.trust.ttls" :key="sec" :value="Number(sec)">{{ t }}</option></select></div>
          <div class="field"><label for="tt-exp">{{ s.trust.certExpiry }}</label><input id="tt-exp" v-model="tf.expires" class="mono" type="text" inputmode="numeric" placeholder="YYYY-MM-DD" autocomplete="off" aria-describedby="tt-exp-hint" :aria-invalid="!!tcheck.err('tt-exp')" @blur="tf.expires && tcheck.touch('tt-exp')" /><span id="tt-exp-hint" class="hint">{{ s.trust.certExpiryHint }}</span><span v-if="tcheck.err('tt-exp')" class="field-error" role="alert">{{ tcheck.err('tt-exp') }}</span></div>
          <ErrorPanel v-if="error && !editing" :error="error" />
          <div class="row">
            <button class="btn btn-primary" type="submit" :disabled="busy || !admin" :aria-disabled="!tcheck.ok.value" data-test="trust-create">{{ s.trust.create }}</button>
            <span v-if="admin && tcheck.reason.value" class="why-disabled" data-test="trust-why">{{ tcheck.reason.value }}</span>
          </div>
        </form>
      </section>

      <div v-if="tab === 'certs'" class="panel">
        <p v-if="!l.data.value?.certs.length" class="empty">{{ s.trust.noCerts }}</p>
        <div v-else class="table-wrap"><table class="rtable" data-test="certs">
          <thead><tr><th>{{ s.jails.name }}</th><th>{{ s.trust.kind }}</th><th>{{ s.access.permission }}</th><th>{{ s.trust.scope }}</th><th class="hide-sm">{{ s.trust.expires }}</th><th><span class="sr-only">{{ s.trust.actions }}</span></th></tr></thead>
          <tbody><tr v-for="c in l.data.value?.certs" :key="c.metadata.name" :data-cert="c.metadata.name">
            <td class="mono" :data-label="s.jails.name">{{ c.metadata.name }}<div class="faint mono" :title="c.spec.fingerprint">{{ c.spec.fingerprint.slice(0, 23) }}</div></td>
            <td :data-label="s.trust.kind">{{ c.spec.kind }}</td><td class="mono" :data-label="s.access.permission">{{ c.spec.permission }}</td>
            <td :data-label="s.trust.scope"><span v-if="c.spec.global" class="badge warn" data-test="global-badge">{{ s.trust.global2 }}</span><template v-else><span v-for="p in c.spec.projects ?? []" :key="p" class="chip mono">{{ p }}</span><span v-if="!c.spec.projects?.length" class="pill danger">{{ s.trust.noScope }}</span></template></td>
            <td class="faint hide-sm" :data-label="s.trust.expires"><TimeStamp :ts="c.spec.expires_at" /></td>
            <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" :disabled="!admin" :aria-label="`${s.trust.edit} ${c.metadata.name}`" @click="openEdit(c)">{{ s.trust.edit }}</button><button class="btn btn-sm btn-danger" type="button" :disabled="!admin" data-test="cert-revoke" :aria-label="`${s.trust.revoke} ${c.metadata.name}`" @click="askRevokeCert(c)">{{ s.trust.revoke }}</button></div></td>
          </tr></tbody></table></div>
      </div>

      <div v-if="tab === 'users'" class="panel">
        <p v-if="!l.data.value?.users.length" class="empty">{{ s.trust.noUsers }}</p>
        <div v-else class="table-wrap"><table class="rtable" data-test="users">
          <thead><tr><th>{{ s.login.username }}</th><th>{{ s.access.permission }}</th><th>{{ s.trust.scope }}</th><th>{{ s.access.totp }}</th><th><span class="sr-only">{{ s.access.disabled }}</span></th><th><span class="sr-only">{{ s.trust.actions }}</span></th></tr></thead>
          <tbody><tr v-for="u in l.data.value?.users" :key="u.metadata.name" :data-user="u.metadata.name"><td class="mono" :data-label="s.login.username">{{ u.metadata.name }}</td><td class="mono" :data-label="s.access.permission">{{ u.spec.permission }}</td>
            <td :data-label="s.trust.scope"><span v-if="u.spec.global" class="badge warn">{{ s.trust.global2 }}</span><template v-else>{{ scopeText(u.spec) || '-' }}</template></td>
            <td :data-label="s.access.totp">{{ u.spec.totp ? s.trust.on : s.trust.off }}</td><td data-label=""><span v-if="u.spec.disabled" class="pill warn">{{ s.access.disabled }}</span></td>
            <td class="actions"><div class="row-actions"><button class="btn btn-sm" type="button" :disabled="!admin" data-test="user-role" :aria-label="`${s.trust.setRole} ${u.metadata.name}`" @click="openRole(u)">{{ s.trust.setRole }}</button><button class="btn btn-sm" type="button" :disabled="!admin" data-test="user-password" :aria-label="`${s.trust.setPassword} ${u.metadata.name}`" @click="pwUser = u; pw = ''; error = null">{{ s.trust.setPassword }}</button><button class="btn btn-sm btn-danger" type="button" :disabled="!admin" data-test="user-delete" :aria-label="`${s.trust.deleteUser} ${u.metadata.name}`" @click="askDeleteUser(u)">{{ s.trust.deleteUser }}</button></div></td></tr></tbody></table></div>
      </div>

      <div v-if="tab === 'sessions'" class="panel">
        <p v-if="!l.data.value?.sessions.length" class="empty">{{ s.trust.noSessions }}</p>
        <div v-else class="table-wrap"><table class="rtable" data-test="sessions">
          <thead><tr><th>{{ s.trust.user }}</th><th class="hide-sm">{{ s.trust.remote }}</th><th class="hide-sm">{{ s.trust.created }}</th><th>{{ s.trust.lastSeen }}</th><th class="hide-sm">{{ s.trust.sessionExpires }}</th><th><span class="sr-only">{{ s.trust.actions }}</span></th></tr></thead>
          <tbody><tr v-for="x in l.data.value?.sessions" :key="x.id" :data-session="x.id">
            <td class="mono" :data-label="s.trust.user">{{ x.user }}<span v-if="x.current" class="pill info" style="margin-left: 6px">{{ s.trust.current }}</span></td><td class="mono hide-sm" :data-label="s.trust.remote">{{ x.remote || '-' }}</td>
            <td class="faint hide-sm" :data-label="s.trust.created"><TimeStamp :ts="x.created_at" /></td><td class="faint" :data-label="s.trust.lastSeen"><TimeStamp :ts="x.last_seen" /></td><td class="faint hide-sm" :data-label="s.trust.sessionExpires"><TimeStamp :ts="x.expires_at" /></td>
            <td class="actions"><button class="btn btn-sm btn-danger" type="button" :aria-label="`${s.trust.revokeSession} ${x.user}`" @click="askRevokeSession(x)">{{ s.trust.revokeSession }}</button></td></tr></tbody></table></div>
      </div>

      <section v-if="tab === 'whoami'" class="panel" data-test="whoami-panel"><header><h2>{{ s.trust.whoami }}</h2></header>
        <dl v-if="l.data.value?.me" class="body kv">
          <dt>{{ s.trust.user }}</dt><dd class="mono">{{ l.data.value.me.user }}</dd>
          <dt>{{ s.trust.kindLabel }}</dt><dd class="mono">{{ l.data.value.me.kind }}</dd>
          <dt>{{ s.trust.permission }}</dt><dd class="mono">{{ l.data.value.me.permission }}</dd>
          <dt>{{ s.trust.scopeLabel }}</dt><dd><span v-if="l.data.value.me.global" class="badge warn">{{ s.trust.global2 }}</span><template v-else><span v-for="p in l.data.value.me.projects ?? []" :key="p" class="chip mono">{{ p }}</span><span v-if="!l.data.value.me.projects?.length" class="pill danger">{{ s.trust.noScope }}</span></template></dd>
        </dl><p v-else class="empty">-</p></section>
    </LoadState>
    </div>

    <Modal :open="!!issued" :title="s.trust.createTitle(issued?.name ?? '')" wide @close="() => {}">
      <Callout tone="warn">{{ s.trust.shownOnce }}</Callout>
      <div class="field" style="margin-top: 12px"><span class="label">{{ s.trust.token }}</span><CopyField :value="issued?.token ?? ''" :label="s.trust.token" /></div>
      <div class="field"><span class="label">{{ s.trust.command }}</span><CopyField :value="command" label="command" /></div>
      <template v-if="publicCA">
        <Callout tone="info" data-test="public-ca">{{ s.trust.publicCA }}</Callout>
        <div class="field" style="margin-top: 12px"><span class="label">{{ s.trust.publicCommand }}</span><CopyField :value="publicCommand" label="public-command" /></div>
      </template>
      <p v-if="issued" class="faint">{{ s.trust.expiresAt(stamp(issued.expires_at)) }}</p>
      <template #footer><button class="btn btn-primary" type="button" data-test="secret-done" @click="issued = null; l.reload()">{{ s.access.done }}</button></template>
    </Modal>

    <Modal :open="creatingUser" :title="s.trust.newUserTitle" @close="creatingUser = false">
      <form id="nu" novalidate @submit.prevent="ucheck.submit(createUser)">
        <p class="hint faint">{{ s.form.requiredNote }}</p>
        <div class="field"><label for="nu-name">{{ s.trust.userName }} <span class="req" aria-hidden="true">*</span></label><input id="nu-name" v-model="nu.name" class="mono" type="text" required autocomplete="off" aria-describedby="nu-name-hint" :aria-invalid="!!ucheck.err('nu-name')" @blur="nu.name && ucheck.touch('nu-name')" /><span id="nu-name-hint" class="hint">{{ nameHint('identity') }}</span><span v-if="ucheck.err('nu-name')" class="field-error" role="alert">{{ ucheck.err('nu-name') }}</span></div>
        <div class="field"><label for="nu-role">{{ s.trust.role }}</label><select id="nu-role" v-model="nu.role"><option v-for="r in roles" :key="r.value" :value="r.value">{{ r.value }}</option></select><span class="hint">{{ s.access.roles[nu.role] }}</span></div>
        <ScopePicker v-model:projects="nu.projects" v-model:global="nu.global" :names="names" :show-error="ucheck.tried.value" first-id="nu-scope" />
        <div class="field"><label for="nu-pw">{{ s.trust.userPassword }}</label><input id="nu-pw" v-model="nu.password" type="password" autocomplete="new-password" /><span class="hint">{{ s.trust.passwordHint }}</span></div>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><span v-if="ucheck.reason.value" class="why-disabled">{{ ucheck.reason.value }}</span><button class="btn" type="button" @click="creatingUser = false">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="nu" :disabled="busy" :aria-disabled="!ucheck.ok.value" data-test="user-create">{{ s.trust.createUser }}</button></template>
    </Modal>

    <Modal :open="!!pwUser" :title="s.trust.passwordSet(pwUser?.metadata.name ?? '')" @close="pwUser = null">
      <form id="up" @submit.prevent="setPassword">
        <p class="muted">{{ s.trust.passwordText }}</p>
        <div class="field"><label for="up-pw">{{ s.trust.userPassword }}</label><input id="up-pw" v-model="pw" type="password" autocomplete="new-password" /><span class="hint">{{ s.trust.passwordGenerate }}</span></div>
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><button class="btn" type="button" @click="pwUser = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="up" :disabled="busy" data-test="user-password-go">{{ s.trust.setPassword }}</button></template>
    </Modal>

    <Modal :open="!!roleUser" :title="s.trust.roleTitle(roleUser?.metadata.name ?? '')" @close="roleUser = null">
      <form id="ur" @submit.prevent="saveRole">
        <div class="field"><label for="ur-role">{{ s.trust.role }}</label><select id="ur-role" v-model="rf.permission"><option v-for="r in roles" :key="r.value" :value="r.value">{{ r.value }}</option></select></div>
        <ScopePicker v-model:projects="rf.projects" v-model:global="rf.global" :names="names" />
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><span v-if="!(rf.global || rf.projects.length)" class="why-disabled">{{ s.trust.scopeMissing }}</span><button class="btn" type="button" @click="roleUser = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="ur" :disabled="busy || !(rf.global || rf.projects.length)" data-test="user-role-go">{{ s.trust.saveRole }}</button></template>
    </Modal>
    <Modal :open="!!generated" :title="s.trust.generated" @close="() => {}">
      <Callout tone="warn">{{ s.trust.userShownOnce }}</Callout>
      <div class="field" style="margin-top: 12px"><span class="label">{{ generated?.user }}</span><CopyField :value="generated?.password ?? ''" :label="s.trust.userPassword" /></div>
      <template #footer><button class="btn btn-primary" type="button" data-test="user-secret-done" @click="generated = null">{{ s.trust.userDone }}</button></template>
    </Modal>

    <Modal :open="!!editing" :title="s.trust.editTitle(editing?.metadata.name ?? '')" @close="editing = null">
      <form id="ce" @submit.prevent="saveCert">
        <div class="field"><label for="ce-role">{{ s.trust.role }}</label><select id="ce-role" v-model="ef.permission"><option v-for="r in roles" :key="r.value" :value="r.value">{{ r.value }}</option></select></div>
        <ScopePicker v-model:projects="ef.projects" v-model:global="ef.global" :names="names" />
        <ErrorPanel v-if="error" :error="error" />
      </form>
      <template #footer><span v-if="!(ef.global || ef.projects.length)" class="why-disabled">{{ s.trust.scopeMissing }}</span><button class="btn" type="button" @click="editing = null">{{ s.app.cancel }}</button><button class="btn btn-primary" type="submit" form="ce" :disabled="busy || !(ef.global || ef.projects.length)" data-test="cert-save">{{ s.trust.save }}</button></template>
    </Modal>
  </div>
</template>
