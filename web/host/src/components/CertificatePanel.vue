<script setup lang="ts">
// The certificate of the console and the API (extension host_certificate): what the TLS listener serves, where it
// comes from, and the three ways to change it: upload one, request one with ACME, or go back to the generated one.
import { computed, nextTick, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { runOp } from '@jailops/shared/composables/ops'
import { session } from '@jailops/shared/composables/session'
import { ApiError } from '@jailops/shared/api/client'
import { stamp } from '@jailops/shared/lib/format'
import Callout from '@jailops/shared/components/Callout.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import CopyField from '@jailops/shared/components/CopyField.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import Modal from '@jailops/shared/components/Modal.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import { isGlobalAdmin } from '@/composables/project'
import { acmeProblems, acmeSpec, pemProblems, retargetRemoteAdd, ACME_PRODUCTION, ACME_STAGING, type AcmeForm } from '@/lib/setup'

// hostname: the name the host was just given (the setup wizard); the daemon still knows the one it started with.
const props = defineProps<{ hostname?: string }>()
const emit = defineEmits<{ changed: [] }>()
const hostName = computed(() => props.hostname || session.info?.hostname || '')
const remoteAdd = computed(() => (c.value?.remote_add && c.value.source !== 'acme' ? retargetRemoteAdd(c.value.remote_add, session.info?.hostname ?? '', hostName.value) : c.value?.remote_add ?? ''))
defineExpose({ openUpload, openAcme, source: () => c.value?.source })
const l = useLoad(() => api.host.certificate())
const admin = computed(() => isGlobalAdmin())
const c = computed(() => l.data.value)
const canWrite = computed(() => admin.value && !!c.value && !c.value.configured && c.value.listener)
const asError = (e: unknown) => (e instanceof ApiError ? e : new ApiError({ message: String(e) }))

// Follow an ACME request until the CA answered.
let timer: ReturnType<typeof setTimeout> | undefined
watch(() => l.data.value, () => {
  clearTimeout(timer)
  if (c.value?.acme?.state === 'requesting') timer = setTimeout(() => void l.reload(), 1000)
})
onBeforeUnmount(() => clearTimeout(timer))

const sourceTone: Record<string, string> = { 'self-signed': 'warn', configured: 'info', uploaded: 'ok', acme: 'ok' }
const stateTone: Record<string, string> = { valid: 'ok', requesting: 'info pulse', error: 'danger', idle: '' }

// ---- upload ----
const up = reactive({ open: false, certificate: '', key: '', hostname: '', touched: false })
const upErr = ref<ApiError | null>(null)
const upProblems = computed(() => pemProblems(up.certificate, up.key, up.hostname))
const busy = ref(false)
function openUpload(): void {
  Object.assign(up, { open: true, certificate: '', key: '', hostname: props.hostname || (c.value?.current.names[0] ?? session.info?.hostname ?? ''), touched: false })
  upErr.value = null
}
async function upload(): Promise<void> {
  up.touched = true
  if (Object.keys(upProblems.value).length) return focusFirst(upProblems.value, { certificate: 'cu-cert', key: 'cu-key', hostname: 'cu-host' })
  busy.value = true
  upErr.value = null
  try {
    await runOp(s.cert.uploadTitle, () => api.host.uploadCertificate({ certificate: up.certificate.trim() + '\n', key: up.key.trim() + '\n', hostname: up.hostname.trim() }), { silent: true })
    up.open = false
    await l.reload()
    emit('changed')
  } catch (e) {
    upErr.value = asError(e)
  } finally {
    busy.value = false
  }
}

// ---- ACME ----
const ac = reactive<AcmeForm & { open: boolean; touched: boolean }>({ open: false, domains: '', email: '', challenge: 'http-01', staging: false, terms: false, touched: false })
const acErr = ref<ApiError | null>(null)
const acProblems = computed(() => acmeProblems(ac))
const directory = computed(() => (ac.staging ? ACME_STAGING : ACME_PRODUCTION))
function openAcme(): void {
  const prev = c.value?.acme?.spec
  Object.assign(ac, { open: true, domains: (prev?.domains ?? []).join(' ') || (hostName.value.includes('.') ? hostName.value : ''), email: prev?.email ?? '',
    challenge: prev?.challenge ?? 'http-01', staging: prev?.directory_url === ACME_STAGING, terms: false, touched: false })
  acErr.value = null
}
async function requestAcme(): Promise<void> {
  ac.touched = true
  if (Object.keys(acProblems.value).length) return focusFirst(acProblems.value, { domains: 'ca-dom', email: 'ca-mail', terms: 'ca-terms' })
  busy.value = true
  acErr.value = null
  try {
    await runOp(s.cert.acmeTitle, () => api.host.useAcme(acmeSpec(ac)), { silent: true })
    ac.open = false
    await l.reload()
    emit('changed')
  } catch (e) {
    acErr.value = asError(e)
  } finally {
    busy.value = false
  }
}

// ---- self-signed again ----
const back = ref(false)
async function selfSigned(): Promise<void> {
  await runOp(s.cert.selfTitle, () => api.host.useSelfSigned())
  await l.reload()
  emit('changed')
}
const errOf = (p: Record<string, string>, f: string, touched: boolean) => (touched ? p[f] : undefined)
/** A submit with problems moves the focus to the first field that has one. */
function focusFirst(p: Record<string, string>, ids: Record<string, string>): void {
  const k = Object.keys(ids).find((f) => p[f])
  if (k) void nextTick(() => (document.getElementById(ids[k]) ?? document.querySelector<HTMLElement>(`[data-test="${ids[k]}"]`))?.focus())
}
const firstOf = (p: Record<string, string>) => Object.values(p)[0] ?? ''
</script>

<template>
  <section class="panel" data-test="cert-panel">
    <header><h2>{{ s.cert.title }}</h2>
      <span v-if="c" class="pill" :class="sourceTone[c.source]" data-test="cert-source">{{ s.cert.sources[c.source] ?? c.source }}</span>
    </header>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!c" @retry="l.reload">
      <div v-if="c" class="panel-body stack">
        <p class="muted">{{ s.cert.lead }}</p>
        <Callout v-if="!c.listener" tone="info">{{ s.cert.noListener }}</Callout>
        <Callout v-if="c.configured" tone="info" data-test="cert-configured">{{ s.cert.configured }}</Callout>
        <dl class="kv" data-test="cert-current">
          <dt>{{ s.cert.subject }}</dt><dd class="mono wrap">{{ c.current.subject || '-' }}</dd>
          <dt>{{ s.cert.names }}</dt><dd><span v-for="n in c.current.names" :key="n" class="chip mono">{{ n }}</span><span v-if="!c.current.names.length" class="faint">-</span></dd>
          <dt>{{ s.cert.issuer }}</dt><dd class="mono wrap">{{ c.current.self_signed ? s.cert.selfSignedIssuer : c.current.issuer }}</dd>
          <dt>{{ s.cert.validUntil }}</dt><dd data-test="cert-valid"><TimeStamp :ts="c.current.not_after" /> <span class="pill" :class="c.current.days_left < 14 ? 'danger' : c.current.days_left < 30 ? 'warn' : 'ok'">{{ s.cert.daysLeft(c.current.days_left) }}</span></dd>
          <dt>{{ s.cert.trust }}</dt><dd>{{ c.current.public_ca ? s.cert.publicCA : s.cert.pinned }}</dd>
        </dl>
        <div class="field"><span class="label">{{ s.cert.fingerprint }}</span><CopyField :value="c.current.fingerprint" label="fingerprint" /></div>
        <div v-if="remoteAdd" class="field"><span class="label">{{ s.cert.remoteAdd }}</span><CopyField :value="remoteAdd" label="remote-add" /><span class="hint">{{ c.current.public_ca ? s.cert.remoteAddPublic : s.cert.remoteAddPinned }}</span></div>

        <div v-if="c.acme" class="stack" data-test="cert-acme">
          <h3>{{ s.cert.acme }}</h3>
          <p class="row"><span class="pill" :class="stateTone[c.acme.state] ?? ''" data-test="acme-state">{{ s.cert.states[c.acme.state] ?? c.acme.state }}</span>
            <span class="mono faint">{{ c.acme.spec.domains.join(', ') }}</span></p>
          <Callout v-if="c.acme.last_error" tone="danger" data-test="acme-error">{{ s.cert.lastError(c.acme.last_error) }}<template v-if="c.acme.next_attempt"> {{ s.cert.nextAttempt(stamp(c.acme.next_attempt)) }}</template></Callout>
          <p v-if="c.acme.renew_at" class="faint">{{ s.cert.renewAt(stamp(c.acme.renew_at)) }}</p>
          <template v-if="c.redirect">
            <Callout v-if="c.redirect.managed && !c.redirect.applied" tone="warn" data-test="acme-apply-fw">{{ s.cert.applyFirewall(c.acme.spec.challenge === 'tls-alpn-01' ? 443 : 80, c.acme.challenge_port) }}</Callout>
            <p v-else-if="c.redirect.managed" class="faint">{{ s.cert.redirectManaged }}</p>
            <div v-else-if="c.redirect.lines?.length" class="field" data-test="acme-lines"><span class="label">{{ s.cert.redirectLines }}</span><pre class="mono cert-pre">{{ c.redirect.lines.join('\n') }}</pre></div>
          </template>
        </div>
        <Callout v-for="w in c.warnings ?? []" :key="w" tone="warn">{{ w.charAt(0).toUpperCase() + w.slice(1) }}.</Callout>
        <p v-if="!admin" class="faint">{{ s.cert.adminOnly }}</p>
        <div class="row">
          <button class="btn" type="button" :disabled="!canWrite" data-test="cert-upload" @click="openUpload">{{ s.cert.upload }}</button>
          <button class="btn" type="button" :disabled="!canWrite" data-test="cert-acme-btn" @click="openAcme">{{ s.cert.requestAcme }}</button>
          <button v-if="c.source !== 'self-signed'" class="btn btn-ghost" type="button" :disabled="!canWrite" data-test="cert-self" @click="back = true">{{ s.cert.useSelf }}</button>
        </div>
      </div>
    </LoadState>

    <Modal :open="up.open" :title="s.cert.uploadTitle" wide @close="up.open = false">
      <form id="cert-up" novalidate @submit.prevent="upload">
        <div class="field"><label for="cu-cert">{{ s.cert.certificate }} <span class="req" aria-hidden="true">*</span></label>
          <textarea id="cu-cert" v-model="up.certificate" class="mono" rows="6" spellcheck="false" :aria-invalid="!!errOf(upProblems, 'certificate', up.touched)" placeholder="-----BEGIN CERTIFICATE-----" data-test="cu-cert"></textarea>
          <span v-if="errOf(upProblems, 'certificate', up.touched)" class="err" data-test="field-error">{{ errOf(upProblems, 'certificate', up.touched) }}</span>
          <span v-else class="hint">{{ s.cert.certificateHint }}</span></div>
        <div class="field"><label for="cu-key">{{ s.cert.key }} <span class="req" aria-hidden="true">*</span></label>
          <textarea id="cu-key" v-model="up.key" class="mono" rows="5" spellcheck="false" autocomplete="off" :aria-invalid="!!errOf(upProblems, 'key', up.touched)" placeholder="-----BEGIN PRIVATE KEY-----" data-test="cu-key"></textarea>
          <span v-if="errOf(upProblems, 'key', up.touched)" class="err" data-test="field-error">{{ errOf(upProblems, 'key', up.touched) }}</span>
          <span v-else class="hint">{{ s.cert.keyHint }}</span></div>
        <div class="field"><label for="cu-host">{{ s.cert.hostname }} <span class="req" aria-hidden="true">*</span></label>
          <input id="cu-host" v-model="up.hostname" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf(upProblems, 'hostname', up.touched)" data-test="cu-host" />
          <span v-if="errOf(upProblems, 'hostname', up.touched)" class="err" data-test="field-error">{{ errOf(upProblems, 'hostname', up.touched) }}</span>
          <span v-else class="hint">{{ s.cert.hostnameHint }}</span></div>
        <ErrorPanel v-if="upErr" :error="upErr" />
      </form>
      <template #footer>
        <span v-if="up.touched && firstOf(upProblems)" class="why-disabled">{{ s.form.fixFirst(firstOf(upProblems)) }}</span>
        <button class="btn btn-ghost" type="button" @click="up.open = false">{{ s.app.cancel }}</button>
        <button class="btn btn-primary" type="submit" form="cert-up" :disabled="busy" data-test="cu-go">{{ s.cert.uploadGo }}</button>
      </template>
    </Modal>

    <Modal :open="ac.open" :title="s.cert.acmeTitle" wide @close="ac.open = false">
      <form id="cert-acme" novalidate @submit.prevent="requestAcme">
        <p class="muted">{{ s.cert.acmeLead }}</p>
        <div class="field"><label for="ca-dom">{{ s.cert.domains }} <span class="req" aria-hidden="true">*</span></label>
          <input id="ca-dom" v-model="ac.domains" class="mono" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errOf(acProblems, 'domains', ac.touched)" data-test="ca-domains" />
          <span v-if="errOf(acProblems, 'domains', ac.touched)" class="err" data-test="field-error">{{ errOf(acProblems, 'domains', ac.touched) }}</span>
          <span v-else class="hint">{{ s.cert.domainsHint }}</span></div>
        <div class="field"><label for="ca-mail">{{ s.cert.email }}</label>
          <input id="ca-mail" v-model="ac.email" type="email" autocomplete="email" :aria-invalid="!!errOf(acProblems, 'email', ac.touched)" data-test="ca-email" />
          <span v-if="errOf(acProblems, 'email', ac.touched)" class="err" data-test="field-error">{{ errOf(acProblems, 'email', ac.touched) }}</span>
          <span v-else class="hint">{{ s.cert.emailHint }}</span></div>
        <fieldset class="field plain-set"><legend class="label">{{ s.cert.challenge }}</legend>
          <label class="check"><input v-model="ac.challenge" type="radio" value="http-01" name="ca-ch" data-test="ca-http" />{{ s.cert.http01 }}</label>
          <label class="check"><input v-model="ac.challenge" type="radio" value="tls-alpn-01" name="ca-ch" data-test="ca-alpn" />{{ s.cert.tlsAlpn01 }}</label>
        </fieldset>
        <label class="check"><input v-model="ac.staging" type="checkbox" data-test="ca-staging" />{{ s.cert.staging }}</label>
        <p class="faint mono wrap" data-test="ca-directory">{{ directory }}</p>
        <label class="check"><input id="ca-terms" v-model="ac.terms" type="checkbox" :aria-invalid="!!errOf(acProblems, 'terms', ac.touched)" data-test="ca-terms" />{{ s.cert.terms(c?.acme?.terms_url || s.cert.termsOfDirectory) }}</label>
        <span v-if="errOf(acProblems, 'terms', ac.touched)" class="err" data-test="field-error">{{ errOf(acProblems, 'terms', ac.touched) }}</span>
        <Callout tone="info" style="margin-top: 12px">{{ s.cert.acmeLimits }}</Callout>
        <ErrorPanel v-if="acErr" :error="acErr" />
      </form>
      <template #footer>
        <span v-if="ac.touched && firstOf(acProblems)" class="why-disabled">{{ s.form.fixFirst(firstOf(acProblems)) }}</span>
        <button class="btn btn-ghost" type="button" @click="ac.open = false">{{ s.app.cancel }}</button>
        <button class="btn btn-primary" type="submit" form="cert-acme" :disabled="busy" data-test="ca-go">{{ s.cert.acmeGo }}</button>
      </template>
    </Modal>

    <ConfirmDialog :open="back" :title="s.cert.selfTitle" :confirm-label="s.cert.useSelf" danger :run="selfSigned" @close="back = false">
      <Callout tone="warn" data-test="self-warning">{{ s.cert.selfWarning }}</Callout>
    </ConfirmDialog>
  </section>
</template>

<style scoped>
h3 { font-size: 14px; margin: 8px 0 0; }
.wrap { overflow-wrap: anywhere; }
.cert-pre { margin: 0; padding: 8px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); white-space: pre; overflow-x: auto; }
.plain-set { border: 0; padding: 0; margin: 0 0 12px; min-width: 0; }
textarea { width: 100%; min-width: 0; }
</style>
