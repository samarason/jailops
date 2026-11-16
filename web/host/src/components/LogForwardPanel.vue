<script setup lang="ts">
import { computed, ref } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { hasExt } from '@jailops/shared/composables/session'
import { useLoad } from '@jailops/shared/composables/load'
import { bytes, stamp } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import ConfirmDialog from '@jailops/shared/components/ConfirmDialog.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import LogSinkDialog from '@/components/LogSinkDialog.vue'
import { failingLong, statusOf, withSink } from '@/lib/logforward'
import type { LogForwardTestResult, LogSink } from '@jailops/shared/api/types'

const available = computed(() => hasExt('log_forward'))
const l = useLoad(async () => (available.value ? api.logs.forward() : null))
const fw = computed(() => l.data.value?.data)
const sinks = computed(() => fw.value?.spec.sinks ?? [])
// the generation is the ETag; the header wins when the server sends one
const etag = computed(() => l.data.value?.etag ?? `"${fw.value?.status.generation ?? 0}"`)
const editing = ref<LogSink | null>(null)
const adding = ref(false)
const removing = ref<LogSink | null>(null)
const resetting = ref(false)
const tests = ref<Record<string, LogForwardTestResult | 'busy' | ApiError>>({})
const denied = computed(() => l.error.value?.code === 'forbidden')

const st = (n: string) => statusOf(fw.value, n)
const num = (n: number | undefined) => (n ?? 0).toLocaleString('en')
/** What a sink reads, said in a few words. */
function scope(k: LogSink): string {
  const x = k.sources ?? {}
  if (x.no_jails) return s.forward.auditOnly
  const parts: string[] = []
  if (x.projects?.length) parts.push(`${s.forward.projects.toLowerCase()} ${x.projects.join(', ')}`)
  if (x.jails?.length) parts.push(`${s.forward.jails.toLowerCase()} ${x.jails.join(', ')}`)
  if (x.labels && Object.keys(x.labels).length) parts.push(Object.entries(x.labels).map(([a, b]) => `${a}=${b}`).join(', '))
  if (x.exclude_jails?.length || (x.exclude_labels && Object.keys(x.exclude_labels).length)) parts.push(`${s.forward.excludeJails.toLowerCase()} ${[...(x.exclude_jails ?? []), ...Object.entries(x.exclude_labels ?? {}).map(([a, b]) => `${a}=${b}`)].join(', ')}`)
  const out = [parts.length ? parts.join('; ') : s.forward.scopeAll, s.forward.filesOf((x.files?.length ? x.files : ['messages']).join(', '))]
  if (!x.no_app_logs) out.push(s.forward.withAppLogs)
  if (x.audit) out.push(s.forward.withAudit)
  return out.join(', ')
}

async function test(k: LogSink): Promise<void> {
  tests.value = { ...tests.value, [k.name]: 'busy' }
  try {
    const r = await api.logs.testForward(k.name)
    tests.value = { ...tests.value, [k.name]: r.kind === 'sync' ? r.data : new ApiError({ message: 'unexpected reply' }) }
  } catch (e) {
    tests.value = { ...tests.value, [k.name]: e instanceof ApiError ? e : new ApiError({ message: String(e) }) }
  }
  await l.reload()
}
const testOf = (n: string) => tests.value[n]
const isResult = (x: unknown): x is LogForwardTestResult => !!x && typeof x === 'object' && 'ok' in x
const remove = () => api.logs.putForward({ sinks: withSink(sinks.value, null, removing.value?.name) }, etag.value)
const reset = () => api.logs.resetForward()
</script>

<template>
  <div data-test="forward">
    <Callout v-if="!available" tone="info">{{ s.forward.unavailable }}</Callout>
    <template v-else>
      <p class="muted">{{ s.forward.lead }}</p>
      <Callout v-if="denied" tone="info">{{ s.forward.adminOnly }}</Callout>
      <LoadState v-else :loading="l.loading.value" :error="l.error.value" :has-data="!!fw" @retry="l.reload">
        <div class="row fw-head">
          <Callout tone="info" class="grow" data-test="fw-origin" :data-origin="fw?.status.origin">
            {{ fw?.status.origin === 'api' ? s.forward.originApi(fw?.status.updated_at ? stamp(fw.status.updated_at) : '') : s.forward.originConfig }}
          </Callout>
          <button v-if="fw?.status.origin === 'api'" class="btn" type="button" data-test="fw-reset" @click="resetting = true"><Icon name="undo" />{{ s.forward.reset }}</button>
          <button class="btn btn-primary" type="button" data-test="fw-add" @click="adding = true"><Icon name="plus" />{{ s.forward.add }}</button>
        </div>
        <p v-if="!sinks.length" class="empty">{{ s.forward.empty }}</p>
        <div class="stack">
          <section v-for="k in sinks" :key="k.name" class="panel" :data-sink="k.name">
            <header>
              <div class="row">
                <h2 class="mono">{{ k.name }}</h2>
                <span class="badge info">{{ k.type === 'syslog' ? s.forward.syslog : s.forward.webhook }}</span>
                <span class="pill" :class="st(k.name)?.failing_since ? 'danger' : st(k.name)?.last_success ? 'ok' : ''" data-test="fw-state">{{ st(k.name)?.failing_since ? s.forward.failing : st(k.name)?.last_success ? s.forward.healthy : s.forward.idle }}</span>
              </div>
            </header>
            <div class="body stack">
              <dl class="kv">
                <dt>{{ s.forward.to }}</dt><dd class="mono fw-wrap">{{ k.to }}<span v-if="k.facility" class="faint"> · {{ k.facility }}</span></dd>
                <dt>{{ s.forward.sourcesTitle }}</dt><dd>{{ scope(k) }}<span class="faint"> · {{ s.ulogs.sources(st(k.name)?.sources ?? 0) }}</span></dd>
                <template v-if="k.ca_file"><dt>{{ s.forward.caFile }}</dt><dd class="mono fw-wrap">{{ k.ca_file }}</dd></template>
                <template v-if="k.token_file"><dt>{{ s.forward.tokenFile }}</dt><dd class="mono fw-wrap">{{ k.token_file }}</dd></template>
              </dl>
              <div class="fw-stats" data-test="fw-stats">
                <div><span class="faint">{{ s.forward.sent }}</span><strong class="mono">{{ num(st(k.name)?.sent) }}</strong></div>
                <div><span class="faint">{{ s.forward.queued }}</span><strong class="mono">{{ num(st(k.name)?.queued) }}</strong></div>
                <div><span class="faint">{{ s.forward.dropped }}</span><strong class="mono" data-test="fw-dropped">{{ num(st(k.name)?.dropped) }}</strong></div>
                <div v-if="st(k.name)?.skipped_bytes" :title="s.forward.skippedHint"><span class="faint">{{ s.forward.skipped }}</span><strong class="mono">{{ bytes(st(k.name)?.skipped_bytes) }}</strong></div>
                <div><span class="faint">{{ s.forward.lastSuccess }}</span><strong><TimeStamp v-if="st(k.name)?.last_success" :ts="st(k.name)?.last_success" /><template v-else>{{ s.forward.never }}</template></strong></div>
                <div v-if="st(k.name)?.failing_since"><span class="faint">{{ s.forward.failingSince }}</span><strong><TimeStamp :ts="st(k.name)?.failing_since" /></strong></div>
              </div>
              <Callout v-if="st(k.name)?.last_error" :tone="failingLong(st(k.name)) ? 'danger' : 'warn'" data-test="fw-error"><strong>{{ s.forward.lastError }}</strong>: <span class="mono fw-wrap">{{ st(k.name)?.last_error }}</span></Callout>
              <Callout v-if="st(k.name)?.warning" tone="warn" data-test="fw-warning">{{ s.forward.plaintext }}</Callout>
              <div class="row-actions">
                <button class="btn btn-sm" type="button" :disabled="testOf(k.name) === 'busy'" data-test="fw-test" @click="test(k)"><Icon name="radio" />{{ testOf(k.name) === 'busy' ? s.forward.testing : s.forward.test }}</button>
                <button class="btn btn-sm" type="button" :aria-label="`${s.forward.edit} ${k.name}`" data-test="fw-edit" @click="editing = k">{{ s.forward.edit }}</button>
                <button class="btn btn-sm btn-danger" type="button" :aria-label="`${s.forward.remove} ${k.name}`" data-test="fw-remove" @click="removing = k">{{ s.forward.remove }}</button>
              </div>
              <div role="status" data-test="fw-test-result">
                <template v-if="isResult(testOf(k.name))">
                  <Callout :tone="(testOf(k.name) as LogForwardTestResult).ok ? 'ok' : 'danger'">
                    {{ (testOf(k.name) as LogForwardTestResult).ok ? s.forward.testOk((testOf(k.name) as LogForwardTestResult).millis) : s.forward.testFail((testOf(k.name) as LogForwardTestResult).error ?? '') }}
                    <br /><span class="faint">{{ s.forward.testLine }}:</span> <span class="mono fw-wrap">{{ (testOf(k.name) as LogForwardTestResult).line }}</span>
                  </Callout>
                </template>
                <Callout v-else-if="testOf(k.name) instanceof ApiError" tone="danger">{{ (testOf(k.name) as ApiError).message }}</Callout>
              </div>
            </div>
          </section>
        </div>
      </LoadState>
    </template>
    <LogSinkDialog :open="adding || !!editing" :sink="editing" :sinks="sinks" :etag="etag" @close="adding = false; editing = null" @done="l.reload" />
    <ConfirmDialog :open="!!removing" :title="s.forward.removeTitle(removing?.name ?? '')" :confirm-label="s.forward.remove" danger :run="remove" @close="removing = null" @done="l.reload">
      <Callout tone="warn">{{ s.forward.removeText(removing?.name ?? '') }}</Callout>
    </ConfirmDialog>
    <ConfirmDialog :open="resetting" :title="s.forward.resetTitle" :confirm-label="s.forward.reset" :run="reset" @close="resetting = false" @done="l.reload">
      <Callout tone="warn">{{ s.forward.resetText }}</Callout>
    </ConfirmDialog>
  </div>
</template>

<style scoped>
.fw-head { gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.fw-head .grow { flex: 1 1 320px; margin: 0; }
.fw-wrap { overflow-wrap: anywhere; }
.fw-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
.fw-stats > div { display: grid; gap: 2px; padding: 6px 8px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface-2); }
.fw-stats span { font-size: 12px; }
.fw-stats .ts { white-space: normal; }
</style>
