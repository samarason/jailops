<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { useLoad } from '@jailops/shared/composables/load'
import { canFirewallTest } from '@/composables/fwtest'
import {
  askable, caseViews, commandOf, endFamilies, endValue, familyChoice, formFromQuery, formIssues, packetOf, queryOf, toRequest, verdictOf,
  type CaseView, type Decision, type HopView, type TestForm, type Verdict,
} from '@/lib/fwtest'
import CopyField from '@jailops/shared/components/CopyField.vue'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import type { FirewallTestResult, Jail } from '@jailops/shared/api/types'

// The firewall test as a picture: where a connection starts, the anchors it meets, and what decides at each. The server
// answers (POST /firewall/test); this page only asks and draws. The form lives in the address of the page.

const route = useRoute()
const router = useRouter()
const form = reactive<TestForm>(formFromQuery(route.query))
const touched = ref(false)
const busy = ref(false)
const error = ref<ApiError | null>(null)
const result = ref<FirewallTestResult | null>(null)
const ran = ref('')
// the question as it was asked: the form may have changed since
const asked = ref<TestForm>({ ...form })
const verdictEl = ref<HTMLElement | null>(null)

const l = useLoad<Jail[]>(() => api.jails.list().catch(() => []))
const jails = computed(() => l.data.value ?? [])
const allowed = computed(() => canFirewallTest())

function addressesOf(name: string): string[] {
  const j = jails.value.find((x) => x.metadata.name === name)
  if (!j) return []
  if (j.status.addresses?.length) return j.status.addresses
  return (j.spec.network ?? []).flatMap((n) => [n.ipv4, n.ipv6]).filter((a): a is string => !!a && a !== 'auto' && a !== 'none')
}
const issues = computed(() => formIssues(form))
const valid = computed(() => !Object.keys(issues.value).length)
const shown = (k: 'from' | 'to' | 'port' | 'icmpType'): string => {
  const i = issues.value[k]
  if (!i) return ''
  // an empty end or port is not nagged before the first Run; a wrong one is shown as you type
  if (i === 'required' || i === 'portRequired') return touched.value ? s.fwtest.issue[i] : ''
  return s.fwtest.issue[i]
}
const isIcmp = computed(() => form.proto === 'icmp' || form.proto === 'icmp6')
const hasPort = computed(() => form.proto === 'tcp' || form.proto === 'udp')
const offerFamily = computed(() => familyChoice(endFamilies(form.from, addressesOf), endFamilies(form.to, addressesOf)))
const command = computed(() => (valid.value ? commandOf(form) : ''))
const cases = computed<CaseView[]>(() => (result.value ? caseViews(result.value) : []))
const verdict = computed<Verdict>(() => verdictOf(result.value?.verdict ?? ''))
const stale = computed(() => !!result.value && ran.value !== JSON.stringify(queryOf(form)))

watch(() => form.proto, (p) => {
  if (p === 'icmp' || p === 'icmp6') form.port = ''
  else form.icmpType = ''
})
watch(offerFamily, (o) => { if (!o) form.family = '' })

function swap(): void {
  const t = form.from
  form.from = form.to
  form.to = t
}

async function run(): Promise<void> {
  touched.value = true
  if (!valid.value) return
  busy.value = true
  error.value = null
  const key = JSON.stringify(queryOf(form))
  try {
    const r = await api.firewall.test(toRequest(form))
    result.value = r.kind === 'sync' ? (r.data as FirewallTestResult) : null
    ran.value = key
    asked.value = { ...form }
    // the question goes into the address, so the result can be linked and reloaded
    void router.replace({ query: { tab: 'test', ...queryOf(form) } })
    await nextTick()
    verdictEl.value?.focus()
  } catch (e) {
    result.value = null
    error.value = e instanceof ApiError ? e : new ApiError({ message: String(e) })
  } finally {
    busy.value = false
  }
}

// A link to a result asks at once; the back button brings the form of that address back.
let first = true
watch(() => [allowed.value, route.query], () => {
  if (!allowed.value) return
  const q = route.query
  const now = formFromQuery(q)
  if (JSON.stringify(queryOf(now)) === JSON.stringify(queryOf(form)) && !first) return
  Object.assign(form, now)
  if (askable(q) && (first || JSON.stringify(queryOf(now)) !== ran.value)) void run()
  first = false
}, { immediate: true })

// ---- reading a result -------------------------------------------------------------------------------------------

function decidedBy(d: Decision): string {
  const label = d.comment || d.name || ''
  switch (d.kind) {
    case 'policy': return s.fwtest.by.policy(d.policy ?? '', d.rule ?? 0, label)
    case 'projectPolicy': return s.fwtest.by.projectPolicy(d.policy ?? '', d.rule ?? 0, label)
    case 'managedPolicy': return s.fwtest.by.managedPolicy(d.policy ?? '', d.rule ?? 0, label)
    case 'default': return s.fwtest.by.default
    case 'isolation': return s.fwtest.by.isolation
    case 'fixed': return s.fwtest.by.fixed[d.stage] ?? s.fwtest.by.other(d.stage)
  }
  return s.fwtest.by.none
}
const verdictText = (v: Verdict): string => s.fwtest[v]
const verdictIcon = (v: Verdict) => (v === 'pass' ? 'checkCircle' : v === 'block' ? 'circleX' : 'circleHelp')
const verdictLong = (v: Verdict): string => s.fwtest[`${v}Long` as 'passLong' | 'blockLong' | 'unknownLong']
const hopTitle = (h: HopView): string => (h.side === 'source' ? s.fwtest.hop.source(h.jail) : s.fwtest.hop.destination(h.jail))
const endName = (v: string): string => (v === 'host' ? s.fwtest.host : endValue(v))
</script>

<template>
  <section class="stack" data-test="fwtest">
    <p class="muted">{{ s.fwtest.lead }}</p>
    <p v-if="!allowed" class="muted" data-test="fwtest-needs">{{ s.fwtest.needOperator }}</p>
    <template v-else>
      <form class="panel" novalidate data-test="fwtest-form" @submit.prevent="run">
        <div class="body">
          <div class="ft-ends">
            <div class="field">
              <label for="ft-from">{{ s.fwtest.from }}</label>
              <input id="ft-from" v-model.trim="form.from" class="mono" type="text" list="ft-jails" autocomplete="off" spellcheck="false" autocapitalize="off" :aria-invalid="!!shown('from')" :aria-describedby="shown('from') ? 'ft-from-err' : 'ft-from-hint'" data-test="fwtest-from" />
              <span v-if="shown('from')" id="ft-from-err" class="field-error" role="alert">{{ shown('from') }}</span>
              <span v-else id="ft-from-hint" class="hint">{{ s.fwtest.endHint }}</span>
            </div>
            <button class="btn ft-swap" type="button" :aria-label="s.fwtest.swap" :title="s.fwtest.swap" data-test="fwtest-swap" @click="swap"><Icon name="arrowLeftRight" /></button>
            <div class="field">
              <label for="ft-to">{{ s.fwtest.to }}</label>
              <input id="ft-to" v-model.trim="form.to" class="mono" type="text" list="ft-jails" autocomplete="off" spellcheck="false" autocapitalize="off" :aria-invalid="!!shown('to')" :aria-describedby="shown('to') ? 'ft-to-err' : 'ft-to-hint'" data-test="fwtest-to" />
              <span v-if="shown('to')" id="ft-to-err" class="field-error" role="alert">{{ shown('to') }}</span>
              <span v-else id="ft-to-hint" class="hint">{{ s.fwtest.endHint }}</span>
            </div>
          </div>
          <datalist id="ft-jails">
            <option v-for="j in jails" :key="j.metadata.name" :value="`jail:${j.metadata.name}`" />
            <option value="host" />
          </datalist>
          <div class="ft-opts">
            <div class="field">
              <label for="ft-proto">{{ s.fwtest.proto }}</label>
              <select id="ft-proto" v-model="form.proto" data-test="fwtest-proto">
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
                <option value="icmp6">icmp6</option>
              </select>
            </div>
            <div v-if="hasPort" class="field">
              <label for="ft-port">{{ s.fwtest.port }}</label>
              <input id="ft-port" v-model.trim="form.port" class="mono" type="text" inputmode="numeric" autocomplete="off" :aria-invalid="!!shown('port')" :aria-describedby="shown('port') ? 'ft-port-err' : 'ft-port-hint'" data-test="fwtest-port" />
              <span v-if="shown('port')" id="ft-port-err" class="field-error" role="alert">{{ shown('port') }}</span>
              <span v-else id="ft-port-hint" class="hint">{{ s.fwtest.portHint }}</span>
            </div>
            <div v-if="isIcmp" class="field">
              <label for="ft-icmp">{{ s.fwtest.icmpType }}</label>
              <input id="ft-icmp" v-model.trim="form.icmpType" class="mono" type="text" autocomplete="off" spellcheck="false" placeholder="echoreq" :aria-invalid="!!shown('icmpType')" :aria-describedby="shown('icmpType') ? 'ft-icmp-err' : 'ft-icmp-hint'" data-test="fwtest-icmp" />
              <span v-if="shown('icmpType')" id="ft-icmp-err" class="field-error" role="alert">{{ shown('icmpType') }}</span>
              <span v-else id="ft-icmp-hint" class="hint">{{ s.fwtest.icmpHint(form.proto) }}</span>
            </div>
            <div v-if="offerFamily" class="field">
              <label for="ft-family">{{ s.fwtest.family }}</label>
              <select id="ft-family" v-model="form.family" data-test="fwtest-family">
                <option value="">{{ s.fwtest.familyAuto }}</option>
                <option value="4">{{ s.fwtest.family4 }}</option>
                <option value="6">{{ s.fwtest.family6 }}</option>
              </select>
            </div>
          </div>
          <div class="row">
            <button class="btn btn-primary" type="submit" :disabled="busy" data-test="fwtest-run"><Icon name="play" />{{ s.fwtest.run }}</button>
            <span v-if="busy" class="muted" role="status">{{ s.fwtest.running }}</span>
            <span v-else-if="stale" class="muted" role="status" data-test="fwtest-stale">{{ s.fwtest.reload }}</span>
          </div>
        </div>
      </form>
      <div v-if="command" class="field" data-test="fwtest-command">
        <span class="label">{{ s.fwtest.command }}</span>
        <CopyField :value="command" :label="s.fwtest.commandLabel" />
      </div>
      <ErrorPanel v-if="error" :error="error" data-test="fwtest-error" />

      <div v-if="result" class="stack" :class="{ 'ft-stale': stale }" data-test="fwtest-result">
        <div ref="verdictEl" class="ft-verdict" :class="verdict" role="status" tabindex="-1" data-test="fwtest-verdict">
          <Icon :name="verdictIcon(verdict)" />
          <strong data-test="verdict-word">{{ verdictText(verdict) }}</strong>
          <span>{{ verdictLong(verdict) }}</span>
        </div>
        <p v-if="!cases.length" class="muted">{{ s.fwtest.noCases }}</p>
        <article v-for="c in cases" :key="c.key" class="panel ft-case" :data-test="`case-${c.family}`">
          <header>
            <h3 class="ft-case-title"><span class="pill info">{{ s.fwtest.case(c.family) }}</span> <span class="mono">{{ packetOf(c) }}</span></h3>
            <span class="ft-chip" :class="c.verdict"><Icon :name="verdictIcon(c.verdict)" />{{ verdictText(c.verdict) }}</span>
          </header>
          <div class="body">
            <ol class="ft-flow" :aria-label="s.fwtest.flow">
              <li class="ft-node ft-end" data-test="node-from">
                <span class="ft-kicker">{{ s.fwtest.end.from }}</span>
                <span class="mono ft-name">{{ endName(asked.from || c.from) }}</span>
                <span v-if="endName(asked.from || c.from) !== c.from" class="mono ft-addr">{{ c.from }}</span>
              </li>
              <template v-for="h in c.hops" :key="h.key">
                <li class="ft-arrow" aria-hidden="true"><Icon name="arrowRight" /></li>
                <li class="ft-node ft-hop" :class="h.verdict" :data-test="`hop-${h.side}`">
                  <span class="ft-state"><Icon :name="verdictIcon(h.verdict)" />{{ verdictText(h.verdict) }}</span>
                  <strong class="ft-title">{{ hopTitle(h) }}</strong>
                  <span class="ft-anchor mono" :title="s.fwtest.hop.anchor">{{ h.anchor }}</span>
                  <span class="faint ft-at">{{ s.fwtest.hop.at[h.direction] }}</span>
                  <span class="ft-by" data-test="hop-by">{{ h.verdict === 'unknown' && h.why ? h.why : decidedBy(h.decision) }}</span>
                  <p v-if="h.drift" class="faint ft-drift">{{ s.fwtest.drift }}</p>
                  <details v-if="h.decision.pf || h.skipped.length" class="ft-details" :data-test="`details-${h.side}`">
                    <summary>{{ s.fwtest.details }}</summary>
                    <div v-if="h.decision.pf" class="ft-detail">
                      <span class="label">{{ s.fwtest.pf }}</span>
                      <code class="mono ft-pf">{{ h.decision.pf }}</code>
                    </div>
                    <div v-if="h.skipped.length" class="ft-detail">
                      <span class="label">{{ s.fwtest.skipped }}</span>
                      <ul class="plain ft-skipped" data-test="skipped">
                        <li v-for="(k, i) in h.skipped" :key="i">
                          <span>{{ decidedBy(k.decision) }}</span>
                          <span class="faint"> - {{ k.why }}</span>
                        </li>
                      </ul>
                    </div>
                  </details>
                </li>
              </template>
              <li class="ft-arrow" aria-hidden="true"><Icon name="arrowRight" /></li>
              <li class="ft-node ft-end" :class="{ stop: c.stopped }" data-test="node-to">
                <span class="ft-kicker">{{ c.stopped ? s.fwtest.notReached : s.fwtest.end.to }}</span>
                <span class="mono ft-name">{{ endName(asked.to || c.to) }}</span>
                <span v-if="endName(asked.to || c.to) !== c.to" class="mono ft-addr">{{ c.to }}</span>
                <span v-if="c.stopped" class="faint">{{ s.fwtest.notReachedText }}</span>
              </li>
            </ol>
          </div>
        </article>
        <div v-if="result.caveats?.length" class="panel" data-test="fwtest-caveats">
          <header><h3>{{ s.fwtest.notCovered }}</h3></header>
          <div class="body"><ul class="ft-caveats"><li v-for="(c, i) in result.caveats" :key="i">{{ c }}</li></ul></div>
        </div>
      </div>
    </template>
  </section>
</template>

<style>
.ft-ends { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr); gap: 0 8px; align-items: start; }
.ft-swap { margin-top: 22px; }
.ft-opts { display: flex; flex-wrap: wrap; gap: 0 12px; }
.ft-opts .field { min-width: 140px; }
.ft-verdict { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-radius: var(--radius-lg); border: 1px solid var(--border); font-size: 15px; flex-wrap: wrap; }
.ft-verdict strong { font-size: 20px; letter-spacing: 0.04em; }
.ft-verdict .icon { width: 24px; height: 24px; }
.ft-verdict.pass { background: var(--ok-bg); color: var(--ok); border-color: var(--ok); }
.ft-verdict.block { background: var(--danger-bg); color: var(--danger); border-color: var(--danger); }
.ft-verdict.unknown { background: var(--warn-bg); color: var(--warn); border-color: var(--warn); }
.ft-verdict:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.ft-stale { opacity: 0.6; }
.ft-case-title { margin: 0; font-size: 14px; text-transform: none; letter-spacing: 0; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.ft-chip { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; font-size: 12px; }
.ft-chip.pass { color: var(--ok); }
.ft-chip.block { color: var(--danger); }
.ft-chip.unknown { color: var(--warn); }
.ft-flow { list-style: none; margin: 0; padding: 0; display: flex; align-items: stretch; gap: 8px; }
.ft-node { flex: 1 1 0; min-width: 0; border: 1px solid var(--border); border-left-width: 4px; border-radius: var(--radius); padding: 10px; background: var(--surface-2); display: grid; gap: 4px; align-content: start; overflow-wrap: anywhere; }
.ft-end { flex: 0 1 190px; }
.ft-end.stop { border-style: dashed; }
.ft-hop { flex: 1 1 0; }
.ft-hop.pass { border-left-color: var(--ok); }
.ft-hop.block { border-left-color: var(--danger); }
.ft-hop.unknown { border-left-color: var(--warn); }
.ft-kicker { font-size: 12px; color: var(--text-3); }
.ft-name { font-weight: 600; }
.ft-state { display: inline-flex; align-items: center; gap: 6px; font-weight: 700; font-size: 12px; letter-spacing: 0.04em; }
.ft-hop.pass .ft-state { color: var(--ok); }
.ft-hop.block .ft-state { color: var(--danger); }
.ft-hop.unknown .ft-state { color: var(--warn); }
.ft-anchor { font-size: 12px; color: var(--text-2); }
.ft-at, .ft-addr { font-size: 12px; }
.ft-by { font-size: 14px; }
.ft-arrow { display: grid; place-items: center; color: var(--text-3); flex: 0 0 auto; }
.ft-details { margin-top: 4px; font-size: 13px; }
.ft-details summary { cursor: pointer; color: var(--accent); }
.ft-detail { display: grid; gap: 4px; margin-top: 6px; }
.ft-pf { display: block; padding: 6px 8px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); white-space: pre-wrap; overflow-wrap: anywhere; }
.ft-skipped { display: grid; gap: 4px; }
.ft-caveats { margin: 0; padding-left: 18px; display: grid; gap: 4px; }
@media (max-width: 800px) {
  .ft-ends { grid-template-columns: minmax(0, 1fr); }
  .ft-swap { margin-top: 0; justify-self: start; margin-bottom: 8px; }
  .ft-flow { flex-direction: column; }
  .ft-end { flex: 0 0 auto; }
  .ft-arrow .icon { transform: rotate(90deg); }
}
</style>
