<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { session } from '@jailops/shared/composables/session'
import { bytes, sentence } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import { attention } from '@/lib/attention'

const safe = <T,>(p: Promise<T>): Promise<T | undefined> => p.catch(() => undefined)
const l = useLoad(async () => {
  const [repo, hosts, sessions, cert] = await Promise.all([api.repository(), safe(api.hosts.list()), safe(api.sessions.list()), safe(api.certificate())])
  return { repo, hosts, sessions: (sessions ?? []).filter((x) => !x.closed_at), cert }
}, { every: 10000 })
const r = computed(() => l.data.value?.repo)
const items = computed(() => (r.value ? attention({ repo: r.value, hosts: l.data.value?.hosts }) : []))
const set = (t: string | undefined) => !!t && !t.startsWith('0001')
const next = computed(() => Object.entries(r.value?.next_runs ?? {}).sort((a, b) => a[1].localeCompare(b[1])))
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.overview.title }}</h1><span class="muted mono">{{ session.info?.hostname }}</span></div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!r" @retry="l.reload">
      <div v-if="r" class="stack">
        <Callout tone="info" data-test="keyless">{{ s.keyless }}</Callout>
        <section>
          <Callout v-if="!items.length" tone="ok">{{ s.overview.allClear }}</Callout>
          <div v-else class="panel" data-test="attention">
            <header><h2>{{ s.overview.attention }} ({{ items.length }})</h2></header>
            <ul class="attn">
              <li v-for="a in items" :key="a.key"><span class="pill" :class="a.tone">{{ a.tone === 'danger' ? 'Error' : 'Warning' }}</span><router-link v-if="a.to" :to="a.to">{{ a.text }}</router-link><span v-else>{{ a.text }}</span></li>
            </ul>
          </div>
        </section>
        <section class="panel">
          <header><h2>{{ s.overview.repository }}</h2><span class="mono faint">{{ r.id }}</span></header>
          <div class="body stats">
            <div><span class="faint">{{ s.overview.mode }}</span><span class="v"><span class="pill" :class="r.mode === 'online' ? 'ok' : r.mode === 'read-only' ? 'warn' : 'danger'" data-test="mode">{{ s.maintenance.modes[r.mode] ?? sentence(r.mode) }}</span></span><span class="faint">{{ s.overview.modeText[r.mode] }}</span></div>
            <div><span class="faint">{{ s.overview.backend }}</span><span class="v mono">{{ r.backend }}</span></div>
            <div><span class="faint">{{ s.overview.size }}</span><span class="v mono" data-test="size">{{ bytes(r.bytes) }}</span></div>
            <div><span class="faint">{{ s.overview.chunks }}</span><span class="v mono">{{ r.chunks.toLocaleString('en') }}</span></div>
            <div><span class="faint">{{ s.overview.snapshots }}</span><span class="v mono">{{ r.snapshots }}</span><span class="faint">{{ s.overview.groups }}: {{ r.groups }}</span></div>
            <div><span class="faint">{{ s.overview.sessions }}</span><span class="v mono" data-test="sessions">{{ r.open_sessions }}</span></div>
            <div><span class="faint">{{ s.overview.lastGc }}</span><span class="v v-time"><TimeStamp v-if="set(r.last_gc)" :ts="r.last_gc" /><template v-else>{{ s.overview.never }}</template></span></div>
            <div><span class="faint">{{ s.overview.lastVerify }}</span><span class="v v-time"><TimeStamp v-if="set(r.last_verify)" :ts="r.last_verify" /><template v-else>{{ s.overview.never }}</template></span></div>
            <div><span class="faint">{{ s.overview.quarantined }}</span><span class="v mono" :class="{ bad: r.quarantined > 0 }" data-test="quarantined">{{ r.quarantined }}</span></div>
            <div><span class="faint">{{ s.overview.failed }}</span><span class="v mono" :class="{ bad: r.failed_snapshots > 0 }">{{ r.failed_snapshots }}</span></div>
            <div><span class="faint">{{ s.overview.protected }}</span><span class="v mono">{{ r.protected_snapshots }}</span></div>
            <div><span class="faint">{{ s.overview.pending }}</span><span class="v mono">{{ r.pending_deletions }}</span></div>
          </div>
        </section>
        <div class="grid-2">
          <section class="panel">
            <header><h2>{{ s.overview.scheduled }}</h2></header>
            <p v-if="!next.length" class="empty">{{ s.overview.noSchedule }}</p>
            <div v-else class="table-wrap"><table><thead class="sr-only"><tr><th>{{ s.overview.scheduled }}</th><th>{{ s.overview.next }}</th></tr></thead><tbody><tr v-for="[k, t] in next" :key="k"><td class="mono">{{ k }}</td><td><TimeStamp :ts="t" /></td></tr></tbody></table></div>
          </section>
          <section v-if="l.data.value?.cert" class="panel">
            <header><h2>{{ s.overview.certificate }}</h2></header>
            <div class="body"><p class="mono" data-test="fingerprint">{{ l.data.value.cert.fingerprint }}</p><p class="muted">{{ s.overview.certificateHint }}</p></div>
          </section>
        </div>
        <section v-if="l.data.value?.sessions.length" class="panel" data-test="open-sessions">
          <header><h2>{{ s.overview.openSessions }}</h2></header>
          <div class="table-wrap"><table>
            <thead><tr><th>{{ s.overview.group }}</th><th>{{ s.overview.state }}</th><th class="num">{{ s.overview.uploaded }}</th><th class="hide-sm">{{ s.overview.lease }}</th></tr></thead>
            <tbody><tr v-for="x in l.data.value.sessions" :key="x.id"><td class="mono">{{ x.group_id }}</td><td><span class="pill info pulse">{{ sentence(x.state) }}</span></td><td class="num mono">{{ bytes(x.bytes_put) }}</td><td class="faint hide-sm"><TimeStamp :ts="x.lease_expires_at" /></td></tr></tbody></table></div>
        </section>
      </div>
    </LoadState>
  </div>
</template>

<style>
.attn { list-style: none; margin: 0; padding: 0; }
.attn li { display: flex; gap: 10px; align-items: center; padding: 6px 12px; border-bottom: 1px solid var(--border); }
.attn li:last-child { border-bottom: 0; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 16px; }
.stats > div { display: grid; gap: 2px; align-content: start; }
.stats .v { font-size: 20px; font-weight: 600; font-variant-numeric: tabular-nums; }
@media (max-width: 600px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; } .stats .v { font-size: 17px; } }
.stats .v-time { font-size: 15px; }
.stats .v-time .ts { white-space: normal; }
.stats .bad { color: var(--danger); }
</style>
