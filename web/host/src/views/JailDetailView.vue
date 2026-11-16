<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { ApiError } from '@jailops/shared/api/client'
import { useLoad } from '@jailops/shared/composables/load'
import { can, hasExt } from '@jailops/shared/composables/session'
import { askLifecycle, askDelete, isLocked, lifecycle, type Lifecycle } from '@/composables/jailActions'
import { confirmAction } from '@jailops/shared/composables/confirm'
import { canShell, loadJailTab, saveJailTab } from '@/composables/shell'
import { projectState } from '@/composables/project'
import { jailId, pushRecent } from '@/lib/search'
import JailLabels from '@/components/JailLabels.vue'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import TabBar from '@jailops/shared/components/TabBar.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import { codeText } from '@jailops/shared/lib/describe'
import UnlockDialog from '@/components/UnlockDialog.vue'
import AttachVolumeDialog from '@/components/AttachVolumeDialog.vue'
import LockChip from '@/components/LockChip.vue'
import { runOp } from '@jailops/shared/composables/ops'
import { bytes, sentence, snapshotLabel } from '@jailops/shared/lib/format'
import StatePill from '@/components/StatePill.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import RollbackDialog from '@/components/RollbackDialog.vue'
import UpgradeDialog from '@/components/UpgradeDialog.vue'
import RenameDialog from '@/components/RenameDialog.vue'
import { canRename } from '@/composables/rename'
import { renamedAddress } from '@/lib/rename'
import { sourcesOf, flatten } from '@/lib/configKeys'
import JailConfigTab from '@/components/JailConfigTab.vue'
import JailDevicesTab from '@/components/JailDevicesTab.vue'
import JailExecTab from '@/components/JailExecTab.vue'
import JailUpdatesTab from '@/components/JailUpdatesTab.vue'
import JailLogsTab from '@/components/JailLogsTab.vue'
import JailAccessTab from '@/components/JailAccessTab.vue'
import { isInstalledApp } from '@/lib/access'
import ProvisionPanel from '@/components/ProvisionPanel.vue'
import AddrCopy from '@jailops/shared/components/AddrCopy.vue'
import { shortAddr } from '@jailops/shared/lib/format'
import ErrorPanel from '@jailops/shared/components/ErrorPanel.vue'
import type { Jail, Lease, JailSnapshot } from '@jailops/shared/api/types'

const route = useRoute()
const router = useRouter()
const name = computed(() => String(route.params.name))

const l = useLoad(async () => {
  const { data: jail, etag } = await api.jailConfig.get(name.value)
  // The server's expanded view says where every value comes from; without it only the jail's own values are shown.
  const expanded = await api.jailConfig.expanded(name.value).catch(() => undefined)
  const sources = expanded ? sourcesOf(expanded) : Object.fromEntries(Object.entries(flatten(jail.spec)).map(([k, v]) => [k, { value: v, source: 'jail' }]))
  const snaps = can('snapshots') ? await api.jails.snapshots(name.value).catch(() => [] as JailSnapshot[]) : []
  const nets = [...new Set(jail.spec.network?.map((n) => n.network) ?? [])]
  const leases = (await Promise.all(nets.map((n) => api.networks.leases(n).catch(() => [] as Lease[])))).flat().filter((x) => x.jail === jail.metadata.name)
  const dns = nets.length ? (await api.networks.get(nets[0]).catch(() => undefined))?.data.status?.dns : undefined
  return { jail, etag, sources, snaps, leases, dns }
})
// How the jail resolves names (the same lines as `jailops jail info`): where it asks, its own names, where the rest goes.
const dnsLines = computed(() => {
  const d = l.data.value?.dns
  const j = jail.value
  if (!d || !j) return []
  const ns = (d.nameservers ?? []).join(', ') + (d.source === 'gateway' ? ` (${s.jail.dnsGateway})` : d.source === 'network' ? ` (${s.jail.dnsOwn})` : '')
  const out: [string, string][] = [[s.jail.dnsNameserver, ns || '-']]
  if (d.suffix) {
    const zone = `${j.metadata.project}.${d.suffix}`
    const addrs = [...(j.status.addresses ?? []), ...(j.spec.network ?? []).flatMap((n) => [n.ipv4, n.ipv6])].filter((a): a is string => !!a && a !== 'none' && a !== 'auto')
    const v4 = addrs.some((a) => !a.includes(':'))
    const v6 = addrs.some((a) => a.includes(':') && !a.toLowerCase().startsWith('fe80'))
    const names = [`${j.metadata.name}.${zone}`, j.metadata.name, ...(v4 ? [`${j.metadata.name}.v4.${zone}`] : []), ...(v6 ? [`${j.metadata.name}.v6.${zone}`] : [])]
    out.push([s.jail.dnsSearch, zone], [s.jail.dnsNames, names.join(', ')])
    if (d.forward?.length) out.push([s.jail.dnsOthers, s.jail.dnsForwarded(d.forward.join(', '))])
    else if (d.recurse) out.push([s.jail.dnsOthers, s.jail.dnsRoot])
  } else if (d.source === 'network') {
    out.push([s.jail.dnsNames, s.jail.dnsNoNamesOwn], [s.jail.dnsOthers, s.jail.dnsOwnOthers])
  } else {
    out.push([s.jail.dnsNames, s.jail.dnsNoNames])
  }
  return out
})
const jail = computed<Jail | undefined>(() => l.data.value?.jail)
const snaps = computed(() => [...(l.data.value?.snaps ?? [])].sort((a, b) => (b.metadata.created_at ?? '').localeCompare(a.metadata.created_at ?? '')))
const maxWritten = computed(() => Math.max(1, ...snaps.value.map((x) => x.status.written ?? 0)))

type Tab = 'overview' | 'config' | 'devices' | 'updates' | 'logs' | 'access' | 'console'
const tabList = computed(() => ([
  ['overview', s.jail.overview, true],
  ['config', s.config.tab, true],
  ['devices', s.devices.tab, true],
  ['updates', s.updates.tab, hasExt('updates')],
  ['logs', s.logs.tab, hasExt('jail_logs')],
  // who may connect: for the jails an app installation made
  ['access', s.appAccess.tab, hasExt('app_access') && isInstalledApp(jail.value)],
  // the console session needs the extension and operator in the project, as `jailops exec`
  ['console', s.exec.tab, canShell(jail.value?.metadata.project)],
] as Array<[Tab, string, boolean]>).filter((t) => t[2]).map(([key, label]) => ({ key, label })))
// ?tab=logs&file=nginx/access.log opens a tab directly (the app pages link to a jail's log viewer). The Access tab
// appears once the jail is known to be an app; a ?tab=access waits for it.
const { tab } = useTabQuery<Tab>(() => tabList.value.map((t) => t.key), 'overview')
const logFile = typeof route.query.file === 'string' ? route.query.file : ''
const projectOf = () => jail.value?.metadata.project || projectState.current

// /jails/NAME/shell arrives as ?tab=console&connect=1: the request is kept here and taken off the address, so a reload
// or the back button does not open a second session. The Shell buttons ask the same way.
const shellAsk = ref(route.query.connect === '1' ? 1 : 0)
if (shellAsk.value) {
  const { connect: _c, ...rest } = route.query
  void router.replace({ query: rest })
}
const shellOK = computed(() => !!jail.value && canShell(jail.value.metadata.project) && !locked.value)
function openShell(): void {
  const j = jail.value
  if (!j) return
  // start is tier 1: it runs at once; the console waits for the jail to run, then connects
  if (j.status.power !== 'running' && j.status.power !== 'starting') void lifecycle(name.value, 'start').then(() => l.reload(), () => undefined)
  tab.value = 'console'
  shellAsk.value++
}

// The last tab of each jail is remembered; a page opened without ?tab= opens on it.
let restored = !!route.query.tab || !!shellAsk.value
watch([tab, () => tabList.value.map((t) => t.key).join(), () => jail.value?.metadata.name], ([t]) => {
  if (!jail.value) return
  if (!restored) {
    const want = loadJailTab(projectOf(), name.value)
    if (want && !tabList.value.some((x) => x.key === want)) return // a tab that appears later (Access) is waited for
    restored = true
    if (want && want !== t) {
      tab.value = want as Tab
      return
    }
  }
  saveJailTab(projectOf(), name.value, t)
})
watch(() => jail.value?.metadata.name, (n) => { if (n) pushRecent({ id: jailId(projectOf(), n), kind: 'jail', title: n, to: `/jails/${encodeURIComponent(n)}`, project: projectOf() || undefined }) })
const rollbackOpen = ref(false)
const rollbackSnap = ref<string | undefined>()
const upgradeOpen = ref(false)
const unlockOpen = ref(false)
const attachOpen = ref(false)
// volumes are attached and detached while the jail is stopped
const stoppedOnly = computed(() => !!jail.value && ['running', 'starting', 'stopping'].includes(jail.value.status.power))
function detach(volume: string): void {
  const name = jail.value?.metadata.name
  if (!name) return
  confirmAction({
    title: s.jail.detachTitle(volume, name), confirmLabel: s.jail.detach, text: s.jail.detachText,
    run: () => runOp(s.jail.detachTitle(volume, name), () => api.jails.detach(name, volume)),
    done: () => void l.reload(),
  })
}
const locked = computed(() => !!jail.value && isLocked(jail.value))
const snapComment = ref('')
// Rename (extension rename, admin in the project): only a stopped jail is renamed, so a running or locked one says
// what to do first instead of opening the dialog. Afterwards the page moves to the new name.
const renameOpen = ref(false)
const mayRename = computed(() => !!jail.value && canRename('jail', projectOf()))
const renameWhy = computed(() => {
  const j = jail.value
  if (!j) return ''
  if (locked.value) return s.rename.unlockFirst
  return j.status.jid || ['running', 'starting', 'stopping'].includes(j.status.power) ? s.rename.stopFirst : ''
})
function openRename(): void {
  if (!renameWhy.value) renameOpen.value = true
}
function renamed(to: string): void {
  void router.replace(renamedAddress('jail', name.value, to, route.fullPath) ?? `/jails/${encodeURIComponent(to)}`)
}
const actionError = ref<ApiError | null>(null)

function openRollback(snap?: string): void {
  rollbackSnap.value = snap
  rollbackOpen.value = true
}
function act(a: Lifecycle): void {
  actionError.value = null
  if (jail.value) askLifecycle(name.value, a, jail.value.status.power, l.reload)
}
/** Delete the jail (typed name), or uninstall it when it is an app (named, with what is lost). */
function remove(): void {
  if (jail.value) askDelete(jail.value, snaps.value, () => void router.push('/jails'))
}
const isApp = computed(() => isInstalledApp(jail.value))
const hasDrift = computed(() => !!jail.value?.status.drift?.length)
/** A failed apply with its next step: the jail's firewall policy when pf refused the rules, else the doctor. */
const applyFailed = computed(() => (jail.value?.status.conditions ?? []).filter((c) => c.status === 'False' && c.reason === 'ApplyFailed'))
const pfProblem = (msg = '') => /\bpf|anchor|firewall/i.test(msg)
async function snapshot(): Promise<void> {
  actionError.value = null
  try {
    await runOp(s.jail.snapshotTaken(name.value), () => api.jails.snapshot(name.value, { metadata: {}, spec: { jail: name.value, comment: snapComment.value || undefined } }))
    snapComment.value = ''
  } catch (e) {
    actionError.value = e instanceof ApiError ? e : null
  }
}

/** Rows that put the desired and the observed value of one field side by side. */
const rows = computed(() => {
  const j = jail.value
  if (!j) return []
  const specAddr = (j.spec.network ?? []).flatMap((n) => [n.ipv4, n.ipv6].filter((a): a is string => !!a && a !== 'none')).map((a) => a)
  const fixed = specAddr.filter((a) => a !== 'auto')
  const live = j.status.addresses ?? []
  const addrDiff = j.status.power === 'running' && fixed.some((a) => !live.some((x) => x.split('/')[0] === a.split('/')[0]))
  const pinned = j.spec.image.includes('#')
  const imgDiff = pinned && !!j.status.generation && !j.spec.image.endsWith(j.status.generation.replace(/^.*#/, '#')) && j.spec.image !== j.status.generation
  const wantRun = j.spec.boot?.autostart ? 'running (autostart)' : '-'
  return [
    { field: s.jail.image, spec: j.spec.image, status: j.status.generation ? j.status.generation + (j.status.freebsd_version ? ` (${j.status.freebsd_version})` : '') : '-', diff: imgDiff },
    { field: s.jail.addresses, spec: specAddr.map(shortAddr).join(', ') || '-', status: live.map(shortAddr).join(', ') || s.jail.notRunning, diff: addrDiff },
    { field: s.jail.power, spec: wantRun, status: j.status.power, diff: !!j.spec.boot?.autostart && j.status.power !== 'running' },
  ]
})
const attentionItems = computed(() => {
  const j = jail.value
  if (!j) return []
  return (j.status.conditions ?? []).filter((c) => c.status === 'False' && c.reason !== 'ApplyFailed')
})
</script>

<template>
  <div>
    <router-link class="back" to="/jails"><Icon name="chevronLeft" />{{ s.jail.back }}</router-link>
    <template v-if="l.error.value?.code === 'not_found'">
      <div class="page-head"><h1 class="mono">{{ name }}</h1></div>
      <p class="empty panel">{{ s.jail.notFound }}</p>
    </template>
    <LoadState :loading="l.loading.value" :error="l.error.value?.code === 'not_found' ? null : l.error.value" :has-data="!!jail" @retry="l.reload">
      <div v-if="jail" class="stack">
        <div class="page-head">
          <div class="row">
            <h1 class="mono">{{ jail.metadata.name }}</h1>
            <StatePill :state="jail.status.power" />
            <span v-if="jail.status.jid" class="faint mono">jid {{ jail.status.jid }}</span>
          </div>
          <div class="row-actions">
            <button v-if="shellOK && (jail.status.power === 'running' || jail.status.power === 'starting')" class="btn btn-primary" type="button" data-test="jail-shell" @click="openShell"><Icon name="terminal" />{{ s.shell.open }}</button>
            <button v-else-if="shellOK" class="btn" type="button" data-test="jail-shell" @click="openShell"><Icon name="terminal" />{{ s.shell.startOpen }}</button>
            <button v-if="locked" class="btn btn-primary" type="button" data-test="unlock" @click="unlockOpen = true"><Icon name="lockOpen" />{{ s.keys.unlock }}</button>
            <button v-else-if="jail.status.power !== 'running'" class="btn" type="button" @click="act('start')"><Icon name="play" />{{ s.jails.start }}</button>
            <template v-else>
              <button class="btn" type="button" @click="act('stop')"><Icon name="square" />{{ s.jails.stop }}</button>
              <button class="btn" type="button" @click="act('restart')"><Icon name="rotateCw" />{{ s.jails.restart }}</button>
            </template>
            <button v-if="can('snapshots')" class="btn" type="button" @click="openRollback()" :disabled="!snaps.length"><Icon name="undo" />{{ s.jail.rollback }}</button>
            <button class="btn" type="button" @click="upgradeOpen = true"><Icon name="arrowUp" />{{ s.jail.upgrade }}</button>
            <template v-if="mayRename">
              <button class="btn" type="button" data-test="jail-rename" :aria-disabled="!!renameWhy" :aria-describedby="renameWhy ? 'jail-rename-why' : undefined" @click="openRename">{{ s.rename.open(s.rename.kinds.jail) }}</button>
              <span v-if="renameWhy" id="jail-rename-why" class="why-disabled" data-test="jail-rename-why">{{ renameWhy }}</span>
            </template>
            <button class="btn btn-danger" type="button" data-test="jail-delete" @click="remove"><Icon name="trash" />{{ isApp ? s.jails.uninstall : s.jails.delete }}</button>
          </div>
        </div>
        <JailLabels :jail="jail" @saved="l.reload" />
        <ErrorPanel v-if="actionError" :error="actionError" />
        <Callout v-if="locked" tone="warn" data-test="locked-callout">{{ s.keys.lockedHint }} <LockChip v-if="jail.status.locked?.length" :volumes="jail.status.locked" :jail="jail.metadata.name" /></Callout>

        <Callout v-for="c in applyFailed" :key="c.type" tone="danger" data-test="apply-failed">
          <p><strong>{{ s.jail.applyFailed }}</strong>: <span class="mono">{{ c.message }}</span></p>
          <p v-if="pfProblem(c.message) && jail.spec.firewall?.policies?.length">{{ s.jail.applyFailedPf(jail.spec.firewall.policies.join(', ')) }} <router-link to="/firewall" data-test="apply-next">{{ s.jail.openPolicy(jail.spec.firewall.policies[0]) }}</router-link></p>
          <p v-else>{{ s.jail.applyFailedOther }} <router-link to="/doctor" data-test="apply-next">{{ s.jail.openDoctor }}</router-link></p>
          <p class="muted" style="margin: 0">{{ s.jail.noReconcile }}</p>
        </Callout>
        <Callout v-for="c in attentionItems" :key="c.type" tone="danger"><strong>{{ c.reason ? codeText(c.reason) : sentence(c.type) }}</strong>{{ c.message ? ': ' + c.message : '' }}</Callout>

        <TabBar v-model="tab" :tabs="tabList" :label="s.jail.sections" id="jail" />
        <div id="jail-panel" role="tabpanel" :aria-labelledby="`jail-tab-${tab}`">
        <JailConfigTab v-if="tab === 'config'" :jail="jail" :sources="l.data.value?.sources ?? {}" @saved="l.reload" />
        <JailDevicesTab v-else-if="tab === 'devices'" :jail="jail" :sources="l.data.value?.sources ?? {}" @saved="l.reload" />
        <JailUpdatesTab v-else-if="tab === 'updates'" :jail="jail" @saved="l.reload" />
        <JailLogsTab v-else-if="tab === 'logs'" :jail="jail" :file="logFile" />
        <JailAccessTab v-else-if="tab === 'access'" :jail="jail" />
        <JailExecTab v-else-if="tab === 'console'" :jail="jail" :connect="shellAsk" @changed="l.reload" />
        <template v-else>
        <section class="panel" aria-labelledby="svs">
          <header><h2 id="svs">{{ s.jail.specVsStatus }}</h2></header>
          <div class="table-wrap">
            <table class="rtable" data-test="spec-status">
              <thead><tr><th>&nbsp;</th><th>{{ s.jail.spec }}</th><th>{{ s.jail.status }}</th></tr></thead>
              <tbody>
                <tr v-for="r in rows" :key="r.field" :class="{ drift: r.diff && hasDrift }" :data-drift="r.diff && hasDrift">
                  <th scope="row">{{ r.field }}</th>
                  <td class="mono" :data-label="s.jail.spec">{{ r.spec }}</td>
                  <td class="mono" :data-label="s.jail.status">{{ r.status }}<span v-if="r.diff && hasDrift" class="pill warn" style="margin-left: 8px">{{ s.jails.drift }}</span></td>
                </tr>
                <tr><th scope="row">{{ s.jail.layout }}</th><td :data-label="s.jail.spec">{{ jail.spec.layout || 'thin' }}</td><td class="faint" :data-label="s.jail.status">-</td></tr>
                <tr><th scope="row">{{ s.jail.hostname }}</th><td class="mono" :data-label="s.jail.spec">{{ jail.spec.hostname || jail.metadata.name }}</td><td class="faint" :data-label="s.jail.status">-</td></tr>
                <tr><th scope="row">{{ s.jail.update }}</th><td :data-label="s.jail.spec">{{ jail.spec.update?.strategy || 'manual' }}<span v-if="jail.spec.update?.window" class="faint"> · {{ jail.spec.update.window }}</span></td><td class="faint" :data-label="s.jail.status">-</td></tr>
                <tr>
                  <th scope="row">{{ s.jail.resources }}</th>
                  <td class="mono" :data-label="s.jail.spec">{{ [jail.spec.resources?.cpu ? `cpu ${jail.spec.resources.cpu}` : '', jail.spec.resources?.memory ? `mem ${jail.spec.resources.memory}` : '', jail.spec.resources?.disk ? `disk ${jail.spec.resources.disk}` : '', jail.spec.resources?.pids ? `pids ${jail.spec.resources.pids}` : ''].filter(Boolean).join(' · ') || '-' }}</td>
                  <td class="faint" :data-label="s.jail.status">-</td>
                </tr>
                <tr><th scope="row">{{ s.jail.boot }}</th><td :data-label="s.jail.spec">{{ jail.spec.boot?.autostart ? s.jail.autostart : '-' }}<span v-if="jail.spec.encrypted" class="badge info" style="margin-left: 8px">{{ s.jail.encrypted }}</span></td><td class="faint" :data-label="s.jail.status"><TimeStamp v-if="jail.status.power === 'running'" :ts="jail.status.started_at" /><span v-else>-</span></td></tr>
              </tbody>
            </table>
          </div>
          <div class="body">
            <h3>{{ s.jail.driftTitle }}</h3>
            <Callout v-if="jail.status.drift?.length" tone="warn" data-test="drift">
              <ul class="plain"><li v-for="d in jail.status.drift" :key="d" class="mono">{{ d }}</li></ul>
            </Callout>
            <p v-else class="muted">{{ s.jail.driftNone }}</p>
            <template v-if="jail.status.conditions?.length">
              <h3 style="margin-top: 12px">{{ s.jail.conditions }}</h3>
              <ul class="plain">
                <li v-for="c in jail.status.conditions" :key="c.type"><span class="pill" :class="c.status === 'True' ? 'ok' : c.status === 'False' ? 'danger' : ''">{{ c.reason && c.status === 'False' ? codeText(c.reason) : sentence(c.type) }}</span> <span class="muted">{{ c.message }}</span></li>
              </ul>
            </template>
          </div>
        </section>

        <section v-if="can('snapshots')" class="panel" aria-labelledby="snaps">
          <header>
            <h2 id="snaps">{{ s.jail.snapshots }}</h2>
            <form class="row-actions" @submit.prevent="snapshot">
              <input v-model="snapComment" type="text" :placeholder="s.jail.snapshotComment" :aria-label="s.jail.snapshotComment" style="width: 200px" />
              <button class="btn btn-sm" type="submit"><Icon name="camera" />{{ s.jail.snapshotNow }}</button>
            </form>
          </header>
          <p v-if="!snaps.length" class="empty">{{ s.jail.snapshotsEmpty }}</p>
          <ol v-else class="timeline" data-test="timeline">
            <li v-for="x in snaps" :key="x.metadata.name">
              <div class="tl-main">
                <span class="tl-name" :title="x.metadata.name">{{ snapshotLabel(x.metadata.name) }}</span>
                <TimeStamp v-if="snapshotLabel(x.metadata.name) === x.metadata.name" class="faint" :ts="x.metadata.created_at" />
                <span v-if="x.spec.comment" class="muted">{{ x.spec.comment }}</span>
              </div>
              <div class="tl-written" :title="s.jail.writtenHint">
                <span class="faint">{{ s.jail.written }}</span>
                <span class="mono num" data-test="written">{{ bytes(x.status.written ?? 0) }}</span>
                <div class="meter" aria-hidden="true"><span :style="{ width: ((x.status.written ?? 0) / maxWritten) * 100 + '%' }"></span></div>
              </div>
              <button class="btn btn-sm" type="button" @click="openRollback(x.metadata.name)"><Icon name="undo" />{{ s.jail.rollback }}</button>
            </li>
          </ol>
        </section>

        <div class="grid-2">
          <section class="panel">
            <header><h2>{{ s.jail.network }}</h2></header>
            <p v-if="!jail.spec.network?.length" class="empty">{{ s.jail.noNetwork }}</p>
            <div v-else class="table-wrap">
              <table>
                <thead><tr><th>{{ s.nav.networks }}</th><th>IPv4</th><th>IPv6</th><th>MAC</th></tr></thead>
                <tbody>
                  <tr v-for="n in jail.spec.network" :key="n.network">
                    <td><router-link class="mono" to="/networks">{{ n.network }}</router-link></td>
                    <td><AddrCopy :value="n.ipv4" /></td><td><AddrCopy :value="n.ipv6" /></td><td class="mono">{{ n.mac || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="body" v-if="dnsLines.length">
              <h3>{{ s.jail.dns }}</h3>
              <dl class="kv"><template v-for="[k, x] in dnsLines" :key="k"><dt>{{ k }}</dt><dd class="mono">{{ x }}</dd></template></dl>
            </div>
            <div class="body" v-if="l.data.value?.leases.length">
              <h3>{{ s.jail.leases }}</h3>
              <ul class="plain"><li v-for="x in l.data.value.leases" :key="x.address"><AddrCopy :value="x.address" /> <span class="faint">{{ x.network }}</span></li></ul>
            </div>
          </section>
          <section class="panel">
            <header><h2>{{ s.jail.firewall }}</h2></header>
            <div class="body">
              <p v-if="!jail.spec.firewall?.policies?.length" class="muted">{{ s.jail.noPolicy }}</p>
              <dl v-else class="kv">
                <dt>{{ s.firewall.policies }}</dt><dd><template v-for="(n, i) in jail.spec.firewall.policies" :key="n">{{ i ? ', ' : '' }}<router-link class="mono" :to="`/firewall?policy=${n}`">{{ n }}</router-link></template></dd>
                <dt>{{ s.jail.tags }}</dt><dd class="mono">{{ jail.spec.firewall.tags?.join(', ') || '-' }}</dd>
              </dl>
            </div>
          </section>
        </div>

        <div class="grid-2">
          <section class="panel">
            <header><h2>{{ s.jail.volumes }}</h2><button v-if="hasExt('volumes')" class="btn btn-sm" type="button" data-test="attach-volume-open" :disabled="stoppedOnly" :title="stoppedOnly ? s.jail.attachStopped : undefined" @click="attachOpen = true"><Icon name="plus" />{{ s.jail.attach }}</button></header>
            <p v-if="!jail.spec.volumes?.length" class="empty">{{ s.jail.noVolumes }}</p>
            <div v-else class="table-wrap">
              <table data-test="jail-volumes">
                <thead><tr><th>{{ s.jails.volumeName }}</th><th>{{ s.jail.mount }}</th><th><span class="sr-only">{{ s.app.actions }}</span></th></tr></thead>
                <tbody>
                  <tr v-for="v in jail.spec.volumes" :key="v.volume" :data-volume="v.volume">
                    <td class="mono"><router-link :to="`/volumes/${encodeURIComponent(v.volume)}`">{{ v.volume }}</router-link></td>
                    <td class="mono">{{ v.mount }}<span v-if="v.read_only" class="badge info" style="margin-left: 6px">{{ s.jail.readOnly }}</span><span v-if="jail.status.locked?.includes(v.volume)" class="badge warn" style="margin-left: 6px" :data-locked-volume="v.volume">{{ s.volumes.locked }}</span></td>
                    <td class="actions"><button v-if="hasExt('volumes')" class="btn btn-sm" type="button" :data-detach="v.volume" :disabled="stoppedOnly" :title="stoppedOnly ? s.jail.attachStopped : undefined" @click="detach(v.volume)">{{ s.jail.detach }}</button></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <ProvisionPanel v-if="hasExt('provisioning')" :jail="jail" @done="l.reload" />
        </template>
        </div>
        <RollbackDialog :open="rollbackOpen" :jail="jail.metadata.name" :snapshots="snaps" :initial="rollbackSnap" @close="rollbackOpen = false" @done="l.reload" />
        <UpgradeDialog :open="upgradeOpen" :jail="jail" @close="upgradeOpen = false" @done="l.reload" />
        <RenameDialog :open="renameOpen" kind="jail" :name="jail.metadata.name" :etag="l.data.value?.etag" @close="renameOpen = false" @done="renamed" />
        <UnlockDialog :open="unlockOpen" :volume="jail.status.locked?.[0] ?? ''" @close="unlockOpen = false" @done="l.reload" />
        <AttachVolumeDialog :open="attachOpen" :jail="jail.metadata.name" :attached="(jail.spec.volumes ?? []).map((v) => v.volume)" @close="attachOpen = false" @done="l.reload" />
      </div>
    </LoadState>
  </div>
</template>

<style>
.back { display: inline-flex; align-items: center; gap: 4px; margin-bottom: 8px; text-decoration: none; color: var(--text-2); }
.plain { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }
tr.drift td, tr.drift th { background: var(--warn-bg); }
.timeline { list-style: none; margin: 0; padding: 0 12px; }
.timeline li { display: grid; grid-template-columns: minmax(0, 1fr) 180px auto; gap: 12px; align-items: center; padding: 8px 0 8px 16px; border-left: 2px solid var(--border-strong); position: relative; }
.timeline li::before { content: ''; position: absolute; left: -5px; top: 16px; width: 8px; height: 8px; border-radius: 50%; background: var(--surface); border: 2px solid var(--border-strong); }
.tl-name { font-weight: 500; }
[data-test='spec-status'] tbody th { font-weight: 600; }
.tl-main { display: flex; gap: 8px; flex-wrap: wrap; align-items: baseline; min-width: 0; }
.tl-written { display: grid; grid-template-columns: auto 1fr; gap: 0 8px; font-size: 12px; }
.tl-written .meter { grid-column: 1 / -1; height: 4px; margin-top: 2px; }
@media (max-width: 800px) { .timeline li { grid-template-columns: minmax(0, 1fr); gap: 4px; } }
</style>
