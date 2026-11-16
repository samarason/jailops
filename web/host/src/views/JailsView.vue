<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { can } from '@jailops/shared/composables/session'
import { askLifecycle, askStopMany, lifecycleMany, isLocked, type Lifecycle } from '@/composables/jailActions'
import { canEditLabels, canShell, goShell, shellPath } from '@/composables/shell'
import { knownLabels, matchTerms, parseQuery, withLabel } from '@/lib/labels'
import { loadFilter, saveFilter } from '@/lib/jailFilter'
import JailFilter from '@/components/JailFilter.vue'
import LabelChips from '@/components/LabelChips.vue'
import BulkLabelDialog from '@/components/BulkLabelDialog.vue'
import { session } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'
import UnlockDialog from '@/components/UnlockDialog.vue'
import LockChip from '@/components/LockChip.vue'
import { shortAddr } from '@jailops/shared/lib/format'
import { patchLevel } from '@/lib/images'
import JailCreateForm from '@/components/JailCreateForm.vue'
import { currentProject } from '@/composables/project'
import StatePill from '@/components/StatePill.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import type { PowerState } from '@jailops/shared/api/types'

const route = useRoute()
const router = useRouter()
const l = useLoad(() => api.jails.list())
const creating = ref(false)
const lookups = useLoad(async () => ({
  images: await api.images.list().catch(() => []), storage: await api.storage.list().catch(() => []), networks: await api.networks.list().catch(() => []),
}))
function openCreate(): void {
  void lookups.reload()
  creating.value = true
}
// The filter lives in the address (?q=env%3Dprod&state=running): shareable, and every finished change (a chip, a
// state, a suggestion, Enter) is a step the back button undoes; typing replaces the step it is in. The last filter
// is remembered per user and project and comes back on a bare /jails.
const str = (v: unknown) => (typeof v === 'string' ? v : '')
const q = ref(str(route.query.q))
const state = ref<PowerState | ''>(str(route.query.state) as PowerState | '')
const sel = ref<Set<string>>(new Set())
const filters: Array<PowerState | ''> = ['', 'running', 'stopped', 'starting', 'stopping', 'error', 'locked']
const unlocking = ref('')
const labelling = ref(false)
const scope = () => `${session.user}|${projectState.current}`

if (!q.value && !state.value) {
  const saved = loadFilter(scope())
  if (saved.q || saved.state) {
    q.value = saved.q
    state.value = saved.state as PowerState | ''
    void router.replace({ query: { ...route.query, ...(saved.q ? { q: saved.q } : {}), ...(saved.state ? { state: saved.state } : {}) } })
  }
}
function setQuery(push: boolean): void {
  // the address and the memory get the filter without the blank being typed after it
  const text = q.value.trim()
  const query = { ...(text ? { q: text } : {}), ...(state.value ? { state: state.value } : {}) }
  saveFilter(scope(), { q: text, state: state.value })
  if (str(route.query.q) === text && str(route.query.state) === state.value) return
  void (push ? router.push({ query }) : router.replace({ query }))
}
let typing: ReturnType<typeof setTimeout> | undefined
watch(q, () => {
  clearTimeout(typing)
  typing = setTimeout(() => setQuery(false), 300)
})
watch(() => [route.query.q, route.query.state], () => {
  // the back button, or a link to a filtered list
  if (str(route.query.q).trim() !== q.value.trim()) q.value = str(route.query.q)
  state.value = str(route.query.state) as PowerState | ''
})
function commit(v: string): void {
  clearTimeout(typing)
  q.value = v
  setQuery(true)
}
function pickState(f: PowerState | ''): void {
  state.value = f
  setQuery(true)
}
function pick(k: string, v: string): void {
  commit(withLabel(q.value, k, v))
}
function clearAll(): void {
  clearTimeout(typing)
  q.value = ''
  state.value = ''
  setQuery(true)
}

const terms = computed(() => parseQuery(q.value))
const known = computed(() => knownLabels(l.data.value ?? []))
const shown = computed(() =>
  (l.data.value ?? []).filter((j) => (!state.value || j.status.power === state.value) && matchTerms(j, terms.value)).sort((a, b) => a.metadata.name.localeCompare(b.metadata.name)),
)
const filtered = computed(() => !!(q.value.trim() || state.value))
const shellOK = computed(() => canShell())
const labelsOK = computed(() => canEditLabels())
/** The generation without the image name the column already shows, with the FreeBSD patch level of its packages:
 *  freebsd-15-1 #g4 · p6. */
const genShort = (image: string, gen: string) => (gen.startsWith(image.replace(/[#@].*$/, '') + '#') ? gen.slice(gen.indexOf('#')) : gen)
const genLabel = (image: string, gen: string, freebsd?: string) => [genShort(image, gen), patchLevel(freebsd)].filter(Boolean).join(' · ')
const chosenJails = computed(() => shown.value.filter((j) => sel.value.has(j.metadata.name)))
const allSelected = computed(() => shown.value.length > 0 && shown.value.every((j) => sel.value.has(j.metadata.name)))
function toggleAll(): void {
  sel.value = allSelected.value ? new Set() : new Set(shown.value.map((j) => j.metadata.name))
}
function toggle(n: string): void {
  const x = new Set(sel.value)
  if (x.has(n)) x.delete(n)
  else x.add(n)
  sel.value = x
}
const chosen = computed(() => [...sel.value].filter((n) => shown.value.some((j) => j.metadata.name === n)))

async function bulkStart(): Promise<void> {
  await lifecycleMany(chosen.value, 'start')
  sel.value = new Set()
}
function bulkStop(): void {
  askStopMany(shown.value.filter((j) => sel.value.has(j.metadata.name)), () => (sel.value = new Set()))
}
function one(n: string, a: Lifecycle, power: string): void {
  askLifecycle(n, a, power)
}
</script>

<template>
  <div>
    <div class="page-head"><h1>{{ s.jails.title }}</h1><button class="btn btn-primary" type="button" data-test="new-jail" @click="openCreate"><Icon name="plus" />{{ s.jails.create }}</button></div>
    <div class="row toolbar">
      <JailFilter v-model="q" :known="known" @commit="commit" />
      <div class="row state-filter" role="group" :aria-label="s.jails.state">
        <button v-for="f in filters" :key="f" class="btn btn-sm" type="button" :aria-pressed="state === f" :class="{ 'btn-primary': state === f }" @click="pickState(f)">{{ f ? (s.state as Record<string, string>)[f] : s.jails.all }}</button>
      </div>
      <div v-if="filtered && l.data.value" class="row filter-sum">
        <span class="faint" data-test="filter-count">{{ s.filter.count(shown.length, l.data.value.length) }}</span>
        <button class="btn btn-sm btn-ghost" type="button" data-test="filter-clear" @click="clearAll"><Icon name="x" />{{ s.filter.clear }}</button>
      </div>
    </div>
    <div v-if="chosen.length" class="row bulk panel" role="region" :aria-label="s.jails.actions">
      <strong>{{ s.jails.selected(chosen.length) }}</strong>
      <div class="row-actions">
        <button class="btn btn-sm" type="button" @click="bulkStart"><Icon name="play" />{{ s.jails.startSel }}</button>
        <button class="btn btn-sm" type="button" data-test="bulk-stop" @click="bulkStop"><Icon name="square" />{{ s.jails.stopSel }}</button>
        <button v-if="labelsOK" class="btn btn-sm" type="button" data-test="bulk-labels" @click="labelling = true"><Icon name="tag" />{{ s.labels.bulk }}</button>
      </div>
    </div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="panel">
        <p v-if="!shown.length && (l.data.value ?? []).length" class="empty">{{ s.jails.empty }}</p>
        <div v-else-if="!shown.length" class="empty jails-empty" data-test="jails-empty">
          <p>{{ s.jails.emptyNone }}</p>
          <div class="row-actions" style="justify-content: center">
            <button class="btn btn-primary" type="button" data-test="empty-new-jail" @click="openCreate"><Icon name="plus" />{{ s.jails.create }}</button>
            <router-link v-if="can('apps')" class="btn" to="/apps"><Icon name="store" />{{ s.jails.emptyApps }}</router-link>
          </div>
        </div>
        <div v-else class="table-wrap">
          <table class="rtable" data-test="jails-table">
            <thead>
              <tr>
                <th style="width: 32px"><input type="checkbox" :checked="allSelected" :aria-label="s.jails.selectAll" @change="toggleAll" /></th>
                <th>{{ s.jails.name }}</th>
                <th>{{ s.jails.state }}</th>
                <th>{{ s.labels.title }}</th>
                <th class="hide-sm">{{ s.jails.image }}</th>
                <th class="hide-sm">{{ s.jails.addresses }}</th>
                <th>{{ s.jails.drift }}</th>
                <th class="hide-sm hide-md">{{ s.jails.started }}</th>
                <th><span class="sr-only">{{ s.jails.actions }}</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="j in shown" :key="j.metadata.name" :data-jail="j.metadata.name">
                <td class="check-cell"><input type="checkbox" :checked="sel.has(j.metadata.name)" :aria-label="s.jails.selectRow(j.metadata.name)" @change="toggle(j.metadata.name)" /></td>
                <td :data-label="s.jails.name"><router-link class="mono jail-link" :to="`/jails/${j.metadata.name}`">{{ j.metadata.name }}</router-link></td>
                <td :data-label="s.jails.state"><StatePill :state="j.status.power" /><LockChip v-if="j.status.locked?.length" :volumes="j.status.locked" :jail="j.metadata.name" /></td>
                <td class="labels-cell" :data-label="s.labels.title"><LabelChips :labels="j.metadata.labels" :max="2" pick @pick="pick" /></td>
                <td class="mono hide-sm" :data-label="s.jails.image">{{ j.spec.image }}<span v-if="j.status.generation" class="faint" data-test="jail-generation" :title="j.status.freebsd_version">{{ ' ' + genLabel(j.spec.image, j.status.generation, j.status.freebsd_version) }}</span></td>
                <td class="mono hide-sm" :data-label="s.jails.addresses">{{ (j.status.addresses ?? []).map(shortAddr).join(', ') || '-' }}</td>
                <td :data-label="s.jails.drift"><span v-if="j.status.drift?.length" class="pill warn">{{ s.overview.drift(j.status.drift.length) }}</span><span v-else class="faint">{{ s.jails.inSync }}</span></td>
                <td class="faint hide-sm hide-md nowrap started-cell" :data-label="s.jails.started"><TimeStamp v-if="j.status.power === 'running'" :ts="j.status.started_at" /><span v-else>-</span></td>
                <td class="actions">
                  <div class="row-actions">
                    <template v-if="shellOK && !isLocked(j)">
                      <router-link v-if="j.status.power === 'running' || j.status.power === 'starting'" class="btn btn-sm" :to="shellPath(j.metadata.name)" :aria-label="s.shell.openTitle(j.metadata.name)" :title="s.shell.openTitle(j.metadata.name)" :data-shell="j.metadata.name"><Icon name="terminal" />{{ s.shell.open }}</router-link>
                      <button v-else class="btn btn-sm" type="button" :aria-label="s.shell.startOpenTitle(j.metadata.name)" :title="s.shell.startOpenTitle(j.metadata.name)" :data-shell="j.metadata.name" @click="goShell(router, j.metadata.name, j.status.power)"><Icon name="terminal" />{{ s.shell.open }}</button>
                    </template>
                    <button v-if="isLocked(j)" class="btn btn-sm" type="button" :data-unlock="j.metadata.name" :aria-label="s.jails.actionTitle(s.keys.unlock, j.metadata.name)" @click="unlocking = j.status.locked?.[0] ?? ''"><Icon name="lockOpen" />{{ s.keys.unlock }}</button>
                    <button v-else-if="j.status.power !== 'running'" class="btn btn-sm" type="button" :aria-label="s.jails.actionTitle(s.jails.start, j.metadata.name)" @click="one(j.metadata.name, 'start', j.status.power)"><Icon name="play" />{{ s.jails.start }}</button>
                    <template v-else>
                      <button class="btn btn-sm" type="button" :aria-label="s.jails.actionTitle(s.jails.stop, j.metadata.name)" :data-stop="j.metadata.name" @click="one(j.metadata.name, 'stop', j.status.power)"><Icon name="square" />{{ s.jails.stop }}</button>
                      <button class="btn btn-sm" type="button" :aria-label="s.jails.actionTitle(s.jails.restart, j.metadata.name)" :title="s.jails.restart" @click="one(j.metadata.name, 'restart', j.status.power)"><Icon name="rotateCw" /><span class="restart-word">{{ s.jails.restart }}</span></button>
                    </template>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </LoadState>
    <BulkLabelDialog :open="labelling" :jails="chosenJails" :known="known" @close="labelling = false" @done="l.reload" />
    <UnlockDialog :open="!!unlocking" :volume="unlocking" @close="unlocking = ''" @done="l.reload" />
    <JailCreateForm :open="creating" :project="currentProject" :images="lookups.data.value?.images ?? []" :storage="lookups.data.value?.storage ?? []" :networks="lookups.data.value?.networks ?? []" @close="creating = false" @done="l.reload" />
  </div>
</template>

<style>
.toolbar { margin-bottom: 12px; align-items: flex-start; }
.state-filter { padding-top: 2px; }
.filter-sum { padding-top: 4px; }
.labels-cell { min-width: 150px; }
@media (min-width: 601px) { .labels-cell .lchips { flex-wrap: nowrap; } }
@media (max-width: 1500px) { .hide-md { display: none; } }
.bulk { padding: 6px 12px; margin-bottom: 12px; background: var(--accent-soft); }
.jails-empty p { margin-bottom: 12px; }
.jail-link { font-weight: 500; }
@media (min-width: 601px) { .jail-link { white-space: nowrap; } }
@media (max-width: 800px) { .hide-sm { display: none; } }
/* phone cards: the label beside the value keeps each card short; the start time stays on the jail page */
@media (max-width: 600px) {
  table.rtable[data-test='jails-table'] td[data-label]:not([data-label='']) { position: relative; padding-left: 92px; min-height: 24px; }
  table.rtable[data-test='jails-table'] td[data-label]:not([data-label=''])::before { position: absolute; left: 0; top: 4px; width: 88px; }
  table.rtable[data-test='jails-table'] td.started-cell { display: none; }
  /* the select box floats over the card's first line: above the cells, so a tap reaches it */
  table.rtable[data-test='jails-table'] td.check-cell { position: relative; z-index: 1; }
}
@media (min-width: 601px) { [data-test='jails-table'] td.actions .row-actions { flex-wrap: nowrap; justify-content: flex-end; } }
</style>
