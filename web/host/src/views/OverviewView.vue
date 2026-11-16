<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { session, can, isHub } from '@jailops/shared/composables/session'
import { attention } from '@/composables/attention'
import { bytes, percent, sentence } from '@jailops/shared/lib/format'
import TimeStamp from '@jailops/shared/components/TimeStamp.vue'
import StatePill from '@/components/StatePill.vue'
import Meter from '@jailops/shared/components/Meter.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import type { PowerState, Jail } from '@jailops/shared/api/types'
import { projectState } from '@/composables/project'
import Icon from '@jailops/shared/components/Icon.vue'
import { isLocked } from '@/composables/jailActions'
import { isGlobalAdmin } from '@/composables/project'
import { useRouter } from 'vue-router'
import NewReleaseNotice from '@/components/NewReleaseNotice.vue'

const router = useRouter()
const safe = <T,>(p: Promise<T>): Promise<T | undefined> => p.catch(() => undefined)

const l = useLoad(async () => {
  const [jails, networks, ops, remotes, backups, pool, doctor, storage, images] = await Promise.all([
    projectState.current ? api.jails.list() : Promise.resolve([] as Jail[]),
    can('networks') ? safe(api.networks.list()) : undefined,
    can('operations') ? safe(api.operations.list()) : undefined,
    isHub.value ? safe(api.remotes.list()) : undefined,
    can('backups') ? safe(api.backups.list()) : undefined,
    can('resources') ? safe(api.pool()) : undefined,
    can('doctor') ? safe(api.doctor()) : undefined,
    safe(api.storage.list()),
    safe(api.images.list()),
  ])
  return { jails, networks, ops, remotes, backups, pool, doctor, storage, images }
})

/** First run: what the host still needs before a jail can exist, in the order the pieces depend on each other. */
const steps = computed(() => {
  const d = l.data.value
  if (!d) return []
  const hasStorage = (d.storage?.length ?? 1) > 0
  const hasProject = projectState.projects.length > 0
  const hasImage = (d.images?.length ?? 1) > 0
  const hasJail = d.jails.length > 0
  const list = [
    { key: 'storage', done: hasStorage, to: '/storage', title: s.start.storage, text: s.start.storageText },
    { key: 'project', done: hasProject, to: '/projects', title: s.start.project, text: s.start.projectText },
    { key: 'image', done: hasImage, to: hasImage ? '/images' : '/images?create=1', title: s.start.image, text: s.start.imageText },
    { key: 'jail', done: hasJail, to: '/jails', title: s.start.jail, text: s.start.jailText },
  ]
  return list.every((x) => x.done) ? [] : list
})
const nextStep = computed(() => steps.value.find((x) => !x.done)?.key)
const baseStates: PowerState[] = ['running', 'starting', 'stopping', 'stopped', 'error']
const counts = computed(() => {
  const c: Record<string, number> = { running: 0, starting: 0, stopping: 0, stopped: 0, error: 0 }
  for (const j of l.data.value?.jails ?? []) c[j.status.power] = (c[j.status.power] ?? 0) + 1
  return c
})
// jails whose encrypted volumes wait for a passphrase: each is unlocked on its own page, with its own passphrase
const locked = computed(() => (l.data.value?.jails ?? []).filter(isLocked).map((j) => j.metadata.name).sort())
const states = computed<PowerState[]>(() => (locked.value.length ? [...baseStates, 'locked'] : baseStates))
const items = computed(() => (l.data.value ? attention(l.data.value) : []))
const recent = computed(() => [...(l.data.value?.ops ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 8))
const pool = computed(() => l.data.value?.pool)
const poolPct = computed(() => (pool.value ? percent(pool.value.allocated, pool.value.size) : 0))
</script>

<template>
  <div>
    <div class="page-head">
      <h1>{{ s.overview.title }}</h1>
      <span class="muted mono">{{ session.info?.hostname }} · {{ session.info?.environment.os }} {{ session.info?.environment.kernel_version }} · {{ session.info?.environment.arch }}</span>
    </div>
    <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
      <div class="stack">
        <section v-if="steps.length" class="panel" data-test="getting-started" aria-labelledby="gs">
          <header><h2 id="gs">{{ s.start.title }}</h2></header>
          <div class="body">
            <p class="muted">{{ s.start.lead }}</p>
            <ol class="steps">
              <li v-for="x in steps" :key="x.key" :data-step="x.key" :data-done="x.done">
                <Icon :name="x.done ? 'checkCircle' : 'circle'" />
                <div class="grow"><strong>{{ x.title }}</strong><span v-if="x.done" class="sr-only"> ({{ s.start.done }})</span><div class="muted">{{ x.text }}</div></div>
                <router-link v-if="!x.done" class="btn btn-sm" :class="{ 'btn-primary': x.key === nextStep }" :to="x.to">{{ s.start.open }}</router-link>
              </li>
            </ol>
          </div>
        </section>
        <NewReleaseNotice :images="l.data.value?.images" :may-create="can('images') && isGlobalAdmin()" @create="router.push('/images?create=1')" />
        <Callout v-if="!projectState.current && can('projects') && projectState.projects.length" tone="info" data-test="overview-no-project">{{ s.project.noneChosenText }} <router-link to="/projects">{{ s.project.goProjects }}</router-link></Callout>
        <Callout v-if="locked.length" tone="warn" data-test="locked-banner">
          <strong>{{ s.keys.banner(locked.length) }}.</strong> {{ s.keys.bannerLead }}
          <template v-for="(n, i) in locked" :key="n"><router-link class="mono" :to="`/jails/${n}`" :data-locked-link="n">{{ n }}</router-link>{{ i < locked.length - 1 ? ', ' : '' }}</template>
        </Callout>
        <section aria-labelledby="att">
          <h2 id="att" class="sr-only">{{ s.overview.attention }}</h2>
          <Callout v-if="!items.length" tone="ok">{{ s.overview.allClear }}</Callout>
          <div v-else class="panel" data-test="attention">
            <header><h2>{{ s.overview.attention }} ({{ items.length }})</h2></header>
            <ul class="attn">
              <li v-for="a in items" :key="a.key" :class="a.tone">
                <span class="pill" :class="a.tone">{{ a.tone === 'danger' ? s.state.error : s.overview.cond }}</span>
                <router-link v-if="a.to" :to="a.to">{{ a.text }}</router-link>
                <span v-else>{{ a.text }}</span>
              </li>
            </ul>
          </div>
        </section>

        <section class="tiles" :aria-label="s.overview.jailsByState">
          <router-link v-for="st in states" :key="st" class="tile panel" :to="{ path: '/jails', query: { state: st } }" :data-tile="st">
            <span class="tile-n">{{ counts[st] }}</span>
            <StatePill :state="st" />
          </router-link>
        </section>

        <div class="grid-2">
          <section class="panel">
            <header><h2>{{ s.overview.pool }}</h2><span v-if="pool" class="mono muted">{{ pool.name }}</span></header>
            <div class="body">
              <template v-if="pool">
                <Meter :value="poolPct" :label="s.overview.pool" :warn-at="75" :danger-at="90" />
                <p class="muted pool-figures" style="margin-top: 6px">
                  <span>{{ bytes(pool.allocated) }} {{ s.overview.used }}</span> · <span>{{ bytes(pool.free) }} {{ s.overview.free }}</span> · <span>{{ bytes(pool.size) }}</span> · <span>{{ Math.round(poolPct) }}%</span>
                </p>
              </template>
              <p v-else class="muted">{{ s.overview.poolUnknown }}</p>
            </div>
          </section>
          <section class="panel">
            <header><h2>{{ s.overview.recent }}</h2><router-link v-if="can('operations')" to="/operations">{{ s.nav.operations }}</router-link></header>
            <p v-if="!recent.length" class="empty">{{ s.overview.noOps }}</p>
            <div v-else class="table-wrap">
              <table>
                <thead class="sr-only"><tr><th>{{ s.overview.recent }}</th><th>{{ s.overview.opStatus }}</th><th>{{ s.overview.opWhen }}</th></tr></thead>
                <tbody>
                  <tr v-for="o in recent" :key="o.id">
                    <td>{{ o.description }}</td>
                    <td><span class="pill" :class="{ ok: o.status === 'success', danger: o.status === 'failure', info: o.status === 'running', warn: o.status === 'cancelled' }">{{ sentence(o.status) }}</span></td>
                    <td class="faint nowrap"><TimeStamp :ts="o.created_at" /></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </LoadState>
  </div>
</template>

<style>
.steps { list-style: none; margin: 8px 0 0; padding: 0; }
.steps li { display: flex; gap: 12px; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); }
.steps li:last-child { border-bottom: 0; }
.steps li[data-done='true'] { opacity: 0.65; }
.attn { list-style: none; margin: 0; padding: 0; }
.attn li { display: flex; gap: 10px; align-items: center; padding: 6px 12px; border-bottom: 1px solid var(--border); }
.attn li:last-child { border-bottom: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
.tile { display: flex; flex-direction: column; gap: 4px; padding: 10px 12px; text-decoration: none; color: var(--text); align-items: flex-start; }
.tile:hover { background: var(--surface-2); }
.pool-figures span { white-space: nowrap; }
.tile-n { font-size: 28px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums; }
</style>
