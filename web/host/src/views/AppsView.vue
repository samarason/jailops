<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { useLoad } from '@jailops/shared/composables/load'
import { can } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'
import { useInstallGate } from '@/composables/apps'
import { categoryCounts, installedJails, searchApps } from '@/lib/apps'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import AppIcon from '@/components/AppIcon.vue'
import AppsInstalled from '@/components/AppsInstalled.vue'
import AppInstallDialog from '@/components/AppInstallDialog.vue'
import TabBar from '@jailops/shared/components/TabBar.vue'
import { useTabQuery } from '@jailops/shared/composables/tabs'
import type { AppDetail, Jail } from '@jailops/shared/api/types'

const route = useRoute()
const router = useRouter()
const gate = useInstallGate()

// The catalog is small (one file per app): the details give the cards their icons and ports.
const l = useLoad(async () => {
  const list = await api.apps.list()
  const details = await Promise.all(list.filter((a) => a.valid).map((a) => api.apps.get(a.name).catch(() => null)))
  return { list, details: Object.fromEntries(details.filter((d): d is AppDetail => !!d).map((d) => [d.definition.name, d])) as Record<string, AppDetail> }
})
// Installed apps are jails of the current project; without a project there is nothing to list.
const jl = useLoad(async () => (projectState.current || !can('projects') ? installedJails(await api.jails.list()) : ([] as Jail[])))
watch(() => projectState.current, () => void jl.reload())

type Tab = 'catalog' | 'installed'
const { tab } = useTabQuery<Tab>(() => ['catalog', 'installed'], 'catalog')
const q = ref(typeof route.query.q === 'string' ? route.query.q : '')
const cat = ref(typeof route.query.category === 'string' ? route.query.category : '')
watch([q, cat], () => {
  const { q: _q, category: _c, ...rest } = route.query
  void router.replace({ query: { ...rest, ...(q.value ? { q: q.value } : {}), ...(cat.value ? { category: cat.value } : {}) } })
})
const tabItems = computed(() => [
  { key: 'catalog' as Tab, label: s.apps.catalogTab, count: all.value.length },
  { key: 'installed' as Tab, label: s.apps.installedTab, count: jl.data.value?.length ?? 0 },
])

const all = computed(() => l.data.value?.list ?? [])
const chips = computed(() => categoryCounts(all.value, q.value))
const total = computed(() => searchApps(all.value, q.value).length)
const shown = computed(() => searchApps(all.value, q.value, cat.value))
const details = computed(() => l.data.value?.details ?? {})

const installing = ref<AppDetail | null>(null)
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h1>{{ s.apps.title }}</h1>
        <p class="muted apps-lead">{{ s.apps.lead }}</p>
      </div>
    </div>
    <TabBar v-model="tab" :tabs="tabItems" :label="s.apps.sections" id="apps" />
    <div id="apps-panel" role="tabpanel" :aria-labelledby="`apps-tab-${tab}`">
      <LoadState :loading="l.loading.value" :error="l.error.value" :has-data="!!l.data.value" @retry="l.reload">
        <template v-if="tab === 'catalog'">
          <div class="apps-tools">
            <div class="apps-search">
              <Icon name="search" />
              <input v-model="q" type="search" :placeholder="s.apps.search" :aria-label="s.apps.searchLabel" :title="s.apps.searchLabel" data-test="apps-search" />
            </div>
            <div class="row apps-chips" role="group" :aria-label="s.apps.categories">
              <button class="apps-chip" type="button" :aria-pressed="cat === ''" data-category="" @click="cat = ''">{{ s.apps.all }}<span class="apps-chipn">{{ total }}</span></button>
              <button v-for="c in chips" :key="c.category" class="apps-chip" type="button" :aria-pressed="cat === c.category" :data-category="c.category" @click="cat = cat === c.category ? '' : c.category">{{ s.apps.category[c.category] ?? c.category }}<span class="apps-chipn">{{ c.count }}</span></button>
            </div>
          </div>
          <Callout v-if="gate.reason.value && all.length" tone="info" class="apps-gate" data-test="install-blocked">{{ gate.reason.value }} <router-link v-if="gate.toProject.value" :to="gate.toProject.value">{{ s.apps.toProject }}</router-link></Callout>
          <p v-if="!all.length" class="empty panel" data-test="apps-empty">{{ s.apps.empty }}</p>
          <div v-else-if="!shown.length" class="empty panel" data-test="apps-nomatch">
            <p>{{ s.apps.noMatch }}</p>
            <button class="btn btn-sm" type="button" @click="q = ''; cat = ''">{{ s.apps.clearSearch }}</button>
          </div>
          <p class="sr-only" role="status">{{ s.apps.count(shown.length) }}</p>
          <ul v-if="shown.length" class="app-grid" data-test="app-grid">
            <li v-for="a in shown" :key="a.name" class="app-card" :class="{ 'is-invalid': !a.valid }" :data-app="a.name">
              <div class="app-card-head">
                <AppIcon :name="a.name" :title="a.title" :icon="details[a.name]?.icon" :size="44" />
                <div class="grow">
                  <h2 class="app-card-title"><router-link class="app-card-link" :to="`/apps/${a.name}`">{{ a.title || a.name }}</router-link></h2>
                  <div class="faint mono app-card-name">{{ a.name }}<span v-if="a.version"> · {{ a.version }}</span></div>
                </div>
                <span v-if="a.source === 'local'" class="badge info" :title="a.overrides ? s.apps.overridesTitle : s.apps.localTitle" data-test="app-local">{{ s.apps.local }}</span>
                <span v-if="!a.valid" class="pill danger">{{ s.apps.invalid }}</span>
              </div>
              <p class="app-card-sum">{{ a.summary }}</p>
              <p v-if="!a.valid" class="app-card-err" data-test="invalid-reason"><strong>{{ s.apps.invalidText }}</strong> <span class="mono">{{ a.error }}</span></p>
              <div class="app-card-foot">
                <span v-if="a.category" class="chip">{{ s.apps.category[a.category] ?? a.category }}</span>
                <span v-for="p in details[a.name]?.definition.ports ?? []" :key="p.port + p.proto" class="chip mono app-port" :title="p.description">{{ p.port }}/{{ p.proto }}</span>
                <span class="grow"></span>
                <button v-if="a.valid && details[a.name]" class="btn btn-sm app-card-act" type="button" :disabled="!!gate.block.value" :title="gate.reason.value || undefined" :data-test="`install-${a.name}`" @click="installing = details[a.name]"><Icon name="pkg" />{{ s.apps.install }}</button>
              </div>
            </li>
          </ul>
        </template>
        <AppsInstalled v-else :jails="jl.data.value ?? []" :loading="jl.loading.value" :error="jl.error.value" :details="details" @retry="jl.reload" @changed="jl.reload" />
      </LoadState>
    </div>
    <AppInstallDialog :open="!!installing" :detail="installing" @close="installing = null" @done="jl.reload" />
  </div>
</template>

<style>
.apps-lead { max-width: 72ch; margin: 4px 0 0; }
.apps-tools { display: flex; gap: 10px 16px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
.apps-search { position: relative; flex: 1 1 260px; max-width: 420px; }
.apps-search .icon { position: absolute; left: 9px; top: 8px; color: var(--text-3); pointer-events: none; }
.apps-search input { padding-left: 32px; }
.apps-chips { gap: 6px; }
.apps-chip { display: inline-flex; align-items: center; gap: 6px; min-height: 28px; padding: 2px 6px 2px 10px; border: 1px solid var(--border-strong); border-radius: 999px; background: var(--surface); cursor: pointer; font-size: 13px; color: var(--text-2); }
.apps-chip:hover { background: var(--surface-2); color: var(--text); }
.apps-chip[aria-pressed='true'] { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
.apps-chipn { min-width: 20px; padding: 0 6px; border-radius: 999px; background: var(--surface-2); color: var(--text-2); font-size: 12px; text-align: center; }
.apps-chip[aria-pressed='true'] .apps-chipn { background: var(--accent-hover); color: var(--accent-text); }
.apps-gate { margin-bottom: 12px; }
.app-grid { list-style: none; margin: 0; padding: 0; display: grid; gap: 12px; grid-template-columns: repeat(auto-fill, minmax(min(100%, 290px), 1fr)); }
.app-card { position: relative; display: flex; flex-direction: column; gap: 8px; padding: 14px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); transition: border-color var(--dur), box-shadow var(--dur); min-width: 0; }
.app-card:hover { border-color: var(--border-strong); box-shadow: var(--shadow); }
.app-card:focus-within { border-color: var(--focus); }
.app-card.is-invalid { border-style: dashed; }
.app-card.is-invalid .app-icon { filter: grayscale(1); opacity: 0.7; }
.app-card-head { display: flex; gap: 12px; align-items: center; min-width: 0; }
.app-card-title { font-size: 15px; }
.app-card-link { color: var(--text); text-decoration: none; }
.app-card-link::after { content: ''; position: absolute; inset: 0; border-radius: var(--radius-lg); }
.app-card-link:focus-visible { outline: none; }
.app-card-link:focus-visible::after { outline: 2px solid var(--focus); outline-offset: 2px; }
.app-card-name { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.app-card-sum { color: var(--text-2); margin: 0; flex: 1 1 auto; }
.app-card-err { margin: 0; font-size: 12px; color: var(--danger); overflow-wrap: anywhere; }
.app-card-foot { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
.app-card-foot .chip { margin: 0; }
.app-port { color: var(--text-2); }
.app-card-act { position: relative; z-index: 1; }
</style>
