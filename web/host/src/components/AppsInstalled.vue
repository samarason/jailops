<script setup lang="ts">
import { s } from '@/i18n'
import { askDelete } from '@/composables/jailActions'
import { can, hasExt } from '@jailops/shared/composables/session'
import { projectState } from '@/composables/project'
import { LABEL_APP, LABEL_HASH, LABEL_VERSION, openLinks } from '@/lib/apps'
import type { ApiError } from '@jailops/shared/api/client'
import Icon from '@jailops/shared/components/Icon.vue'
import Callout from '@jailops/shared/components/Callout.vue'
import LoadState from '@jailops/shared/components/LoadState.vue'
import AddrCopy from '@jailops/shared/components/AddrCopy.vue'
import AppIcon from '@/components/AppIcon.vue'
import StatePill from '@/components/StatePill.vue'
import LabelChips from '@/components/LabelChips.vue'
import { useRouter } from 'vue-router'
import { withLabel } from '@/lib/labels'
import { canShell, shellPath } from '@/composables/shell'
import type { AppDetail, Jail } from '@jailops/shared/api/types'

// The jails of the project that carry the label jailops.app: the project's jail list narrowed on the
// client, as the command line does. Ports and links come from the app's definition in the catalog.
defineProps<{ jails: Jail[]; loading: boolean; error: ApiError | null; details: Record<string, AppDetail> }>()
const emit = defineEmits<{ retry: []; changed: [] }>()
// uninstalling is deleting the jail the installation made (the dialog says so and lists the data that goes)
const uninstall = (j: Jail) => askDelete(j, [], () => emit('changed'))
const appOf = (j: Jail) => j.metadata.labels?.[LABEL_APP] ?? ''
const router = useRouter()
const filter = (k: string, v: string) => void router.push({ path: '/jails', query: { q: withLabel('', k, v) } })
</script>

<template>
  <div data-test="apps-installed">
    <Callout v-if="can('projects') && !projectState.current" tone="info">{{ s.apps.needProject }}</Callout>
    <LoadState v-else :loading="loading" :error="error" :has-data="!loading || !!jails.length" @retry="emit('retry')">
      <p class="muted">{{ s.apps.installedLead }}</p>
      <div class="panel">
        <p v-if="!jails.length" class="empty" data-test="installed-empty">{{ s.apps.noInstalled }}</p>
        <div v-else class="table-wrap">
          <table class="rtable" data-test="installed-table">
            <thead>
              <tr>
                <th>{{ s.apps.app }}</th>
                <th>{{ s.apps.jail }}</th>
                <th class="hide-sm">{{ s.install.version }}</th>
                <th>{{ s.apps.state }}</th>
                <th class="hide-sm">{{ s.apps.addresses }}</th>
                <th class="hide-sm">{{ s.apps.ports }}</th>
                <th><span class="sr-only">{{ s.jails.actions }}</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="j in jails" :key="j.metadata.name" :data-installed="j.metadata.name">
                <td :data-label="s.apps.app">
                  <div class="inst-app">
                    <AppIcon :name="appOf(j)" :title="details[appOf(j)]?.definition.title" :icon="details[appOf(j)]?.icon" :size="28" />
                    <div>
                      <router-link :to="`/apps/${appOf(j)}`">{{ details[appOf(j)]?.definition.title || appOf(j) }}</router-link>
                      <span v-if="details[appOf(j)]?.source === 'local'" class="badge info inst-changed" :title="s.apps.localTitle" data-test="app-local">{{ s.apps.local }}</span>
                      <span v-if="details[appOf(j)] && j.metadata.labels?.[LABEL_HASH] && j.metadata.labels[LABEL_HASH] !== details[appOf(j)].hash" class="badge warn inst-changed" :title="s.apps.changedTitle">{{ s.apps.changed }}</span>
                    </div>
                  </div>
                </td>
                <td :data-label="s.apps.jail"><router-link class="mono" :to="`/jails/${j.metadata.name}`">{{ j.metadata.name }}</router-link><div class="inst-labels"><LabelChips :labels="j.metadata.labels" :max="2" pick @pick="filter" /></div></td>
                <td class="mono hide-sm" :data-label="s.install.version">{{ j.metadata.labels?.[LABEL_VERSION] || '-' }}</td>
                <td :data-label="s.apps.state"><StatePill :state="j.status.power" /></td>
                <td class="hide-sm" :data-label="s.apps.addresses"><span v-if="!j.status.addresses?.length" class="faint">-</span><div v-for="a in j.status.addresses" :key="a"><AddrCopy :value="a" /></div></td>
                <td class="hide-sm" :data-label="s.apps.ports"><span v-for="p in details[appOf(j)]?.definition.ports ?? []" :key="p.port + p.proto" class="chip mono" :title="p.description">{{ p.name }} {{ p.port }}/{{ p.proto }}</span></td>
                <td class="actions"><div class="row-actions">
                  <a v-for="o in openLinks(j, details[appOf(j)]?.definition.ports)" :key="o.url" class="btn btn-sm" :href="o.url" target="_blank" rel="noopener noreferrer" :title="s.apps.openTitle(o.url)" :aria-label="s.apps.openTitle(o.url)" :data-test="`open-${j.metadata.name}`"><Icon name="externalLink" />{{ s.apps.open }}</a>
                  <router-link v-if="hasExt('app_access')" class="btn btn-sm btn-ghost" :to="{ path: `/jails/${j.metadata.name}`, query: { tab: 'access' } }" :data-test="`access-${j.metadata.name}`"><Icon name="shield" />{{ s.appAccess.tab }}</router-link>
                  <router-link v-if="canShell() && j.status.power === 'running'" class="btn btn-sm btn-ghost" :to="shellPath(j.metadata.name)" :aria-label="s.shell.openTitle(j.metadata.name)" :data-shell="j.metadata.name"><Icon name="terminal" />{{ s.shell.open }}</router-link>
                  <router-link class="btn btn-sm btn-ghost" :to="{ path: `/jails/${j.metadata.name}`, query: { tab: 'logs' } }"><Icon name="fileText" />{{ s.logs.tab }}</router-link>
                  <button class="btn btn-sm btn-danger" type="button" :data-test="`uninstall-${j.metadata.name}`" :aria-label="s.jails.uninstallTitle(appOf(j), j.metadata.name)" @click="uninstall(j)"><Icon name="trash" />{{ s.jails.uninstall }}</button>
                </div></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </LoadState>
  </div>
</template>

<style>
.inst-app { display: flex; gap: 8px; align-items: center; }
.inst-changed { margin-left: 6px; }
.inst-labels { margin-top: 2px; }
</style>
