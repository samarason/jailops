<script setup lang="ts">
import { computed } from 'vue'
import { s } from '@/i18n'
import { watch } from 'vue'
import { can, isHub, hasExt, session } from '@jailops/shared/composables/session'
import ProjectSwitcher from '@/components/ProjectSwitcher.vue'
import { initProjects, projectState } from '@/composables/project'
import { useRoute } from 'vue-router'
import NoProject from '@/components/NoProject.vue'
import PendingBanner from '@/components/PendingBanner.vue'
import AppShell, { type NavItem } from '@jailops/shared/components/AppShell.vue'
import Icon from '@jailops/shared/components/Icon.vue'
import QuickSwitcher from '@/components/QuickSwitcher.vue'
import { openSwitcher } from '@/composables/search'

const items = computed<NavItem[]>(() => ([
  { to: '/', label: s.nav.overview, icon: 'layoutDashboard', show: true },
  { to: '/jails', label: s.nav.jails, icon: 'box', show: can('jails') },
  { to: '/volumes', label: s.nav.volumes, icon: 'database', show: hasExt('volumes') },
  { to: '/projects', label: s.nav.projects, icon: 'users', show: can('projects') },
  { to: '/storage', label: s.nav.storage, icon: 'hardDrive', show: can('storage') },
  { to: '/images', label: s.nav.images, icon: 'layers', show: can('images') },
  { to: '/apps', label: s.nav.apps, icon: 'store', show: can('apps') },
  { to: '/networks', label: s.nav.networks, icon: 'network', show: can('networks') },
  { to: '/firewall', label: s.nav.firewall, icon: 'shield', show: can('firewall') },
  { to: '/profiles', label: s.nav.profiles, icon: 'wrench', show: can('jails') },
  { to: '/updates', label: s.nav.updates, icon: 'arrowUp', show: hasExt('updates') },
  { to: '/backups', label: s.nav.backups, icon: 'archive', show: can('backups') },
  { to: '/host', label: s.nav.host, icon: 'monitor', show: hasExt('host_identity') },
  { to: '/hosts', label: s.nav.hosts, icon: 'server', show: isHub.value },
  { to: '/logs', label: s.nav.logs, icon: 'fileText', show: hasExt('logs_unified') || hasExt('log_forward') },
  { to: '/operations', label: s.nav.operations, icon: 'listChecks', show: can('operations') },
  { to: '/events', label: s.nav.events, icon: 'radio', show: can('events') },
  { to: '/doctor', label: s.nav.doctor, icon: 'activity', show: can('doctor') },
  { to: '/audit', label: s.nav.audit, icon: 'scrollText', show: can('audit') },
  { to: '/access', label: s.nav.access, icon: 'keyRound', show: true },
] as Array<NavItem & { show: boolean }>).filter((i) => i.show))
const route = useRoute()
/** A page that works inside a project needs one: there is no default project to fall back to. */
const needsProject = computed(() => !!route.meta.project && can('projects') && !projectState.current)
watch(() => session.authed, (a) => { if (a && can('projects')) void initProjects() }, { immediate: true })
const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)
</script>

<template>
  <AppShell :brand="s.app.name" :subtitle="s.app.role" :items="items" :events="can('events')">
    <template v-if="can('projects')" #header><ProjectSwitcher /></template>
    <template v-if="session.authed" #search="{ where }">
      <button class="btn search-btn" :class="`search-${where}`" type="button" :aria-label="s.search.openTitle" :title="s.search.openTitle" :data-test="`search-open-${where}`" aria-haspopup="dialog" @click="openSwitcher">
        <Icon name="search" /><span class="search-word">{{ s.search.open }}</span><kbd class="search-kbd">{{ mac ? '⌘K' : 'Ctrl K' }}</kbd>
      </button>
    </template>
    <PendingBanner v-if="session.authed && hasExt('host_pending')" />
    <NoProject v-if="needsProject" />
    <!-- keyed by the path: another jail (from the search) is a new page, not the old one with a new name -->
    <router-view v-else :key="route.path" />
  </AppShell>
  <QuickSwitcher v-if="session.authed" :pages="items" />
</template>

<style>
.search-btn { justify-content: flex-start; color: var(--text-2); }
.search-side { width: 100%; background: var(--surface-2); }
.search-side .search-word { flex: 1; text-align: left; }
.search-kbd { font-size: 11px; padding: 0 5px; border: 1px solid var(--border-strong); border-radius: var(--radius); background: var(--surface); color: var(--text-2); }
.search-top { min-width: 36px; min-height: 36px; padding: 4px 8px; }
.search-top .search-kbd { display: none; }
@media (max-width: 480px) { .search-top .search-word { display: none; } }
</style>
