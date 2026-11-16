<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { common as s } from '../i18n/common'
import { session, logout } from '../composables/session'
import { startEvents, stopEvents, eventState } from '../composables/events'
import { theme, cycleTheme } from '../composables/theme'
import Icon from './Icon.vue'
import BrandMark from './BrandMark.vue'
import ToastHost from './ToastHost.vue'
import ConfirmHost from './ConfirmHost.vue'
import type { IconName } from '../lib/icons'

export interface NavItem { to: string; label: string; icon: IconName }

const props = defineProps<{ brand: string; items: NavItem[]; events: boolean; subtitle?: string }>()
const route = useRoute()
const router = useRouter()
const menuOpen = ref(false)

const themeIcon = computed<IconName>(() => (theme.value === 'light' ? 'sun' : theme.value === 'dark' ? 'moon' : 'monitor'))
const link = computed(() => (eventState.link === 'live' ? s.app.live : eventState.link === 'reconnecting' ? s.app.reconnecting(Math.ceil(eventState.retryIn / 1000)) : s.app.connecting))

watch(() => session.authed, (a) => {
  if (a && props.events) startEvents()
  else {
    stopEvents()
    if (!a && !route.meta.public) void router.replace('/login?next=' + encodeURIComponent(route.fullPath))
  }
}, { immediate: true })
watch(() => route.fullPath, () => (menuOpen.value = false))
// Escape closes the drawer and gives the focus back to the menu button
function closeMenu(): void {
  menuOpen.value = false
  ;(document.querySelector('.menu-btn') as HTMLElement | null)?.focus()
}

async function out(): Promise<void> {
  await logout()
  await router.replace('/login')
}
</script>

<template>
  <a class="skip" href="#main">{{ s.app.skip }}</a>
  <!-- a public page (the login, a first-run wizard) stands alone, without the navigation -->
  <slot v-if="route.meta.public" />
  <div v-else class="shell" :class="{ 'menu-open': menuOpen }">
    <header class="topbar">
      <button class="btn btn-ghost btn-icon menu-btn" type="button" :aria-label="s.app.menu" :aria-expanded="menuOpen" aria-controls="sidebar" @click="menuOpen = !menuOpen"><Icon name="menu" /></button>
      <span class="brand"><BrandMark />{{ brand }}<span v-if="subtitle" class="faint sub"> {{ subtitle }}</span></span>
      <span class="grow"></span>
      <slot name="search" where="top" />
      <span class="host mono faint">{{ session.info?.hostname }}</span>
    </header>
    <nav id="sidebar" class="sidebar" :aria-label="s.app.mainNav" @keydown.esc="menuOpen && closeMenu()">
      <div class="brand brand-side"><BrandMark :size="26" />{{ brand }}<span v-if="subtitle" class="faint sub"> {{ subtitle }}</span>
        <button class="btn btn-ghost btn-icon drawer-close" type="button" :aria-label="s.app.closeMenu" data-test="drawer-close" @click="closeMenu"><Icon name="x" /></button>
      </div>
      <!-- an app's search: once in the side bar and once in the phone's top bar -->
      <div v-if="$slots.search" class="side-search"><slot name="search" where="side" /></div>
      <router-link v-for="i in items" :key="i.to" :to="i.to" class="navlink" exact-active-class="active" :active-class="i.to === '/' ? '' : 'active'">
        <Icon :name="i.icon" />{{ i.label }}
      </router-link>
      <div class="side-foot">
        <div v-if="events" class="faint link-state" :data-link="eventState.link">{{ link }}</div>
        <div class="row" style="flex-wrap: nowrap">
          <button class="btn btn-sm grow" type="button" @click="cycleTheme"><Icon :name="themeIcon" />{{ s.app.theme[theme] }}</button>
          <button class="btn btn-sm btn-icon" type="button" :aria-label="s.app.signOut" :title="s.app.signOut" @click="out"><Icon name="logOut" /></button>
        </div>
        <div v-if="session.user" class="faint" style="font-size: 12px" data-test="whoami">{{ session.user }}<span v-if="session.role"> · <span class="mono">{{ session.role }}</span></span></div>
        <div class="faint mono" style="font-size: 12px">{{ session.info?.version }}</div>
      </div>
    </nav>
    <div v-if="menuOpen" class="scrim" @click="menuOpen = false"></div>
    <main id="main" class="main" tabindex="-1">
      <div v-if="$slots.header" class="ctxbar"><slot name="header" /></div>
      <div v-if="session.demo" class="callout info demo-banner" role="note"><Icon name="info" /><span>{{ s.app.demoBanner }}</span></div>
      <div v-if="session.wrongRole" class="callout danger demo-banner" role="alert"><Icon name="alertCircle" /><span>{{ s.app.wrongRole(session.wrongRole) }}</span></div>
      <slot />
    </main>
  </div>
  <ToastHost />
  <ConfirmHost />
</template>

<style>
.shell { display: grid; grid-template-columns: var(--sidebar-w) minmax(0, 1fr); min-height: 100vh; }
.topbar { display: none; }
.sidebar { position: sticky; top: 0; height: 100vh; overflow-y: auto; padding: 12px 8px; background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; gap: 2px; }
.brand { font-weight: 600; letter-spacing: 0.02em; }
.brand-side { padding: 4px 10px 12px; font-size: 16px; color: var(--accent); }
.drawer-close { display: none; margin-left: auto; color: var(--text-2); }
.brand .sub { font-size: 12px; font-weight: 400; color: var(--text-3); margin-left: 6px; }
@media (max-width: 480px) { .topbar .sub { display: none; } }
.navlink { display: flex; align-items: center; gap: 10px; padding: 4px 10px; border-radius: var(--radius); color: var(--text-2); text-decoration: none; min-height: 30px; flex: none; }
.navlink:hover { background: var(--surface-2); color: var(--text); }
.navlink.active { background: var(--accent-soft); color: var(--text); font-weight: 600; }
.navlink.active .icon { color: var(--accent); }
/* the theme switch and sign out stay in view on a short screen: the footer sticks to the bottom of the scrolling bar */
.side-foot { margin-top: auto; display: grid; gap: 6px; padding: 10px 4px 0; position: sticky; bottom: -12px; padding-bottom: 12px; background: var(--surface); border-top: 1px solid var(--border); }
.link-state { font-size: 12px; }
.side-search { padding: 0 2px 8px; }
.main { padding: 16px 20px 80px; min-width: 0; max-width: 1400px; width: 100%; }
.main:focus { outline: none; }
.demo-banner { margin-bottom: 12px; }
.ctxbar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.scrim { display: none; }
@media (max-width: 800px) {
  .shell { grid-template-columns: minmax(0, 1fr); }
  .topbar { display: flex; align-items: center; gap: 8px; padding: 6px var(--gutter); background: var(--surface); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 20; }
  .topbar .brand { color: var(--accent); }
  .host { font-size: 12px; overflow: hidden; text-overflow: ellipsis; max-width: 45vw; }
  .sidebar { position: fixed; z-index: 40; left: 0; top: 0; width: min(280px, 85vw); transform: translateX(-100%); transition: transform var(--dur); visibility: hidden; }
  .menu-open .sidebar { transform: none; visibility: visible; }
  .drawer-close { display: inline-flex; }
  .brand-side { display: flex; }
  .menu-open .scrim { display: block; position: fixed; inset: 0; background: rgb(0 0 0 / 0.4); z-index: 30; }
  .main { padding: 12px var(--gutter) 96px; }
}
</style>
