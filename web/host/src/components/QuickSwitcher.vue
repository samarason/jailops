<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { s } from '@/i18n'
import { can, hasExt, session } from '@jailops/shared/composables/session'
import { projectState, switchProject } from '@/composables/project'
import { askLifecycle } from '@/composables/jailActions'
import { canShell, goShell } from '@/composables/shell'
import { closeSwitcher, indexState, loadAllProjects, openSwitcher, pageEntries, refreshIndex, saveAllProjects, switcherState } from '@/composables/search'
import { entry, loadRecent, pushRecent, rank, typingTarget, type Entry, type Kind } from '@/lib/search'
import Icon from '@jailops/shared/components/Icon.vue'
import StatePill from '@/components/StatePill.vue'
import LabelChips from '@/components/LabelChips.vue'
import type { NavItem } from '@jailops/shared/components/AppShell.vue'
import type { IconName } from '@jailops/shared/lib/icons'

// The quick switcher: Ctrl+K (Cmd+K) anywhere, `/` where no text is typed, or the Search button. A combobox over a
// listbox of grouped results; the focus stays in the box and the arrow keys move the active option. A jail row has
// quick actions: Shift+Enter opens its shell, Alt+L its logs, Alt+S starts or stops it (stop asks first, as
// everywhere).
const props = defineProps<{ pages: NavItem[] }>()
const router = useRouter()
const route = useRoute()

const q = ref('')
const dq = ref('')
const active = ref(0)
const all = ref(loadAllProjects())
const input = ref<HTMLInputElement | null>(null)
const box = ref<HTMLElement | null>(null)
const list = ref<HTMLElement | null>(null)
let opener: HTMLElement | null = null
let debounce: ReturnType<typeof setTimeout> | undefined

const multi = computed(() => can('projects') && projectState.projects.length > 1)
const allProjects = computed(() => multi.value && all.value)

const kindIcon: Record<Kind, IconName> = { jail: 'box', app: 'store', image: 'layers', network: 'network', project: 'users', storage: 'hardDrive', page: 'layoutDashboard' }

interface Section { key: string; label: string; icon: IconName; items: Entry[]; more: number }

const pages = computed(() => pageEntries(props.pages))
const entries = computed(() => [...indexState.entries, ...pages.value])
const recent = ref(loadRecent())
const ranked = computed(() => rank(entries.value, dq.value))

const sections = computed<Section[]>(() => {
  if (!dq.value.trim()) {
    const byId = new Map(entries.value.map((e) => [e.id, e]))
    const rec = recent.value.map((r) => byId.get(r.id) ?? entry({ kind: r.kind, id: r.id, title: r.title, to: r.to, project: r.project, icon: kindIcon[r.kind] ?? 'box' }))
    const out: Section[] = []
    if (rec.length) out.push({ key: 'recent', label: s.search.recent, icon: 'history', items: rec, more: 0 })
    const seen = new Set(rec.map((e) => e.id))
    out.push({ key: 'jump', label: s.search.jump, icon: 'layoutDashboard', items: pages.value.filter((p) => !seen.has(p.id)).slice(0, rec.length ? 6 : 10), more: 0 })
    return out
  }
  return ranked.value.groups.map((g) => ({ key: g.kind, label: s.search.groups[g.kind], icon: kindIcon[g.kind], items: g.items, more: g.more }))
})
const flat = computed(() => sections.value.flatMap((x) => x.items))
const total = computed(() => (dq.value.trim() ? ranked.value.total : flat.value.length))
const current = computed<Entry | undefined>(() => flat.value[active.value])
const optId = (i: number) => `qs-opt-${i}`
const indexOf = (e: Entry) => flat.value.indexOf(e)
const announce = computed(() => (indexState.loading && !indexState.loaded ? s.search.loading : dq.value.trim() ? s.search.count(total.value) : ''))

watch(q, (v) => {
  clearTimeout(debounce)
  // the first letters answer at once; a burst of typing is ranked once it pauses
  debounce = setTimeout(() => (dq.value = v), v.length < 2 ? 0 : 60)
})
watch(dq, () => (active.value = 0))
watch(flat, (f) => { if (active.value >= f.length) active.value = Math.max(0, f.length - 1) })
watch(active, async () => {
  await nextTick()
  list.value?.querySelector(`#${optId(active.value)}`)?.scrollIntoView?.({ block: 'nearest' })
})

watch(() => switcherState.open, async (o) => {
  if (o) {
    opener = document.activeElement as HTMLElement | null
    recent.value = loadRecent()
    q.value = ''
    dq.value = ''
    active.value = 0
    lastPointer = ''
    void refreshIndex(allProjects.value)
    await nextTick()
    input.value?.focus()
  }
})
watch(allProjects, (a) => {
  saveAllProjects(a)
  if (switcherState.open) void refreshIndex(a)
})

/** Close and give the focus back to what had it, before a navigation or a confirmation takes it. */
function close(): void {
  if (!switcherState.open) return
  closeSwitcher()
  opener?.focus?.()
}

function remember(e: Entry): void {
  pushRecent({ id: e.id, kind: e.kind, title: e.title, to: e.to, project: e.project })
}
/** A jail of another project switches the console to that project first, as the project switcher would. */
function enter(e: Entry): void {
  if (e.project && can('projects') && e.project !== projectState.current) switchProject(e.project)
}
function choose(e: Entry | undefined): void {
  if (!e) return
  remember(e)
  close()
  enter(e)
  void router.push(e.to)
}

const shellOK = (e: Entry) => e.kind === 'jail' && e.state !== 'locked' && canShell(e.project)
const logsOK = (e: Entry) => e.kind === 'jail' && hasExt('jail_logs')
const power = (e: Entry): 'start' | 'stop' | '' => (e.kind !== 'jail' ? '' : e.state === 'running' ? 'stop' : e.state === 'stopped' || e.state === 'error' ? 'start' : '')

function shell(e: Entry | undefined): void {
  if (!e || !shellOK(e)) return
  remember(e)
  close()
  enter(e)
  void goShell(router, e.title, e.state ?? '')
}
function logs(e: Entry | undefined): void {
  if (!e || !logsOK(e)) return
  remember(e)
  close()
  enter(e)
  void router.push({ path: e.to, query: { tab: 'logs' } })
}
function toggle(e: Entry | undefined): void {
  const a = e && power(e)
  if (!e || !a) return
  close()
  enter(e)
  // start runs at once; stop names the jail and asks (tier 2)
  askLifecycle(e.title, a, e.state ?? '')
}

// The pointer picks the active option only when it really moves: a list that scrolls under a resting pointer (the
// arrow keys scroll it) sends mouse moves too, which would undo the keys.
let lastPointer = ''
function hover(ev: MouseEvent, e: Entry): void {
  const at = `${ev.screenX},${ev.screenY}`
  if (at === lastPointer) return
  const first = !lastPointer
  lastPointer = at
  if (!first) active.value = indexOf(e)
}

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'
function onKey(e: KeyboardEvent): void {
  const n = flat.value.length
  if (e.key === 'Escape') {
    e.preventDefault()
    e.stopPropagation()
    close()
  } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault()
    if (n) active.value = (active.value + (e.key === 'ArrowDown' ? 1 : n - 1)) % n
  } else if ((e.key === 'Home' || e.key === 'End') && e.ctrlKey) {
    e.preventDefault()
    active.value = e.key === 'Home' ? 0 : Math.max(0, n - 1)
  } else if (e.key === 'Enter' && e.target === input.value) {
    e.preventDefault()
    if (e.shiftKey) shell(current.value)
    else choose(current.value)
  } else if (e.altKey && e.code === 'KeyL') {
    e.preventDefault()
    logs(current.value)
  } else if (e.altKey && e.code === 'KeyS') {
    e.preventDefault()
    toggle(current.value)
  } else if (e.key === 'Tab' && box.value) {
    const items = [...box.value.querySelectorAll<HTMLElement>(FOCUSABLE)]
    if (!items.length) return
    const first = items[0]
    const last = items[items.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }
}

/** Ctrl+K or Cmd+K anywhere but in the terminal (the shell's own Ctrl+K), `/` where nothing is typed. */
function onGlobal(e: KeyboardEvent): void {
  if (e.defaultPrevented || !session.authed || route.meta.public) return
  const t = e.target instanceof Element ? e.target : null
  if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') {
    if (t?.closest('.term')) return
    e.preventDefault()
    if (switcherState.open) close()
    else if (!document.querySelector('.modal-backdrop')) openSwitcher()
    return
  }
  if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !switcherState.open && !typingTarget(document.activeElement) && !document.querySelector('.modal-backdrop')) {
    e.preventDefault()
    openSwitcher()
  }
}
onMounted(() => window.addEventListener('keydown', onGlobal))
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onGlobal)
  clearTimeout(debounce)
})
// a navigation that did not come from here (the back button) closes the box
watch(() => route.fullPath, () => { if (switcherState.open) closeSwitcher() })
</script>

<template>
  <Teleport to="body">
    <div v-if="switcherState.open" class="modal-backdrop qs-backdrop" data-test="qs-backdrop" @mousedown.self="close">
      <div ref="box" class="qs" role="dialog" aria-modal="true" :aria-label="s.search.title" data-test="quick-switcher" :data-query="dq" @keydown="onKey">
        <div class="qs-head">
          <Icon name="search" />
          <input
            ref="input" v-model="q" class="qs-input" type="text" role="combobox" autocomplete="off" spellcheck="false" autocapitalize="off" enterkeyhint="go"
            :aria-label="s.search.input" :placeholder="s.search.placeholder" aria-autocomplete="list" :aria-expanded="flat.length > 0"
            aria-controls="qs-list" :aria-activedescendant="flat.length ? optId(active) : undefined" aria-describedby="qs-keys" data-test="qs-input"
          />
          <button class="btn btn-ghost btn-sm qs-esc" type="button" :aria-label="s.search.close" data-test="qs-close" @click="close"><kbd>Esc</kbd></button>
        </div>
        <div v-if="multi" class="qs-scope">
          <label class="qs-all"><input v-model="all" type="checkbox" data-test="qs-all" /> {{ s.search.allProjects }}</label>
          <span class="faint">{{ allProjects ? s.search.allProjectsHint(projectState.projects.length) : s.search.inProject(projectState.current) }}</span>
        </div>
        <div v-if="flat.length" id="qs-list" ref="list" class="qs-list" role="listbox" :aria-label="s.search.results">
          <div v-for="g in sections" :key="g.key" class="qs-group" role="group" :aria-labelledby="`qs-g-${g.key}`">
            <div :id="`qs-g-${g.key}`" class="qs-ghead"><Icon :name="g.icon" />{{ g.label }}</div>
            <div
              v-for="e in g.items" :id="optId(indexOf(e))" :key="g.key + e.id" class="qs-row" role="option" :aria-selected="indexOf(e) === active"
              :aria-describedby="e.kind === 'jail' ? 'qs-opt-hint' : undefined" :data-qs="e.id" :data-kind="e.kind"
              @click="choose(e)" @mousemove="hover($event, e)"
            >
              <Icon class="qs-icon" :name="e.icon" />
              <span class="qs-main">
                <span class="qs-line">
                  <span class="qs-title" :class="{ mono: e.kind !== 'page' }">{{ e.title }}</span>
                  <StatePill v-if="e.state" :state="e.state" />
                  <span v-if="e.kind !== 'jail' && e.kind !== 'page' && g.key === 'recent'" class="faint qs-kind">{{ s.search.kind[e.kind] }}</span>
                  <LabelChips v-if="e.kind === 'jail'" class="qs-chips" :labels="e.labels" :max="3" />
                </span>
                <span v-if="e.sub" class="qs-sub">{{ e.sub }}</span>
              </span>
              <span v-if="e.kind === 'jail'" class="qs-acts" aria-hidden="true">
                <span v-if="shellOK(e)" class="qs-act" data-act="shell" :title="s.search.shell + ' (Shift+Enter)'" @click.stop="shell(e)"><Icon name="terminal" /><span class="qs-act-t">{{ s.search.shell }}</span><kbd class="qs-kbd">⇧↵</kbd></span>
                <span v-if="logsOK(e)" class="qs-act" data-act="logs" :title="s.search.logs + ' (Alt+L)'" @click.stop="logs(e)"><Icon name="fileText" /><span class="qs-act-t">{{ s.search.logs }}</span></span>
                <span v-if="power(e)" class="qs-act" :data-act="power(e)" :title="(power(e) === 'stop' ? s.search.stop : s.search.start) + ' (Alt+S)'" @click.stop="toggle(e)"><Icon :name="power(e) === 'stop' ? 'square' : 'play'" /><span class="qs-act-t">{{ power(e) === 'stop' ? s.search.stop : s.search.start }}</span></span>
              </span>
              <Icon v-else class="qs-go" name="chevronLeft" />
            </div>
            <div v-if="g.more" class="qs-more faint" data-test="qs-more">{{ s.search.more(g.more) }}</div>
          </div>
        </div>
        <div v-else class="qs-empty" data-test="qs-empty">
          <template v-if="indexState.loading && !indexState.loaded">{{ s.search.loading }}</template>
          <template v-else-if="dq.trim()"><p><strong>{{ s.search.none(dq.trim()) }}</strong></p><p class="faint">{{ s.search.noneHint }}</p></template>
          <template v-else>{{ s.search.noRecent }}</template>
        </div>
        <footer id="qs-keys" class="qs-foot faint">
          <span><kbd>↑</kbd><kbd>↓</kbd> {{ s.search.keys.move }}</span>
          <span><kbd>↵</kbd> {{ s.search.keys.open }}</span>
          <span><kbd>⇧↵</kbd> {{ s.search.keys.shell }}</span>
          <span><kbd>Alt L</kbd> {{ s.search.keys.logs }}</span>
          <span><kbd>Alt S</kbd> {{ s.search.keys.power }}</span>
          <span><kbd>Esc</kbd> {{ s.search.keys.close }}</span>
        </footer>
        <span id="qs-opt-hint" class="sr-only">{{ s.search.optionHint }}</span>
        <span class="sr-only" role="status" aria-live="polite" data-test="qs-status">{{ announce }}</span>
      </div>
    </div>
  </Teleport>
</template>

<style>
.qs-backdrop { padding-top: 10vh; }
.qs { width: min(680px, 100%); background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius-lg); box-shadow: var(--shadow); display: flex; flex-direction: column; max-height: min(640px, calc(100dvh - 10vh - var(--gutter))); overflow: hidden; }
.qs-head { display: flex; align-items: center; gap: 10px; padding: 8px 8px 8px 14px; border-bottom: 1px solid var(--border); color: var(--text-2); }
.qs-head > .icon { flex: none; }
.qs-head .qs-input { flex: 1; min-width: 0; border: 0; background: transparent; font-size: 16px; padding: 8px 0; color: var(--text); box-shadow: none; }
.qs-head .qs-input:focus { outline: none; box-shadow: none; }
.qs:focus-within .qs-head { box-shadow: inset 0 -2px 0 var(--focus); }
.qs-esc kbd { font-size: 11px; padding: 1px 5px; border: 1px solid var(--border-strong); border-radius: var(--radius); color: var(--text-2); }
.qs-scope { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 6px 14px; border-bottom: 1px solid var(--border); background: var(--surface-2); font-size: 13px; }
.qs-all { display: inline-flex; align-items: center; gap: 6px; font-weight: 500; }
.qs-list { overflow-y: auto; padding: 4px 6px 8px; min-height: 0; flex: 1 1 auto; }
.qs-ghead { display: flex; align-items: center; gap: 6px; padding: 10px 8px 4px; font-size: 12px; font-weight: 600; letter-spacing: 0.03em; text-transform: uppercase; color: var(--text-3); }
.qs-ghead .icon { width: 14px; height: 14px; }
.qs-row { display: flex; align-items: center; gap: 10px; padding: 6px 8px; border-radius: var(--radius); cursor: pointer; min-height: 44px; border-left: 3px solid transparent; }
.qs-row[aria-selected='true'] { background: var(--accent-soft); border-left-color: var(--accent); }
.qs-icon { flex: none; color: var(--text-3); }
.qs-row[aria-selected='true'] .qs-icon { color: var(--accent); }
.qs-main { flex: 1; min-width: 0; display: grid; gap: 1px; }
.qs-line { display: flex; align-items: center; gap: 8px; min-width: 0; flex-wrap: nowrap; overflow: hidden; }
.qs-title { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: none; max-width: 60%; }
.qs-chips { flex-wrap: nowrap; overflow: hidden; }
.qs-kind { font-size: 12px; }
.qs-sub { font-size: 12px; color: var(--text-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.qs-row[aria-selected='true'] .qs-sub { color: var(--text-2); }
.qs-acts { display: flex; gap: 4px; flex: none; }
.qs-act { display: inline-flex; align-items: center; gap: 4px; min-height: 30px; padding: 2px 8px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); color: var(--text-2); font-size: 12px; white-space: nowrap; }
.qs-act:hover { border-color: var(--accent); color: var(--text); }
.qs-act .icon { width: 14px; height: 14px; }
.qs-kbd { font-size: 11px; color: var(--text-3); }
.qs-row:not([aria-selected='true']) .qs-act:not([data-act='shell']) { display: none; }
.qs-row:not([aria-selected='true']) .qs-kbd { display: none; }
.qs-go { flex: none; transform: rotate(180deg); color: var(--text-3); visibility: hidden; }
.qs-row[aria-selected='true'] .qs-go { visibility: visible; }
.qs-more { padding: 4px 8px 2px 38px; font-size: 12px; }
.qs-empty { padding: 24px 16px; text-align: center; color: var(--text-2); }
.qs-empty p { margin: 0 0 4px; }
.qs-foot { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 8px 14px; border-top: 1px solid var(--border); background: var(--surface-2); font-size: 12px; }
.qs-foot kbd { display: inline-block; min-width: 18px; padding: 0 4px; margin-right: 2px; border: 1px solid var(--border-strong); border-radius: var(--radius); background: var(--surface); color: var(--text-2); text-align: center; font-size: 11px; }
@media (max-width: 600px) {
  .qs-backdrop { padding-top: 8px; }
  .qs { max-height: calc(100dvh - 16px); }
  .qs-foot { display: none; }
  .qs-act-t, .qs-kbd { display: none; }
  .qs-act { min-width: 36px; min-height: 36px; justify-content: center; }
  .qs-row:not([aria-selected='true']) .qs-act:not([data-act='shell']) { display: inline-flex; }
  .qs-chips { display: none; }
  .qs-title { max-width: 100%; }
}
</style>
