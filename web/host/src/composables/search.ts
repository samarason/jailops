import { reactive } from 'vue'
import { s } from '@/i18n'
import { api } from '@/api/endpoints'
import { can } from '@jailops/shared/composables/session'
import { dataVersion } from '@jailops/shared/composables/events'
import { projectState } from '@/composables/project'
import { shortAddr } from '@jailops/shared/lib/format'
import { entry, type Entry } from '@/lib/search'
import { LABEL_APP } from '@/lib/apps'
import type { NavItem } from '@jailops/shared/components/AppShell.vue'
import type { Jail } from '@jailops/shared/api/types'

// The quick switcher's index: the lists the console already reads, loaded once when the switcher opens and again
// after the server reported a change, the project changed or a minute passed. Everything stays in memory; a list the
// identity may not read is left out.

export const switcherState = reactive({ open: false })

export function openSwitcher(): void {
  switcherState.open = true
}
export function closeSwitcher(): void {
  switcherState.open = false
}

const ALL_KEY = 'jailops.searchAll'
export function loadAllProjects(): boolean {
  try {
    return localStorage.getItem(ALL_KEY) === '1'
  } catch {
    return false
  }
}
export function saveAllProjects(v: boolean): void {
  try {
    localStorage.setItem(ALL_KEY, v ? '1' : '0')
  } catch {
    /* the choice lasts while the page is open */
  }
}

export function jailEntry(j: Jail, project: string | undefined, showProject: boolean): Entry {
  const addrs = (j.status.addresses ?? []).map(shortAddr)
  const app = j.metadata.labels?.[LABEL_APP]
  const sub = [showProject && project ? s.search.inProject(project) : '', j.spec.image, addrs.join(', '), app ? s.search.runsApp(app) : ''].filter(Boolean).join(' · ')
  return entry({
    kind: 'jail', id: `jail:${project ?? ''}:${j.metadata.name}`, title: j.metadata.name, sub, to: `/jails/${encodeURIComponent(j.metadata.name)}`,
    icon: 'box', project, state: j.status.power, labels: j.metadata.labels ?? {}, app,
    extra: [j.spec.image, ...(j.status.addresses ?? []), ...addrs, app ?? '', showProject ? project ?? '' : ''],
  })
}

export function pageEntries(items: NavItem[]): Entry[] {
  return items.map((i) => entry({ kind: 'page', id: `page:${i.to}`, title: i.label, to: i.to, icon: i.icon, extra: [i.to.replace('/', '')] }))
}

async function jailsOf(all: boolean): Promise<Entry[]> {
  if (!can('jails')) return []
  const multi = can('projects')
  if (multi && !all && !projectState.current) return []
  const projects = multi ? (all ? projectState.projects.map((p) => p.metadata.name) : [projectState.current]) : ['']
  const lists = await Promise.all(projects.map((p) => (p ? api.jails.list(p) : api.jails.list()).then((l) => l.map((j) => jailEntry(j, p || undefined, all && multi))).catch(() => [] as Entry[])))
  return lists.flat()
}

async function others(): Promise<Entry[]> {
  const out: Entry[] = []
  const [apps, images, networks, storage] = await Promise.all([
    can('apps') ? api.apps.list().catch(() => []) : [],
    can('images') ? api.images.list().catch(() => []) : [],
    can('networks') ? api.networks.list().catch(() => []) : [],
    can('storage') ? api.storage.list().catch(() => []) : [],
  ])
  for (const a of apps) if (a.valid) out.push(entry({ kind: 'app', id: `app:${a.name}`, title: a.name, sub: [a.title && a.title.toLowerCase() !== a.name ? a.title : '', a.summary].filter(Boolean).join(': '), to: `/apps/${encodeURIComponent(a.name)}`, icon: 'store', extra: [a.title ?? '', a.category ?? '', a.summary ?? ''] }))
  for (const i of images) out.push(entry({ kind: 'image', id: `image:${i.metadata.name}`, title: i.metadata.name, sub: [i.spec.release, i.spec.os].filter(Boolean).join(' · '), to: '/images', icon: 'layers', labels: i.metadata.labels, extra: [i.spec.release, ...(i.spec.aliases ?? [])] }))
  for (const n of networks) out.push(entry({ kind: 'network', id: `network:${n.metadata.name}`, title: n.metadata.name, sub: [n.spec.ipv4?.subnet, n.spec.ipv6?.subnet].filter(Boolean).join(' · '), to: '/networks', icon: 'network', labels: n.metadata.labels, extra: [n.spec.ipv4?.subnet ?? '', n.spec.ipv6?.subnet ?? ''] }))
  for (const x of storage) out.push(entry({ kind: 'storage', id: `storage:${x.metadata.name}`, title: x.metadata.name, sub: [x.spec.dataset, x.spec.comment].filter(Boolean).join(' · '), to: '/storage', icon: 'hardDrive', extra: [x.spec.dataset, x.spec.comment ?? ''] }))
  if (can('projects')) for (const p of projectState.projects) out.push(entry({ kind: 'project', id: `project:${p.metadata.name}`, title: p.metadata.name, sub: p.spec.comment, to: `/projects/${encodeURIComponent(p.metadata.name)}`, icon: 'users', labels: p.metadata.labels, extra: [p.spec.comment ?? ''] }))
  return out
}

export const indexState = reactive({ entries: [] as Entry[], loading: false, loaded: false })
let stamp = { key: '', version: -1, at: 0 }

/** Load the index unless what is there is still current. */
export async function refreshIndex(all: boolean, force = false): Promise<void> {
  const key = `${projectState.current}|${all}`
  if (!force && indexState.loaded && stamp.key === key && stamp.version === dataVersion.value && Date.now() - stamp.at < 60_000) return
  stamp = { key, version: dataVersion.value, at: Date.now() }
  indexState.loading = true
  try {
    const [j, o] = await Promise.all([jailsOf(all), others()])
    if (stamp.key !== key) return
    indexState.entries = [...j, ...o]
    indexState.loaded = true
  } finally {
    indexState.loading = false
  }
}
