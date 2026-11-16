// The quick switcher's index and ranking: pure functions over plain entries, so thousands of objects rank in a few
// milliseconds and the tests need no view.
import type { IconName } from '@jailops/shared/lib/icons'
import { parseQuery, termHolds, type Labels, type Term } from './labels'

export type Kind = 'jail' | 'app' | 'image' | 'network' | 'project' | 'storage' | 'page'
export const KINDS: Kind[] = ['jail', 'app', 'image', 'network', 'project', 'storage', 'page']

export interface Entry {
  kind: Kind
  /** Unique over the index: kind, project and name. */
  id: string
  title: string
  /** One line under the title (image and addresses, a summary). */
  sub?: string
  to: string
  icon: IconName
  /** The project a jail belongs to; choosing it switches to that project first. */
  project?: string
  /** A jail's power state, for the pill and the quick actions. */
  state?: string
  labels?: Labels
  /** The app an installed jail runs (its jailops.app label). */
  app?: string
  /** Lower-case text a word is looked for in; the title is always the first. */
  fields: string[]
}

export function entry(e: Omit<Entry, 'fields'> & { extra?: string[] }): Entry {
  const { extra = [], ...rest } = e
  const labels = Object.entries(e.labels ?? {}).map(([k, v]) => `${k}=${v}`)
  return { ...rest, fields: [e.title, ...extra, ...labels].filter(Boolean).map((f) => f.toLowerCase()) }
}

/** Every fuzzy score is below this; a word found as it is scores above. */
const FUZZY_MAX = 400
const boundary = (c: string | undefined) => c === undefined || !/[a-z0-9]/.test(c)

/**
 * How well a lower-case word matches a lower-case text, -1 for not at all: the whole text, then a prefix, then the
 * start of a part (after '-', '.', '/', '='), then anywhere, then the letters in order (fuzzy, two letters or more).
 * Shorter texts and earlier hits rank higher.
 */
export function scoreText(q: string, t: string): number {
  if (!q) return 0
  if (t === q) return 1000
  if (t.startsWith(q)) return 900 - Math.min(t.length - q.length, 99)
  const i = t.indexOf(q)
  if (i > 0) return (boundary(t[i - 1]) ? 700 : 500) - Math.min(i, 99)
  if (q.length < 2) return -1
  let from = 0
  let score = 0
  let run = 0
  let first = -1
  for (const ch of q) {
    const k = t.indexOf(ch, from)
    if (k < 0) return -1
    if (first < 0) first = k
    run = k === from && from > 0 ? run + 1 : 0
    score += 10 + run * 6 + (boundary(t[k - 1]) ? 8 : 0)
    from = k + 1
  }
  const gaps = from - first - q.length
  return Math.max(1, Math.min(FUZZY_MAX - 100, score) - Math.min(first, 40) - Math.min(gaps * 2, 120))
}

/** The score of one entry for the parsed query, -1 when a term does not hold. The title counts most. */
export function scoreEntry(e: Entry, terms: Term[]): number {
  let total = 0
  for (const t of terms) {
    if (t.kind !== 'word') {
      // only what carries labels answers a label term
      if (!e.labels || !termHolds(t, e.labels, e.fields)) return -1
      if (!t.not) total += 200
      continue
    }
    if (t.not) {
      if (e.fields.some((f) => f.includes(t.text))) return -1
      continue
    }
    // letters in order count in the title only: across labels and addresses they would match nearly everything
    let best = -1
    e.fields.forEach((f, i) => {
      const s = scoreText(t.text, f)
      if (i === 0 ? s >= 0 : s >= FUZZY_MAX) best = Math.max(best, i === 0 ? s : Math.round(s * 0.7))
    })
    if (best < 0) return -1
    total += best
  }
  return total
}

export interface Group {
  kind: Kind
  items: Entry[]
  /** Matches left out of this group: the query should be refined. */
  more: number
}

export interface Ranked {
  groups: Group[]
  total: number
}

/**
 * The matches by kind, each group capped (`perGroup`, more for jails), the groups ordered by their best match and
 * then by KINDS. An empty query gives nothing: the switcher shows the recent items then.
 */
export function rank(entries: Entry[], query: string, perGroup = 5, jailsPerGroup = 8): Ranked {
  const terms = parseQuery(query)
  if (!terms.length) return { groups: [], total: 0 }
  const by = new Map<Kind, Array<{ e: Entry; s: number }>>()
  for (const e of entries) {
    const s = scoreEntry(e, terms)
    if (s < 0) continue
    const l = by.get(e.kind) ?? []
    l.push({ e, s })
    by.set(e.kind, l)
  }
  let total = 0
  const groups: Array<Group & { best: number }> = []
  for (const kind of KINDS) {
    const l = by.get(kind)
    if (!l?.length) continue
    l.sort((a, b) => b.s - a.s || a.e.title.localeCompare(b.e.title))
    const cap = kind === 'jail' ? jailsPerGroup : perGroup
    total += l.length
    groups.push({ kind, items: l.slice(0, cap).map((x) => x.e), more: Math.max(0, l.length - cap), best: l[0].s })
  }
  groups.sort((a, b) => b.best - a.best || KINDS.indexOf(a.kind) - KINDS.indexOf(b.kind))
  return { groups: groups.map(({ best: _b, ...g }) => g), total }
}

// ---- recent items: per console origin, at most RECENT_MAX, never required ----

export interface Recent {
  id: string
  kind: Kind
  title: string
  to: string
  project?: string
}

const RECENT_KEY = 'jailops.recent'
export const RECENT_MAX = 8

function readAll(): Record<string, Recent[]> {
  try {
    const v = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '{}') as unknown
    return v && typeof v === 'object' ? (v as Record<string, Recent[]>) : {}
  } catch {
    return {}
  }
}

export function loadRecent(scope = typeof location !== 'undefined' ? location.origin : ''): Recent[] {
  const l = readAll()[scope]
  return Array.isArray(l) ? l.filter((r) => r && typeof r.id === 'string' && typeof r.to === 'string').slice(0, RECENT_MAX) : []
}

export function pushRecent(r: Recent, scope = typeof location !== 'undefined' ? location.origin : ''): void {
  try {
    const all = readAll()
    all[scope] = [r, ...(all[scope] ?? []).filter((x) => x.id !== r.id)].slice(0, RECENT_MAX)
    localStorage.setItem(RECENT_KEY, JSON.stringify(all))
  } catch {
    /* storage blocked: nothing is remembered */
  }
}

export const jailId = (project: string | undefined, name: string) => `jail:${project ?? ''}:${name}`

/** Whether the focus is somewhere typing goes: `/` then belongs to it, not to the switcher. */
export function typingTarget(el: Element | null): boolean {
  if (!el || !(el instanceof HTMLElement)) return false
  if (el.isContentEditable) return true
  const tag = el.tagName
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true
  if (tag === 'INPUT') return !['checkbox', 'radio', 'button', 'submit', 'reset', 'range', 'color', 'file'].includes((el as HTMLInputElement).type)
  return el.getAttribute('role') === 'textbox' || !!el.closest('.term')
}
