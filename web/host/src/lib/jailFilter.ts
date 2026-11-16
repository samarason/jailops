// The last filter of the jail list, per console origin and per user and project. A convenience: blocked or broken
// storage leaves the list unfiltered.

const KEY = 'jailops.jailsFilter'

export interface SavedFilter { q: string; state: string }

function all(): Record<string, Record<string, SavedFilter>> {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? '{}') as unknown
    return v && typeof v === 'object' ? (v as Record<string, Record<string, SavedFilter>>) : {}
  } catch {
    return {}
  }
}

export function loadFilter(scope: string, origin = typeof location !== 'undefined' ? location.origin : ''): SavedFilter {
  const f = all()[origin]?.[scope]
  return { q: typeof f?.q === 'string' ? f.q : '', state: typeof f?.state === 'string' ? f.state : '' }
}

export function saveFilter(scope: string, f: SavedFilter, origin = typeof location !== 'undefined' ? location.origin : ''): void {
  try {
    const a = all()
    const mine = { ...(a[origin] ?? {}) }
    if (f.q || f.state) mine[scope] = { q: f.q, state: f.state }
    else delete mine[scope]
    a[origin] = mine
    localStorage.setItem(KEY, JSON.stringify(a))
  } catch {
    /* storage blocked: the filter lasts while the page is open */
  }
}
