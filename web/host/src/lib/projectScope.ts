// The current project travels as `?project=<name>` on every project-level call (sdk/PROTOCOL.md,
// Projects). Host-level routes (images, networks, storage, projects, users, ...) never get it.

/** First path segments of the routes that belong to a project, or that are narrowed by one. */
export const PROJECT_LEVEL = new Set(['jails', 'volumes', 'firewall', 'backup-policies', 'backups', 'restores', 'operations', 'events', 'audit', 'profiles', 'updates'])

export function withProject(path: string, project: string): string {
  if (!project) return path
  const [pathname, query = ''] = path.split('?')
  const first = pathname.split('/').filter(Boolean)[0] ?? ''
  if (!PROJECT_LEVEL.has(first)) return path
  const params = new URLSearchParams(query)
  if (params.has('project')) return path
  params.set('project', project)
  return `${pathname}?${params.toString()}`
}

const KEY = 'jailops.project'

/** The remote a project choice belongs to: the daemon or hub this console is served from. */
export function remoteKey(origin = typeof location !== 'undefined' ? location.origin : ''): string {
  return origin
}

export function loadChoice(remote = remoteKey()): string {
  try {
    const all = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Record<string, string>
    return all[remote] ?? ''
  } catch {
    return ''
  }
}

export function saveChoice(project: string, remote = remoteKey()): void {
  try {
    const all = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Record<string, string>
    all[remote] = project
    localStorage.setItem(KEY, JSON.stringify(all))
  } catch {
    /* storage blocked: the choice lasts for this page only */
  }
}

/** By name: the order of the switcher. No project comes first, none is special. */
export function orderProjects<T extends { metadata: { name: string } }>(list: T[]): T[] {
  return [...list].sort((a, b) => a.metadata.name.localeCompare(b.metadata.name))
}

export interface QuotaRow { key: string; used: number; limit: number; pct: number }

/** Usage against each quota that is set (zero is unlimited). Memory is compared in bytes. */
export function quotaRows(spec: { quotas?: { jails?: number; cpu?: number; memory?: string; pids?: number; addresses?: number } }, status: { jails: number; cpu: number; memory_used: number; addresses: number }, parseSize: (s: string | undefined) => number | null): QuotaRow[] {
  const q = spec.quotas ?? {}
  const rows: QuotaRow[] = []
  const add = (key: string, used: number, limit: number | null | undefined) => {
    if (limit) rows.push({ key, used, limit, pct: Math.min(100, (used / limit) * 100) })
  }
  add('jails', status.jails, q.jails)
  add('cpu', status.cpu, q.cpu)
  add('memory', status.memory_used, parseSize(q.memory))
  add('addresses', status.addresses, q.addresses)
  return rows
}

/** The tightest quota, for the one-line summary in the switcher. */
export function tightest(rows: QuotaRow[]): QuotaRow | undefined {
  return [...rows].sort((a, b) => b.pct - a.pct)[0]
}
