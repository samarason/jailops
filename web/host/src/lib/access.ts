// Who may connect to an installed app (docs/apps.md, "Who may connect"): the checks the Allow dialog makes before it
// asks the server, which decides in the end.
import type { AppAllow, Jail } from '@jailops/shared/api/types'

/** The label an installation puts on the jail it makes. */
export const APP_LABEL = 'jailops.app'

export function isInstalledApp(j: Jail | undefined): boolean {
  return !!j?.metadata.labels?.[APP_LABEL]
}

function isIPv4(s: string): boolean {
  const p = s.split('.')
  return p.length === 4 && p.every((x) => /^(0|[1-9][0-9]{0,2})$/.test(x) && Number(x) <= 255)
}

function isIPv6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.includes(':::')) return false
  const dbl = s.split('::')
  if (dbl.length > 2) return false
  const groups = (part: string): string[] | null => {
    if (part === '') return []
    const g = part.split(':')
    const last = g[g.length - 1]
    // an embedded IPv4 address takes the room of two groups
    if (last.includes('.')) {
      if (!isIPv4(last)) return null
      g.splice(g.length - 1, 1, '0', '0')
    }
    return g.every((x) => /^[0-9a-fA-F]{1,4}$/.test(x)) ? g : null
  }
  const head = groups(dbl[0])
  if (dbl.length === 1) return head !== null && head.length === 8 && !dbl[0].split(':').slice(0, -1).some((x) => x.includes('.'))
  const tail = groups(dbl[1])
  return head !== null && tail !== null && head.length + tail.length <= 7
}

/** An IPv4 or IPv6 address, or a prefix of one ("192.0.2.7", "192.0.2.0/24", "2001:db8::/64"). */
export function isAddressOrPrefix(s: string): boolean {
  const [addr, bits, more] = s.trim().split('/')
  if (more !== undefined || !addr) return false
  const v4 = isIPv4(addr)
  if (!v4 && !isIPv6(addr)) return false
  if (bits === undefined) return true
  if (!/^(0|[1-9][0-9]{0,2})$/.test(bits)) return false
  return Number(bits) <= (v4 ? 32 : 128)
}

const DB_RE = /^[a-z][a-z0-9_]{0,62}$/

/** The reason a database name is refused, or '' (the server checks the same). */
export function dbIssue(n: string): '' | 'dbFormat' | 'dbReserved' {
  if (n === '') return ''
  if (!DB_RE.test(n)) return 'dbFormat'
  if (['postgres', 'public', 'template0', 'template1'].includes(n) || n.startsWith('pg_')) return 'dbReserved'
  return ''
}

/** The database a jail source gets when none is named: its name with "-" turned into "_". */
export function defaultDb(jail: string): string {
  return jail.replace(/-/g, '_')
}

/** "N" or "N/tcp" or "N/udp", 1 to 65535. */
export function isPort(s: string): boolean {
  const m = /^([0-9]{1,5})(\/(tcp|udp))?$/.exec(s.trim())
  return !!m && Number(m[1]) >= 1 && Number(m[1]) <= 65535
}

export type SourceKind = 'jail' | 'set' | 'cidr' | 'host'

export interface AllowForm {
  kind: SourceKind
  jail: string
  set: string
  cidr: string
  ports: string
  db: string
}

export type AllowIssue = 'noJail' | 'noSet' | 'cidr' | 'ports' | 'dbFormat' | 'dbReserved' | 'dbNeeded'

/** What is wrong with the form, field by field. withDb says the app has an access block. */
export function validateAllow(f: AllowForm, withDb: boolean): Partial<Record<'source' | 'ports' | 'db', AllowIssue>> {
  const out: Partial<Record<'source' | 'ports' | 'db', AllowIssue>> = {}
  if (f.kind === 'jail' && !f.jail) out.source = 'noJail'
  if (f.kind === 'set' && !f.set) out.source = 'noSet'
  if (f.kind === 'cidr' && !isAddressOrPrefix(f.cidr)) out.source = 'cidr'
  if (portList(f.ports).some((p) => !isPort(p))) out.ports = 'ports'
  if (withDb) {
    const d = dbIssue(f.db.trim())
    if (d) out.db = d
    else if (!f.db.trim() && f.kind !== 'jail') out.db = 'dbNeeded'
  }
  return out
}

export function portList(s: string): string[] {
  return s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
}

/** The source as the server reads it. */
export function sourceOf(f: AllowForm): string {
  switch (f.kind) {
    case 'jail': return 'jail:' + f.jail
    case 'set': return 'set:' + f.set
    case 'cidr': return f.cidr.trim()
    case 'host': return 'host'
  }
}

export function allowBody(f: AllowForm, withDb: boolean, dry = false): AppAllow {
  const b: AppAllow = { source: sourceOf(f) }
  const ports = portList(f.ports)
  if (ports.length) b.ports = ports
  if (withDb && f.db.trim()) b.database = f.db.trim()
  if (dry) b.dry_run = true
  return b
}
