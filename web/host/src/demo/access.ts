// Who may connect to the demo's installed apps: the database jail lets the web jail in, the web jail lets the host
// in. Allow and deny change this state the way the server does, without a host behind them.
import type { AppAccess, AppAccessGrant, AppAllow, AppAllowResult, AppDeny, AppDenyResult, App, Jail } from '@jailops/shared/api/types'

type Answer<T> = { ok: T } | { status: number; code: string; message: string; hint?: string }

interface State { closed: boolean; grants: AppAccessGrant[]; roles: Record<string, boolean> }

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString()
// A server writes the allocated address into the spec; the demo's jails may still say auto, so they get a fixed one.
const addrOf = (j: Jail): string[] => {
  const fixed = (j.spec.network ?? []).flatMap((n) => [n.ipv4, n.ipv6]).filter((a): a is string => !!a && a !== 'auto' && a !== 'none').map((a) => a.split('/')[0])
  return fixed.length ? fixed : [`10.20.0.${60 + [...j.metadata.name].reduce((n, c) => (n + c.charCodeAt(0)) % 100, 0)}`]
}

function rulesOf(from: string[], ports: string[]): string[] {
  const by: Record<string, string[]> = {}
  for (const p of ports) {
    const [n, proto = 'tcp'] = p.split('/')
    ;(by[proto] ??= []).push(n)
  }
  return Object.keys(by).sort().map((proto) => `allow in ${proto} from ${from.join(',')} to port ${by[proto].join(',')}`)
}

function pfOf(jail: string, from: string[], ports: string[]): string[] {
  const nums = ports.map((p) => p.split('/')[0])
  const port = nums.length > 1 ? `{ ${nums.join(' ')} }` : nums[0]
  const table = (x: string) => (x.startsWith('jail:') ? `<j_${x.slice(5).replace(/-/g, '_')}>` : x.startsWith('set:') ? `<s_${x.slice(4)}>` : x) // a reference is a table: it follows the jail or the set
  const names = from.map(table)
  const src = names.length > 1 ? `{ ${names.join(' ')} }` : names[0]
  return [`pass out quick on { jo1a${jail.length}b } inet proto tcp from ${src} to 10.20.0.0/32 port ${port}`]
}

const password = () => {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const b = new Uint8Array(32)
  crypto.getRandomValues(b)
  return Array.from(b, (x) => abc[x % abc.length]).join('')
}

export function demoAccess(jails: () => Jail[], sets: () => Array<{ metadata: { name: string }; spec: { addresses: Array<{ address: string }> } }>, def: (app: string) => App | undefined) {
  const state = new Map<string, State>()
  const web = '10.20.0.11'
  state.set('db', {
    closed: true, roles: { web: true },
    grants: [{
      source: 'jail:web', source_kind: 'jail', addresses: [`${web}/32`], ports: ['5432/tcp'], database: 'web', role: 'web', role_created: true, database_created: true,
      rules: rulesOf(['jail:web'], ['5432/tcp']), pf: pfOf('db', ['jail:web'], ['5432/tcp']), hba: [`host web web ${web}/32 scram-sha-256`],
      created_at: ago(86400 * 3), created_by: 'admin',
    }],
  })
  state.set('web', {
    closed: true, roles: {},
    grants: [{ source: 'host', source_kind: 'host', addresses: ['10.20.0.1/32'], ports: ['80/tcp', '443/tcp'], rules: rulesOf(['10.20.0.1'], ['80/tcp', '443/tcp']), pf: pfOf('web', ['10.20.0.1'], ['80/tcp', '443/tcp']), created_at: ago(86400 * 9), created_by: 'admin' }],
  })

  const portsOf = (a: App | undefined): string[] => (a?.ports ?? []).filter((p) => !a?.access || p.name === a.access.port).map((p) => `${p.port}/${p.proto ?? 'tcp'}`)

  function get(j: Jail): AppAccess {
    const app = j.metadata.labels?.['jailops.app'] ?? ''
    const d = def(app)
    const st = state.get(j.metadata.name)
    const out: AppAccess = { jail: j.metadata.name, project: j.metadata.project ?? '', app, type: d?.access?.type, policy: `app-${j.metadata.name}`, closed: !!st?.closed, ports: portsOf(d), grants: structuredClone(st?.grants ?? []) }
    if (!st) out.warnings = ['the jail is open to its network: it was installed before app access, and its first allow closes it to every other source']
    if (j.status.power !== 'running') (out.warnings ??= []).push('the jail is stopped: its anchor is not loaded and pg_hba.conf is not checked')
    return out
  }

  function install(jail: string): void {
    state.set(jail, { closed: true, grants: [], roles: {} })
  }

  function allow(j: Jail, b: AppAllow): Answer<AppAllowResult> {
    const name = j.metadata.name
    const app = j.metadata.labels?.['jailops.app'] ?? ''
    const d = def(app)
    let canonical = b.source
    let kind = 'cidr'
    let from: string[] = []
    let prefixes: string[] = []
    if (b.source === 'host') {
      kind = 'host'; from = ['10.20.0.1']; prefixes = ['10.20.0.1/32']
    } else if (b.source.startsWith('@')) {
      return { status: 400, code: 'invalid', message: `source "${b.source}": @ is not used: write jail:${b.source.slice(1)} or set:${b.source.slice(1)}` }
    } else if (b.source.startsWith('jail:')) {
      const n = b.source.slice(5)
      const src = jails().find((x) => x.metadata.name === n && x.metadata.project === j.metadata.project)
      if (!src) return { status: 404, code: 'not_found', message: `jail "${n}" not found in project ${j.metadata.project}`, hint: 'jailops list shows the names' }
      if (n === name) return { status: 400, code: 'invalid', message: 'a jail always reaches itself; name another source' }
      kind = 'jail'; const addrs = addrOf(src); from = [b.source]; prefixes = addrs.map((a) => `${a}/32`)
      if (!addrs.length) return { status: 400, code: 'invalid', message: `jail "${n}" has no address to allow` }
    } else if (b.source.startsWith('set:')) {
      const n = b.source.slice(4)
      const set = sets().find((x) => x.metadata.name === n)
      if (!set) return { status: 404, code: 'not_found', message: `address set "${n}" not found in project ${j.metadata.project}`, hint: 'jailops firewall address-set list shows the names' }
      kind = 'address-set'; from = [b.source]; prefixes = set.spec.addresses.map((e) => e.address)
    } else {
      canonical = b.source.replace(/\/(32|128)$/, '')
      from = [canonical]; prefixes = [b.source.includes('/') ? b.source : `${b.source}/${b.source.includes(':') ? 128 : 32}`]
    }
    const ports = (b.ports?.length ? b.ports : portsOf(d)).map((p) => (p.includes('/') ? p : `${p}/tcp`)).sort()
    if (!ports.length) return { status: 400, code: 'invalid', message: `app ${app} declares no ports; name one with --port N[/tcp|udp]` }
    const st = state.get(name) ?? { closed: false, grants: [], roles: {} }
    const notes: string[] = []
    if (!state.has(name)) notes.push(`jail ${name} was open to its network until now (installed before app access); from now on it is closed to every source that is not allowed`)
    const i = st.grants.findIndex((g) => g.source === canonical)
    const g: AppAccessGrant = { source: canonical, source_kind: kind, addresses: prefixes, ports, rules: rulesOf(from, ports), pf: pfOf(name, from, ports), created_at: new Date().toISOString(), created_by: 'demo' }
    const res: AppAllowResult = { jail: name, grant: g, changed: true, steps: [`firewall policy app-${name}: ${g.rules.join('; ')}`], dry_run: b.dry_run }
    let pw = ''
    if (d?.access) {
      const db = b.database || (i >= 0 ? st.grants[i].database : '') || (kind === 'jail' ? canonical.slice(5).replace(/-/g, '_') : '')
      if (!db) return { status: 400, code: 'invalid', message: 'name the database of this grant with --db NAME (a source that is not a jail has no default)' }
      if (i >= 0 && st.grants[i].database !== db) return { status: 409, code: 'conflict', message: `${canonical} already has access to database ${st.grants[i].database}`, hint: 'deny it first to give it another database' }
      if (j.status.power !== 'running') return { status: 409, code: 'busy', message: `jail "${name}" is stopped; the role and the database are made with psql in it`, hint: `start it with jailops start ${name}` }
      Object.assign(g, { database: db, role: db, role_created: true, database_created: true, hba: prefixes.map((p) => `host ${db} ${db} ${p} scram-sha-256`) })
      const known = db in st.roles
      if (!known || !st.roles[db] || b.rotate) {
        res.sql = known ? [`ALTER ROLE "${db}" LOGIN PASSWORD '<generated, shown once>';`] : [`CREATE ROLE "${db}" LOGIN PASSWORD '<generated, shown once>';`, `CREATE DATABASE "${db}" OWNER "${db}";`]
        pw = password()
      }
      res.steps!.push('in the jail, as postgres: psql with the statements on standard input', `${d.access.hba_file}: the managed block gets ${g.hba!.join('; ')}; then the server reloads it`)
    } else {
      let n = `only the firewall changed: the app must itself listen on the jail's address and accept the client (see its configuration files with jailops app info ${app})`
      if (app === 'valkey') n += '; Valkey binds 127.0.0.1 with protected-mode yes until bind and protected-mode in /usr/local/etc/valkey.conf are changed, and requirepass should be set before it is reachable'
      notes.push(n)
    }
    res.notes = notes
    if (b.dry_run) return { ok: res }
    if (i >= 0) { g.created_at = st.grants[i].created_at; g.created_by = st.grants[i].created_by }
    const same = i >= 0 && JSON.stringify(st.grants[i].ports) === JSON.stringify(g.ports) && JSON.stringify(st.grants[i].addresses) === JSON.stringify(g.addresses)
    if (i >= 0) st.grants[i] = g
    else st.grants.push(g)
    if (g.role) st.roles[g.role] = true
    st.closed = true
    state.set(name, st)
    res.changed = !same || !!pw
    const host = addrOf(j)[0] ?? '10.20.0.12'
    if (pw) {
      res.connection_string = `postgres://${g.role}:${pw}@${host}:5432/${g.database}?sslmode=disable`
      notes.push(`the connection string is shown once and stored nowhere; jailops app allow ${name} --from ${canonical} --rotate makes a new password`)
    } else if (g.role) notes.push(`role ${g.role} exists: its password was shown when it was made; --rotate makes a new one`)
    if (!res.changed) notes.push('nothing changed: the grant exists as it is')
    return { ok: res }
  }

  function deny(j: Jail, b: AppDeny): Answer<AppDenyResult> {
    const name = j.metadata.name
    const st = state.get(name)
    const i = st ? st.grants.findIndex((g) => g.source === b.source) : -1
    if (!st || i < 0) return { ok: { jail: name, removed: { source: b.source, source_kind: '', ports: [], rules: [], created_at: '' }, changed: false, notes: [`nothing changed: ${b.source} has no access to ${name}`] } }
    const g = st.grants[i]
    const res: AppDenyResult = { jail: name, removed: g, changed: true, steps: g.rules.map((r) => `firewall policy app-${name}: remove ${r}`), notes: [], dry_run: b.dry_run }
    if (g.role) {
      if (j.status.power !== 'running') return { status: 409, code: 'busy', message: `jail "${name}" is stopped; the role and pg_hba.conf are changed with psql in it`, hint: `start it with jailops start ${name}` }
      const used = st.grants.some((o, k) => k !== i && o.role === g.role)
      if (used) res.notes!.push(`role ${g.role} stays: another grant uses it`)
      else if (b.drop_role) {
        res.sql = [`REASSIGN OWNED BY "${g.role}" TO postgres;`, `DROP OWNED BY "${g.role}";`, `DROP ROLE IF EXISTS "${g.role}";`]
        res.notes!.push(`role ${g.role} is dropped; what it owned now belongs to postgres and database ${g.database} is kept`)
      } else {
        res.sql = [`ALTER ROLE "${g.role}" NOLOGIN PASSWORD NULL;`]
        res.notes!.push(`role ${g.role} keeps its database and loses its login and password; --drop-role drops it`)
      }
    }
    if (b.dry_run) return { ok: res }
    st.grants.splice(i, 1)
    if (g.role) st.roles[g.role] = false
    return { ok: res }
  }

  return { get, allow, deny, install }
}
