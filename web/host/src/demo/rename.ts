// POST <object>/rename in the demo: the plan computed from the references the demo holds (project grants and image
// lists, jail specs, policy rules and set members, profile lists, boot dependencies), the refusals of the server
// (name rule, taken name, running or locked jail, managed object, stale If-Match), and the rename applied to the
// demo data once the operation ends. A new name that starts with "fail" makes the operation fail.
import type {
  AddressSet, ApiErrorBody, Backup, BackupPolicy, FirewallPolicy, Image, Jail, JailSnapshot, Kind, Lease, Network, Profile, Project,
  RenameChange, RenameResult, UpdateRecord, UpdateReport,
} from '@jailops/shared/api/types'
import { nameProblem, nameRules, type NameRule } from '@jailops/shared/lib/names'

export type DemoRenameKind = 'network' | 'image' | 'project' | 'jail' | 'policy' | 'addressSet' | 'profile'

/** The parts of the demo state a rename reads and changes. */
export interface RenameDb {
  jails: Jail[]
  networks: Network[]
  images: Image[]
  projects: Project[]
  policies: FirewallPolicy[]
  sets: AddressSet[]
  profiles: { project: Profile[]; host: Profile[] }
  leases: Record<string, Lease[]>
  snaps: Record<string, JailSnapshot[]>
  history: Record<string, UpdateRecord[]>
  updates: UpdateReport[]
  bpol: BackupPolicy[]
  backups: Backup[]
}

export type RenameAnswer =
  | { error: ApiErrorBody; status: number }
  | { result: RenameResult; apply: () => void; fails?: ApiErrorBody; resource: string }

/** The kind of a rename route: the path segments before the name ("networks", "firewall/policies"). */
export function renameKindOf(seg: string[]): { kind: DemoRenameKind; name: string } | undefined {
  if (seg[seg.length - 1] !== 'rename') return undefined
  if (seg.length === 3) {
    const k = ({ networks: 'network', images: 'image', projects: 'project', jails: 'jail', profiles: 'profile' } as const)[seg[0] as 'networks']
    return k ? { kind: k, name: seg[1] } : undefined
  }
  if (seg.length === 4 && seg[0] === 'firewall') {
    const k = ({ policies: 'policy', 'address-sets': 'addressSet' } as const)[seg[1] as 'policies']
    return k ? { kind: k, name: seg[2] } : undefined
  }
  return undefined
}

const noun: Record<DemoRenameKind, string> = { network: 'network', image: 'image', project: 'project', jail: 'jail', policy: 'firewall policy', addressSet: 'address set', profile: 'profile' }
const apiKind: Record<DemoRenameKind, Kind> = { network: 'Network', image: 'Image', project: 'Project', jail: 'Jail', policy: 'FirewallPolicy', addressSet: 'AddressSet', profile: 'Profile' } as unknown as Record<DemoRenameKind, Kind> // Profile is a kind of its own outside the generated union
const rule: Record<DemoRenameKind, NameRule> = { network: 'network', image: 'image', project: 'project', jail: 'jail', policy: 'object', addressSet: 'addressSet', profile: 'object' }
const path: Record<DemoRenameKind, string> = { network: 'networks', image: 'images', project: 'projects', jail: 'jails', policy: 'firewall/policies', addressSet: 'firewall/address-sets', profile: 'profiles' }

const projOf = (m: { project?: string }) => m.project ?? 'web'
const jailObject = (j: Jail) => `jail ${j.metadata.name} (project ${j.metadata.project ?? ''})`
const ref = (object: string, detail: string): RenameChange => ({ kind: 'reference', object, detail })
const swap = (xs: string[] | undefined, from: string, to: string) => (xs ?? []).map((x) => (x === from ? to : x))
const isRunning = (j: Jail) => !!j.status.jid || ['running', 'starting', 'stopping'].includes(j.status.power)

/**
 * The answer to POST .../{from}/rename in the demo. `project` is the project of a project-level object (host for the
 * host profiles); `ifMatch` the If-Match header as sent.
 */
export function demoRename(db: RenameDb, kind: DemoRenameKind, from: string, to: string, project: string, ifMatch: string | undefined): RenameAnswer {
  const n = noun[kind]
  const refuse = (status: number, code: string, message: string, hint?: string, detail?: Record<string, string>): RenameAnswer => ({ status, error: { code, message, ...(hint ? { hint } : {}), ...(detail ? { detail } : {}) } as ApiErrorBody })
  // the object, the others of its kind it must not collide with
  const scoped = <T extends { metadata: { name: string; project?: string } }>(xs: T[]) => xs.filter((x) => projOf(x.metadata) === project)
  const profiles = project === 'host' ? db.profiles.host : db.profiles.project
  const pool: Array<{ metadata: { name: string; generation?: number; managed_by?: string; project?: string } }> =
    kind === 'network' ? db.networks : kind === 'image' ? db.images : kind === 'project' ? db.projects
      : kind === 'jail' ? db.jails.filter((j) => (j.metadata.project ?? '') === project)
        : kind === 'policy' ? scoped(db.policies) : kind === 'addressSet' ? scoped(db.sets) : profiles
  const obj = pool.find((x) => x.metadata.name === from)
  if (!obj) return refuse(404, 'not_found', `${n} "${from}" not found`)
  const bad = nameProblem(to, rule[kind])
  if (bad) return refuse(400, 'invalid', `new name "${to}" must match ${nameRules[rule[kind]].re.source}${to.length > nameRules[rule[kind]].max ? ' (it is too long)' : ''}`, undefined, { field: 'new_name' })
  if (to === from) return refuse(400, 'invalid', 'the new name is the old name')
  if (pool.some((x) => x.metadata.name === to)) return refuse(409, 'already_exists', `${n} "${to}" already exists`)
  const gen = obj.metadata.generation ?? 0
  const want = ifMatch?.replace(/^W\//, '').replace(/"/g, '').trim()
  if (want && want !== '*' && Number(want) !== gen) return refuse(409, 'conflict', `${n} "${from}" changed: current generation is ${gen}`, 'read it again and repeat the rename', { generation: String(gen) })
  const managed = obj.metadata.managed_by
  if (managed) {
    return managed.startsWith('hub:')
      ? refuse(403, 'forbidden', `${n} "${from}" is managed by a hub (${managed})`, 'rename it on the hub, which applies the new name to its hosts')
      : refuse(403, 'forbidden', `${n} "${from}" is managed by ${managed}`, 'rename it in the repository that defines it; the next sync applies the new name')
  }

  const changes: RenameChange[] = [{ kind: 'object', object: `${n} ${from}`, detail: `renamed to ${to}` }]
  const warnings: string[] = []
  const edits: Array<() => void> = []
  const jailsIn = (p: string) => db.jails.filter((j) => (j.metadata.project ?? '') === p)

  if (kind === 'network') {
    const net = obj as Network
    for (const p of db.projects) {
      if ((p.spec.networks ?? []).some((g) => g.network === from)) {
        changes.push(ref(`project ${p.metadata.name}`, `spec.networks: ${from} -> ${to}`))
        edits.push(() => { p.spec.networks = (p.spec.networks ?? []).map((g) => (g.network === from ? { ...g, network: to } : g)) })
      }
    }
    for (const j of db.jails) {
      const idx = (j.spec.network ?? []).map((a, i) => (a.network === from ? i : -1)).filter((i) => i >= 0)
      if (!idx.length) continue
      changes.push(ref(jailObject(j), idx.map((i) => `spec.network[${i}].network: ${from} -> ${to}`).join('; ')))
      edits.push(() => { j.spec.network = (j.spec.network ?? []).map((a) => (a.network === from ? { ...a, network: to } : a)) })
    }
    if (net.spec.ipv4?.nat) changes.push({ kind: 'anchor', object: `PF anchor jailops/net.${from}`, detail: `loaded as jailops/net.${to}` })
    edits.push(() => {
      if (db.leases[from]) { db.leases[to] = db.leases[from].map((l) => ({ ...l, network: to })); delete db.leases[from] }
    })
  }

  if (kind === 'image') {
    const img = obj as Image
    for (const p of db.projects) {
      if ((p.spec.images ?? []).includes(from)) {
        changes.push(ref(`project ${p.metadata.name}`, `spec.images: ${from} -> ${to}`))
        edits.push(() => { p.spec.images = swap(p.spec.images, from, to) })
      }
    }
    const imgRef = (r: string) => r.split(/[@#]/)[0] === from
    const newRef = (r: string) => to + r.slice(from.length)
    for (const j of db.jails) {
      if (!imgRef(j.spec.image)) continue
      changes.push(ref(jailObject(j), `spec.image: ${j.spec.image} -> ${newRef(j.spec.image)}`))
      edits.push(() => {
        j.spec.image = newRef(j.spec.image)
        if (j.status.generation && imgRef(j.status.generation)) j.status.generation = newRef(j.status.generation)
      })
    }
    changes.push({ kind: 'dataset', object: `dataset tank/jailops/images/${from}`, detail: `renamed to tank/jailops/images/${to}` })
    if (img.status.auto_upgrade?.recent?.length) changes.push({ kind: 'state', object: `nightly upgrade runs of image ${from}`, detail: `${from}.json -> ${to}.json` })
    if (db.backups.some((b) => (b.spec.bundle.image_generation ?? '').split('#')[0] === from)) warnings.push(`backups taken before the rename name the image "${from}": a restore of one asks for an image of that name`)
    edits.push(() => {
      for (const g of img.status.generations ?? []) { g.name = newRef(g.name) }
    })
  }

  if (kind === 'project') {
    for (const j of jailsIn(from)) {
      changes.push(ref(jailObject(j), `metadata.project: ${from} -> ${to}`))
      edits.push(() => { j.metadata.project = to })
    }
    const moved: Array<[string, Array<{ metadata: { name: string; project?: string } }>]> = [['firewall policy', db.policies], ['address set', db.sets], ['profile', db.profiles.project], ['backup policy', db.bpol]]
    for (const [what, xs] of moved) {
      for (const x of xs.filter((y) => projOf(y.metadata) === from)) {
        changes.push(ref(`${what} ${x.metadata.name}`, `moved to project ${to}`))
        edits.push(() => { x.metadata.project = to })
      }
    }
    changes.push({ kind: 'dataset', object: `dataset tank/jailops/${from}`, detail: `renamed to tank/jailops/${to}` })
    changes.push({ kind: 'anchor', object: `PF anchor jailops/${from}`, detail: `loaded as jailops/${to}` })
    changes.push(ref('identities', `1 users, 2 tokens and 0 trust tokens: projects ${from} -> ${to}`))
    warnings.push('the audit log, the operations and the backups made so far keep the old project name')
    edits.push(() => { for (const u of db.updates) if (u.project === from) u.project = to })
  }

  if (kind === 'jail') {
    const j = obj as Jail
    if (isRunning(j)) return refuse(409, 'busy', `jail "${from}" is running`, `stop it first (jailops stop ${from}); a jail is renamed while it is stopped`)
    if (j.status.power === 'locked' || j.status.locked?.length) return refuse(409, 'locked', `jail "${from}" has locked volumes`, `unlock it first (jailops jail unlock ${from})`)
    for (const o of jailsIn(project)) {
      if (o !== j && (o.spec.boot?.depends ?? []).includes(from)) {
        changes.push(ref(jailObject(o), `spec.boot.depends: ${from} -> ${to}`))
        edits.push(() => { o.spec.boot = { ...o.spec.boot, depends: swap(o.spec.boot?.depends, from, to) } })
      }
    }
    changes.push({ kind: 'dataset', object: `dataset tank/jailops/${project}/${from}`, detail: `renamed to tank/jailops/${project}/${to}` })
    changes.push({ kind: 'anchor', object: `PF anchor jailops/${project}/${from}`, detail: `loaded as jailops/${project}/${to}` })
    if (db.history[from]?.length) changes.push({ kind: 'state', object: `update history of jail ${from}`, detail: `${from}.json -> ${to}.json` })
    if (!j.spec.hostname) warnings.push(`the jail has no hostname of its own: it is "${to}" from its next start`)
    else if (j.spec.hostname === from) warnings.push(`the hostname of the jail stays "${from}"; \`jailops set ${to} hostname=${to}\` changes it`)
    edits.push(() => {
      for (const ls of Object.values(db.leases)) for (const l of ls) if (l.jail === from) l.jail = to
      if (db.snaps[from]) { db.snaps[to] = db.snaps[from].map((x) => ({ ...x, spec: { ...x.spec, jail: to } })); delete db.snaps[from] }
      if (db.history[from]) { db.history[to] = db.history[from].map((x) => ({ ...x, jail: to })); delete db.history[from] }
      for (const u of db.updates) if (u.jail === from && u.project === project) u.jail = to
    })
  }

  if (kind === 'policy') {
    for (const j of jailsIn(project)) {
      if (!j.spec.firewall?.policies?.includes(from)) continue
      changes.push(ref(jailObject(j), `spec.firewall.policies: ${from} -> ${to}`))
      edits.push(() => { j.spec.firewall = { ...j.spec.firewall, policies: (j.spec.firewall?.policies ?? []).map((n) => (n === from ? to : n)) } })
    }
    const p = db.projects.find((x) => x.metadata.name === project)
    if (p?.spec.firewall_policies?.includes(from)) {
      changes.push(ref(`project ${project}`, `spec.firewall_policies (mandatory policy): ${from} -> ${to}`))
      edits.push(() => { p.spec.firewall_policies = (p.spec.firewall_policies ?? []).map((n) => (n === from ? to : n)) })
    }
  }

  if (kind === 'addressSet') {
    const at = (xs: string[] | undefined) => (xs ?? []).includes(`set:${from}`)
    for (const pol of scoped(db.policies)) {
      const d: string[] = []
      ;(pol.spec.rules ?? []).forEach((r, i) => {
        if (at(r.from)) d.push(`rules[${i}].from: set:${from} -> set:${to}`)
        if (at(r.to)) d.push(`rules[${i}].to: set:${from} -> set:${to}`)
      })
      if (!d.length) continue
      changes.push(ref(`firewall policy ${pol.metadata.name}`, d.join('; ')))
      edits.push(() => {
        pol.spec.rules = (pol.spec.rules ?? []).map((r) => ({ ...r, ...(r.from ? { from: swap(r.from, `set:${from}`, `set:${to}`) } : {}), ...(r.to ? { to: swap(r.to, `set:${from}`, `set:${to}`) } : {}) }))
        pol.metadata.generation = (pol.metadata.generation ?? 0) + 1
      })
    }
    for (const x of scoped(db.sets)) {
      if (!(x.spec.addresses ?? []).some((a) => a.address === `set:${from}`)) continue
      changes.push(ref(`address set ${x.metadata.name}`, `spec.addresses: set:${from} -> set:${to}`))
      edits.push(() => { x.spec.addresses = (x.spec.addresses ?? []).map((a) => (a.address === `set:${from}` ? { ...a, address: `set:${to}` } : a)); x.metadata.generation = (x.metadata.generation ?? 0) + 1 })
    }
  }

  if (kind === 'profile') {
    const users = project === 'host' ? db.jails : jailsIn(project)
    for (const j of users) {
      if (!(j.spec.profiles ?? []).includes(from)) continue
      changes.push(ref(jailObject(j), `spec.profiles: ${from} -> ${to}`))
      edits.push(() => { j.spec.profiles = swap(j.spec.profiles, from, to) })
    }
  }

  const counts: Record<string, number> = {}
  for (const c of changes) counts[c.kind] = (counts[c.kind] ?? 0) + 1
  const steps = changes.map((c) => `${c.object}: ${c.detail}`)
  const scope = ['jail', 'policy', 'addressSet', 'profile'].includes(kind) ? project : undefined
  const result: RenameResult = { kind: apiKind[kind], ...(scope ? { project: scope } : {}), from, to, changes, counts, steps, ...(warnings.length ? { warnings } : {}) }
  const apply = () => {
    for (const e of edits) e()
    obj.metadata.name = to
    obj.metadata.generation = gen + 1
  }
  // the demo's failed rename: nothing changes, as the server rolls a failed run back
  const fails = to.startsWith('fail')
    ? { code: 'internal', message: `rename ${n} ${from} to ${to} failed at step ${changes.length > 1 ? 2 : 1}: ${changes[changes.length > 1 ? 1 : 0].object}: device busy`, hint: 'nothing was changed: the steps that ran were undone; run the rename again', detail: { step: String(changes.length > 1 ? 2 : 1) } } as ApiErrorBody
    : undefined
  return { result, apply, fails, resource: `/api/v1/${path[kind]}/${from}` }
}
