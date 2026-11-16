// An in-process Transport that answers like the real API, so the whole UI (including async
// operations, ETags, events and API errors) can be exercised without a server. Only loaded
// for `?demo`.
import { storedToken } from '@jailops/shared/api/client'
import type { EventStream, RawRequest, RawResponse, StreamHandlers, Transport } from '@jailops/shared/api/client'
import type { ApiEvent, ApiErrorBody, Operation, RestorePreflight, FirewallPolicy, AddressSet, AddressSetSpec, FirewallRule, FirewallTestRequest, Token, Backup, Jail, JailRollback, Volume, JailUpgrade, PowerState, ImageAutoUpgrade } from '@jailops/shared/api/types'
import * as d from './data'
import * as d2 from './data2'
import * as da from './apps'
import * as dh from './host'
import { validDNSName } from '@/lib/host'
import * as dw from './wireguard'
import * as dc from './cert'
import { DEMO_SETUP_TOKEN, DEMO_CLIENT_ADDRESS } from './setupToken'
import { passwordProblem, validUserName, cleanToken } from '@/lib/setup'
import { demoForward, unifiedRead, type DemoReply } from './logs'
import { demoAccess } from './access'
import { volumeName } from '@/lib/apps'
import { defaultImage } from '@/lib/images'
import { lookupKey, setValue, expandedSources, flatten } from '@/lib/configKeys'
import { loadChoice, saveChoice } from '@/lib/projectScope'
import { SET_NAME, setUsers, validateSet, type SetMsgs } from '@/lib/firewall'
import { nameProblem, type NameRule } from '@jailops/shared/lib/names'
import { labelKeyProblem, labelValueProblem, labelsProblem, MAX_LABELS } from '@/lib/labels'
import { demoRename, renameKindOf } from './rename'
import { demoFirewallTest, DemoFwError } from './fwtest'

interface DemoOp extends Operation {
  startedAt: number
  duration: number
  onDone?: () => void
  done?: boolean
  metadataFinal?: unknown
  /** Ends the operation with this error instead of success (the demo's failed installation). */
  failure?: ApiErrorBody
}

const GiB = 1024 ** 3
export interface DemoOptions {
  /** Start signed out so the login view can be shown. */
  signedOut?: boolean
  /** Speed factor for operation durations (tests use a large one). */
  speed?: number
}

const sleep0 = () => Promise.resolve()

export function demoTransport(opts: DemoOptions = {}): Transport {
  // Like a user who has already chosen a project (`project switch web`); `?demo=fresh` is a first visit with none.
  // `?demo=setup` is a host that was just installed and has no administrator yet: the first-run wizard.
  const setupMode = typeof location !== 'undefined' && location.search.includes('demo=setup')
  const emptyMode = typeof location !== 'undefined' && (location.search.includes('empty') || setupMode)
  if (typeof location !== 'undefined' && !location.search.includes('fresh') && !emptyMode) { if (!loadChoice()) saveChoice('web') }
  const speed = opts.speed ?? 1
  let authed = !opts.signedOut && !setupMode
  // the first administrator: needed until the wizard made one; wrong tokens are counted like the daemon counts them
  const setup = { required: setupMode, fails: 0, until: 0 }
  let signedInAs = ''
  const db = {
    jails: [...d.jails(), ...d2.stagingJails()], snaps: d.snapshots(), images: d.images(), networks: d.networks(), leases: d.leases(),
    policies: d.policies(), sets: d.addressSets(), targets: d.targets(), bpol: d.backupPolicies(), backups: d.backups(),
    remotes: d.remotes(), audit: d.audit(), tokens: d.tokens(), users: d.users(), certs: d.certificates(),
    volumes: d.volumes(), vsnaps: {} as Record<string, import('@jailops/shared/api/types').VolumeSnapshot[]>,
    ops: [] as DemoOp[],
    storage: d2.storages(), sessions: d2.sessions(), certs2: d2.certificates(), profiles: d2.profiles(), updates: [] as import('@jailops/shared/api/types').UpdateReport[], history: {} as Record<string, import('@jailops/shared/api/types').UpdateRecord[]>, projects: [] as ReturnType<typeof d2.projects>,
    host: dh.hostState(),
    fw: dh.loadFirewall() ?? dh.firewallState(typeof location !== 'undefined' && location.search.includes('pending')),
    wireguard: dw.tunnels(),
    key: { status: 'present' as 'none' | 'present' | 'escrowed', domain: 'kd-7f3a91', path: '/var/db/jailops/backup.key' },
    cert: dc.certState(),
  }
  for (const j of db.jails) {
    j.spec.provision = d2.provisionSpec(j.metadata.name)
    j.status.provisioned_at = d2.provisionedAt(j.metadata.name)
    if (j.metadata.name === 'web') j.spec.update = { mode: 'notify', schedule: '0 4 * * *', packages: true, os: true, reboot: 'manual' }
    if (j.metadata.name === 'db') j.spec.update = { mode: 'managed', schedule: '0 3 * * 0', packages: true, os: true, reboot: 'manual' }
    j.spec.profiles = j.metadata.name === 'web' ? ['web-limits'] : j.spec.profiles
  }
  db.updates = d2.updateReports(db.jails)
  for (const j of db.jails) db.history[j.metadata.name] = d2.updateHistory(j.metadata.name)
  if (emptyMode) {
    // A host that was just installed: nothing is configured yet (`?demo=empty`).
    db.jails = []; db.snaps = {} as typeof db.snaps; db.images = []; db.networks = []; db.leases = {} as typeof db.leases
    db.volumes = []; db.storage = []; db.profiles = { project: [], host: [] } as typeof db.profiles; db.updates = []; db.policies = []; db.sets = []
    db.targets = []; db.bpol = []; db.backups = []; db.remotes = []; db.wireguard = []
  }
  // `?demo=noimage`: a host with projects, networks and jails but no image yet (the install and create forms offer
  // to create the base image)
  if (typeof location !== 'undefined' && location.search.includes('noimage')) db.images = []
  // `?demo=newrelease`: the host was upgraded to 15.2 and only the image of 15.1 exists (the new release notice);
  // `?demo=nightlyfail`: the last nightly upgrade of freebsd-15-1 failed at a jail
  const newRelease = typeof location !== 'undefined' && location.search.includes('newrelease')
  if (typeof location !== 'undefined' && location.search.includes('nightlyfail')) {
    const fb = db.images.find((i) => i.metadata.name === 'freebsd-15-1')
    if (fb?.status.auto_upgrade) fb.status.auto_upgrade.recent = d.autoUpgradeRuns(true)
  }
  const countByProject = () => { const c: Record<string, number> = {}; for (const j of db.jails) c[j.metadata.project ?? ''] = (c[j.metadata.project ?? ''] ?? 0) + 1; return c }
  db.projects = d2.projects(countByProject())
  if (emptyMode) db.projects = []
  const shells = new Map<string, { h: StreamHandlers; line: string; jail: string }>()
  // The jails of the demo that have bash in them: those created here (a new FreeBSD jail gets it at its first start)
  // and those set up with shell-setup. The seeded jails are older and have none.
  const bashReady = new Set<string>()
  const BASH = '/usr/local/bin/bash'
  const shellPath = (v: string) => (v === 'bash' ? BASH : v === 'sh' ? '/bin/sh' : v)
  // the server's rule (api.CheckPrompt), in short: no quote, no backquote, $ only as \$, no \\ and no control characters
  const promptProblem = (v: string): string =>
    v === 'default' || v === 'none' ? '' : /['`\x00-\x1f\x7f]/.test(v) ? 'the prompt may not contain a quote, a backquote or a control character' : /\$/.test(v.replace(/\\\$/g, '')) || /\\\\/.test(v) ? 'the prompt may contain $ only as \\$ (variables and commands in the prompt are not accepted)' : /[{}]/.test(v.replace(/\\D\{[^}]*\}/g, '').replace(/\{(jail|project|host)\}/g, '')) ? 'a { or } in the prompt must be one of {jail}, {project}, {host}' : ''
  const freebsdImage = (ref: string) => (db.images.find((i) => i.metadata.name === String(ref).split(/[@#]/)[0])?.spec.os ?? 'freebsd') === 'freebsd'
  const logs = da.demoLogs()
  const forward = demoForward('bsd01.example.net')
  const access = demoAccess(() => db.jails, () => db.sets, (app) => { const x = da.detail(app); return x && x !== 'invalid' ? x.definition : undefined })
  for (const o of d.operations()) db.ops.push({ ...o, startedAt: Date.parse(o.created_at), duration: o.status === 'running' ? 600_000 : 0, done: o.status !== 'running' })
  // encrypted volumes: the passphrase of each, and the wrong ones counted as the daemon counts them
  const volPass: Record<string, string> = { secrets: d.demoVaultPassphrase }
  const volFails: Record<string, { n: number; until: number }> = {}
  const subs = new Set<StreamHandlers>()
  const pending: Array<{ jail: string; to: PowerState; at: number }> = []
  let seq = 2000

  // A real server answers with fresh JSON every time; clone so in-place demo mutations are seen as changes.
  const ok = (metadata: unknown, etag?: string): RawResponse => ({ status: 200, etag, envelope: { type: 'sync', status: 'Success', status_code: 200, metadata: metadata === undefined || metadata === null ? metadata : structuredClone(metadata) } })
  const fail = (status: number, e: ApiErrorBody): RawResponse => ({ status, envelope: { type: 'error', status: 'Failure', status_code: status, error: e } })
  const etagOf = (generation: number | undefined) => `"${generation ?? 0}"`

  function emit(action: string, source: string, who = 'demo'): void {
    const e: ApiEvent = { type: 'lifecycle', timestamp: new Date().toISOString(), metadata: { action, source, requestor: who } }
    subs.forEach((h) => h.onEvent(e))
  }
  function startOp(desc: string, resources: Operation['resources'], duration: number, apply: () => void, metadata?: unknown, may_cancel = true, failure?: ApiErrorBody): RawResponse {
    // failure is part of the operation from the start: the answer to the request is computed below, and an operation
    // whose duration has run out in that millisecond would be reported as a success before a later line set it
    const op: DemoOp = {
      id: `op-${++seq}`, description: desc, status: 'pending', resources, may_cancel, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      startedAt: Date.now(), duration: duration / speed, onDone: apply, metadataFinal: metadata, failure,
    }
    db.ops.unshift(op)
    return { status: 202, envelope: { type: 'async', status: 'Operation created', status_code: 100, operation: `/api/v1/operations/${op.id}`, metadata: view(op) } }
  }
  function view(o: DemoOp): Operation {
    if (!o.done && o.status !== 'cancelled') {
      const t = Date.now() - o.startedAt
      if (t >= o.duration && o.failure) {
        o.done = true
        o.status = 'failure'
        o.error = o.failure
        o.onDone?.()
      } else if (t >= o.duration) {
        o.done = true
        o.status = 'success'
        o.progress = 100
        o.metadata = o.metadataFinal as never
        o.onDone?.()
      } else {
        o.status = t < 150 / speed ? 'pending' : 'running'
        o.progress = Math.min(95, Math.round((t / o.duration) * 100))
      }
      o.updated_at = new Date().toISOString()
    }
    const { startedAt: _s, duration: _d, onDone: _o, done: _x, metadataFinal: _m, failure: _f, ...pub } = o
    return pub
  }
  function settleJails(): void {
    for (let i = pending.length - 1; i >= 0; i--) {
      const p = pending[i]
      if (Date.now() >= p.at) {
        const j = db.jails.find((x) => x.metadata.name === p.jail)
        if (j) {
          j.status.power = p.to
          if (p.to === 'running') {
            j.status.jid = 100 + Math.floor(Math.random() * 50)
            j.status.started_at = new Date().toISOString()
            j.status.addresses = [(db.leases[j.spec.network?.[0]?.network ?? 'lan']?.find((l) => l.jail === j.metadata.name)?.address ?? '10.20.0.50') + '/24']
          } else {
            j.status.jid = undefined
            j.status.addresses = []
            j.status.started_at = undefined
          }
        }
        pending.splice(i, 1)
      }
    }
  }
  const jailOr404 = (n: string): Jail | undefined => db.jails.find((j) => j.metadata.name === n)
  const flaky = new Set<string>()

  // the name of a new object, as the server's create handlers check it (shared lib/names.ts holds the limits)
  const badName = (name: string, rule: NameRule, what = 'name'): RawResponse | undefined => {
    const p = name ? nameProblem(name, rule) : 'Required.'
    return p ? fail(400, { code: 'invalid', message: `${what} "${name}": ${p}`, detail: { field: 'name' } }) : undefined
  }

  // POST /images: the definition only, checked like service.validateImage and the image sources do
  function imageCreate(body: Record<string, any>): RawResponse {
    const name = String(body.metadata?.name ?? '')
    const sp = (body.spec ?? {}) as import('@jailops/shared/api/types').ImageSpec
    const badImg = badName(name, 'image')
    if (badImg) return badImg
    if (db.images.some((i) => i.metadata.name === name)) return fail(409, { code: 'already_exists', message: `image "${name}" already exists` })
    if (!sp.os || !sp.release) return fail(400, { code: 'invalid', message: 'spec.os and spec.release are required' })
    if (sp.source?.type === 'pkgbase' && !/^[0-9]+\.[0-9]+(-|$)/.test(sp.release)) return fail(400, { code: 'invalid', message: `release "${sp.release}" is not <major>.<minor>-<type>` })
    if (!['amd64', 'arm64'].includes(sp.arch)) return fail(400, { code: 'invalid', message: `unsupported architecture "${sp.arch}"` })
    const bad = autoUpgradeProblem(sp.auto_upgrade)
    if (bad) return bad
    const img = { metadata: { name, scope: 'fleet' as const, generation: 1, created_at: new Date().toISOString() }, spec: sp, status: { generations: [], aliases: {}, ...autoUpgradeStatus(sp.auto_upgrade) } }
    db.images.push(img as never)
    emit('created', `/api/v1/images/${name}`)
    return { ...ok(img), status: 201 }
  }

  // spec.auto_upgrade: the time of day is HH:MM, as service.parseAutoUpgradeAt reads it
  function autoUpgradeProblem(a: ImageAutoUpgrade | undefined): RawResponse | null {
    if (!a?.at || /^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(a.at)) return null
    return fail(400, { code: 'invalid', message: `auto_upgrade.at "${a.at}" must be a time of day such as 03:00` })
  }
  const autoUpgradeStatus = (a: ImageAutoUpgrade | undefined) => (a?.enabled ? { auto_upgrade: { next: d.nextNight(a.at || '03:00') } } : {})
  // PATCH /images/{name}: a merge patch; the console sends spec.auto_upgrade only
  function imagePatch(name: string, body: Record<string, any>): RawResponse {
    const img = db.images.find((i) => i.metadata.name === name)
    if (!img) return fail(404, { code: 'not_found', message: `Image ${name} not found` })
    const a = body.spec?.auto_upgrade as ImageAutoUpgrade | null | undefined
    if (a === null) delete img.spec.auto_upgrade
    else if (a) {
      const merged = { ...(img.spec.auto_upgrade ?? { enabled: false }), ...a }
      const bad = autoUpgradeProblem(merged)
      if (bad) return bad
      img.spec.auto_upgrade = merged
    }
    const recent = img.status.auto_upgrade?.recent
    const next = img.spec.auto_upgrade?.enabled ? d.nextNight(img.spec.auto_upgrade.at || '03:00') : undefined
    img.status.auto_upgrade = next || recent ? { ...(next ? { next } : {}), ...(recent ? { recent } : {}) } : undefined
    img.metadata.generation = (img.metadata.generation ?? 1) + 1
    emit('updated', `/api/v1/images/${name}`)
    return ok(img)
  }

  async function route(req: RawRequest): Promise<RawResponse> {
    await sleep0()
    if (!authed && storedToken()) authed = true // any bearer token is accepted in the demo
    settleJails()
    const url = new URL(req.path, 'http://x')
    const path = url.pathname.replace(/\/$/, '')
    const seg = path.split('/').filter(Boolean).map(decodeURIComponent)
    const m = req.method
    const body = (req.body === undefined ? {} : JSON.parse(JSON.stringify(req.body))) as Record<string, any> // the wire is JSON: never keep the caller's reactive objects

    if (path === '' && m === 'GET') {
      const info = d.server()
      if (newRelease) info.environment = { ...info.environment, kernel_version: '15.2-RELEASE-p1' }
      return ok({ ...info, auth: authed ? 'trusted' : 'untrusted' })
    }
    if (seg[0] === 'setup') return setupRoute(seg, m, body)
    if (seg[0] === 'auth') {
      if (seg[1] === 'session') return authed ? ok({ ...d2.identity(), ...(signedInAs ? { user: signedInAs } : {}), csrf: 'demo-csrf' }) : fail(401, { code: 'unauthorized', message: 'No session.' })
      if (seg[1] === 'login') {
        if (!body.username) return fail(400, { code: 'invalid', message: 'username is required' })
        if (body.username === 'alice' && !body.totp) return fail(401, { code: 'unauthorized', message: 'A one-time code is required.', hint: 'Enter the six digits from your authenticator.', detail: { totp: 'required' } })
        authed = true
        if (setupMode) signedInAs = String(body.username)
        return ok({ user: body.username, permission: 'admin', csrf: 'demo-csrf' })
      }
      authed = false
      return ok({})
    }
    if (!authed) return fail(401, { code: 'unauthorized', message: 'Authentication is required.', hint: 'Sign in with a token or a user.' })
    if (m === 'GET' && seg[0] === 'resources') return ok(d.pool())
    // There is no default project: what works inside one needs it named, like the real server.
    const project = url.searchParams.get('project') ?? ''
    if (!project && ['jails', 'volumes', 'firewall', 'profiles', 'updates', 'restores'].includes(seg[0])) return fail(400, { code: 'invalid', message: 'a project is required', hint: "name one with --project NAME (list them with 'jailops project list')" })
    const inProject = (j: Jail) => (j.metadata.project ?? '') === project
    for (const p of db.projects) p.status.jails = countByProject()[p.metadata.name] ?? 0
    const rn = m === 'POST' ? renameKindOf(seg) : undefined
    if (rn) return renameRoute(rn.kind, rn.name, body, project, req)
    const extra = extraRoutes(seg, m, body, url, req, project)
    if (extra) return extra

    switch (seg[0]) {
      case 'jails': return jailsRoute(seg, m, body, inProject, url)
      case 'volumes': return volumesRoute(seg, m, body, project)
      case 'images':
        if (seg.length === 1 && m === 'POST') return imageCreate(body)
        if (seg.length === 1) return ok(db.images)
        if (seg.length === 2 && m === 'PATCH') return imagePatch(seg[1], body)
        if (seg[2] === 'generations' && m === 'POST') {
          const img = db.images.find((i) => i.metadata.name === seg[1])
          if (!img) return fail(404, { code: 'not_found', message: `Image ${seg[1]} not found` })
          const gens = (img.status.generations ??= [])
          const n = Math.max(0, ...gens.map((g) => g.number)) + 1
          // the first build downloads the whole base system; an image whose name starts with "fail" cannot reach the
          // package repository (the demo's failed build), one that starts with "flaky" only at its first try
          const fails = seg[1].startsWith('fail') || (seg[1].startsWith('flaky') && !flaky.has(seg[1]))
          if (seg[1].startsWith('flaky')) flaky.add(seg[1])
          const op = startOp(`Build image ${seg[1]}`, { images: [`/api/v1/images/${seg[1]}`] }, 3000, () => {
            if (fails) return
            gens.push({ number: n, name: `${seg[1]}#g${n}`, parent: n > 1 ? n - 1 : undefined, manifest: Math.random().toString(16).slice(2).padEnd(40, 'e'), packages: n === 1 ? 212 : 222, freebsd_version: img.spec.os === 'freebsd' ? '15.1-RELEASE-p6' : undefined, created_at: new Date().toISOString(), refs: [] })
            // the aliases of the definition follow the newest generation
            const aliases = (img.status.aliases ??= {})
            for (const a of img.spec.aliases ?? []) aliases[a] = n
            emit('image-generation-created', `/api/v1/images/${seg[1]}/generations/${n}`)
          })
          if (fails) {
            const o = db.ops[0]
            o.failure = { code: 'internal', message: 'pkg: https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1/meta.conf: No address record', hint: 'check that the host reaches the package repository', detail: { step: 'install-sets' } }
          }
          return op
        }
        if (seg[2] === 'upgrade' && m === 'POST') {
          const img = db.images.find((i) => i.metadata.name === seg[1])
          if (!img) return fail(404, { code: 'not_found', message: `Image ${seg[1]} not found` })
          return startOp(`Upgrade image ${seg[1]}`, { images: [`/api/v1/images/${seg[1]}`] }, 6000, () => {
            const n = Math.max(...(img.status.generations ?? []).map((g) => g.number)) + 1
            img.status.generations!.push({ number: n, name: `${seg[1]}#g${n}`, parent: n - 1, manifest: Math.random().toString(16).slice(2).padEnd(40, 'e'), packages: 222, freebsd_version: img.spec.os === 'freebsd' ? '15.1-RELEASE-p6' : undefined, created_at: new Date().toISOString(), refs: [] })
          })
        }
        if (seg[2] === 'aliases' && seg[3] && (m === 'PUT' || m === 'DELETE')) {
          const img = db.images.find((i) => i.metadata.name === seg[1])
          if (!img) return fail(404, { code: 'not_found', message: `Image ${seg[1]} not found` })
          const aliases = (img.status.aliases ??= {})
          if (m === 'DELETE') {
            if (!(seg[3] in aliases)) return fail(404, { code: 'not_found', message: `Image ${seg[1]} has no alias ${seg[3]}` })
            delete aliases[seg[3]]
            img.spec.aliases = (img.spec.aliases ?? []).filter((a) => a !== seg[3])
          } else {
            const n = body?.generation || Math.max(0, ...(img.status.generations ?? []).map((g) => g.number))
            if (!(img.status.generations ?? []).some((g) => g.number === n)) return fail(404, { code: 'not_found', message: `Generation g${n} does not exist` })
            aliases[seg[3]] = n
            if (!(img.spec.aliases ?? []).includes(seg[3])) img.spec.aliases = [...(img.spec.aliases ?? []), seg[3]]
          }
          return ok(img)
        }
        break
      case 'networks':
        if (seg.length === 1 && m === 'POST') {
          const badNet = badName(String(body.metadata?.name ?? ''), 'network')
          if (badNet) return badNet
          if (db.networks.some((n) => n.metadata.name === body.metadata?.name)) return fail(409, { code: 'already_exists', message: `Network ${body.metadata.name} already exists.` })
          const sp = body.spec as import('@jailops/shared/api/types').Network['spec']
          const net = { metadata: { name: body.metadata.name, scope: 'host' as const, generation: 1, created_at: new Date().toISOString() }, spec: { ...sp }, status: { allocated: 0, free: 100 } }
          return startOp(`Create network ${body.metadata.name}`, {}, 500, () => db.networks.push(net as never), undefined, false)
        }
        if (seg.length === 1) return ok(db.networks)
        if (seg[2] === 'leases') return ok(db.leases[seg[1]] ?? [])
        if (seg.length === 2) {
          const net = db.networks.find((n) => n.metadata.name === seg[1])
          if (!net) return fail(404, { code: 'not_found', message: `Network ${seg[1]} not found` })
          if (m === 'GET') return ok(net, etagOf(net.metadata.generation))
          if (m === 'PUT') {
            if (req.headers?.['If-Match'] && req.headers['If-Match'] !== etagOf(net.metadata.generation)) return fail(412, { code: 'conflict', message: 'The network changed since you loaded it.', hint: 'Reload and apply your change again.' })
            const sp = body.spec as import('@jailops/shared/api/types').Network['spec']
              return startOp(`Save network ${seg[1]}`, { networks: [`/api/v1/networks/${seg[1]}`] }, 500, () => { net.spec = { ...sp }; net.metadata.generation = (net.metadata.generation ?? 0) + 1 }, undefined, false)
          }
          if (m === 'DELETE') {
            const by = db.projects.find((p) => (p.spec.networks ?? []).some((g) => g.network === seg[1]))
            if (by) return fail(409, { code: 'conflict', message: `Network ${seg[1]} is granted to project ${by.metadata.name}.`, hint: `Remove the grant on the page of project ${by.metadata.name} first.` })
            return startOp(`Delete network ${seg[1]}`, { networks: [`/api/v1/networks/${seg[1]}`] }, 500, () => {
              db.networks = db.networks.filter((n) => n !== net)
              delete db.leases[seg[1]]
              emit('network-deleted', `/api/v1/networks/${seg[1]}`)
            }, undefined, false)
          }
        }
        break
      case 'firewall': return firewallRoute(seg, m, body, req, project)
      case 'backups': return backupsRoute(seg, m, body, project)
      case 'backup-targets': return ok(db.targets)
      case 'backup-policies':
        // the canned policies are the web project's; another project has none of them
        return ok(db.bpol.filter((p) => (p.metadata.project ?? 'web') === project))
      case 'doctor': return ok({ time: new Date().toISOString(), host: 'bsd01.example.net', status: 'fail', checks: [
        { name: 'zfs.pool', status: 'ok', message: 'pool tank is ONLINE' },
        { name: 'kernel.module.if_epair', status: 'ok', message: 'loaded' },
        { name: 'kernel.module.pf', status: 'ok', message: 'loaded' },
        { name: 'pf.anchor.mail', status: 'fail', message: 'anchor jailops/mail is not loaded', hint: 'Fix the syntax error at line 14 of the policy mail-edge, then run jailops reconcile.', detail: { policy: 'mail-edge', line: '14' } },
        { name: 'linuxulator', status: 'warn', message: 'linprocfs is not mounted', hint: 'Add linprocfs to /etc/fstab.' },
        { name: 'jail.kernel.vimage', status: 'unknown', message: 'could not be determined on this platform' },
        { name: 'apps.access', status: 'ok', message: '2 grants; every firewall rule and pg_hba.conf line is in place' },
      ] })
      case 'restores': return restore(body)
      case 'remotes': return ok(db.remotes)
      case 'operations':
        if (seg.length === 1) return ok(db.ops.map(view))
        {
          const o = db.ops.find((x) => x.id === seg[1])
          if (!o) return fail(404, { code: 'not_found', message: `Operation ${seg[1]} not found` })
          if (m === 'DELETE') {
            if (!o.may_cancel) return fail(403, { code: 'forbidden', message: 'This operation cannot be cancelled.' })
            o.status = 'cancelled'
            o.done = true
            return ok({})
          }
          return ok(view(o))
        }
      case 'audit': return ok(db.audit)
      case 'tokens':
        if (m === 'GET') return ok(db.tokens)
        if (m === 'POST') {
          if (db.tokens.some((t) => t.metadata.name === body.metadata?.name)) return fail(409, { code: 'already_exists', message: `Token ${body.metadata.name} already exists` })
          const t: Token = { metadata: { ...body.metadata, scope: 'fleet', created_at: new Date().toISOString() }, spec: body.spec }
          db.tokens.push(t)
          emit('token-created', `/api/v1/tokens/${t.metadata.name}`)
          return ok({ ...t, secret: 'jot_' + Array.from({ length: 40 }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 36)]).join('') })
        }
        if (m === 'DELETE') {
          db.tokens = db.tokens.filter((t) => t.metadata.name !== seg[1])
          return ok({})
        }
        break
      case 'users':
        if (m === 'POST' && seg.length === 1) {
          if (db.users.some((u) => u.metadata.name === body.metadata?.name)) return fail(409, { code: 'already_exists', message: `User ${body.metadata.name} already exists` })
          const u = { metadata: { ...body.metadata, scope: 'fleet', created_at: new Date().toISOString() }, spec: body.spec }
          db.users.push(u)
          return ok({ user: u, ...(body.password ? {} : { password: 'demo-generated-passphrase' }) })
        }
        if (seg.length === 2 && seg[1] === 'password') return ok(body.password ? {} : { password: 'demo-generated-passphrase' })
        if (seg.length === 2 && m === 'PATCH') {
          const u = db.users.find((x) => x.metadata.name === seg[1])
          if (!u) return fail(404, { code: 'not_found', message: `No such user ${seg[1]}` })
          u.spec = { ...u.spec, ...body.spec }
          return ok(u)
        }
        if (seg.length === 2 && m === 'DELETE') {
          db.users = db.users.filter((x) => x.metadata.name !== seg[1])
          return ok({})
        }
        return ok(db.users)
      case 'certificates':
        if (m === 'DELETE') {
          db.certs = db.certs.filter((c) => c.metadata.name !== seg[1])
          return ok({})
        }
        return ok(db.certs)
    }
    return fail(404, { code: 'not_found', message: `No such route: ${m} ${path}` })
  }

  function jailsRoute(seg: string[], m: string, body: Record<string, any>, inProject: (j: Jail) => boolean, url: URL): RawResponse {
    if (seg.length === 1 && m === 'POST') {
      const name = String(body.metadata?.name ?? '')
      const badJail = badName(name, 'jail')
      if (badJail) return badJail
      if (db.jails.some((x) => x.metadata.name === name && inProject(x))) return fail(409, { code: 'already_exists', message: `Jail ${name} already exists.` })
      const project = url.searchParams.get('project') ?? ''
      const attachProblem = attachRefused(name, project, (body.spec?.volumes ?? []) as VolumeAttach[])
      if (attachProblem) return attachProblem
      const spec = { ...body.spec } as Jail['spec']
      if (spec.prompt && promptProblem(spec.prompt)) return fail(400, { code: 'invalid', message: 'prompt: ' + promptProblem(spec.prompt), detail: { field: 'prompt' } })
      if (freebsdImage(spec.image)) {
        // jails.shell and jails.prompt of the demo host: bash and the default prompt
        spec.shell = shellPath(spec.shell || 'bash')
        if (!spec.prompt && spec.shell === BASH) spec.prompt = 'default'
        if (spec.shell === BASH) bashReady.add(name)
      }
      const labels = (body.metadata?.labels ?? undefined) as Record<string, string> | undefined
      if (labels && labelsProblem(labels)) return fail(400, { code: 'invalid', message: `the labels are invalid (${labelsProblem(labels)})` })
      const jail: Jail = { metadata: { name, scope: 'host', generation: 1, created_at: new Date().toISOString(), ...(project ? { project } : {}), ...(labels && Object.keys(labels).length ? { labels } : {}) }, spec, status: { power: 'stopped', addresses: [], conditions: [{ type: 'Reconciled', status: 'True' }] } }
      return startOp(`Create jail ${name}`, { jails: [`/api/v1/jails/${name}`] }, 800, () => { db.jails.push(jail) }, undefined, false)
    }
    if (seg.length === 1) return ok(db.jails.filter(inProject))
    const j = jailOr404(seg[1])
    if (!j || !inProject(j)) return fail(404, { code: 'not_found', message: `Jail ${seg[1]} not found` })
    const name = j.metadata.name
    const src = `/api/v1/jails/${name}`
    if (seg.length === 2 && url.searchParams.get('expanded') === 'true') {
      const profs = [...db.profiles.project, ...db.profiles.host].filter((p) => (j.spec.profiles ?? []).includes(p.metadata.name))
      let merged = JSON.parse(JSON.stringify(j.spec)) as Jail['spec']
      const own = flatten(j.spec)
      const src = expandedSources(j.spec, profs)
      const sources: Record<string, string> = {}
      for (const [k, v] of Object.entries(src)) {
        sources[k] = v.source === 'jail' ? 'jail' : 'profile:' + v.source
        const f = lookupKey(k)
        if (f && !(k in own)) merged = setValue(merged, f.def, f.dev, v.value)
      }
      return ok({ jail: { ...j, spec: merged }, sources })
    }
    if (seg.length === 3 && seg[2] === 'config' && m === 'POST') {
      const set = (body.set ?? {}) as Record<string, string>
      const unset = (body.unset ?? []) as string[]
      let spec = JSON.parse(JSON.stringify(j.spec)) as Jail['spec']
      const restart: string[] = []
      for (const [k, v] of Object.entries(set)) {
        const f = lookupKey(k)
        if (!f) return fail(400, { code: 'invalid', message: `unknown configuration key "${k}"`, hint: 'jailops config keys lists them', detail: { key: k } })
        if (f.def.type === 'int' && !/^-?\d+$/.test(v)) return fail(400, { code: 'invalid', message: `${k}: "${v}" must be a number`, detail: { key: k } })
        if (k.endsWith('.mtu') && (Number(v) < 576 || Number(v) > 9216)) return fail(400, { code: 'invalid', message: `${k}: "${v}" must be a number between 576 and 9216`, detail: { key: k } })
        const val = k === 'shell' ? shellPath(v) : v
        if (k === 'shell' && val && val !== '/bin/sh' && val !== BASH) return fail(400, { code: 'invalid', message: `shell: ${v} does not exist in the jail`, detail: { key: k } })
        if (k === 'prompt' && promptProblem(v)) return fail(400, { code: 'invalid', message: 'prompt: ' + promptProblem(v), detail: { key: k } })
        if (f.def.restart_required && flatten(j.spec)[k] !== val) restart.push(k)
        spec = setValue(spec, f.def, f.dev, val)
      }
      for (const k of unset) {
        const f = lookupKey(k)
        if (!f) return fail(400, { code: 'invalid', message: `unknown configuration key "${k}"`, detail: { key: k } })
        if (f.def.restart_required && flatten(j.spec)[k] !== undefined) restart.push(k)
        spec = setValue(spec, f.def, f.dev, '')
      }
      j.spec = spec
      j.metadata.generation = (j.metadata.generation ?? 0) + 1
      emit('jail-updated', src)
      return startOp(`Configure ${name}`, { jails: [src] }, 300, () => undefined, { ...j, restart_required: restart.sort(), restarted: false }, false)
    }
    if (seg.length === 2 && m === 'DELETE') {
      // the jail and its snapshots go; the volumes it attached stay; a running jail is stopped first, as on the server
      return startOp(`Delete jail ${name}`, { jails: [src] }, 900, () => {
        db.jails = db.jails.filter((x) => x !== j)
        delete db.snaps[name]
        emit('jail-deleted', src)
      }, undefined, false)
    }
    // PATCH /jails/{name}: a merge patch, as service.MergePatch applies it; the console sends metadata.labels only
    if (seg.length === 2 && m === 'PATCH') {
      if (body.spec !== undefined) return fail(400, { code: 'unsupported', message: 'the demo patches labels only' })
      const patch = (body.metadata?.labels ?? {}) as Record<string, string | null>
      const next: Record<string, string> = { ...(j.metadata.labels ?? {}) }
      for (const [k, v] of Object.entries(patch)) {
        if (v === null) delete next[k]
        else if (typeof v !== 'string') return fail(400, { code: 'invalid', message: `patched object is invalid: the value of label "${k}" is not a string` })
        else next[k] = v
      }
      const bad = Object.keys(next).length > MAX_LABELS ? `an object has at most ${MAX_LABELS} labels (got ${Object.keys(next).length})`
        : Object.entries(next).map(([k, v]) => (labelKeyProblem(k) ? `invalid label key "${k}"` : labelValueProblem(v) === 'valueLong' ? `the value of label "${k}" is longer than 253 bytes` : labelValueProblem(v) ? `the value of label "${k}" holds control or invisible characters` : '')).find(Boolean)
      if (bad) return fail(400, { code: 'invalid', message: bad, hint: bad.startsWith('invalid label key') ? "letters, digits, '-', '_' and '.', beginning and ending with a letter or digit, at most 63 characters, with an optional prefix and '/' (example.org/tier)" : undefined })
      j.metadata.labels = Object.keys(next).length ? next : undefined
      j.metadata.generation = (j.metadata.generation ?? 0) + 1
      emit('jail-updated', src)
      return ok(j, etagOf(j.metadata.generation))
    }
    if (seg.length === 2) return ok(j, etagOf(j.metadata.generation))
    switch (seg[2]) {
      case 'snapshots':
        if (m === 'GET') return ok(db.snaps[name] ?? [])
        return startOp(`Snapshot ${name}`, { jails: [src] }, 1200, () => {
          const n = `manual-${Date.now().toString(36)}`
          ;(db.snaps[name] ??= []).push({ metadata: { name: n, scope: 'host', created_at: new Date().toISOString() }, spec: { jail: name, comment: body.spec?.comment }, status: { written: 0 } })
          emit('jail-snapshot-created', src)
        }, undefined, false)
      case 'volumes': return jailVolumesRoute(seg, m, body, j)
      case 'state': {
        const a = body.action as string
        if (a !== 'stop' && j.status.power === 'locked') return fail(409, { code: 'locked', message: `jail "${name}" is locked: the encrypted volume(s) ${(j.status.locked ?? []).join(', ')} wait for a passphrase`, hint: `jailops volume unlock ${(j.status.locked ?? [])[0] ?? ''}` })
        if (a === 'start' && j.status.power === 'running') return fail(409, { code: 'busy', message: `Jail ${name} is already running.` })
        const lostDir = a === 'stop' ? undefined : (j.spec.volumes ?? []).map((x) => db.volumes.find((v) => v.metadata.name === x.volume && (v.metadata.project ?? '') === (j.metadata.project ?? ''))).find((v) => v?.spec.path && v.status?.state === 'lost')
        if (lostDir) return fail(409, { code: 'busy', message: `volume "${lostDir.metadata.name}" is lost: the directory is not on a mount (${lostDir.spec.path})`, hint: 'mount it again; the jail starts when it is there' })
        if (a === 'start' && name === 'mail') return fail(500, { code: 'internal', message: 'jail: mail: exec.prestart failed', hint: 'Run jailops doctor on the host, then retry.', detail: { exit_code: '1' } })
        const to: PowerState = a === 'stop' ? 'stopped' : 'running'
        j.status.power = a === 'stop' ? 'stopping' : 'starting'
        pending.push({ jail: name, to, at: Date.now() + 1500 / speed })
        return startOp(`${a} ${name}`, { jails: [src] }, 1500, () => emit(`jail-${a === 'stop' ? 'stopped' : 'started'}`, src), undefined, true)
      }
      case 'rollback': {
        const r = body as JailRollback
        if ((r.scope === 'data' || r.scope === 'all') && !r.confirm_data_loss) return fail(400, { code: 'data_loss_unconfirmed', message: 'This rollback discards data and was not confirmed.', hint: 'Set confirm_data_loss after showing the bytes to the operator.' })
        return startOp(`Rollback ${name} (${r.scope ?? 'root'})`, { jails: [src] }, 2200, () => {
          if (r.scope === 'data' || r.scope === 'all') (db.snaps[name] ?? []).forEach((s) => (s.status.written = 0))
          if (r.scope !== 'data') j.status.generation = 'freebsd-15-1#g3'
          emit('jail-rolled-back', src)
        })
      }
      case 'upgrade': {
        const u = body as JailUpgrade
        const target = u.generation || 'freebsd-15-1#g5'
        const preview = {
          from_generation: j.status.generation ?? '', to_generation: target,
          steps: ['Preflight: no dependent clones, replication idle', 'Snapshot all datasets (rollback point)', 'Stop the jail', 'Clone the target generation to root.new', 'Merge /etc with etcupdate', 'Swap root and root.new', 'Start and run the health check'],
          etc_conflicts: name === 'web' ? ['/etc/ssl/openssl.cnf'] : [], warnings: j.status.power === 'running' ? ['The jail will be stopped for about 20 seconds.'] : [],
        }
        if (u.dry_run) return ok(preview)
        return startOp(`Upgrade ${name} to ${target}`, { jails: [src] }, 3500, () => {
          j.status.generation = target
          emit('jail-upgraded', src)
        })
      }
    }
    return fail(404, { code: 'not_found', message: 'No such route' })
  }

  // POST <object>/rename (extension rename): a dry run answers the plan, a rename is an operation that ends with it
  function renameRoute(kind: Parameters<typeof demoRename>[1], name: string, body: Record<string, any>, project: string, req: RawRequest): RawResponse {
    const a = demoRename(db, kind, name, String(body.new_name ?? ''), project, req.headers?.['If-Match'])
    if ('error' in a) return fail(a.status, a.error)
    if (body.dry_run) return ok({ ...a.result, dry_run: true })
    const r = startOp(`rename ${a.result.kind.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase()} ${name} to ${a.result.to}`, { [a.resource.split('/')[3]]: [a.resource] }, 1200, () => {
      if (a.fails) return
      a.apply()
      emit(`${kind}-renamed`, a.resource.replace(/[^/]+$/, a.result.to))
    }, a.result, false, a.fails)
    return r
  }

  type VolumeAttach = NonNullable<Jail['spec']['volumes']>[number]
  const usesOf = (project: string, volume: string) => db.jails.filter((x) => (x.metadata.project ?? '') === project).flatMap((x) => (x.spec.volumes ?? []).filter((v) => v.volume === volume).map((v) => ({ jail: x.metadata.name, mount: v.mount, ...(v.read_only ? { read_only: true } : {}) })))
  /** A volume as the server reports it: the jails that attach it and what is worth a warning, computed now. */
  function volView(v: Volume): Volume {
    const project = v.metadata.project ?? ''
    const uses = usesOf(project, v.metadata.name)
    const rw = uses.filter((u) => !u.read_only).map((u) => u.jail)
    const warnings = rw.length > 1 ? [`writable in more than one jail (${rw.join(', ')}): the jails share the files and their locking; a mail store, a database or a package cache needs one writer`] : []
    return { ...v, status: { ...(v.status ?? { used: 0 }), used: v.status?.used ?? 0, attached_to: uses, ...(warnings.length ? { warnings } : {}) } }
  }
  /** The refusals of a volume that is a directory of the host: nothing of a dataset applies to it. */
  const hostDirRefused = (name: string): RawResponse => fail(400, { code: 'invalid', message: `volume "${name}" is a directory of the host: it has no snapshots, no key and no size of its own`, hint: "its files are the host's; snapshot, copy or back them up there" })
  /** The checks of an attachment, as the server makes them: the volume exists, an encrypted one has one jail, the path is sane. */
  function attachRefused(jail: string, project: string, list: VolumeAttach[], running = false): RawResponse | null {
    if (running) return fail(409, { code: 'busy', message: `jail "${jail}" is running: volumes are attached and detached while it is stopped`, hint: `jailops stop ${jail}` })
    const seen = new Set<string>()
    const mounts = new Set<string>()
    for (const a of list) {
      if (!a.mount || !a.mount.startsWith('/') || a.mount === '/' || a.mount.includes('..')) return fail(400, { code: 'invalid', message: `volume "${a.volume}" has a bad mount path "${a.mount}"` })
      if (seen.has(a.volume)) return fail(400, { code: 'invalid', message: `volume "${a.volume}" is attached twice` })
      if (mounts.has(a.mount)) return fail(400, { code: 'invalid', message: `duplicate mount point "${a.mount}"` })
      seen.add(a.volume)
      mounts.add(a.mount)
      const v = db.volumes.find((x) => x.metadata.name === a.volume && (x.metadata.project ?? '') === project)
      if (!v) return fail(404, { code: 'not_found', message: `volume "${a.volume}" does not exist in project "${project}"`, hint: `jailops volume create ${a.volume}` })
      const other = v.spec.encrypted ? usesOf(project, a.volume).find((u) => u.jail !== jail) : undefined
      if (other) return fail(409, { code: 'conflict', message: `volume "${a.volume}" is encrypted and attached to jail "${other.jail}" already: an encrypted volume is attached to one jail`, hint: `jailops volume detach ${other.jail} ${a.volume}` })
    }
    return null
  }
  function jailVolumesRoute(seg: string[], m: string, body: Record<string, any>, j: Jail): RawResponse {
    const name = j.metadata.name
    const project = j.metadata.project ?? ''
    const src = `/api/v1/jails/${name}`
    if (seg.length === 3 && m === 'GET') return ok(j.spec.volumes ?? [])
    const running = ['running', 'starting', 'stopping'].includes(j.status.power)
    if (seg.length === 3 && m === 'POST') {
      const att: VolumeAttach = { volume: String(body.volume ?? ''), mount: String(body.mount ?? ''), ...(body.read_only ? { read_only: true } : {}) }
      if (!att.volume || !att.mount) return fail(400, { code: 'invalid', message: 'name the volume and the path it has in the jail' })
      if ((j.spec.volumes ?? []).some((v) => v.volume === att.volume)) return fail(409, { code: 'already_exists', message: `volume "${att.volume}" is attached to jail "${name}" already`, hint: `jailops volume detach ${name} ${att.volume} to attach it elsewhere in the jail` })
      const refused = attachRefused(name, project, [...(j.spec.volumes ?? []), att], running)
      if (refused) return refused
      return startOp(`Attach volume ${att.volume} to jail ${name}`, { jails: [src] }, 500, () => {
        j.spec.volumes = [...(j.spec.volumes ?? []), att]
        j.metadata.generation = (j.metadata.generation ?? 0) + 1
        emit('jail-updated', src)
      }, undefined, false)
    }
    if (seg.length === 4 && m === 'DELETE') {
      if (!(j.spec.volumes ?? []).some((v) => v.volume === seg[3])) return fail(404, { code: 'not_found', message: `volume attachment "${seg[3]}" not found` })
      if (running) return attachRefused(name, project, [], true) as RawResponse
      return startOp(`Detach volume ${seg[3]} from jail ${name}`, { jails: [src] }, 500, () => {
        j.spec.volumes = (j.spec.volumes ?? []).filter((v) => v.volume !== seg[3])
        j.metadata.generation = (j.metadata.generation ?? 0) + 1
        emit('jail-updated', src)
      }, undefined, false)
    }
    return fail(404, { code: 'not_found', message: 'no such route' })
  }

  /** Locks follow the volumes: a jail that attaches a locked volume is locked. */
  function relock(project: string): void {
    for (const j of db.jails) {
      if ((j.metadata.project ?? '') !== project) continue
      const locked = (j.spec.volumes ?? []).filter((a) => db.volumes.find((v) => v.metadata.name === a.volume && (v.metadata.project ?? '') === project)?.status?.locked).map((a) => a.volume)
      j.status.locked = locked.length ? locked : undefined
      if (locked.length && j.status.power !== 'running') j.status.power = 'locked'
      if (!locked.length && j.status.power === 'locked') j.status.power = 'stopped'
    }
  }

  function newAppVolume(name: string, mount: string, project: string, app: string, jail: string): Volume {
    return { metadata: { name, scope: 'host', generation: 1, created_at: new Date().toISOString(), project, labels: { [da.LABEL]: app } }, spec: { storage: 'default', uid: 0, gid: 0, mode: '0755', comment: `data of ${jail} (${app}): ${mount}` }, status: { dataset: `tank/jailops/projects/${project}/volumes/${name}`, mountpoint: `/jailops/projects/${project}/volumes/${name}`, used: 0 } }
  }

  function volumesRoute(seg: string[], m: string, body: Record<string, any>, project: string): RawResponse {
    const mine = (v: Volume) => (v.metadata.project ?? '') === project
    if (seg.length === 1 && m === 'GET') return ok(db.volumes.filter(mine).map(volView))
    if (seg.length === 1 && m === 'POST') {
      const name = String(body.metadata?.name ?? '')
      const bad = badName(name, 'volume')
      if (bad) return bad
      if (db.volumes.some((v) => v.metadata.name === name && mine(v))) return fail(409, { code: 'already_exists', message: `volume "${name}" already exists` })
      const spec = (body.spec ?? {}) as Volume['spec']
      if (spec.path || spec.watch || spec.probe || spec.on_loss) {
        const path = spec.path ?? ''
        if (!path) return fail(400, { code: 'invalid', message: 'only a volume of a host directory is watched', hint: 'give the directory with --path, or leave --watch, --probe and --on-loss out' })
        if (!/^\/[A-Za-z0-9._+@:=,/-]+$/.test(path) || path.split('/').slice(1).some((x) => x === '' || x === '.' || x === '..')) return fail(400, { code: 'invalid', message: `path: ${JSON.stringify(path)} is not a clean absolute path` })
        if (!path.startsWith('/mnt/')) return fail(403, { code: 'forbidden', message: `"${path}" is not below a directory of admin-host-mount in priv.conf` })
        if (spec.size || spec.storage || spec.mode || spec.encrypted || spec.uid || spec.gid) return fail(400, { code: 'invalid', message: "a volume of a host directory has no size, storage, owner, mode or encryption: the files are the host's" })
        if (!spec.watch && (spec.probe || spec.on_loss)) return fail(400, { code: 'invalid', message: '--probe and --on-loss say what a watch does', hint: 'add --watch' })
        const hv: Volume = {
          metadata: { name, scope: 'host', generation: 1, created_at: new Date().toISOString(), project, ...(body.metadata?.labels ? { labels: body.metadata.labels } : {}) },
          spec: { uid: 0, gid: 0, path, ...(spec.watch ? { watch: true, probe: spec.probe || 'mounted', on_loss: spec.on_loss || 'none' } : {}), ...(spec.comment ? { comment: spec.comment } : {}) },
          status: { mountpoint: path, used: 0, state: 'ok' },
        }
        return startOp(`Create volume ${name}`, { volumes: [`/api/v1/volumes/${name}`] }, 700, () => { db.volumes.push(hv); emit('volume-created', `/api/v1/volumes/${name}`) }, undefined, false)
      }
      const mode = spec.mode === undefined || spec.mode === '' ? 0o755 : parseInt(String(spec.mode), 8)
      if (!Number.isFinite(mode) || mode < 0 || mode > 0o777 || !/^[0-7]+$/.test(String(spec.mode ?? '755'))) return fail(400, { code: 'invalid', message: `mode "${spec.mode}" is not an octal mode up to 0777` })
      if ((spec.uid ?? 0) < 0 || (spec.gid ?? 0) < 0) return fail(400, { code: 'invalid', message: 'uid and gid are numbers from 0' })
      const pass = typeof body.passphrase === 'string' ? body.passphrase : ''
      if (spec.encrypted && (pass.length < 12 || pass.length > 512 || /[\r\n]/.test(pass))) return fail(400, { code: 'invalid', message: pass ? 'the passphrase must be between 12 and 512 bytes long' : 'an encrypted volume needs a passphrase' })
      if (!spec.encrypted && pass) return fail(400, { code: 'invalid', message: 'a passphrase was given but the volume is not encrypted' })
      if (spec.encrypted) volPass[name] = pass
      const storage = spec.storage || 'default'
      const v: Volume = {
        metadata: { name, scope: 'host', generation: 1, created_at: new Date().toISOString(), project, ...(body.metadata?.labels ? { labels: body.metadata.labels } : {}) },
        spec: { storage, uid: spec.uid ?? 0, gid: spec.gid ?? 0, mode: '0' + mode.toString(8).padStart(3, '0'), ...(spec.size ? { size: spec.size } : {}), ...(spec.encrypted ? { encrypted: true } : {}), ...(spec.comment ? { comment: spec.comment } : {}) },
        status: { dataset: `tank/jailops/projects/${project}/volumes/${name}`, mountpoint: `/jailops/projects/${project}/volumes/${name}`, used: 0 },
      }
      return startOp(`Create volume ${name}`, { volumes: [`/api/v1/volumes/${name}`] }, 700, () => { db.volumes.push(v); emit('volume-created', `/api/v1/volumes/${name}`) }, undefined, false)
    }
    const v = db.volumes.find((x) => x.metadata.name === seg[1] && mine(x))
    if (!v) return fail(404, { code: 'not_found', message: `volume "${seg[1]}" not found` })
    const name = v.metadata.name
    const src = `/api/v1/volumes/${name}`
    if (seg.length === 2 && m === 'GET') return ok(volView(v), etagOf(v.metadata.generation))
    if (seg.length === 2 && m === 'PUT') {
      const spec = (body.spec ?? {}) as Volume['spec']
      if (v.spec.path) {
        if ((spec.path ?? undefined) !== v.spec.path) return fail(400, { code: 'invalid', message: 'the path of a volume cannot change', hint: 'a volume keeps its directory: make a new volume for another one' })
        v.spec = { ...v.spec, watch: spec.watch || undefined, probe: spec.watch ? spec.probe || 'mounted' : undefined, on_loss: spec.watch ? spec.on_loss || 'none' : undefined, comment: spec.comment }
        v.metadata.generation = (v.metadata.generation ?? 0) + 1
        emit('volume-updated', src)
        return ok(volView(v), etagOf(v.metadata.generation))
      }
      for (const f of ['storage', 'uid', 'gid', 'mode', 'encrypted'] as const) {
        if ((spec[f] ?? undefined) !== (v.spec[f] ?? undefined) && !(f === 'storage' && !spec.storage)) return fail(400, { code: 'invalid', message: `the ${f} of a volume cannot change` })
      }
      v.spec = { ...v.spec, size: spec.size, comment: spec.comment }
      v.metadata.generation = (v.metadata.generation ?? 0) + 1
      emit('volume-updated', src)
      return ok(volView(v), etagOf(v.metadata.generation))
    }
    if (seg.length === 2 && m === 'DELETE') {
      const uses = usesOf(project, name)
      if (uses.length) return fail(409, { code: 'busy', message: `volume "${name}" is attached to ${uses.map((u) => u.jail).join(', ')}: detach it before it is deleted`, hint: `jailops volume detach ${uses[0].jail} ${name}` })
      return startOp(`Delete volume ${name}`, { volumes: [src] }, 700, () => { db.volumes = db.volumes.filter((x) => x !== v); delete db.vsnaps[`${project}/${name}`]; emit('volume-deleted', src) }, undefined, false)
    }
    const sk = `${project}/${name}`
    if (v.spec.path && ['snapshots', 'rollback', 'unlock', 'lock', 'passphrase'].includes(seg[2])) return hostDirRefused(name)
    if (seg[2] === 'snapshots') {
      if (seg.length === 3 && m === 'GET') return ok(db.vsnaps[sk] ?? [])
      if (seg.length === 3 && m === 'POST') {
        const sn = String(body.metadata?.name ?? '') || `snap-${Date.now().toString(36)}`
        if ((db.vsnaps[sk] ?? []).some((x) => x.metadata.name === sn)) return fail(409, { code: 'already_exists', message: `snapshot "${sn}" already exists` })
        return startOp(`Snapshot volume ${name}`, { volumes: [src] }, 600, () => {
          ;(db.vsnaps[sk] ??= []).push({ metadata: { name: sn, scope: 'host', project, created_at: new Date().toISOString() }, spec: { volume: name, comment: body.spec?.comment }, status: { written: 0 } })
          emit('volume-snapshot-created', `${src}/snapshots/${sn}`)
        }, undefined, false)
      }
      if (seg.length === 4 && m === 'DELETE') {
        if (!(db.vsnaps[sk] ?? []).some((x) => x.metadata.name === seg[3])) return fail(404, { code: 'not_found', message: `snapshot "${seg[3]}" not found` })
        return startOp(`Delete snapshot ${seg[3]}`, { volumes: [src] }, 500, () => { db.vsnaps[sk] = (db.vsnaps[sk] ?? []).filter((x) => x.metadata.name !== seg[3]); emit('volume-snapshot-deleted', `${src}/snapshots/${seg[3]}`) }, undefined, false)
      }
    }
    if (seg[2] === 'rollback' && m === 'POST') {
      const list = db.vsnaps[sk] ?? []
      const i = list.findIndex((x) => x.metadata.name === body.snapshot)
      if (!body.snapshot) return fail(400, { code: 'invalid', message: 'name the snapshot to roll back to' })
      if (!body.confirm_data_loss) return fail(400, { code: 'invalid', message: 'a rollback discards what was written to the volume since the snapshot', hint: 'repeat it with confirm_data_loss' })
      if (i < 0) return fail(404, { code: 'not_found', message: `snapshot "${body.snapshot}" not found` })
      const running = usesOf(project, name).find((u) => db.jails.find((j) => j.metadata.name === u.jail && (j.metadata.project ?? '') === project)?.status.power === 'running')
      if (running) return fail(409, { code: 'busy', message: `jail "${running.jail}" has volume "${name}" attached and is running: stop it before the volume is rolled back`, hint: `jailops stop ${running.jail}` })
      return startOp(`Roll volume ${name} back to ${body.snapshot}`, { volumes: [src] }, 900, () => { db.vsnaps[sk] = list.slice(0, i + 1); emit('volume-rolled-back', src) }, undefined, false)
    }
    if (['unlock', 'lock', 'passphrase'].includes(seg[2]) && m === 'POST') return keysRoute(seg[2], v, body, project)
    return fail(404, { code: 'not_found', message: 'no such route' })
  }

  function keysRoute(what: string, v: Volume, body: Record<string, any>, project: string): RawResponse {
    const name = v.metadata.name
    const src = `/api/v1/volumes/${name}`
    if (!v.spec.encrypted) return fail(400, { code: 'invalid', message: `volume "${name}" is not encrypted` })
    const f = (volFails[name] ??= { n: 0, until: 0 })
    if (what !== 'lock' && Date.now() < f.until) return fail(429, { code: 'rate_limited', message: 'too many wrong passphrases for this volume', hint: `wait ${Math.ceil((f.until - Date.now()) / 1000)}s and try again` })
    // a wrong passphrase fails the operation, as on a real host; five in a row lock unlocks out for 30 seconds
    const check = (p: unknown): ApiErrorBody | undefined => {
      if (p === volPass[name]) { f.n = 0; return undefined }
      if (++f.n >= 5) { f.n = 0; f.until = Date.now() + 30_000 }
      return { code: 'bad_passphrase', message: 'the passphrase is not correct' }
    }
    const users = () => usesOf(project, name).map((u) => db.jails.find((j) => j.metadata.name === u.jail && (j.metadata.project ?? '') === project)).filter((j): j is Jail => !!j)
    if (what === 'lock') {
      return startOp(`Lock volume ${name}`, { volumes: [src] }, 900, () => {
        for (const j of users()) Object.assign(j.status, { power: 'stopped', jid: undefined, addresses: [], started_at: undefined })
        v.status = { ...(v.status ?? { used: 0 }), used: v.status?.used ?? 0, locked: true }
        relock(project)
        emit('volume-locked', src)
      })
    }
    if (what === 'passphrase') {
      if (v.status?.locked) return fail(409, { code: 'locked', message: `volume "${name}" is locked`, hint: `jailops volume unlock ${name}` })
      const next = String(body.new_passphrase ?? '')
      if (next.length < 12 || next.length > 512) return fail(400, { code: 'invalid', message: 'the passphrase must be between 12 and 512 bytes long' })
      const err = check(body.old_passphrase)
      return startOp(`Change the passphrase of volume ${name}`, { volumes: [src] }, 900, () => { if (!err) volPass[name] = next }, undefined, false, err)
    }
    if (!body.passphrase) return fail(400, { code: 'invalid', message: 'passphrase must be 1 to 512 bytes without a line break' })
    const err = check(body.passphrase)
    return startOp(`Unlock volume ${name}`, { volumes: [src] }, 900, () => {
      if (err) return
      v.status = { ...(v.status ?? { used: 0 }), used: v.status?.used ?? 0, locked: undefined }
      relock(project)
      emit('volume-unlocked', src)
      if (body.start) for (const j of users()) { j.status.power = 'starting'; pending.push({ jail: j.metadata.name, to: 'running', at: Date.now() }) }
    }, undefined, false, err)
  }

  // The server's texts for a refused address set (internal/validate), so the demo says what the daemon says.
  const setTexts: SetMsgs = {
    setRequired: '', setTooLong: '', setBadName: '', setExists: '',
    setMember: (a) => `address set member "${a}" must be an address, a CIDR, jail:NAME or set:NAME`,
    setCycle: (path) => `address set cycle: ${path}`,
  }
  /** The checks of CreateAddressSet and UpdateAddressSet: name, members and cycles. */
  function setRefused(name: string, spec: AddressSetSpec, inProject: AddressSet[], project: string): RawResponse | null {
    if (!SET_NAME.test(name)) return fail(400, { code: 'invalid', message: `name "${name}" must follow the name rule (lowercase letters, digits and hyphens, starting with a letter, at most 29 characters)`, detail: { field: 'name' } })
    const others = Object.fromEntries(inProject.filter((x) => x.metadata.name !== name).map((x) => [x.metadata.name, x.spec]))
    const e = validateSet(name, { addresses: spec.addresses ?? [] }, others, setTexts)
    if (e.addresses) return fail(400, { code: 'invalid', message: e.addresses, detail: { field: 'addresses' } })
    // set:NAME is a set of the project; jail:NAME may name a jail that is not there (it matches nobody)
    for (const a of spec.addresses ?? []) {
      const n = a.address.startsWith('set:') ? a.address.slice(4) : ''
      if (n && n !== name && !others[n]) {
        return fail(400, { code: 'invalid', message: `address set "${n}" does not exist (a rule or a set names set:${n})`, detail: { field: 'addresses' } })
      }
    }
    return null
  }
  const quoted = (xs: string[]) => xs.map((x) => `"${x}"`).join(', ')

  function firewallRoute(seg: string[], m: string, body: Record<string, any>, req: RawRequest, project: string): RawResponse {
    if (seg[1] === 'test' && seg.length === 2 && m === 'POST') {
      try {
        const proj = db.projects.find((p) => p.metadata.name === project)
        return ok(demoFirewallTest(body as FirewallTestRequest, {
          jails: db.jails.filter((j) => (j.metadata.project ?? '') === project), policies: db.policies.filter((x) => (x.metadata.project ?? 'web') === project),
          sets: db.sets.filter((x) => (x.metadata.project ?? 'web') === project), projectPolicies: proj?.spec.firewall_policies ?? [],
        }))
      } catch (e) {
        if (e instanceof DemoFwError) return fail(e.status, { code: e.code as ApiErrorBody['code'], message: e.message, ...(e.hint ? { hint: e.hint } : {}) })
        throw e
      }
    }
    const isSet = seg[1] === 'address-sets'
    // policies and address sets belong to a project like jails; the canned ones are the web project's
    const all = (isSet ? db.sets : db.policies) as Array<FirewallPolicy | AddressSet>
    const list = all.filter((x) => (x.metadata.project ?? 'web') === project)
    const sets = db.sets.filter((x) => (x.metadata.project ?? 'web') === project)
    const policies = db.policies.filter((x) => (x.metadata.project ?? 'web') === project)
    if (seg.length === 2 && m === 'POST' && isSet) {
      const name = String(body.metadata?.name ?? '')
      if (sets.some((x) => x.metadata.name === name)) return fail(409, { code: 'already_exists', message: `address-set "${name}" already exists` })
      const spec: AddressSetSpec = { ...(body.spec?.comment ? { comment: body.spec.comment } : {}), addresses: body.spec?.addresses ?? [] }
      const refused = setRefused(name, spec, sets, project)
      if (refused) return refused
      const set: AddressSet = { metadata: { name, project, scope: 'fleet', generation: 1, created_at: new Date().toISOString() }, spec }
      db.sets.push(set)
      emit('address-set-created', `/api/v1/firewall/address-sets/${name}`)
      return ok(set, etagOf(1))
    }
    if (seg.length === 2 && m === 'POST') {
      const name = String(body.metadata?.name ?? '')
      if (!/^[a-z][a-z0-9-]{0,62}$/.test(name)) return fail(400, { code: 'invalid', message: `name "${name}" must match ^[a-z][a-z0-9-]{0,62}$`, detail: { field: 'name' } })
      if (list.some((x) => x.metadata.name === name)) return fail(409, { code: 'already_exists', message: `Policy ${name} already exists.` })
      for (const d of ['default_in', 'default_out']) {
        if (body.spec?.[d] !== 'allow' && body.spec?.[d] !== 'deny') return fail(400, { code: 'invalid', message: `${d} is required: allow or deny (a policy says its defaults)`, detail: { field: d } })
      }
      const pol: FirewallPolicy = { metadata: { name, project, scope: 'host', generation: 1, created_at: new Date().toISOString() }, spec: { default_in: body.spec.default_in, default_out: body.spec.default_out, rules: body.spec?.rules ?? [] } }
      db.policies.push(pol)
      emit('firewall-created', `/api/v1/firewall/policies/${name}`)
      return ok(pol)
    }
    if (seg.length === 2) return m === 'GET' ? ok(list) : fail(405, { code: 'invalid', message: `${m} is not allowed here` })
    const item = list.find((x) => x.metadata.name === seg[2])
    if (!item) return fail(404, { code: 'not_found', message: `${isSet ? 'address-set' : 'firewall-policy'} "${seg[2]}" not found` })
    if (m === 'GET') return ok(item, etagOf(item.metadata.generation))
    if (req.headers?.['If-Match'] && req.headers['If-Match'] !== etagOf(item.metadata.generation)) return fail(412, { code: 'conflict', message: 'The object changed since you loaded it.', hint: 'Reload and apply your change again.' })
    if (m === 'DELETE' && isSet) {
      // DeleteAddressSet: refused while a rule of a policy names set:NAME or another set has set:NAME as a member
      const name = seg[2]
      const users = setUsers(name, policies, sets)
      if (users.policies.length) {
        return fail(409, { code: 'busy', message: `address set "${name}" is used by firewall ${users.policies.length > 1 ? 'policies' : 'policy'} ${quoted(users.policies)}`,
          hint: `remove set:${name} from the rules of ${users.policies.join(', ')} first`, detail: { policies: users.policies.join(',') } })
      }
      if (users.sets.length) {
        return fail(409, { code: 'busy', message: `address set "${name}" is a member of ${quoted(users.sets)}`,
          hint: `remove set:${name} from the members of ${users.sets.join(', ')} first`, detail: { sets: users.sets.join(',') } })
      }
      db.sets = db.sets.filter((x) => x !== item)
      emit('address-set-deleted', `/api/v1/firewall/address-sets/${name}`)
      return ok(null)
    }
    if (m === 'DELETE') {
      // DeletePolicy: not the project's mandatory policy, not while a jail of the project uses it
      const name = seg[2]
      const proj = db.projects.find((p) => p.metadata.name === project)
      if (proj?.spec.firewall_policies?.includes(name)) return fail(409, { code: 'busy', message: `firewall policy "${name}" is a mandatory policy of project "${project}"`, hint: 'take it out of spec.firewall_policies of the project first' })
      const user = db.jails.find((j) => (j.metadata.project ?? '') === project && j.spec.firewall?.policies?.includes(name))
      if (user) return fail(409, { code: 'busy', message: `firewall policy "${name}" is used by jail "${user.metadata.name}"` })
      return startOp(`Delete policy ${name}`, { firewall: [`/api/v1/firewall/policies/${name}`] }, 500, () => {
        db.policies = db.policies.filter((x) => x !== item)
        emit('firewall-deleted', `/api/v1/firewall/policies/${name}`)
      }, undefined, false)
    }
    if (m !== 'PUT' && m !== 'PATCH') return fail(405, { code: 'invalid', message: `${m} is not allowed here` })
    // a merge patch keeps what it does not name; a PUT replaces the spec
    const spec = (m === 'PATCH' ? { ...item.spec, ...(body.spec ?? {}) } : body.spec ?? {}) as Record<string, any>
    if (body.metadata?.name && body.metadata.name !== seg[2]) return fail(400, { code: 'invalid', message: 'renaming is not supported' })
    if (isSet) {
      const next: AddressSetSpec = { ...(spec.comment ? { comment: spec.comment } : {}), addresses: spec.addresses ?? [] }
      const refused = setRefused(seg[2], next, sets, project)
      if (refused) return refused
      item.spec = next
      item.metadata.generation = (item.metadata.generation ?? 0) + 1
      emit('address-set-updated', `/api/v1/firewall/address-sets/${seg[2]}`)
      return ok(item, etagOf(item.metadata.generation))
    }
    const rules = (spec.rules ?? []) as FirewallRule[]
    for (let i = 0; i < rules.length; i++) {
      const r = rules[i]
      if (r.redirect && r.direction !== 'in') return fail(400, { code: 'invalid', message: `rules[${i}]: a redirect is allowed on inbound rules only`, detail: { [`rules[${i}].redirect`]: 'redirect is allowed on inbound rules only' } })
      for (const k of ['from', 'to'] as const) {
        for (const a of r[k] ?? []) if (a.startsWith('set:') && !sets.some((x) => x.metadata.name === a.slice(4))) return fail(400, { code: 'invalid', message: `rules[${i}]: unknown address set ${a}`, hint: 'Create the address set first.', detail: { [`rules[${i}].${k}`]: `unknown address set ${a}` } })
      }
    }
    return startOp(`Save ${seg[2]}`, { firewall: [`/api/v1/firewall/${seg[1]}/${seg[2]}`] }, 700, () => {
      item.spec = spec as never
      item.metadata.generation = (item.metadata.generation ?? 0) + 1
      emit('firewall-updated', `/api/v1/firewall/${seg[1]}/${seg[2]}`)
    }, undefined, false)
  }

  function backupsRoute(seg: string[], m: string, body: Record<string, any> = {}, project = ''): RawResponse {
    if (seg[1] === 'run' && m === 'POST') {
      const pol = db.bpol.find((p) => p.metadata.name === body.policy)
      if (!pol) return fail(404, { code: 'not_found', message: `Backup policy ${body.policy} not found` })
      const run = { id: 'run-' + ++seq, kind: 'backup', policy: pol.metadata.name, jail: 'web', started: new Date().toISOString(), finished: new Date().toISOString(), ok: true }
      return startOp(`Run policy ${pol.metadata.name}`, {}, 2000, () => emit('backup-run', '/api/v1/backups/run'), [run], true)
    }
    // the backups of the project's jails only
    if (seg.length === 1) return ok(db.backups.filter((b) => (db.jails.find((j) => j.metadata.name === b.spec.jail)?.metadata.project ?? 'web') === project))
    const b = db.backups.find((x) => x.metadata.name === seg[1])
    if (!b) return fail(404, { code: 'not_found', message: `Backup ${seg[1]} not found` })
    if (seg[2] === 'verify') return startOp(`Verify ${b.spec.snapshot}`, {}, 1500, () => { b.status.verified = true; b.status.failed = false }, { id: 'run-' + ++seq, kind: 'drill', jail: b.spec.jail, depth: body.depth ?? 'deep', ok: true, started: new Date().toISOString(), finished: new Date().toISOString() }, true)
    if (m === 'DELETE') {
      if (b.status.protected) return fail(409, { code: 'busy', message: 'The snapshot is protected by retention.', hint: 'Change the retention policy on the backup node first.' })
      return startOp(`Request deletion of ${b.spec.snapshot}`, {}, 600, () => (b.status.pending_deletion = new Date(Date.now() + 2 * 86400_000).toISOString()), undefined, false)
    }
    return ok(b)
  }

  function restore(body: Record<string, any>): RawResponse {
    const b: Backup | undefined = db.backups.find((x) => x.metadata.name === body.backup)
    if (!b) return fail(404, { code: 'not_found', message: `Backup ${body.backup} not found` })
    const map = (body.network_map ?? {}) as Record<string, string>
    const missing: string[] = []
    const changes: string[] = []
    const errors: string[] = []
    for (const a of b.spec.bundle.spec.network ?? []) {
      const target = map[a.network] ?? a.network
      if (!db.networks.some((n) => n.metadata.name === target)) missing.push(`network ${target}`)
      else if (a.ipv4 && a.ipv4 !== 'auto' && a.ipv4 !== 'none' && !body.keep_ip) changes.push(`allocate a new address on ${target} (was ${a.ipv4})`)
      else if (body.keep_ip && a.ipv4?.startsWith('10.99.')) errors.push(`address ${a.ipv4} is outside every range of network ${target}`)
    }
    const target = body.as || b.spec.jail
    if (b.spec.kind === 'volume') {
      if (db.volumes.some((v) => v.metadata.name === target)) errors.push(`volume ${target} already exists in project web; restore it under another name with as=NAME (a volume is never replaced)`)
      if (b.spec.volume?.encrypted && !body.passphrase) errors.push('the volume is encrypted: give its passphrase; it makes the volume again and is never stored')
      const vreport: RestorePreflight = { ok: !errors.length, missing: [], changes: errors.length ? [] : [`creates volume ${target} in project web from backup ${b.metadata.name}`], errors }
      if (body.dry_run) return ok(vreport)
      if (!vreport.ok) return fail(409, { code: 'invalid', message: 'The restore preflight failed.', hint: 'Run the preflight and fix what it lists.' })
      return startOp(`Restore ${target}`, { volumes: [`/api/v1/volumes/${target}`] }, 3000, () => emit('volume-created', `/api/v1/volumes/${target}`))
    }
    if (db.jails.some((j) => j.metadata.name === target) && !body.replace) errors.push(`jail ${target} already exists; choose another name or allow replacing it`)
    changes.push(`create jail ${target} from ${b.spec.snapshot}`, `use image ${b.spec.bundle.image_generation}`)
    const report: RestorePreflight = { ok: !missing.length && !errors.length, missing, changes, errors }
    if (body.dry_run) return ok(report)
    if (!report.ok) return fail(409, { code: 'invalid', message: 'The restore preflight failed.', hint: 'Run the preflight and fix what it lists.' })
    return startOp(`Restore ${target}`, { jails: [`/api/v1/jails/${target}`] }, 4000, () => {
      emit('jail-restored', `/api/v1/jails/${target}`)
    })
  }


  /** A network belongs to one project: the message the server gives when another one holds it. */
  function heldNetwork(spec: { networks?: Array<{ network: string }> }, self: string): string | undefined {
    for (const g of spec.networks ?? []) {
      const other = db.projects.find((x) => x.metadata.name !== self && (x.spec.networks ?? []).some((h) => h.network === g.network))
      if (other) return `network ${g.network} is already granted to project ${other.metadata.name}`
    }
    return undefined
  }
  function setupRoute(seg: string[], m: string, body: Record<string, any>): RawResponse {
    const gone = fail(404, { code: 'not_found', message: 'the host has an administrator: setup is complete', hint: 'sign in' })
    if (!setup.required) return gone
    if (seg.length === 1 && m === 'GET') return ok({ required: true, token_issued: true, expires_at: new Date(Date.now() + 20 * 3600_000).toISOString() })
    if (seg.length !== 1 || m !== 'POST') return fail(404, { code: 'not_found', message: 'No such route' })
    if (Date.now() < setup.until) return fail(429, { code: 'rate_limited', message: 'too many failed attempts', hint: `try again in ${Math.ceil((setup.until - Date.now()) / 1000)} seconds`, detail: { retry_after: String(Math.ceil((setup.until - Date.now()) / 1000)) } })
    if (cleanToken(String(body.token ?? '')) !== DEMO_SETUP_TOKEN) {
      if (++setup.fails >= 5) { setup.fails = 0; setup.until = Date.now() + 30_000 }
      return fail(401, { code: 'unauthorized', message: 'the setup token is not valid', hint: 'use the token the host printed on its console, or print a new one with jailops-priv setup-token (as root)' })
    }
    const name = String(body.name ?? '')
    if (!validUserName(name)) return fail(400, { code: 'invalid', message: `invalid name "${name}"`, hint: "use lowercase letters, digits, '-', '_' and '.'" })
    const pw = passwordProblem(String(body.password ?? ''), name)
    if (pw) return fail(400, { code: 'invalid', message: `password: ${pw}` })
    setup.required = false
    setup.fails = 0
    const u = { metadata: { name, scope: 'fleet' as const, created_at: new Date().toISOString() }, spec: { permission: 'admin' as const, global: true } }
    db.users.push(u)
    emit('user-created', `/api/v1/users/${name}`, name)
    return ok({ user: u, client_address: DEMO_CLIENT_ADDRESS })
  }

  function hostRoute(seg: string[], m: string, body: Record<string, any>): RawResponse | undefined {
    const r = hostAnswer(seg, m, body)
    if (seg[1] === 'firewall' || seg[1] === 'pending') dh.saveFirewall(db.fw)
    return r
  }
  function hostAnswer(seg: string[], m: string, body: Record<string, any>): RawResponse | undefined {
    if (seg[1] === 'identity' && m === 'GET') return ok(dh.identity(db.host))
    if (seg[1] === 'certificate') {
      const a = m === 'GET' && seg.length === 2 ? dc.certificate(db.cert)
        : m === 'PUT' && seg.length === 2 ? dc.upload(db.cert, body)
        : m === 'POST' && seg[2] === 'acme' ? dc.useAcme(db.cert, body as never, speed)
        : m === 'POST' && seg[2] === 'self-signed' ? dc.useSelfSigned(db.cert) : null
      if (!a) return fail(404, { code: 'not_found', message: 'No such route' })
      if ('error' in a) return fail(a.status, a.error)
      if (m !== 'GET') emit('host-certificate-updated', '/api/v1/host/certificate')
      return ok(a)
    }
    if (seg[1] === 'firewall' && m === 'GET') return ok(dh.firewall(db.fw))
    if (seg[1] === 'pending' && seg.length === 2 && m === 'GET') return ok(dh.pendingState(db.fw))
    if (seg[1] === 'pending' && (seg[2] === 'confirm' || seg[2] === 'revert') && m === 'POST') {
      const r = dh.endPending(db.fw, seg[2], body.id)
      if (r === 'none') return fail(404, { code: 'not_found', message: 'no change is waiting for a confirmation' })
      if (r === 'other') return fail(409, { code: 'conflict', message: `the pending change is not ${body.id}` })
      emit(seg[2] === 'confirm' ? 'host-change-confirmed' : 'host-change-reverted', '/api/v1/host/pending')
      return ok(r)
    }
    // one change waits for its confirmation at a time, and no other host change is made meanwhile
    dh.settleFirewall(db.fw)
    const waiting = db.fw.pending?.change
    if (waiting && m !== 'GET' && !body.dry_run) return fail(409, { code: 'busy', message: `a ${waiting.module} change is waiting for its confirmation (id ${waiting.id})`, hint: 'confirm it with jailops host confirm, or undo it with jailops host revert' })
    if (seg[1] === 'firewall' && m === 'PUT') {
      const within = body.confirm_within ?? 120
      if (!Number.isInteger(within) || within < 10 || within > 1800) return fail(400, { code: 'invalid', message: `the confirmation window is 10 to 1800 seconds, not ${within}` })
      const r = dh.applyFirewall(db.fw, body.spec ?? {}, !!body.dry_run, within)
      if (!r.dry_run && r.changed) emit('host-firewall-updated', '/api/v1/host/firewall')
      return ok(r)
    }
    if (seg[1] === 'identity' && m === 'PUT') {
      const spec = body.spec ?? {}
      if (spec.hostname && !validDNSName(spec.hostname)) return fail(400, { code: 'invalid', message: `hostname "${spec.hostname}" is not a valid host name` })
      const r = dh.applyIdentity(db.host, spec, !!body.dry_run)
      if (!r.dry_run && r.changed) emit('host-identity-updated', '/api/v1/host/identity')
      return ok(r)
    }
    if (seg[1] === 'snapshots' && seg.length === 2 && m === 'GET') return ok(dh.snapshots(db.host))
    if (seg[1] === 'snapshots' && seg[3] === 'restore' && m === 'POST') {
      const r = dh.restoreSnapshot(db.host, seg[2], !!body.dry_run)
      return r ? ok(r) : fail(404, { code: 'not_found', message: `snapshot ${seg[2]} not found` })
    }
    return undefined
  }

  function wireguardRoute(seg: string[], m: string, body: Record<string, any>): RawResponse {
    const wg = (n: string) => db.wireguard.find((w) => w.metadata.name === n)
    const missing = (n: string) => fail(404, { code: 'not_found', message: `wireguard "${n}" not found` })
    const touch = (w: import('@jailops/shared/api/types').WireGuard) => { w.metadata.generation = (w.metadata.generation ?? 0) + 1; w.metadata.updated_at = new Date().toISOString(); emit('wireguard-updated', `/api/v1/wireguard/${w.metadata.name}`) }
    if (seg.length === 1 && m === 'GET') return ok(db.wireguard.map(dw.observe))
    if (seg.length === 1 && m === 'POST') {
      const name = String(body.metadata?.name ?? '')
      const badWg = badName(name, 'tunnel')
      if (badWg) return badWg
      if (wg(name)) return fail(409, { code: 'already_exists', message: `wireguard "${name}" already exists` })
      const port = body.spec?.listen_port ?? 51820
      if (db.wireguard.some((w) => w.spec.listen_port === port)) return fail(409, { code: 'already_exists', message: `listen port ${port} is used by another tunnel` })
      const addr: string[] = body.spec?.address ?? []
      const w = {
        metadata: { name, scope: 'fleet' as const, generation: 1, created_at: new Date().toISOString() },
        spec: { ...body.spec, interface: `wg-${name}`, listen_port: port, allowed_ips: addr.map((a) => (a.includes(':') ? a.replace(/::[0-9a-f]*\//, '::/') : a.replace(/\.\d+\/(\d+)$/, '.0/$1'))), endpoint: body.spec?.endpoint || `vpn.example.com:${port}`, peers: [] },
        status: { public_key: dw.demoKey(), interface: `wg-${name}`, up: true, listen_port: port, firewall_rule: `pass in on $ext_if proto udp to port ${port}`, peers: [], conditions: [] },
      }
      db.wireguard.push(w)
      emit('wireguard-created', `/api/v1/wireguard/${name}`)
      return { ...ok(dw.observe(w)), status: 201 }
    }
    if (seg[1] === 'join' && m === 'POST') {
      const w = dw.fromToken(String(body.token ?? ''), body.name)
      if (!w) return fail(400, { code: 'invalid', message: 'not a WireGuard join token', hint: 'copy the whole token that `jailops wireguard peer add` printed; it starts with jwg1.' })
      if (wg(w.metadata.name)) return fail(409, { code: 'already_exists', message: `wireguard "${w.metadata.name}" already exists` })
      db.wireguard.push(w)
      emit('wireguard-created', `/api/v1/wireguard/${w.metadata.name}`)
      return { ...ok(dw.observe(w)), status: 201 }
    }
    const w = wg(seg[1])
    if (!w) return missing(seg[1])
    if (seg.length === 2 && m === 'GET') return ok(dw.observe(w))
    if (seg.length === 2 && m === 'DELETE') { db.wireguard = db.wireguard.filter((x) => x !== w); emit('wireguard-deleted', `/api/v1/wireguard/${w.metadata.name}`); return ok({}) }
    if (seg[2] === 'peers' && m === 'POST' && seg.length === 3) {
      if (w.spec.mode !== 'server') return fail(400, { code: 'invalid', message: `wireguard "${w.metadata.name}" is a client; peers are added on the server` })
      const name = String(body.name ?? '')
      if (!/^[a-z][a-z0-9-]{0,62}$/.test(name)) return fail(400, { code: 'invalid', message: `name "${name}" must match ^[a-z][a-z0-9-]{0,62}$` })
      if ((w.spec.peers ?? []).some((p) => p.name === name)) return fail(409, { code: 'already_exists', message: `peer "${name}" of wireguard "${w.metadata.name}" already exists`, hint: 'remove it first to issue a new token' })
      const out = dw.enroll(w, name, body.address)
      touch(w)
      return { ...ok(out), status: 201 }
    }
    if (seg[2] === 'peers' && m === 'DELETE' && seg[3]) {
      if (!(w.spec.peers ?? []).some((p) => p.name === seg[3])) return fail(404, { code: 'not_found', message: `peer "${seg[3]}" not found` })
      w.spec.peers = (w.spec.peers ?? []).filter((p) => p.name !== seg[3])
      touch(w)
      return ok(dw.observe(w))
    }
    if ((seg[2] === 'up' || seg[2] === 'down') && m === 'POST') { w.spec.down = seg[2] === 'down'; touch(w); return ok(dw.observe(w)) }
    if (seg[2] === 'rotate-keys' && m === 'POST') {
      w.status.public_key = dw.demoKey()
      return ok({ public_key: w.status.public_key, warning: w.spec.mode === 'server' ? 'every peer must be given the new public key: issue new tokens (jailops wireguard peer remove, then peer add)' : 'the server of this client must be given the new public key: remove the peer there and enroll it again' })
    }
    return fail(404, { code: 'not_found', message: `No such route: ${m} /wireguard/${seg.slice(1).join('/')}` })
  }
  function logsRoute(seg: string[], m: string, body: Record<string, any>, url: URL, req: RawRequest): RawResponse {
    const answer = (r: DemoReply): RawResponse => ('ok' in r ? ok(r.ok, r.etag) : fail(r.status, r.error))
    if (seg.length === 1 && m === 'GET') return answer(unifiedRead(db.jails, logs, url.searchParams))
    if (seg[1] === 'forward' && seg.length === 2) {
      if (m === 'GET') return answer(forward.get())
      if (m === 'PUT') return answer(forward.put(body as never, req.headers?.['If-Match']))
      if (m === 'DELETE') return answer(forward.reset())
    }
    if (seg[1] === 'forward' && seg[2] === 'test' && m === 'POST') return answer(forward.test(String(body.sink ?? '')))
    return fail(404, { code: 'not_found', message: `No such route: ${m} /${seg.join('/')}` })
  }
  function extraRoutes(seg: string[], m: string, body: Record<string, any>, url: URL, req: RawRequest, project: string): RawResponse | undefined {
    const name = seg[1]
    switch (seg[0]) {
      case 'apps': return appsRoute(seg, m, body, project)
      case 'host': return hostRoute(seg, m, body)
      case 'wireguard': return wireguardRoute(seg, m, body)
      case 'logs': return logsRoute(seg, m, body, url, req)
      case 'projects': {
        if (seg.length === 1 && m === 'GET') return ok(db.projects)
        if (seg.length === 1 && m === 'POST') {
          const badProj = badName(String(body.metadata?.name ?? ''), 'project')
          if (badProj) return badProj
          if (db.projects.some((p) => p.metadata.name === body.metadata?.name)) return fail(409, { code: 'already_exists', message: `Project ${body.metadata.name} already exists.` })
          const spec = { ...body.spec }
          const held = heldNetwork(spec, '')
          if (held) return fail(409, { code: 'conflict', message: held })
          if (spec.new_network) { delete spec.new_network; spec.networks = [...(spec.networks ?? []), { network: String(body.metadata.name) }] }
          const created = d2.projects({})[0]
          created.metadata = { name: body.metadata.name, scope: 'host', generation: 1, created_at: new Date().toISOString() }
          created.spec = spec
          created.status = { jails: 0, cpu: 0, memory_used: 0, disk_used: 0, addresses: 0 }
          db.projects.push(created)
          emit('project-created', `/api/v1/projects/${body.metadata.name}`)
          return startOp(`Create project ${body.metadata.name}`, { projects: [] }, 500, () => undefined, undefined, false)
        }
        const p = db.projects.find((x) => x.metadata.name === name)
        if (!p) return fail(404, { code: 'not_found', message: `Project ${name} not found` })
        if (m === 'GET') return url.searchParams.get('host') === 'all' ? ok(d2.aggregate(p)) : ok(p, etagOf(p.metadata.generation))
        if (m === 'PUT') { const held = heldNetwork(body.spec, name); if (held) return fail(409, { code: 'conflict', message: held }); p.spec = body.spec; p.metadata.generation = (p.metadata.generation ?? 0) + 1; return startOp(`Save project ${name}`, {}, 400, () => undefined, undefined, false) }
        if (m === 'DELETE') {
          if ((countByProject()[name] ?? 0) > 0) return fail(409, { code: 'busy', message: `Project ${name} still holds jails.`, hint: 'Delete or move its jails first.' })
          return startOp(`Delete project ${name}`, {}, 400, () => { db.projects = db.projects.filter((x) => x !== p) }, undefined, false)
        }
        return undefined
      }
      case 'storage': {
        if (m === 'GET') return ok(db.storage)
        if (m === 'POST') {
          if (db.storage.some((x) => x.metadata.name === body.metadata?.name)) return fail(409, { code: 'already_exists', message: 'Storage exists.' })
          return startOp(`Create storage ${body.metadata.name}`, {}, 600, () => db.storage.push({ metadata: { name: body.metadata.name, scope: 'host', created_at: new Date().toISOString() }, spec: body.spec, status: { pool: String(body.spec.dataset).split('/')[0], health: 'ONLINE', size: 500 * GiB, used: 1 * GiB, available: 499 * GiB } }), undefined, false)
        }
        if (m === 'DELETE') {
          if (db.projects.some((p) => (p.spec.storage ?? []).some((g) => g.storage === name))) return fail(409, { code: 'busy', message: `Storage ${name} is granted to a project.`, hint: 'Remove the grant first.' })
          return startOp(`Delete storage ${name}`, {}, 400, () => { db.storage = db.storage.filter((x) => x.metadata.name !== name) }, undefined, false)
        }
        return undefined
      }
      case 'trust': {
        if (seg[1] === 'tokens' && m === 'POST') {
          if (!body.global && !(body.projects ?? []).length) return fail(400, { code: 'invalid', message: 'An identity needs projects or global.', hint: 'Choose at least one project, or set global.' })
          const exp = new Date(Date.now() + (body.ttl_seconds || 3600) * 1000).toISOString()
          return ok({ name: body.name, token: 'jbc_' + btoa(JSON.stringify({ v: 1, name: body.name, fp: 'ab12' })).replace(/=/g, '') + '.' + Array.from({ length: 24 }, () => 'abcdef0123456789'[Math.floor(Math.random() * 16)]).join(''), expires_at: exp }, undefined)
        }
        return undefined
      }
      case 'sessions': {
        if (m === 'GET') return ok(db.sessions)
        if (m === 'DELETE') { db.sessions = db.sessions.filter((x) => x.id !== name); return ok(null) }
        return undefined
      }
      case 'certificates': {
        const c = db.certs2.find((x) => x.metadata.name === name)
        if (m === 'GET' && seg.length === 1) return ok(db.certs2)
        if (!c) return fail(404, { code: 'not_found', message: 'Certificate not found' })
        if (m === 'GET') return ok(c, etagOf(c.metadata.generation))
        if (m === 'PUT') {
          if (!body.spec.global && !(body.spec.projects ?? []).length) return fail(400, { code: 'invalid', message: 'An identity needs projects or global.' })
          c.spec = body.spec
          return startOp(`Save ${name}`, {}, 300, () => undefined, undefined, false)
        }
        if (m === 'DELETE') return startOp(`Revoke ${name}`, {}, 300, () => { db.certs2 = db.certs2.filter((x) => x !== c) }, undefined, false)
        return undefined
      }
      case 'profiles': {
        const list = project === 'host' ? db.profiles.host : db.profiles.project
        if (m === 'GET') return ok(list)
        if (m === 'POST') {
          if (list.some((p) => p.metadata.name === body.metadata?.name)) return fail(409, { code: 'already_exists', message: 'Profile exists.' })
          list.push({ ...body, metadata: { ...body.metadata, project } } as never)
          return startOp(`Create profile ${body.metadata.name}`, {}, 300, () => undefined, undefined, false)
        }
        const p = list.find((x) => x.metadata.name === name)
        if (!p) return fail(404, { code: 'not_found', message: 'Profile not found' })
        if (m === 'PUT') { p.spec = body.spec; return startOp(`Save profile ${name}`, {}, 300, () => undefined, undefined, false) }
        if (m === 'DELETE') {
          if (db.jails.some((j) => (j.spec.profiles ?? []).includes(name))) return fail(409, { code: 'busy', message: `Profile ${name} is used by a jail.` })
          const i = list.indexOf(p); list.splice(i, 1)
          return startOp(`Delete profile ${name}`, {}, 300, () => undefined, undefined, false)
        }
        return undefined
      }
      case 'updates': {
        if (seg.length === 1 && m === 'GET') return ok(db.updates.filter((u) => u.project === project))
        if (seg[1] === 'check' && m === 'POST') {
          const names: string[] = body.all ? db.updates.filter((u) => u.project === project).map((u) => u.jail) : body.jails ?? []
          return startOp('Check updates', {}, 800, () => { for (const u of db.updates) if (names.includes(u.jail)) u.checked_at = new Date().toISOString() }, db.updates.filter((u) => names.includes(u.jail)), false)
        }
        if (seg[1] === 'apply' && m === 'POST') {
          const names: string[] = body.all ? db.updates.filter((u) => u.project === project && u.available).map((u) => u.jail) : body.jails ?? []
          const targets = db.updates.filter((u) => names.includes(u.jail))
          if (!targets.length || targets.every((u) => !u.available)) return fail(400, { code: 'invalid', message: 'There is nothing to apply.' })
          const recs: import('@jailops/shared/api/types').UpdateRecord[] = targets.filter((u) => u.available).map((u) => ({ id: 'u' + ++seq, jail: u.jail, project, kind: u.os ? 'os' : 'packages', result: 'ok', started: new Date().toISOString(), finished: new Date().toISOString(), snapshot: 'pre-update-' + Date.now().toString(36), packages: u.packages }))
          return startOp(`Update ${names.join(', ')}`, {}, 2500, () => {
            for (const r of recs) { (db.history[r.jail] ??= []).unshift(r); const u = db.updates.find((x) => x.jail === r.jail)!; u.available = false; u.packages = undefined; u.os = undefined }
            emit('update-applied', '/api/v1/updates')
          }, recs)
        }
        return undefined
      }
      case 'backup': {
        if (seg[1] !== 'key') return undefined
        if (seg[2] === 'escrow') { db.key.status = 'escrowed'; return ok({ ...db.key }) }
        if (m === 'GET') return ok({ ...db.key })
        if (db.key.status !== 'none') return fail(409, { code: 'already_exists', message: 'The host already has a backup key.' })
        db.key.status = (body.recipients ?? []).length ? 'escrowed' : 'present'
        return ok({ domain: db.key.domain, recovery_key: 'JORK-' + Array.from({ length: 6 }, () => Math.random().toString(36).slice(2, 7).toUpperCase()).join('-'), escrowed: db.key.status === 'escrowed' }, undefined)
      }
      case 'jails': {
        const j = db.jails.find((x) => x.metadata.name === name && (x.metadata.project ?? '') === project)
        if (!j || !seg[2]) return undefined
        const src = `/api/v1/jails/${name}`
        if (seg[2] === 'updates' && m === 'GET') return ok(db.history[name] ?? [])
        if (seg[2] === 'access') {
          if (!j.metadata.labels?.[da.LABEL]) return fail(400, { code: 'invalid', message: `jail "${name}" was not installed from the catalog (it has no label jailops.app)` })
          if (seg.length === 3 && m === 'GET') return ok(access.get(j))
          const r = seg.length === 3 && m === 'POST' ? access.allow(j, body as never) : seg[3] === 'deny' && m === 'POST' ? access.deny(j, body as never) : undefined
          if (!r) return undefined
          if ('ok' in r) return ok(r.ok)
          return fail(r.status, { code: r.code, message: r.message, hint: r.hint } as ApiErrorBody)
        }
        if (seg[2] === 'logs' && m === 'GET') {
          const app = j.metadata.labels?.[da.LABEL] ?? ''
          // A stopped jail's root is not mounted: the server answers busy and says how to mount it.
          if (j.status.power === 'stopped') return fail(409, { code: 'busy', message: `jail "${name}" is not mounted`, hint: `start the jail, or mount its root dataset on the host: zfs mount tank/jailops/${project}/${name}/root` })
          if (seg.length === 3) return ok(logs.list(name, app))
          const file = seg.slice(3).join('/')
          const r = logs.read(name, app, file, url.searchParams)
          if (r === 'missing') return fail(404, { code: 'not_found', message: `jail "${name}" has no log file "${file}"`, hint: `list them with GET /api/v1/jails/${name}/logs` })
          if (r === 'compressed') return fail(400, { code: 'invalid', message: `${file} is not readable (compressed)`, hint: 'read the plain rotated copies, or the file from inside the jail' })
          return ok(r)
        }
        if (seg[2] === 'provision' && m === 'POST') {
          if (j.status.provisioned_at && !body.again) return fail(409, { code: 'already_exists', message: 'Provisioning has run before.', hint: 'Use again to run it again.' })
          return startOp(`Provision ${name}`, { jails: [src] }, 1500, () => { j.status.provisioned_at = new Date().toISOString() }, { jail: name, provisioned_at: new Date().toISOString(), steps: ['packages', 'files', 'services'] })
        }
        if (seg[2] === 'shell-setup' && m === 'POST') {
          if (j.status.power !== 'running') return fail(409, { code: 'busy', message: `jail "${name}" is not running; the shell is set up inside it`, hint: 'start it first' })
          const had = bashReady.has(name)
          return startOp(`Set up the shell of jail ${name}`, { jails: [src] }, 1200, () => {
            if (!j.spec.shell) j.spec.shell = BASH
            if (!j.spec.prompt && j.spec.shell === BASH) j.spec.prompt = 'default'
            if (j.spec.shell === BASH) bashReady.add(name)
          }, { jail: name, shell: j.spec.shell || BASH, prompt: j.spec.prompt || 'default', ps1: '\\[\\e[38;5;39m\\]\\u@\\h:\\w\\$\\[\\e[0m\\] ', steps: [had ? `${BASH} is installed` : 'pkg -r ROOT install -y bash', 'wrote /usr/local/etc/profile.d/jailops-prompt.sh'] })
        }
        if (seg[2] === 'console') {
          if (m === 'POST' && seg.length === 3) {
            if (j.status.power !== 'running') return fail(409, { code: 'busy', message: `Jail ${name} is not running.` })
            const sh = (j.spec as unknown as { shell?: string }).shell
            if (sh === BASH && !bashReady.has(name)) return fail(404, { code: 'not_found', message: `the shell ${BASH} does not exist in jail "${name}"`, hint: `install it with \`jailops jail shell-setup ${name}\`, or use FreeBSD's own shell: \`jailops set ${name} shell sh\`` })
            if (sh && sh !== '/bin/sh' && sh !== BASH) return fail(404, { code: 'not_found', message: `The shell ${sh} does not exist in the jail.`, hint: 'Set a shell that exists, or clear the setting to use /bin/sh.' })
            const id = 'x' + ++seq
            shells.set(id, { h: undefined as never, line: '', jail: name })
            return ok({ id }, undefined)
          }
          const sess = shells.get(seg[3])
          if (!sess) return fail(404, { code: 'not_found', message: 'No such exec session.' })
          if (seg[4] === 'input') { shellInput(seg[3], String(body.data ?? '')); return ok(null) }
          if (seg[4] === 'resize') return ok(null)
          if (m === 'DELETE') { shells.delete(seg[3]); return ok(null) }
        }
        return undefined
      }
    }
    void req
    return undefined
  }

  function appsRoute(seg: string[], m: string, body: Record<string, any>, project: string): RawResponse {
    const name = seg[1]
    if (seg.length === 1 && m === 'GET') return ok(da.catalog())
    const det = name ? da.detail(name) : undefined
    if (det === 'invalid') return fail(400, { code: 'invalid', message: `app ${name} is invalid: ${da.invalidApp.error}`, hint: 'fix the file in the catalog directory, or reinstall the jailops-apps package', detail: { file: `/usr/local/share/jailops/apps/${name}.yaml` } })
    if (!det) return fail(404, { code: 'not_found', message: `app ${name} is not in the catalog`, hint: 'jailops app list shows the catalog' })
    if (seg.length === 2 && m === 'GET') return ok(det)
    if (seg[2] !== 'install' || m !== 'POST') return fail(404, { code: 'not_found', message: 'No such route' })
    if (!project) return fail(400, { code: 'invalid', message: 'a project is required', hint: "name one with --project NAME (list them with 'jailops project list')" })
    const p = db.projects.find((x) => x.metadata.name === project)
    if (!p) return fail(404, { code: 'not_found', message: `project ${project} not found` })
    if (body.project && body.project !== project) return fail(400, { code: 'invalid', message: `the body names project ${body.project}, the request ${project}` })
    const jail = String(body.jail || name)
    if (nameProblem(jail, 'jail')) return fail(400, { code: 'invalid', message: `jail name "${jail}" is not a name: ${nameProblem(jail, 'jail')}`, hint: 'lower-case letters, digits and dashes, starting with a letter, at most 32 characters' })
    if (db.jails.some((x) => x.metadata.name === jail && (x.metadata.project ?? '') === project)) return fail(409, { code: 'already_exists', message: `jail ${jail} exists in project ${project}`, hint: 'name the jail with --name, or delete the jail first' })
    const nets = (p.spec.networks ?? []).map((g) => g.network)
    const net = String(body.network || (nets.length === 1 ? nets[0] : ''))
    if (!net) return fail(400, { code: 'invalid', message: `no network named and project ${project} is granted ${nets.length ? 'several' : 'none'}`, hint: `jailops project show ${project} lists the grants` })
    if (!nets.includes(net)) return fail(403, { code: 'forbidden', message: `network ${net} is not granted to project ${project}`, hint: `jailops project show ${project} lists the grants` })
    const stoGrants = (p.spec.storage ?? []).map((g) => g.storage)
    const stos = stoGrants.includes('*') ? db.storage.map((x) => x.metadata.name) : stoGrants
    const sto = String(body.storage || (stos.length === 1 ? stos[0] : ''))
    if (!sto) return fail(400, { code: 'invalid', message: `no storage named and project ${project} is granted ${stos.length ? 'several' : 'none'}`, hint: `jailops project show ${project} lists the grants` })
    if (!stos.includes(sto)) return fail(403, { code: 'forbidden', message: `storage ${sto} is not granted to project ${project}`, hint: `jailops project show ${project} lists the grants` })
    const a = det.definition
    // without a name: the FreeBSD image of the newest release the host runs, as the server picks it
    const image = String(body.image || defaultImage(db.images, newRelease ? '15.2-RELEASE' : '15.1-RELEASE'))
    if (!image) return fail(400, { code: 'invalid', message: 'no image named, and there is no FreeBSD image yet', hint: "create the base image with 'jailops image create freebsd-15-1 --release 15.1-RELEASE', then build it with 'jailops image build freebsd-15-1' (the console's Images page does both with Create image)" })
    const steps = da.installSteps(a, jail, project, image)
    const subnet = db.networks.find((x) => x.metadata.name === net)?.spec.ipv4?.subnet ?? '10.20.0.0/24'
    const addr = subnet.replace(/\.\d+\/\d+$/, '') + '.' + (40 + db.jails.length)
    const limits = { memory: body.limits?.memory ?? a.resources?.memory, disk: body.limits?.disk ?? a.resources?.disk, cpu: Number(body.limits?.cpu ?? a.resources?.cpu ?? 1) }
    const version = a.packages[0]?.version ?? ''
    const src = `/api/v1/jails/${jail}`
    // the data are volumes of the project, <jail>-<name>, made before the jail and kept when it is deleted
    const appVolumes = (a.data ?? []).map((x) => ({ name: `${jail}-${volumeName(x.path)}`.slice(0, 32).replace(/-+$/, ''), mount: x.path }))
    const taken = appVolumes.find((x) => db.volumes.some((v) => v.metadata.name === x.name && (v.metadata.project ?? '') === project))
    if (taken) return fail(409, { code: 'already_exists', message: `volume "${taken.name}" already exists`, hint: `an earlier jail of this name left it: delete it with jailops volume delete ${taken.name}` })
    const j: Jail = {
      metadata: { name: jail, scope: 'host', project, generation: 1, created_at: new Date().toISOString(), labels: { [da.LABEL]: a.name, [`${da.LABEL}.hash`]: det.hash, [`${da.LABEL}.version`]: version } },
      spec: { image, storage: sto, layout: 'thin', network: [{ network: net, ipv4: addr }], volumes: appVolumes.map((x) => ({ volume: x.name, mount: x.mount })), resources: limits, boot: { autostart: true }, shell: BASH, prompt: 'default' },
      status: { power: 'running', jid: 120 + db.jails.length, generation: 'freebsd-15-1#g4', addresses: [`${addr}/${subnet.split('/')[1] ?? '24'}`], started_at: new Date().toISOString(), conditions: [{ type: 'Reconciled', status: 'True' }] },
    }
    bashReady.add(jail)
    const result = {
      app: a.name, hash: det.hash, version, jail: j, addresses: j.status.addresses, ports: (a.ports ?? []).map((x) => ({ ...x, endpoint: `${addr}:${x.port}` })),
      data: a.data, config: a.config, logs: a.logs, notes: a.notes, snapshot: 'app-installed', steps,
    }
    if (body.dry_run) return startOp(`Install app ${a.name} as jail ${jail} (dry run)`, {}, 300, () => undefined, { ...result, jail: { metadata: { name: jail }, spec: { image }, status: { power: 'stopped' } }, version: undefined, addresses: undefined, ports: undefined, snapshot: undefined, dry_run: true }, false)
    // A jail name that starts with "fail" makes the demo fail at the health check and keep the jail, stopped.
    if (jail.startsWith('fail')) {
      const r = startOp(`Install app ${a.name} as jail ${jail}`, { jails: [src] }, 3500, () => {
        j.status = { power: 'stopped', addresses: [], conditions: [{ type: 'Reconciled', status: 'True' }] }
        for (const x of appVolumes) db.volumes.push(newAppVolume(x.name, x.mount, project, a.name, jail))
        db.jails.push(j)
        emit('app.install.failed', src)
      }, undefined, false)
      const op = db.ops[0]
      op.failure = {
        code: 'internal', message: `installing app ${a.name} as jail ${jail} failed at step health-check: no answer within ${a.health?.wait_seconds ?? 60} attempts`,
        hint: `the jail was left stopped for inspection: look inside it with \`jailops shell ${jail}\` after \`jailops start ${jail}\`, and delete it with \`jailops delete ${jail}\` before trying again`,
        detail: { jail, step: 'health-check', jail_kept: 'true' },
      } as ApiErrorBody
      return r
    }
    return startOp(`Install app ${a.name} as jail ${jail}`, { jails: [src] }, 5000, () => {
      for (const x of appVolumes) db.volumes.push(newAppVolume(x.name, x.mount, project, a.name, jail))
      db.jails.push(j)
      access.install(jail)
      db.snaps[jail] = [{ metadata: { name: 'app-installed', scope: 'host', created_at: new Date().toISOString() }, spec: { jail, comment: `installation of ${a.name}` }, status: { written: 0 } }]
      for (const ev of ['jail-created', 'jail-started', 'jail-snapshot-created', 'app.installed']) emit(ev, src)
    }, result, false)
  }

  const PLAIN = '\x1b[32mroot@jail\x1b[0m:\x1b[34m~\x1b[0m# '
  /** What the demo shell shows: the default prompt of JailOps (38;5;39, light blue) in a jail with bash and it. */
  function promptOf(jail: string): string {
    const j = db.jails.find((x) => x.metadata.name === jail)
    return j?.spec.shell === BASH && bashReady.has(jail) && j.spec.prompt === 'default' ? `\x1b[38;5;39mroot@${jail}:/#\x1b[0m ` : PLAIN
  }
  function shellOut(id: string, text: string): void {
    const s = shells.get(id)
    if (!s?.h) return
    s.h.onEvent({ type: 'logging', timestamp: new Date().toISOString(), metadata: { data: btoa(text) } } as ApiEvent)
  }
  function shellInput(id: string, data: string): void {
    const s = shells.get(id)
    if (!s) return
    for (const ch of data) {
      if (ch === '\r') {
        const cmd = s.line.trim()
        s.line = ''
        let out = ''
        if (cmd === 'hostname') out = `${s.jail}.example.net`
        else if (cmd === 'uname -a') out = 'FreeBSD ' + s.jail + ' 15.1-RELEASE FreeBSD 15.1-RELEASE amd64'
        else if (cmd === 'ls') out = '\x1b[34mbin\x1b[0m  \x1b[34metc\x1b[0m  \x1b[34musr\x1b[0m  \x1b[34mvar\x1b[0m'
        else if (cmd.startsWith('echo ')) out = cmd.slice(5)
        else if (cmd === 'exit') { shellOut(id, '\r\nlogout\r\n'); s.h.onEvent({ type: 'logging', timestamp: new Date().toISOString(), metadata: { exit: 0 } } as ApiEvent); return }
        else if (cmd) out = `sh: ${cmd.split(' ')[0]}: not found`
        shellOut(id, '\r\n' + (out ? out + '\r\n' : '') + promptOf(s.jail))
      } else if (ch === '\x7f') {
        if (s.line) { s.line = s.line.slice(0, -1); shellOut(id, '\b \b') }
      } else if (ch >= ' ') {
        s.line += ch
        shellOut(id, ch)
      }
    }
  }

  return {
    request: (req) => route(req),
    stream(path: string, h: StreamHandlers): EventStream {
      const ex = /\/console\/([^/?]+)\/output/.exec(path)
      if (ex) {
        const sess = shells.get(ex[1])
        if (sess) {
          sess.h = h
          const t = setTimeout(() => { h.onOpen?.(); shellOut(ex[1], 'JailOps demo shell. Try: hostname, uname -a, ls, echo hi, exit\r\n' + promptOf(sess.jail)) }, 0)
          return { close: () => { clearTimeout(t); shells.delete(ex[1]) } }
        }
      }
      subs.add(h)
      const t = setTimeout(() => h.onOpen?.(), 0)
      const tick = setInterval(() => {
        const e: ApiEvent = { type: 'logging', timestamp: new Date().toISOString(), metadata: { message: 'reconcile: 7 jails observed, 1 drifted' } }
        h.onEvent(e)
      }, 20_000)
      return { close: () => { clearTimeout(t); clearInterval(tick); subs.delete(h) } }
    },
  }
}
