// Demo of GET /logs (many jails merged by time) and of /logs/forward (the sinks and their state). The merge
// follows the server: every source keeps its own order, the newest 2000 lines are kept, and every source reports
// where it continues; a stopped jail answers as one that is not mounted.
import type { ApiErrorBody, Jail, LogEntry, LogForward, LogForwardSpec, LogForwardTestResult, LogSink, LogSinkStatus, LogSource, LogsRead } from '@jailops/shared/api/types'
import type { DemoRead } from './apps'
import { LABEL } from './apps'

const MAX_SOURCES = 50
const MAX_LINES = 2000

interface Reader {
  list(jail: string, app: string): Array<{ name: string; kind: string; compressed?: boolean }>
  entries(jail: string, app: string, file: string, q: URLSearchParams): DemoRead | 'missing' | 'compressed'
}

export type DemoReply = { ok: unknown; etag?: string } | { status: number; error: ApiErrorBody }

/** GET /logs: the jails the query selects, their files read like the per-jail route, merged by time. */
export function unifiedRead(jails: Jail[], logs: Reader, q: URLSearchParams): DemoReply {
  const all = q.get('all_projects') === 'true'
  const project = q.get('project') ?? ''
  if (!all && !project) return { status: 400, error: { code: 'invalid', message: 'a project is required', hint: 'name one with ?project=, or ask for all_projects=true' } }
  const names = q.getAll('jail')
  const labels = q.getAll('label').map((l) => l.split('='))
  const app = q.get('app') ?? ''
  const file = q.get('file') || 'messages'
  let cursor: Record<string, number> = {}
  try { cursor = JSON.parse(q.get('cursor') || '{}') } catch { return { status: 400, error: { code: 'invalid', message: 'cursor is the next map of a previous reply, as JSON' } } }
  const chosen = jails
    .filter((j) => all || (j.metadata.project ?? '') === project)
    .filter((j) => !names.length || names.includes(j.metadata.name))
    .filter((j) => labels.every(([k, v]) => j.metadata.labels?.[k] === v))
    .filter((j) => !app || j.metadata.labels?.[LABEL] === app)
    .sort((a, b) => `${a.metadata.project}/${a.metadata.name}`.localeCompare(`${b.metadata.project}/${b.metadata.name}`))
  const pairs: Array<{ j: Jail; app: string; file: string }> = []
  for (const j of chosen) {
    const a = j.metadata.labels?.[LABEL] ?? ''
    pairs.push({ j, app: a, file })
    // the logs an installed app declares below /var/log: the demo's apps keep them in a directory of their own
    if (q.get('app_logs') === 'true' && a && j.status.power !== 'stopped') for (const f of logs.list(j.metadata.name, a)) if (f.kind === 'active' && f.name.includes('/') && f.name !== file) pairs.push({ j, app: a, file: f.name })
  }
  const truncatedSources = pairs.length > MAX_SOURCES
  const sources: LogSource[] = []
  const next: Record<string, number> = {}
  const merged: Array<{ ts: number; src: number; i: number; e: LogEntry }> = []
  for (const [idx, p] of pairs.slice(0, MAX_SOURCES).entries()) {
    const name = p.j.metadata.name
    const proj = p.j.metadata.project ?? ''
    const key = `${proj}/${name}/${p.file}`
    const src: LogSource = { key, project: proj, jail: name, file: p.file, next_offset: 0, ...(p.app ? { app: p.app } : {}) }
    sources.push(src)
    if (p.j.status.power === 'stopped') {
      src.error = { code: 'busy', message: `jail "${name}" is not mounted`, hint: `start the jail, or mount its root dataset on the host: zfs mount tank/jailops/${proj}/${name}/root` }
      continue
    }
    const rq = new URLSearchParams()
    for (const k of ['since', 'grep', 'tail']) if (q.get(k)) rq.set(k, q.get(k)!)
    if (cursor[key] !== undefined) rq.set('offset', String(cursor[key]))
    const r = logs.entries(name, p.app, p.file, rq)
    if (r === 'missing') { src.error = { code: 'not_found', message: `jail "${name}" has no log file "${p.file}"` }; continue }
    if (r === 'compressed') { src.error = { code: 'invalid', message: `${p.file} is not readable (compressed)` }; continue }
    src.next_offset = next[key] = r.next_offset
    if (r.rotated) src.rotated = true
    if (r.truncated) src.truncated = true
    r.entries.forEach((l, i) => {
      // a line that starts with blanks carries no time of its own, as the server reads it
      const own = !/^\s/.test(l.text)
      merged.push({ ts: l.ts, src: idx, i, e: { project: proj, jail: name, file: p.file, line: l.text, ...(p.app ? { app: p.app } : {}), ...(own ? { time: new Date(l.ts).toISOString() } : {}) } })
    })
  }
  merged.sort((a, b) => a.ts - b.ts || a.src - b.src || a.i - b.i)
  const cut = Math.max(0, merged.length - MAX_LINES)
  const out: LogsRead = { lines: merged.slice(cut).map((m) => m.e), sources, next }
  if (cut || truncatedSources || sources.some((x) => x.truncated && !cursor[x.key])) out.truncated = true
  return { ok: out }
}

// ---- forwarding ----------------------------------------------------------------------------------------

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString()

function fileSinks(): LogSink[] {
  return [
    { name: 'central', type: 'syslog', to: 'tls://logs.example.com:6514', facility: 'local3', ca_file: '/usr/local/etc/jailops/sinks/logs-ca.pem', sources: { audit: true } },
    { name: 'alerts', type: 'webhook', to: 'https://hooks.example.com/jailops/logs', token_file: '/usr/local/etc/jailops/sinks/hook.token', queue: 2000, sources: { labels: { role: 'web' }, no_app_logs: true } },
  ]
}

function plaintext(k: LogSink): boolean {
  const m = /^(udp|tcp):\/\/(\[[^\]]+\]|[^:/]+)/.exec(k.to)
  if (k.type !== 'syslog' || !m) return false
  const h = m[2].replace(/^\[|\]$/g, '')
  return !(h === 'localhost' || h === '::1' || h.startsWith('127.'))
}

/** The demo's forwarder: the file's list, a stored list that replaces it, and a state per sink. */
export function demoForward(hostname: string) {
  const state = { spec: { sinks: fileSinks() } as LogForwardSpec, origin: 'config', generation: 0, updated: '' }
  const stats = new Map<string, LogSinkStatus>()
  const statusOf = (k: LogSink): LogSinkStatus => {
    let st = stats.get(k.name)
    if (!st) {
      st = { name: k.name, type: k.type, to: k.to, sources: 0, sent: 0, queued: 0, dropped: 0 }
      if (k.name === 'central') Object.assign(st, { sources: 9, sent: 18234, last_success: ago(4) })
      else if (k.name === 'alerts') Object.assign(st, { sources: 3, sent: 912, queued: 2000, dropped: 341, skipped_bytes: 0, last_success: ago(3600), failing_since: ago(720), last_error: 'POST https://hooks.example.com/jailops/logs: 503 Service Unavailable' })
      else st.sources = k.sources?.no_jails ? 1 : 7
      stats.set(k.name, st)
    }
    st.type = k.type
    st.to = k.to
    if (plaintext(k)) st.warning = 'plain syslog to a remote address: the lines cross the network in the clear'
    else delete st.warning
    return st
  }
  const view = (): LogForward => ({
    kind: 'LogForward', spec: structuredClone(state.spec),
    status: { origin: state.origin, generation: state.generation, ...(state.updated ? { updated_at: state.updated } : {}), sinks: state.spec.sinks.map(statusOf) },
  })
  const etag = () => `"${state.generation}"`
  const bad = (message: string, hint?: string): DemoReply => ({ status: 400, error: { code: 'invalid', message, ...(hint ? { hint } : {}) } })

  function validate(spec: LogForwardSpec): DemoReply | undefined {
    const seen = new Set<string>()
    for (const k of spec.sinks ?? []) {
      if (!/^[a-z][a-z0-9-]{0,31}$/.test(k.name ?? '')) return bad(`sink name "${k.name}" must match ^[a-z][a-z0-9-]{0,31}$`)
      if (seen.has(k.name)) return bad(`sink "${k.name}" is listed twice`)
      seen.add(k.name)
      const sch = /^([a-z]+):\/\/[^/]/.exec(k.to ?? '')?.[1]
      if (k.type === 'syslog' && !['udp', 'tcp', 'tls'].includes(sch ?? '')) return bad(`sink "${k.name}": a syslog sink is udp://, tcp:// or tls://HOST[:PORT], not "${k.to}"`)
      if (k.type === 'webhook' && sch !== 'https') return bad(`sink "${k.name}": a webhook is an https:// URL`, 'plain http would send the logs and the token in the clear')
      for (const p of [k.ca_file, k.token_file]) if (p && !p.startsWith('/')) return bad(`sink "${k.name}": "${p}" must be a clean absolute path`)
      if (k.token_file && !k.token_file.startsWith('/usr/local/etc/')) return bad(`sink "${k.name}": token file ${k.token_file} does not exist`, 'create it as root with mode 0600, or 0640 with group jailops; its first line is the token')
    }
    return undefined
  }

  return {
    get(): DemoReply { return { ok: view(), etag: etag() } },
    put(body: LogForwardSpec, ifMatch?: string): DemoReply {
      if (ifMatch && ifMatch !== etag()) return { status: 412, error: { code: 'conflict', message: `the sink list changed: current generation is ${state.generation}`, hint: 'read it again and re-apply your change' } }
      const v = validate(body)
      if (v) return v
      for (const name of [...stats.keys()]) if (!body.sinks.some((k) => k.name === name)) stats.delete(name)
      state.spec = structuredClone({ sinks: body.sinks ?? [] })
      state.origin = 'api'
      state.generation++
      state.updated = new Date().toISOString()
      return { ok: view(), etag: etag() }
    },
    reset(): DemoReply {
      state.spec = { sinks: fileSinks() }
      state.origin = 'config'
      state.generation = 0
      state.updated = ''
      return { ok: view(), etag: etag() }
    },
    test(sink: string): DemoReply {
      const k = state.spec.sinks.find((x) => x.name === sink)
      if (!k) return { status: 404, error: { code: 'not_found', message: `sink "${sink}" not found` } }
      const line = `jailops test line from ${hostname} to sink ${sink}`
      const failing = k.to.includes('hooks.example.com')
      const r: LogForwardTestResult = { sink, ok: !failing, line, millis: failing ? 10003 : 38 }
      if (failing) r.error = 'POST https://hooks.example.com/jailops/logs: 503 Service Unavailable'
      return { ok: r }
    },
  }
}
