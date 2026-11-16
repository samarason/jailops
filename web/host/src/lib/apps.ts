// The catalog pages' pure parts: search and categories, the install form, the step list of an
// installation, the jails that came from the catalog and the links to their web ports.
import { nameRules, validName, validSize } from '@jailops/shared/lib/names'
import { AppCategoryValues } from '@jailops/shared/api/types'
import type { AppCategory, AppInstall, AppPort, AppResources, AppSummary, Jail, Project } from '@jailops/shared/api/types'

/** Labels the installation sets on the jail (docs/apps.md). */
export const LABEL_APP = 'jailops.app'
export const LABEL_VERSION = 'jailops.app.version'
export const LABEL_HASH = 'jailops.app.hash'
/** The snapshot an installation ends with: the point to roll back to. */
export const INSTALL_SNAPSHOT = 'app-installed'

export function matchesApp(a: AppSummary, q: string): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  return [a.name, a.title ?? '', a.summary ?? ''].some((h) => h.toLowerCase().includes(needle))
}

/** The apps that match the search and the category ('' is every category), valid ones first, then by title. */
export function searchApps(list: AppSummary[], q: string, category = ''): AppSummary[] {
  return list
    .filter((a) => matchesApp(a, q) && (!category || a.category === category))
    .sort((a, b) => Number(b.valid) - Number(a.valid) || (a.title || a.name).localeCompare(b.title || b.name))
}

/** Category chips: how many apps of each category match the search, in the catalog's category order, empty ones left out. */
export function categoryCounts(list: AppSummary[], q: string): Array<{ category: AppCategory; count: number }> {
  const hits = list.filter((a) => matchesApp(a, q))
  return AppCategoryValues.map((category) => ({ category, count: hits.filter((a) => a.category === category).length })).filter((c) => c.count > 0)
}

/** A stable monogram for an app without an icon: two letters and a hue derived from the name. */
export function monogram(name: string, title = ''): { text: string; hue: number } {
  const words = (title || name).split(/[\s-]+/).filter(Boolean)
  const text = (words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2)).toUpperCase()
  let h = 0
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return { text, hue: h % 360 }
}

/** Plain text of a definition (description, notes) as paragraphs: blank lines separate them, single line breaks are wrapping. */
export function paragraphs(text: string | undefined): string[] {
  return (text ?? '').split(/\n\s*\n/).map((p) => p.replace(/\s*\n\s*/g, ' ').trim()).filter(Boolean)
}

/** A jail name as the server checks it on an installation: the shared object name rule. */
export const JAIL_NAME = nameRules.jail.re

/** The install form; image is a plain image name ('' leaves the choice to the server). */
export interface InstallForm { jail: string; image: string; network: string; storage: string; memory: string; disk: string; cpu: string }
export type InstallIssue = 'nameInvalid' | 'nameTaken' | 'needNetwork' | 'needStorage' | 'sizeInvalid' | 'cpuInvalid'

/** Field -> problem. Empty when the form may be sent. */
export function validateInstall(f: InstallForm, ctx: { networks: string[]; storage: string[]; taken: string[] }): Partial<Record<keyof InstallForm, InstallIssue>> {
  const out: Partial<Record<keyof InstallForm, InstallIssue>> = {}
  if (!validName(f.jail, 'jail')) out.jail = 'nameInvalid'
  else if (ctx.taken.includes(f.jail)) out.jail = 'nameTaken'
  if (ctx.networks.length && !ctx.networks.includes(f.network)) out.network = 'needNetwork'
  if (ctx.storage.length && !ctx.storage.includes(f.storage)) out.storage = 'needStorage'
  if (f.memory && !validSize(f.memory)) out.memory = 'sizeInvalid'
  if (f.disk && !validSize(f.disk)) out.disk = 'sizeInvalid'
  if (f.cpu && !(Number(f.cpu) > 0)) out.cpu = 'cpuInvalid'
  return out
}

/** The form prefilled for an app: its name as the jail, the only grant of each kind, the resource hints. */
export function initialForm(app: string, hints: AppResources | undefined, networks: string[], storage: string[]): InstallForm {
  return {
    jail: app, image: '', network: networks.length === 1 ? networks[0] : '', storage: storage.length === 1 ? storage[0] : '',
    memory: hints?.memory ?? '', disk: hints?.disk ?? '', cpu: hints?.cpu ?? '',
  }
}

/** The request body. Limits are sent only when they differ from the hints, which the server applies anyway. */
export function installBody(f: InstallForm, hints: AppResources | undefined, dryRun = false): AppInstall {
  const b: AppInstall = { jail: f.jail }
  if (f.image) b.image = f.image
  if (f.network) b.network = f.network
  if (f.storage) b.storage = f.storage
  const changed = (f.memory || '') !== (hints?.memory ?? '') || (f.disk || '') !== (hints?.disk ?? '') || (f.cpu || '') !== (hints?.cpu ?? '')
  if (changed) {
    b.limits = {}
    if (f.memory) b.limits.memory = f.memory.trim()
    if (f.disk) b.limits.disk = f.disk.trim()
    if (f.cpu) b.limits.cpu = Number(f.cpu)
  }
  if (dryRun) b.dry_run = true
  return b
}

/** The networks and storage granted to a project. A storage grant of "*" is every storage of the host. */
export function grants(p: Project | undefined, allStorage: string[]): { networks: string[]; storage: string[] } {
  const networks = (p?.spec.networks ?? []).map((g) => g.network)
  const sto = (p?.spec.storage ?? []).map((g) => g.storage)
  return { networks, storage: sto.includes('*') ? allStorage : sto }
}

/** One step of the plan as the server describes it: "03 install-packages-ports: pkg -r ...". */
export interface Step { n: number; name: string; text: string }
export function parseStep(line: string): Step {
  const m = /^(\d+)\s+([^:\s]+):\s?(.*)$/.exec(line)
  return m ? { n: Number(m[1]), name: m[2], text: m[3] } : { n: 0, name: '', text: line }
}

/**
 * Steps finished, from the operation's progress: the server sets it to (steps done) * 100 / (steps) after every
 * step, capped at 99 until the operation ends, so the count is recovered exactly for plans under 100 steps.
 */
export function stepsDone(progress: number | undefined, total: number, finished = false): number {
  if (finished) return total
  if (!total || !progress) return 0
  return Math.min(total, Math.ceil((progress * total) / 100 - 1e-9))
}

export type StepState = 'done' | 'running' | 'pending' | 'failed'
/** The state of step i. A failure names its step (detail.step); without it the step after the last finished one failed. */
export function stepState(i: number, steps: Step[], done: number, status: 'running' | 'success' | 'failure', failedStep = ''): StepState {
  if (status === 'success') return 'done'
  if (status === 'failure') {
    const at = failedStep ? steps.findIndex((s) => s.name === failedStep) : done
    const f = at < 0 ? done : at
    return i < f ? 'done' : i === f ? 'failed' : 'pending'
  }
  return i < done ? 'done' : i === done ? 'running' : 'pending'
}

/** The volume name the installation gives a data path: /var/db/postgres becomes var-db-postgres. */
export function volumeName(path: string): string {
  return path.split('/').filter(Boolean).join('-')
}

/** The jails of a list that came from the catalog, optionally of one app, by name. */
export function installedJails(jails: Jail[], app = ''): Jail[] {
  return jails
    .filter((j) => {
      const v = j.metadata.labels?.[LABEL_APP]
      return !!v && (!app || v === app)
    })
    .sort((a, b) => a.metadata.name.localeCompare(b.metadata.name))
}

/** Ports that serve a web page. The definition has no marker for it, so the port's name decides: http or https over tcp. */
export function webPorts(ports: AppPort[] | undefined): AppPort[] {
  return (ports ?? []).filter((p) => p.proto === 'tcp' && (p.name === 'http' || p.name === 'https'))
}

/** "Open" links of a running jail: its first address with each exposed web port. */
export function openLinks(jail: Jail, ports: AppPort[] | undefined): Array<{ port: AppPort; url: string }> {
  const first = jail.status.power === 'running' ? (jail.status.addresses ?? [])[0] : undefined
  if (!first) return []
  const ip = first.split('/')[0]
  const host = ip.includes(':') ? `[${ip}]` : ip
  return webPorts(ports)
    .filter((p) => p.expose)
    .map((p) => {
      const tls = p.name === 'https'
      const dflt = tls ? 443 : 80
      return { port: p, url: `${tls ? 'https' : 'http'}://${host}${p.port === dflt ? '' : `:${p.port}`}/` }
    })
}

export type InstallBlock = '' | 'noExtension' | 'noProject' | 'role' | 'scope' | 'noNetwork' | 'noStorage'

/**
 * Why the caller cannot install, or '' when the console should offer it. The server decides: an unknown role
 * (a token without a session) may try, and the grants are checked only when the project is known.
 */
export function installBlock(o: { ext: boolean; needProject: boolean; project: string; role: string; global: boolean; scopes: string[]; known: boolean; networks: string[]; storage: string[] }): InstallBlock {
  if (!o.ext) return 'noExtension'
  if (o.needProject && !o.project) return 'noProject'
  if (o.role && o.role !== 'operator' && o.role !== 'admin') return 'role'
  if (o.role && !o.global && o.project && !o.scopes.includes(o.project)) return 'scope'
  if (o.known && !o.networks.length) return 'noNetwork'
  if (o.known && !o.storage.length) return 'noStorage'
  return ''
}

/** A part of a note line: plain words or a command. */
export interface NotePart { code: boolean; text: string }
/** A block of a note: a paragraph (or list item) of parts, or lines to copy as they are. */
export type NoteBlock = { kind: 'p'; parts: NotePart[] } | { kind: 'pre'; text: string }

const CMD = /^(jailops|service|sysrc|pkg|postconf|postfix|pw|passwd|su|env|sed|openssl|nsd-checkconf|psql|ssh-keygen|CREATE|ALTER|GRANT|DROP)\b/

/** Inline commands of a prose line: a quoted command ('service nginx reload') or a command after a colon. */
function inline(line: string): NotePart[] {
  const out: NotePart[] = []
  const push = (code: boolean, text: string) => { if (text) out.push({ code, text }) }
  const colon = /^(.*?:\s+)(\S.*)$/.exec(line)
  if (colon && CMD.test(colon[2]) && !colon[2].includes(', ')) {
    push(false, colon[1])
    push(true, colon[2])
    return out
  }
  // a quoted command, or "jailops <verb> <ARG>" inside a sentence
  const re = /'([^']*\s[^']*)'|\b(jailops(?: [a-z][a-z-]*){1,2}(?: [A-Z][A-Z_]*)?)/
  let rest = line
  for (let m = re.exec(rest); m; m = re.exec(rest)) {
    push(false, rest.slice(0, m.index))
    push(true, m[1] ?? m[2])
    rest = rest.slice(m.index + m[0].length)
  }
  push(false, rest)
  return out
}

/**
 * The notes of a definition laid out for reading: blank lines separate paragraphs, "- " and "1. " start list items,
 * indented lines after a line that ends with a colon (and SQL or shell lines) are kept as code, and commands inside
 * a sentence are marked as code instead of running into the prose.
 */
export function noteBlocks(text: string | undefined): NoteBlock[] {
  const out: NoteBlock[] = []
  let para: NotePart[] | null = null
  let pre: string[] | null = null
  let prevColon = false
  const flushP = () => { if (para?.length) out.push({ kind: 'p', parts: para }); para = null }
  const flushPre = () => { if (pre?.length) out.push({ kind: 'pre', text: pre.join('\n') }); pre = null }
  for (const raw of (text ?? '').split('\n')) {
    const line = raw.replace(/\s+$/, '')
    const indented = /^\s{2,}\S/.test(line)
    const t = line.trim()
    if (!t) { flushP(); flushPre(); prevColon = false; continue }
    if (indented && (prevColon || pre || CMD.test(t))) {
      flushP()
      ;(pre ??= []).push(t)
      continue
    }
    flushPre()
    const item = /^(- |\d+\.\s)(.*)$/.exec(t)
    if (item) flushP()
    // a list item that is one command ("6. service isms start") ends there
    if (item && CMD.test(item[2]) && !item[2].includes(', ')) {
      out.push({ kind: 'p', parts: [{ code: false, text: item[1] }, { code: true, text: item[2] }] })
      prevColon = false
      continue
    }
    const parts = inline(t)
    if (para) {
      const last = para[para.length - 1]
      if (last && !last.code && parts[0] && !parts[0].code) { last.text += ' ' + parts[0].text; para.push(...parts.slice(1)) }
      else para.push({ code: false, text: ' ' }, ...parts)
    } else para = parts
    prevColon = t.endsWith(':')
  }
  flushP()
  flushPre()
  return out
}
