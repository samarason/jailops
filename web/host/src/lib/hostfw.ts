// The host firewall form: validation that mirrors sdk/api/hostfw.go (the server and the helper check again), the
// spec it sends, and the countdown of a change that waits for its confirmation.
import type { HostFirewall, HostFirewallSpec, HostPendingChange } from '@jailops/shared/api/types'
import { ipv4, ipv6Groups, type FieldError } from './host'
import { NAME_PATTERN } from '@jailops/shared/lib/names'

export const TEMPLATES = ['default', 'custom-rules', 'open'] as const
export const MAX_ALLOW = 64
export const MAX_SETS = 16
export const MAX_SET_MEMBERS = 256
export const MAX_SOURCES = 32
export const MAX_PORTS = 16
export const MAX_COMMENT = 80
export const MAX_SSH_PORTS = 4
export const DEFAULT_CONFIRM = 120
export const MIN_CONFIRM = 10
export const MAX_CONFIRM = 1800

export interface FwRow { proto: string; ports: string; from: string; comment: string }
export interface FwSet { name: string; members: string }
export interface FwForm {
  template: string
  sshPorts: string
  sshFrom: string
  consoleFrom: string
  icmp: boolean
  logging: boolean
  allow: FwRow[]
  sets: FwSet[]
}

/** The entries of a list typed with commas or spaces between them. */
export const words = (s: string): string[] => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

interface Prefix { v6: boolean; bits: number; bytes: number[] }

function addrBytes(s: string): { v6: boolean; bytes: number[] } | null {
  if (ipv4(s)) return { v6: false, bytes: s.split('.').map(Number) }
  const g = ipv6Groups(s)
  if (!g) return null
  return { v6: true, bytes: g.flatMap((x) => [x >> 8, x & 255]) }
}
const mapped = (b: number[]) => b.slice(0, 10).every((x) => x === 0) && b[10] === 255 && b[11] === 255

/** An address or a prefix without host bits; the error says why not. */
export function parsePrefix(s: string): { p?: Prefix; error?: string } {
  const bad = { error: `${s} is not an address or a prefix.` }
  const [a, len, more] = s.split('/')
  if (more !== undefined) return bad
  const ab = addrBytes(a)
  if (!ab || (ab.v6 && mapped(ab.bytes))) return bad
  const max = ab.v6 ? 128 : 32
  if (len === undefined) {
    if (ab.bytes.every((x) => x === 0)) return bad
    return { p: { v6: ab.v6, bits: max, bytes: ab.bytes } }
  }
  if (!/^(0|[1-9][0-9]{0,2})$/.test(len) || Number(len) > max) return bad
  const bits = Number(len)
  for (let i = 0; i < ab.bytes.length; i++) {
    const keep = Math.max(0, Math.min(8, bits - i * 8))
    if ((ab.bytes[i] & (0xff >> keep)) !== 0) return { error: `${s} has host bits set.` }
  }
  return { p: { v6: ab.v6, bits, bytes: ab.bytes } }
}

/** A set name of the host firewall: the name rule, at most 24 characters (its pf table is jo_hf_ and the name). */
const SET_NAME = { test: (v: string) => v.length <= 24 && NAME_PATTERN.test(v) }

/** A port or a range N-M with 1 <= N < M <= 65535. */
export function validPort(p: string): boolean {
  const m = /^([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?$/.exec(p)
  if (!m) return false
  const lo = Number(m[1])
  const hi = m[2] === undefined ? lo : Number(m[2])
  return lo <= 65535 && hi <= 65535 && (m[2] === undefined || hi > lo)
}

/** A comment: at most 80 characters, no line breaks or other control characters, no quotes or backslashes. */
export function commentError(c: string): string | undefined {
  if ([...c].length > MAX_COMMENT) return `At most ${MAX_COMMENT} characters.`
  if (/[\u0000-\u001f\u007f-\u009f"'`\\]/.test(c)) return 'Line breaks, quotes and backslashes are not allowed.'
  return undefined
}

function sourceErrors(list: string[], sets: string[], field: string, out: FieldError[]): void {
  if (list.length > MAX_SOURCES) out.push({ field, message: `At most ${MAX_SOURCES} sources.` })
  const seen = new Set<string>()
  for (const v of list) {
    let key = v
    if (v.startsWith('@')) {
      if (!SET_NAME.test(v.slice(1))) { out.push({ field, message: `${v} is not a set name.` }); return }
      if (!sets.includes(v.slice(1))) { out.push({ field, message: `Set ${v} is not defined.` }); return }
    } else {
      const r = parsePrefix(v)
      if (!r.p) { out.push({ field, message: r.error! }); return }
      key = `${r.p.bytes.join('.')}/${r.p.bits}`
    }
    if (seen.has(key)) { out.push({ field, message: `${v} is listed twice.` }); return }
    seen.add(key)
  }
}

/** Every problem of the form; empty when it may be sent. */
export function validateFw(f: FwForm): FieldError[] {
  const out: FieldError[] = []
  if (!(TEMPLATES as readonly string[]).includes(f.template)) out.push({ field: 'template', message: 'Choose default, custom-rules or open.' })
  const setNames: string[] = []
  if (f.sets.length > MAX_SETS) out.push({ field: 'sets', message: `At most ${MAX_SETS} sets.` })
  f.sets.forEach((s, i) => {
    const name = s.name.trim()
    if (!SET_NAME.test(name)) out.push({ field: `set-${i}-name`, message: 'Lowercase letters, digits and hyphens, starting with a letter, not ending in a hyphen, at most 24 characters.' })
    else if (setNames.includes(name)) out.push({ field: `set-${i}-name`, message: `Set ${name} is defined twice.` })
    setNames.push(name)
    const m = words(s.members)
    if (m.length === 0 || m.length > MAX_SET_MEMBERS) { out.push({ field: `set-${i}-members`, message: `Give 1 to ${MAX_SET_MEMBERS} addresses or prefixes.` }); return }
    const seen = new Set<string>()
    for (const v of m) {
      const r = parsePrefix(v)
      if (!r.p) { out.push({ field: `set-${i}-members`, message: r.error! }); return }
      const key = `${r.p.bytes.join('.')}/${r.p.bits}`
      if (seen.has(key)) { out.push({ field: `set-${i}-members`, message: `${v} is listed twice.` }); return }
      seen.add(key)
    }
  })
  const ports = words(f.sshPorts)
  if (ports.length > MAX_SSH_PORTS) out.push({ field: 'ssh-ports', message: `At most ${MAX_SSH_PORTS} ssh ports.` })
  else if (ports.some((p) => !/^[1-9][0-9]{0,4}$/.test(p) || Number(p) > 65535)) out.push({ field: 'ssh-ports', message: 'Ports are numbers from 1 to 65535.' })
  else if (new Set(ports.map(Number)).size !== ports.length) out.push({ field: 'ssh-ports', message: 'A port is listed twice.' })
  sourceErrors(words(f.sshFrom), setNames, 'ssh-from', out)
  sourceErrors(words(f.consoleFrom), setNames, 'console-from', out)
  if (f.template === 'open' && (words(f.sshFrom).length || words(f.consoleFrom).length)) {
    out.push({ field: 'template', message: 'The open template passes everything: ssh and console sources would have no effect.' })
  }
  if (f.allow.length > 0 && f.template !== 'custom-rules') out.push({ field: 'allow', message: 'Allow rows need the custom-rules template.' })
  if (f.allow.length > MAX_ALLOW) out.push({ field: 'allow', message: `At most ${MAX_ALLOW} allow rows.` })
  f.allow.forEach((r, i) => {
    if (r.proto !== 'tcp' && r.proto !== 'udp') out.push({ field: `allow-${i}-proto`, message: 'tcp or udp.' })
    const p = words(r.ports)
    if (p.length === 0 || p.length > MAX_PORTS) out.push({ field: `allow-${i}-ports`, message: `Give 1 to ${MAX_PORTS} ports.` })
    else if (p.some((x) => !validPort(x))) out.push({ field: `allow-${i}-ports`, message: `${p.find((x) => !validPort(x))} is not a port (1-65535) or a range such as 8000-8100.` })
    else if (new Set(p).size !== p.length) out.push({ field: `allow-${i}-ports`, message: 'A port is listed twice.' })
    sourceErrors(words(r.from), setNames, `allow-${i}-from`, out)
    const ce = commentError(r.comment.trim())
    if (ce) out.push({ field: `allow-${i}-comment`, message: ce })
  })
  return out
}

/** The form filled from the spec the server shows (the last applied one, or the default). */
export function fwFormOf(h: HostFirewall): FwForm {
  const s = h.spec
  return {
    template: s.template || 'default',
    sshPorts: (s.ssh?.ports?.length ? s.ssh.ports : [22]).join(', '),
    sshFrom: (s.ssh?.allow_from ?? []).join(', '),
    consoleFrom: (s.console?.allow_from ?? []).join(', '),
    icmp: s.icmp,
    logging: !!s.logging,
    allow: (s.allow ?? []).map((a) => ({ proto: a.proto, ports: a.ports.join(', '), from: (a.from ?? []).join(', '), comment: a.comment ?? '' })),
    sets: (s.sets ?? []).map((x) => ({ name: x.name, members: x.members.join(', ') })),
  }
}

const opt = <K extends string>(k: K, l: string[]) => (l.length ? { [k]: l } : {}) as Partial<Record<K, string[]>>

/** The whole spec of the form (the firewall is one file and is applied whole). */
export function fwSpecOf(f: FwForm, consolePort: number): HostFirewallSpec {
  const allow = f.template === 'custom-rules' ? f.allow : []
  return {
    template: f.template,
    ssh: { ports: words(f.sshPorts).map(Number), ...opt('allow_from', words(f.sshFrom)) },
    console: { ...(consolePort ? { port: consolePort } : {}), ...opt('allow_from', words(f.consoleFrom)) },
    ...(allow.length ? { allow: allow.map((r) => ({ proto: r.proto, ports: words(r.ports), ...opt('from', words(r.from)), ...(r.comment.trim() ? { comment: r.comment.trim() } : {}) })) } : {}),
    ...(f.sets.length ? { sets: f.sets.map((x) => ({ name: x.name.trim(), members: words(x.members) })) } : {}),
    icmp: f.icmp,
    ...(f.logging ? { logging: true } : {}),
    nat: 'none',
  }
}

export const fwSpecKey = (s: HostFirewallSpec, confirm: number) => JSON.stringify([s, confirm])

/** ssh reachable from any address: the open template, no sources, or a /0 among them (directly or through a set). */
export function sshOpenToWorld(s: HostFirewallSpec): boolean {
  if (s.template === 'open') return true
  const from = s.ssh?.allow_from ?? []
  if (from.length === 0) return true
  const zero = (v: string) => parsePrefix(v).p?.bits === 0
  return from.some((v) => zero(v) || (v.startsWith('@') && (s.sets ?? []).some((x) => x.name === v.slice(1) && x.members.some(zero))))
}

/** The configuration lines still missing to enable the firewall module. */
export function fwEnableLines(h: HostFirewall): { config?: string; helper?: string } {
  return {
    ...(h.status.config_enabled ? {} : { config: 'host:\n  manage:\n    modules: [firewall]' }),
    ...(h.status.helper_enabled ? {} : { helper: 'host-manage = firewall' }),
  }
}

/** A confirmation window the server accepts, or undefined. */
export function confirmWindow(v: number): number | undefined {
  return Number.isInteger(v) && v >= MIN_CONFIRM && v <= MAX_CONFIRM ? v : undefined
}

/** Seconds left of a pending change: what the server said, minus the time since it said it (never the browser's
 * clock against the deadline, which may be off). */
export function secondsLeft(p: Pick<HostPendingChange, 'seconds_left'>, fetchedAt: number, now: number): number {
  return Math.max(0, Math.ceil(p.seconds_left - Math.max(0, now - fetchedAt) / 1000))
}

/** 125 -> "2:05". */
export function countdown(sec: number): string {
  const s = Math.max(0, Math.floor(sec))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}
