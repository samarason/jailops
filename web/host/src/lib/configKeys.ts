// The config key editor works from the registry of sdk/api (configKeys in types.gen.ts, generated from
// api.ConfigKeys), so a key exists in one place. Each key's `path` locates it in the typed spec:
// `resources.cpu`, `network[<device>].mtu`, `env.<var>`. This module reads, writes and validates by path.
import { clone } from './clone'
import { validSize } from '@jailops/shared/lib/names'
import { configKeys, type ConfigKey, type JailSpec, type Profile } from '@jailops/shared/api/types'

export type Spec = Record<string, unknown>

export const ALL_KEYS: ConfigKey[] = [...configKeys]

export const GROUP_ORDER = ['general', 'limits', 'boot', 'update', 'firewall', 'packages', 'env', 'nic', 'disk', 'devfs', 'proxy']

export function groupOf(name: string): string {
  const head = name.split('.')[0]
  if (['limits', 'boot', 'update', 'firewall', 'env', 'nic', 'disk', 'devfs', 'proxy'].includes(head)) return head
  if (name === 'packages') return 'packages'
  return 'general'
}

export const DEVICE_KINDS = ['nic', 'disk', 'devfs', 'proxy'] as const
export type DeviceKind = (typeof DEVICE_KINDS)[number]
const PATH_ROOT: Record<DeviceKind, string> = { nic: 'network', disk: 'volumes', devfs: 'devfs', proxy: 'proxy' }

interface Step { key: string; dev?: boolean }
function steps(path: string): Step[] {
  return path.split('.').map((seg) => {
    const m = /^(\w+)\[<\w+>\]$/.exec(seg)
    return m ? { key: m[1], dev: true } : { key: seg }
  })
}

/** The field a device of a list is named by: the volumes of a jail are named by the volume they attach. */
const idField = (root: string) => (root === 'volumes' ? 'volume' : 'name')

/** Names of the devices of a kind in a spec. Unnamed NICs are eth0, eth1, ... as the server names them. */
export function deviceNames(spec: JailSpec, kind: DeviceKind): string[] {
  const root = PATH_ROOT[kind]
  const list = ((spec as unknown as Spec)[root] as Array<Record<string, string | undefined>> | undefined) ?? []
  return list.map((d, i) => d[idField(root)] || (kind === 'nic' ? `eth${i}` : `${kind}${i}`))
}

function findDevice(spec: Spec, root: string, name: string, create: boolean): Record<string, unknown> | undefined {
  const list = (spec[root] as Array<Record<string, unknown>> | undefined) ?? (create ? (spec[root] = []) as Array<Record<string, unknown>> : undefined)
  if (!list) return undefined
  let i = list.findIndex((d, n) => (d[idField(root)] as string | undefined || (root === 'network' ? `eth${n}` : '')) === name)
  if (i < 0 && create) {
    list.push({ [idField(root)]: name })
    i = list.length - 1
  }
  return list[i]
}

const isList = (k: ConfigKey) => k.type === 'list'

/** Read a key as the string the form shows. */
export function getValue(spec: JailSpec, k: ConfigKey, dev = ''): string {
  const st = steps(k.path)
  let cur: unknown = spec
  for (const s of st) {
    if (cur === undefined || cur === null) return ''
    if (s.dev) cur = findDevice(cur as Spec, s.key, dev, false)
    else if (s.key === '<var>') cur = (cur as Spec)[dev]
    else cur = (cur as Spec)[s.key]
  }
  if (cur === undefined || cur === null) return ''
  if (Array.isArray(cur)) return cur.join(', ')
  if (k.type === 'device') return cur ? 'present' : ''
  if (typeof cur === 'boolean') return String(cur)
  if (typeof cur === 'number') return cur === 0 ? '' : String(cur)
  return String(cur)
}

function convert(k: ConfigKey, v: string): unknown {
  if (isList(k)) return v.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean)
  if (k.type === 'int') return Number(v)
  if (k.type === 'bool') return v === 'true' || v === 'yes' || v === 'on' || v === '1'
  return v
}

/** A copy of the spec with a key set; an empty value unsets it. */
export function setValue(spec: JailSpec, k: ConfigKey, dev: string, value: string): JailSpec {
  const out = clone(spec) as unknown as Spec
  const st = steps(k.path)
  let cur: Spec = out
  for (let i = 0; i < st.length; i++) {
    const s = st[i]
    const last = i === st.length - 1
    if (s.dev) {
      const d = findDevice(cur, s.key, dev, value !== '' || !last)
      if (!d) return out as unknown as JailSpec
      if (last) {
        // the device key itself: empty removes the device
        if (value === '') ((cur[s.key] as Array<Record<string, unknown>>) ?? []).splice(((cur[s.key] as Array<unknown>) ?? []).indexOf(d), 1)
        return out as unknown as JailSpec
      }
      cur = d
    } else if (last) {
      const key = s.key === '<var>' ? dev : s.key
      if (value === '') delete cur[key]
      else cur[key] = convert(k, value)
    } else {
      const key = s.key
      if (cur[key] === undefined || cur[key] === null) cur[key] = {}
      cur = cur[key] as Spec
    }
  }
  return out as unknown as JailSpec
}

export interface Row { key: ConfigKey; name: string; dev: string; group: string }

/** The concrete rows of the editor: fixed keys, plus one row per field of every device the jail has. */
export function rowsFor(spec: JailSpec): Row[] {
  const rows: Row[] = []
  const env = Object.keys(((spec as unknown as Spec).env as Record<string, string> | undefined) ?? {})
  for (const k of ALL_KEYS) {
    const m = /^(nic|disk|devfs|proxy)\.<(device|name)>(\.(.+))?$/.exec(k.name)
    if (k.name === 'env.<var>') {
      for (const v of env) rows.push({ key: k, name: `env.${v}`, dev: v, group: 'env' })
    } else if (m) {
      if (!m[4]) continue // the device key itself is shown as the device header
      for (const d of deviceNames(spec, m[1] as DeviceKind)) rows.push({ key: k, name: `${m[1]}.${d}.${m[4]}`, dev: d, group: m[1] })
    } else rows.push({ key: k, name: k.name, dev: '', group: groupOf(k.name) })
  }
  return rows
}

/** Every key that is set, as the flat map the server calls ConfigValues. */
export function flatten(spec: JailSpec): Record<string, string> {
  const out: Record<string, string> = {}
  for (const r of rowsFor(spec)) {
    const v = getValue(spec, r.key, r.dev)
    if (v !== '') out[r.name] = v
  }
  return out
}

/** The merged view: where each key comes from. Later profiles override earlier ones; the jail wins. */
export function expandedSources(spec: JailSpec, profiles: Profile[]): Record<string, { value: string; source: string }> {
  const out: Record<string, { value: string; source: string }> = {}
  const byName = new Map(profiles.map((p) => [p.metadata.name, p]))
  for (const n of ((spec as unknown as Spec).profiles as string[] | undefined) ?? []) {
    const p = byName.get(n)
    if (p) for (const [k, v] of Object.entries(p.spec.config ?? {})) out[k] = { value: v, source: n }
  }
  for (const [k, v] of Object.entries(flatten(spec))) out[k] = { value: v, source: 'jail' }
  return out
}

export interface Msgs {
  int: string; size: string; rate: string; mac: string; address: string; listen: string; bool: string; name: string
  enum: (opts: string[]) => string
}

/** Validate a value against its key type. Empty means unset and is valid. */
export function validate(k: ConfigKey, value: string, m: Msgs): string | undefined {
  const v = value.trim()
  if (v === '') return undefined
  switch (k.type) {
    case 'int': return /^-?\d+$/.test(v) ? undefined : m.int
    case 'size': return validSize(v) ? undefined : m.size
    case 'rate': return /^[1-9][0-9]*[KMGT]?$/.test(v) ? undefined : m.rate
    case 'bool': return ['true', 'false', 'yes', 'no', 'on', 'off', '1', '0'].includes(v) ? undefined : m.bool
    case 'mac': return /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(v) ? undefined : m.mac
    case 'address': return v === 'auto' || v === 'none' || /^[0-9a-f.:]+$/i.test(v) ? undefined : m.address
    case 'listen': return /^([A-Za-z0-9.:\-\[\]]*):\d{1,5}$/.test(v) ? undefined : m.listen
    case 'enum': return k.values?.includes(v) ? undefined : m.enum(k.values ?? [])
    default: return undefined
  }
}

export function grouped(rows: Row[]): Array<[string, Row[]]> {
  const by = new Map<string, Row[]>()
  for (const r of rows) {
    if (!by.has(r.group)) by.set(r.group, [])
    by.get(r.group)!.push(r)
  }
  return [...by.entries()].sort((a, b) => (GROUP_ORDER.indexOf(a[0]) + 1 || 99) - (GROUP_ORDER.indexOf(b[0]) + 1 || 99))
}

/** Rows whose value differs between two specs, and which of those need a restart. */
export function diff(spec: JailSpec, next: JailSpec): { changed: string[]; restart: string[] } {
  const a = flatten(spec)
  const b = flatten(next)
  const names = new Set([...Object.keys(a), ...Object.keys(b)])
  const changed = [...names].filter((n) => a[n] !== b[n]).sort()
  const need = new Map(rowsFor(next).concat(rowsFor(spec)).map((r) => [r.name, r.key.restart_required]))
  return { changed, restart: changed.filter((n) => need.get(n)) }
}

/** Find the registry entry of a concrete key such as nic.eth1.mtu, and the device or variable it names. */
export function lookupKey(key: string): { def: ConfigKey; dev: string } | undefined {
  const parts = key.split('.')
  for (const k of ALL_KEYS) {
    if (k.name === 'env.<var>') {
      if (parts[0] === 'env' && parts.length >= 2) return { def: k, dev: parts.slice(1).join('.') }
      continue
    }
    const tp = k.name.split('.')
    if (tp.length !== parts.length) continue
    let dev = ''
    let ok = true
    tp.forEach((seg, i) => {
      if (seg.startsWith('<')) dev = parts[i]
      else if (seg !== parts[i]) ok = false
    })
    if (ok) return { def: k, dev }
  }
  return undefined
}

export interface ProfileIssue { key: string; message: string }
/** Check the keys of a profile: each must exist, be allowed in a profile and hold a valid value. */
export function checkProfile(config: Record<string, string>, m: Msgs, text: { unknown: string; notAllowed: string }): ProfileIssue[] {
  const out: ProfileIssue[] = []
  for (const [key, value] of Object.entries(config)) {
    const f = lookupKey(key)
    if (!f) out.push({ key, message: text.unknown })
    else if (!f.def.profile) out.push({ key, message: text.notAllowed })
    else {
      const v = validate(f.def, value, m)
      if (v) out.push({ key, message: v })
    }
  }
  return out
}

/** The `set` and `unset` of POST /jails/{n}/config that turn one spec into another. */
export function configChange(from: JailSpec, to: JailSpec): { set: Record<string, string>; unset: string[] } {
  const a = flatten(from)
  const b = flatten(to)
  const set: Record<string, string> = {}
  const unset: string[] = []
  for (const n of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (a[n] === b[n]) continue
    if (n in b) set[n] = b[n]
    else unset.push(n)
  }
  return { set, unset: unset.sort() }
}

/** Sources of the server's expanded view (`jail` or `profile:<name>`) as the editor shows them. */
export function sourcesOf(exp: { jail: { spec: JailSpec }; sources: Record<string, string> }): Record<string, { value: string; source: string }> {
  const values = flatten(exp.jail.spec)
  const out: Record<string, { value: string; source: string }> = {}
  for (const [k, v] of Object.entries(values)) out[k] = { value: v, source: (exp.sources[k] ?? 'jail').replace(/^profile:/, '') }
  return out
}

/** The help of a key as a user reads it: the registry's description, its spacing tidied. */
export function helpText(d: string | undefined): string {
  return (d ?? '').replace(/\s{2,}/g, ' ').trim()
}
