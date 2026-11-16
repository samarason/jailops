// Pure helpers of the network form. They only catch typing mistakes early; the server's validator is the authority
// (prefix limits, proxy rules, overlaps) and its message is shown as it comes.
import type { Network } from '@jailops/shared/api/types'
import { nameError } from './nameField'
import { clone } from './clone'

export interface NetForm {
  name: string; uplink: string
  v4: boolean; v4subnet: string; v4gateway: string; v4range: string; nat: boolean
  mode: 'none' | 'routed' | 'proxy'; v6subnet: string; v6range: string
}
export const blankNet = (): NetForm => ({ name: '', uplink: '', v4: true, v4subnet: '', v4gateway: '', v4range: '', nat: false, mode: 'none', v6subnet: '', v6range: '' })

function v4int(a: string): number | null {
  const p = a.trim().split('.')
  if (p.length !== 4) return null
  let n = 0
  for (const o of p) {
    if (!/^\d{1,3}$/.test(o) || Number(o) > 255) return null
    n = n * 256 + Number(o)
  }
  return n
}
const v4str = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')

/** "10.20.0.0/24" -> its parts, or null when it is not an IPv4 CIDR. */
export function parseV4Cidr(s: string): { base: number; bits: number } | null {
  const m = /^([\d.]+)\/(\d{1,2})$/.exec(s.trim())
  if (!m) return null
  const a = v4int(m[1])
  const bits = Number(m[2])
  return a === null || bits > 32 ? null : { base: a, bits }
}

/** Gateway = first host, range = the rest of the subnet; what `jailops network create` would suggest. */
export function suggestV4(subnet: string): { gateway: string; range: string } | null {
  const c = parseV4Cidr(subnet)
  if (!c || c.bits > 29) return null
  const size = 2 ** (32 - c.bits)
  const mask = (0xffffffff << (32 - c.bits)) >>> 0
  const net = (c.base & mask) >>> 0
  return { gateway: v4str(net + 1), range: `${v4str(net + 2)}-${v4str(net + size - 2)}` }
}

export const isV6Cidr = (s: string) => /^[0-9a-fA-F:]+\/\d{1,3}$/.test(s.trim()) && s.includes(':') && Number(s.split('/')[1]) <= 128

/** Field -> message for what is plainly wrong; empty when the form may be sent. An existing network (editing)
 *  keeps its name, which may be longer than a new one may be. */
export function checkNet(f: NetForm, existing = false): Record<string, string> {
  const e: Record<string, string> = {}
  // the name rule of the server (shared lib/names.ts); an empty name is the form's "Required."
  if (!existing && f.name && nameError(f.name, 'network')) e.name = nameError(f.name, 'network')
  if (f.v4) {
    const c = parseV4Cidr(f.v4subnet)
    if (f.v4subnet && !c) e.v4subnet = 'Write the subnet as a.b.c.d/len, for example 10.20.0.0/24.'
    const inside = (a: string) => { const n = v4int(a); return !!c && n !== null && ((n & ((0xffffffff << (32 - c.bits)) >>> 0)) >>> 0) === ((c.base & ((0xffffffff << (32 - c.bits)) >>> 0)) >>> 0) }
    if (f.v4gateway && v4int(f.v4gateway) === null) e.v4gateway = 'Not an IPv4 address.'
    else if (c && f.v4gateway && !inside(f.v4gateway)) e.v4gateway = 'The gateway must lie inside the subnet.'
    const r = f.v4range.split('-')
    if (f.v4range && (r.length !== 2 || v4int(r[0]) === null || v4int(r[1]) === null)) e.v4range = 'Write the range as first-last, for example 10.20.0.10-10.20.0.200.'
    else if (c && f.v4range && !(inside(r[0]) && inside(r[1]))) e.v4range = 'The range must lie inside the subnet.'
    if (f.nat && !f.uplink) e.uplink = 'NAT needs an uplink interface.'
  }
  if (f.mode !== 'none') {
    if (f.v6subnet && !isV6Cidr(f.v6subnet)) e.v6subnet = 'Write the prefix as an IPv6 CIDR, for example 2001:db8:20::/64.'
    if (f.v6range && !/^[0-9a-fA-F:]+-[0-9a-fA-F:]+$/.test(f.v6range.trim())) e.v6range = 'Write the range as first-last.'
    if (f.mode === 'proxy' && !f.uplink) e.uplink = 'Proxy mode answers neighbour discovery on an uplink: name it.'
  }
  if (!f.v4 && f.mode === 'none') e.family = 'A network needs IPv4, IPv6, or both.'
  return e
}

/** The form of an existing network, for editing. */
export function formOf(n: Network): NetForm {
  const v4 = n.spec.ipv4
  const v6 = n.spec.ipv6
  return {
    name: n.metadata.name, uplink: n.spec.uplink ?? '',
    v4: !!v4, v4subnet: v4?.subnet ?? '', v4gateway: v4?.gateway ?? '', v4range: v4?.range ?? '', nat: !!v4?.nat,
    mode: (v6?.mode as NetForm['mode']) ?? 'none', v6subnet: v6?.subnet ?? '', v6range: v6?.range ?? '',
  }
}

/** The body of POST /networks, or of PUT for an edit: base keeps what the form does not show (DNS, MTU,
 *  exclusions). */
export function netBody(f: NetForm, base?: Network): Pick<Network, 'metadata' | 'spec'> {
  const spec: Network['spec'] = base ? clone(base.spec) : {}
  delete spec.uplink
  delete spec.ipv4
  delete spec.ipv6
  if (f.uplink.trim()) spec.uplink = f.uplink.trim()
  if (f.v4) spec.ipv4 = { ...(base?.spec.ipv4?.exclude?.length ? { exclude: base.spec.ipv4.exclude } : {}), subnet: f.v4subnet.trim(), gateway: f.v4gateway.trim(), range: f.v4range.trim(), ...(f.nat ? { nat: true } : {}) }
  if (f.mode !== 'none') spec.ipv6 = { mode: f.mode, subnet: f.v6subnet.trim(), range: f.v6range.trim() }
  return { metadata: base ? { ...base.metadata } : { name: f.name }, spec }
}
