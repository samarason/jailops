import type { AddressEntry, AddressSet, AddressSetSpec, FirewallPolicy, FirewallRule } from '@jailops/shared/api/types'
import { NAME_PATTERN, nameRules } from '@jailops/shared/lib/names'
import { ipv4, ipv6Groups } from './host'

export type RuleErrors = Record<string, string> // key: "<index>.<field>"

const PORT = /^\d{1,5}(-\d{1,5})?$/

export function splitList(s: string): string[] {
  return s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
}

export function validPort(p: string): boolean {
  if (!PORT.test(p)) return false
  return p.split('-').every((n) => Number(n) >= 1 && Number(n) <= 65535) && (!p.includes('-') || Number(p.split('-')[0]) <= Number(p.split('-')[1]))
}

/** Client-side checks that mirror the obvious server rules; the server stays the authority. */
export function validateRules(rules: FirewallRule[], msg: { portRange: string; portNeedsProto: string; redirectInOnly: string; hostPortRange: string }): RuleErrors {
  const e: RuleErrors = {}
  rules.forEach((r, i) => {
    if (r.ports?.length) {
      if (r.proto !== 'tcp' && r.proto !== 'udp') e[`${i}.ports`] = msg.portNeedsProto
      else if (!r.ports.every(validPort)) e[`${i}.ports`] = msg.portRange
    }
    if (r.redirect) {
      if (r.direction !== 'in') e[`${i}.redirect`] = msg.redirectInOnly
      else if (!(r.redirect.host_port >= 1 && r.redirect.host_port <= 65535) || !(r.redirect.jail_port >= 1 && r.redirect.jail_port <= 65535)) e[`${i}.redirect`] = msg.hostPortRange
    }
  })
  return e
}

/**
 * Map the detail of an api.Error to rule fields. The server names the failing field as
 * "rules[2].ports" or "rules.2.ports"; anything else stays in the error panel only.
 */
export function detailToRuleErrors(detail: Record<string, string> | undefined): RuleErrors {
  const out: RuleErrors = {}
  for (const [k, v] of Object.entries(detail ?? {})) {
    const m = /^(?:spec\.)?rules(?:\[(\d+)\]|\.(\d+))\.(\w+)/.exec(k)
    if (m) out[`${m[1] ?? m[2]}.${m[3]}`] = v
  }
  return out
}

export function blankRule(): FirewallRule {
  return { name: '', action: 'allow', direction: 'in', proto: 'tcp', from: [], to: [], ports: [] }
}

// Address sets. The checks mirror internal/validate (SetName, AddressSetSpec, FlattenSet) as the server runs them on a
// create or a replace; the server stays the authority.

/** The rule of an address set name: it becomes part of a PF table name. */
export const SET_NAME = nameRules.addressSet.re
export const SET_NAME_MAX = nameRules.addressSet.max

/** The messages, named as in the firewall strings of the i18n file (pass s.firewall). */
export interface SetMsgs {
  setRequired: string
  setTooLong: string
  setBadName: string
  setExists: string
  setMember: (a: string) => string
  setCycle: (path: string) => string
}

/** The fields of the set form; a key is set only when the field has a problem. */
export type SetErrors = Partial<Record<'name' | 'addresses', string>>

function v4Bytes(s: string): number[] | null {
  return ipv4(s) ? s.split('.').map(Number) : null
}

/**
 * An address or a CIDR as the server parses a member: IPv4 without leading zeros, IPv6 with no zone and not in
 * the IPv4-mapped form, a prefix length without a sign or leading zeros of at most 32 or 128. Host bits may be
 * set (the server masks them).
 */
export function setMember(s: string): boolean {
  // jail:NAME is a jail of the project (its addresses), set:NAME another set; the server checks that a set exists
  if (s.startsWith('jail:')) return s.length - 5 <= 29 && NAME_PATTERN.test(s.slice(5))
  if (s.startsWith('set:')) return s.length - 4 <= 29 && NAME_PATTERN.test(s.slice(4))
  const slash = s.lastIndexOf('/')
  const addr = slash < 0 ? s : s.slice(0, slash)
  let bits = 32
  if (!v4Bytes(addr)) {
    const g = ipv6Groups(addr)
    if (!g || (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff)) return false
    bits = 128
  }
  if (slash < 0) return true
  const len = s.slice(slash + 1)
  return /^(0|[1-9][0-9]{0,2})$/.test(len) && Number(len) <= bits
}

/** Empty when the name may be created, else the message under the field. */
export function setNameError(name: string, taken: string[], msg: SetMsgs): string {
  if (!name) return msg.setRequired
  if (name.length > SET_NAME_MAX) return msg.setTooLong
  if (!SET_NAME.test(name)) return msg.setBadName
  if (taken.includes(name)) return msg.setExists
  return ''
}

/**
 * The spec the form sends: members one per line (commas and spaces also separate them). A line
 * that ends in `# a comment` is ONE member with that comment (what it is: what a reviewer of the firewall reads next to
 * `set:office` in a rule); an IPv4 and an IPv6 network are two lines, each with its own comment. `comment` is what the set
 * as a whole is.
 */
export function setSpec(members: string, comment = ''): AddressSetSpec {
  const addresses: AddressEntry[] = []
  for (const line of members.split('\n')) {
    const at = line.indexOf('#')
    if (at < 0) {
      addresses.push(...splitList(line).map((address) => ({ address })))
      continue
    }
    const address = line.slice(0, at).trim() // a line with a comment is one member: "a, b # c" is not an address, which the check says
    const c = line.slice(at + 1).trim()
    if (address) addresses.push(c ? { address, comment: c } : { address })
  }
  const spec: AddressSetSpec = { addresses }
  if (comment.trim()) spec.comment = comment.trim()
  return spec
}

/** The text of the members box for a set: one line per member, `member  # comment` when it has one. */
export function setTextOf(spec: AddressSetSpec): string {
  return (spec.addresses ?? []).map((a) => (a.comment ? `${a.address}  # ${a.comment}` : a.address)).join('\n')
}

/**
 * The problems of a set the server would refuse: a member that is no address, CIDR, jail:NAME or set:NAME, or a set:NAME
 * that closes a cycle of sets. `others` are the sets of the project; an empty set is allowed. A member set:NAME that does
 * not exist is the server's to refuse; a jail:NAME that does not exist is allowed (it matches nobody).
 */
export function validateSet(name: string, spec: AddressSetSpec, others: Record<string, AddressSetSpec>, msg: SetMsgs): SetErrors {
  const e: SetErrors = {}
  const bad = (spec.addresses ?? []).find((a) => !setMember(a.address))
  if (bad !== undefined) e.addresses = msg.setMember(bad.address)
  if (bad === undefined && name) {
    const sets = { ...others, [name]: spec }
    const walk = (n: string, path: string[]): string => {
      if (path.includes(n)) return msg.setCycle([...path, n].join(' -> '))
      const s = sets[n]
      if (!s) return '' // a jail, or a name the server checks
      for (const a of s.addresses ?? []) {
        if (!a.address.startsWith('set:')) continue
        const p = walk(a.address.slice(4), [...path, n])
        if (p) return p
      }
      return ''
    }
    const p = walk(name, [])
    if (p) e.addresses = p
  }
  return e
}

/** What refers to a set: the policies with set:NAME in a rule and the sets that have set:NAME as a member. The server refuses
 *  to delete a set while either list has entries. */
export function setUsers(name: string, policies: FirewallPolicy[], sets: AddressSet[]): { policies: string[]; sets: string[] } {
  const ref = 'set:' + name
  return {
    policies: policies.filter((p) => (p.spec.rules ?? []).some((r) => r.from?.includes(ref) || r.to?.includes(ref))).map((p) => p.metadata.name),
    sets: sets.filter((x) => (x.spec.addresses ?? []).some((a) => a.address === ref)).map((x) => x.metadata.name),
  }
}

/** The field a server error names (detail.field of a validation error), with the server's message. */
export function detailToSetErrors(e: { message: string; detail?: Record<string, string> } | null | undefined): SetErrors {
  const f = e?.detail?.field
  return f === 'name' || f === 'addresses' ? { [f]: e!.message } : {}
}
