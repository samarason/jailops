// The demo's answer to POST /firewall/test. It walks the demo's policies the way the server walks the rendered anchor:
// the deny rules of all the policies first, then the allow rules, then the defaults (the strictest of the policies),
// and a raw PF fragment that is reached before a decision makes the answer "cannot say". The pf lines are written for
// the demo. Only loaded for `?demo`.
import type { AddressSet, FirewallPolicy, FirewallRule, FirewallTestCase, FirewallTestHop, FirewallTestRequest, FirewallTestResult, FirewallTestRule, FirewallTestSkipped, Jail } from '@jailops/shared/api/types'

interface Ip { fam: 4 | 6; n: bigint }

function parseIP(s: string): Ip | null {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    const p = s.split('.').map(Number)
    if (p.some((x) => x > 255)) return null
    return { fam: 4, n: p.reduce((a, x) => (a << 8n) + BigInt(x), 0n) }
  }
  if (!s.includes(':')) return null
  const [head, tail = ''] = s.split('::')
  const h = head ? head.split(':') : []
  const t = tail ? tail.split(':') : []
  const groups = s.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h
  if (groups.length !== 8) return null
  return { fam: 6, n: groups.reduce((a, g) => (a << 16n) + BigInt(parseInt(g || '0', 16)), 0n) }
}

function inCidr(addr: Ip, cidr: string): boolean {
  const [a, bits] = cidr.split('/')
  const net = parseIP(a)
  if (!net || net.fam !== addr.fam) return false
  const total = net.fam === 4 ? 32 : 128
  const keep = BigInt(total - (bits === undefined ? total : Number(bits)))
  return addr.n >> keep === net.n >> keep
}

const plain = (a: string): string => a.split('/')[0]
/** The demo network is dual-stack: a jail with IPv4 10.20.0.N is also 2001:db8:10::N. */
const v6Of = (v4: string): string => `2001:db8:10::${Number(v4.split('.')[3] ?? 0)}`

export interface DemoFwState {
  jails: Jail[]
  policies: FirewallPolicy[]
  sets: AddressSet[]
  /** The mandatory policies of the project, in the order they are rendered. */
  projectPolicies: string[]
}

export class DemoFwError extends Error {
  constructor(public status: number, public code: string, message: string, public hint?: string) { super(message) }
}

interface End { name: string; jail?: Jail; addrs: Ip[]; text: Record<number, string> }

function jailAddrs(j: Jail): string[] {
  let v4 = (j.status.addresses ?? []).map(plain).filter((a) => !a.includes(':'))
  // a jail that does not run has no address yet: the demo gives it the one its network will
  if (!v4.length) v4 = [`10.20.0.${10 + j.metadata.name.length}`]
  return [...v4, ...v4.map(v6Of)]
}

function endOf(v: string, st: DemoFwState): End {
  if (v === 'host') return { name: 'host', addrs: [parseIP('10.20.0.1')!, parseIP('2001:db8:10::1')!], text: { 4: '10.20.0.1', 6: '2001:db8:10::1' } }
  if (v.startsWith('@')) throw new DemoFwError(400, 'invalid', `@ is not used: write jail:${v.slice(1)}`)
  if (v.startsWith('set:') || v.startsWith('tag:')) throw new DemoFwError(400, 'invalid', `${v} is not one end of a connection`, 'name a jail of the project (jail:NAME) or one address')
  if (v.startsWith('jail:')) {
    const j = st.jails.find((x) => x.metadata.name === v.slice(5))
    if (!j) throw new DemoFwError(404, 'not_found', `jail "${v.slice(5)}" not found`, "list them with 'jailops jail list'; check --project, --host and --remote too")
    const all = jailAddrs(j)
    if (!all.length) throw new DemoFwError(400, 'invalid', `jail "${j.metadata.name}" has no address to test`)
    return { name: v, jail: j, addrs: all.map((a) => parseIP(a)!), text: Object.fromEntries(all.map((a) => [parseIP(a)!.fam, a])) }
  }
  const ip = parseIP(v)
  if (!ip) throw new DemoFwError(400, 'invalid', `${v} is not an address, a jail (jail:NAME) or host`)
  const owner = st.jails.find((j) => jailAddrs(j).includes(v))
  return { name: owner ? `jail:${owner.metadata.name}` : v, jail: owner, addrs: [ip], text: { [ip.fam]: v } }
}

/** The members of an endpoint of a rule, resolved the way the renderer resolves them. */
function members(e: string, st: DemoFwState, seen: string[] = []): string[] | 'any' {
  if (e === 'any') return 'any'
  if (e.startsWith('tag:')) {
    const tag = e.slice(4)
    return st.jails.filter((j) => j.spec.firewall?.tags?.includes(tag) || j.metadata.labels?.role === tag).flatMap(jailAddrs)
  }
  if (e.startsWith('jail:')) {
    const j = st.jails.find((x) => x.metadata.name === e.slice(5))
    return j ? jailAddrs(j) : []
  }
  if (e.startsWith('set:')) {
    const n = e.slice(4)
    const set = st.sets.find((x) => x.metadata.name === n)
    if (set && !seen.includes(n)) return set.spec.addresses.flatMap((a) => { const m = members(a.address, st, [...seen, n]); return m === 'any' ? [] : m })
    return []
  }
  return [e]
}

function matchEnds(list: string[] | undefined, ip: Ip, st: DemoFwState): boolean {
  if (!list?.length) return true
  return list.some((e) => {
    const m = members(e, st)
    return m === 'any' || m.some((x) => inCidr(ip, x.includes('/') ? x : `${x}/${ip.fam === 4 ? 32 : 128}`))
  })
}

function matchPort(ports: string[] | undefined, p: number): boolean {
  if (!ports?.length) return true
  return ports.some((x) => { const [a, b] = x.split('-').map(Number); return p >= a && p <= (b ?? a) })
}

interface Cand { rule: FirewallRule; policy: string; project: boolean; no: number }

function line(c: { action: string; dir: string; proto?: string; port?: string; from: string; to: string; fam: number; gw: boolean }): string {
  const act = c.action === 'allow' ? 'pass' : 'block drop'
  return `${act} ${c.dir} quick on ${c.gw ? 'jo0g0a' : 'jo0web0a'} ${c.fam === 4 ? 'inet' : 'inet6'}${c.proto ? ` proto ${c.proto}` : ''} from ${c.from} to ${c.to}${c.port ? ` port ${c.port}` : ''}`
}

/** One anchor: the rules of the jail's policies in the direction, the way the renderer orders them. */
function hop(side: 'source' | 'destination', jail: Jail, dir: 'in' | 'out', pkt: { fam: 4 | 6; proto: string; port: number; src: Ip; dst: Ip; icmp: string }, st: DemoFwState): FirewallTestHop {
  const names = [...st.projectPolicies, ...(jail.spec.firewall?.policies ?? []).filter((p) => !st.projectPolicies.includes(p))]
  const pols = names.map((n) => ({ name: n, project: st.projectPolicies.includes(n), spec: st.policies.find((p) => p.metadata.name === n)?.spec })).filter((p) => p.spec)
  const all: Cand[] = pols.flatMap((p) => (p.spec!.rules ?? []).map((rule, i) => ({ rule, policy: p.name, project: p.project, no: i + 1 })).filter((c) => c.rule.direction === dir))
  const matches = (c: Cand): boolean =>
    (!c.rule.proto || c.rule.proto === pkt.proto) && matchPort(c.rule.ports, pkt.port) && matchEnds(c.rule.from, pkt.src, st) && matchEnds(c.rule.to, pkt.dst, st)
  const live = all.filter((c) => !c.rule.disabled)
  const denies = live.filter((c) => c.rule.action === 'deny')
  const allows = live.filter((c) => c.rule.action === 'allow')
  const gw = side === 'destination'
  const toRule = (c: Cand): FirewallTestRule => ({
    stage: 'policy', policy: c.policy, project_policy: c.project || undefined, rule: c.no, name: c.rule.name, comment: c.rule.comment,
    pf: line({ action: c.rule.action, dir: gw ? 'out' : 'in', proto: c.rule.proto, port: c.rule.ports?.join(','), from: c.rule.from?.join(', ') || 'any', to: c.rule.to?.join(', ') || (gw ? plainAddr(pkt.dst) : 'any'), fam: pkt.fam, gw }),
  })
  const skipped: FirewallTestSkipped[] = all.filter((c) => c.rule.disabled && matches(c)).map((c) => ({ rule: toRule(c), why: 'the rule is switched off' }))
  const base = { side, jail: jail.metadata.name, anchor: `jailops/web/${jail.metadata.name}`, direction: gw ? 'out' : 'in', loaded_matches_rendered: 'true' }
  const hit = denies.find(matches)
  if (hit) {
    const also = allows.filter(matches).map((c): FirewallTestSkipped => ({ rule: toRule(c), why: 'a deny rule wins over every allow rule, whatever the order of the policies' }))
    return { ...base, verdict: 'block', decided_by: toRule(hit), skipped: [...also, ...skipped] }
  }
  const ok = allows.find(matches)
  if (ok) return { ...base, verdict: 'pass', decided_by: toRule(ok), skipped }
  const raw = pols.find((p) => p.spec!.raw)
  if (raw) return { ...base, verdict: 'unknown', why: `policy ${raw.name} has a raw PF fragment that comes before the default: the test cannot say what it does with this connection`, skipped }
  const key = dir === 'in' ? 'default_in' : 'default_out'
  const deny = pols.some((p) => p.spec![key] === 'deny')
  const verdict = deny ? 'block' : 'pass'
  const dec: FirewallTestRule = { stage: 'default', pf: line({ action: deny ? 'deny' : 'allow', dir: gw ? 'out' : 'in', from: 'any', to: gw ? plainAddr(pkt.dst) : 'any', fam: pkt.fam, gw }) }
  return { ...base, verdict, decided_by: dec, skipped }
}
const plainAddr = (a: Ip): string => (a.fam === 4 ? [24n, 16n, 8n, 0n].map((s) => String((a.n >> s) & 255n)).join('.') : `2001:db8:10::${Number(a.n & 0xffffn)}`)

export function demoFirewallTest(req: FirewallTestRequest, st: DemoFwState): FirewallTestResult {
  const proto = req.proto || 'tcp'
  if (!['tcp', 'udp', 'icmp', 'icmp6'].includes(proto)) throw new DemoFwError(400, 'invalid', `proto "${proto}" must be tcp, udp, icmp or icmp6`)
  if ((proto === 'tcp' || proto === 'udp') && !(req.port && req.port >= 1 && req.port <= 65535)) throw new DemoFwError(400, 'invalid', `a ${proto} test needs a port from 1 to 65535`)
  const from = endOf(req.from, st)
  const to = endOf(req.to, st)
  const fams = ([4, 6] as const).filter((f) => (proto === 'icmp' ? f === 4 : proto === 'icmp6' ? f === 6 : true) && (!req.family || Number(req.family) === f) && from.text[f] && to.text[f])
  const cases: FirewallTestCase[] = fams.map((f) => {
    const pkt = { fam: f, proto, port: req.port ?? 0, src: parseIP(from.text[f])!, dst: parseIP(to.text[f])!, icmp: req.icmp_type ?? '' }
    const hops: FirewallTestHop[] = []
    // what the jail sends is judged by the rules that go out; what reaches a jail by the rules that come in
    if (from.jail) hops.push(hop('source', from.jail, 'out', pkt, st))
    if (hops.every((h) => h.verdict === 'pass') && to.jail) hops.push(hop('destination', to.jail, 'in', pkt, st))
    const verdict = hops.some((h) => h.verdict === 'block') ? 'block' : hops.some((h) => h.verdict === 'unknown') ? 'unknown' : 'pass'
    return { family: f === 4 ? 'inet' : 'inet6', from: from.text[f], to: to.text[f], proto, port: req.port || undefined, icmp_type: proto.startsWith('icmp') ? (req.icmp_type || 'echoreq') : undefined, verdict, hops }
  })
  const verdict = cases.some((c) => c.verdict === 'block') ? 'block' : cases.some((c) => c.verdict === 'unknown') ? 'unknown' : 'pass'
  const caveats = ['the answer is for a new connection: a connection that is already open (pf keeps its state) is not asked about']
  if (proto.startsWith('icmp') && !req.icmp_type) caveats.unshift('no ICMP type was given: the test is an echo request (ping); other types may meet other rules')
  if (req.from === 'host' || req.to === 'host' || (!from.jail && !to.jail) || !to.jail) caveats.push("the host's own pf.conf and NAT are not covered")
  return { verdict, cases, caveats }
}
