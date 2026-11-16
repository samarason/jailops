import type { FirewallTestCase, FirewallTestHop, FirewallTestRequest, FirewallTestResult, FirewallTestRule } from '@jailops/shared/api/types'
import { setMember } from './firewall'

// The firewall test (POST /firewall/test): the form, the address of a result, and the flow a result is drawn as. Pure
// functions only: the page renders what they return. The server decides every verdict; nothing here evaluates a rule.

export type Proto = 'tcp' | 'udp' | 'icmp' | 'icmp6'
export const PROTOS: readonly Proto[] = ['tcp', 'udp', 'icmp', 'icmp6']

export interface TestForm {
  from: string
  to: string
  proto: Proto
  port: string
  icmpType: string
  family: '' | '4' | '6'
}

export const blankForm = (): TestForm => ({ from: '', to: '', proto: 'tcp', port: '', icmpType: '', family: '' })

export type EndKind = 'jail' | 'address' | 'host' | ''

/** What an end is: a jail (`jail:web`), an address, or the host. Empty for nothing or something else. */
export function endKind(v: string): EndKind {
  const t = v.trim()
  if (t === 'host') return 'host'
  if (/^jail:[a-z][a-z0-9-]{0,28}$/.test(t) && !t.endsWith('-')) return 'jail'
  if (t && !t.includes('/') && !t.startsWith('jail:') && !t.startsWith('set:') && setMember(t)) return 'address'
  return ''
}

/** The end as the API takes it: what was typed, without the spaces around it. */
export function endValue(v: string): string {
  return v.trim()
}

export type Issue = 'required' | 'bad' | 'portRequired' | 'portBad' | 'icmpBad' | 'same'
export type Issues = Partial<Record<'from' | 'to' | 'port' | 'icmpType', Issue>>

/** The problems of a form, by field; empty when it can be run. */
export function formIssues(f: TestForm): Issues {
  const out: Issues = {}
  if (!f.from.trim()) out.from = 'required'
  else if (!endKind(f.from)) out.from = 'bad'
  if (!f.to.trim()) out.to = 'required'
  else if (!endKind(f.to)) out.to = 'bad'
  if (!out.from && !out.to && endValue(f.from) === endValue(f.to)) out.to = 'same'
  if (f.proto === 'tcp' || f.proto === 'udp') {
    const p = f.port.trim()
    if (!p) out.port = 'portRequired'
    else if (!/^[1-9][0-9]{0,4}$/.test(p) || Number(p) > 65535) out.port = 'portBad'
  }
  if ((f.proto === 'icmp' || f.proto === 'icmp6') && f.icmpType.trim() && !/^[a-z][a-z0-9-]{0,31}$/.test(f.icmpType.trim())) out.icmpType = 'icmpBad'
  return out
}

export const formValid = (f: TestForm): boolean => !Object.keys(formIssues(f)).length

/** The request the form sends. */
export function toRequest(f: TestForm): FirewallTestRequest {
  const r: FirewallTestRequest = { from: endValue(f.from), to: endValue(f.to), proto: f.proto }
  if (f.proto === 'tcp' || f.proto === 'udp') r.port = Number(f.port.trim())
  if ((f.proto === 'icmp' || f.proto === 'icmp6') && f.icmpType.trim()) r.icmp_type = f.icmpType.trim()
  if (f.family) r.family = f.family
  return r
}

/** The `jailops firewall test` line that asks the same question. */
export function commandOf(f: TestForm): string {
  const r = toRequest(f)
  const parts = ['jailops', 'firewall', 'test', '--from', r.from, '--to', r.to]
  if (r.proto && r.proto !== 'tcp') parts.push('--proto', r.proto)
  if (r.port) parts.push('--port', String(r.port))
  if (r.icmp_type) parts.push('--icmp-type', r.icmp_type)
  if (r.family) parts.push('--family', r.family)
  return parts.join(' ')
}

// The form lives in the address of the page, so a result can be linked and reloaded.
const KEYS = { from: 'from', to: 'to', proto: 'proto', port: 'port', icmpType: 'type', family: 'family' } as const

export function formFromQuery(q: Record<string, unknown>): TestForm {
  const str = (k: string): string => (typeof q[k] === 'string' ? (q[k] as string) : '')
  const proto = str(KEYS.proto) as Proto
  const fam = str(KEYS.family)
  return {
    from: str(KEYS.from), to: str(KEYS.to), proto: PROTOS.includes(proto) ? proto : 'tcp', port: str(KEYS.port),
    icmpType: str(KEYS.icmpType), family: fam === '4' || fam === '6' ? fam : '',
  }
}

/** The query that holds a form: only what differs from the blank form, so a plain page has a plain address. */
export function queryOf(f: TestForm): Record<string, string> {
  const q: Record<string, string> = {}
  if (f.from.trim()) q[KEYS.from] = f.from.trim()
  if (f.to.trim()) q[KEYS.to] = f.to.trim()
  if (f.proto !== 'tcp') q[KEYS.proto] = f.proto
  if (f.port.trim()) q[KEYS.port] = f.port.trim()
  if (f.icmpType.trim()) q[KEYS.icmpType] = f.icmpType.trim()
  if (f.family) q[KEYS.family] = f.family
  return q
}

export const QUERY_KEYS: readonly string[] = Object.values(KEYS)

/** True when a query names a question that can be asked at once (a link to a result). */
export const askable = (q: Record<string, unknown>): boolean => !!q[KEYS.from] && !!q[KEYS.to] && formValid(formFromQuery(q))

/** Which families an end has: a jail by its addresses, an address by its own, the host both (it has a gateway in each). */
export function endFamilies(v: string, jailAddresses: (name: string) => string[]): Array<'4' | '6'> {
  const t = v.trim()
  switch (endKind(t)) {
    case 'host': return ['4', '6']
    case 'address': return t.includes(':') ? ['6'] : ['4']
    case 'jail': {
      const fams = new Set<'4' | '6'>()
      for (const a of jailAddresses(t.replace(/^jail:/, ''))) fams.add(a.includes(':') ? '6' : '4')
      return [...fams].sort()
    }
  }
  return []
}

/** The family selector is offered only when both ends have both families: otherwise the answer is one case anyway. */
export const familyChoice = (a: Array<'4' | '6'>, b: Array<'4' | '6'>): boolean => a.length === 2 && b.length === 2

// ---- the flow of a result -------------------------------------------------------------------------------------

export type Verdict = 'pass' | 'block' | 'unknown'
export const verdictOf = (v: string): Verdict => (v === 'pass' || v === 'block' ? v : 'unknown')

/** What decided a hop, in the words of the console. `by` is the rule's own stage, the rest says which one. */
export type DecisionKind = 'policy' | 'projectPolicy' | 'managedPolicy' | 'default' | 'isolation' | 'fixed' | 'none'
export interface Decision {
  kind: DecisionKind
  stage: string
  policy?: string
  rule?: number
  name?: string
  comment?: string
  pf: string
}

export function decisionOf(r: FirewallTestRule | undefined): Decision {
  if (!r) return { kind: 'none', stage: '', pf: '' }
  const base = { stage: r.stage, policy: r.policy, rule: r.rule, name: r.name, comment: r.comment, pf: r.pf }
  switch (r.stage) {
    case 'policy': return { ...base, kind: r.managed ? 'managedPolicy' : r.project_policy ? 'projectPolicy' : 'policy' }
    case 'default': return { ...base, kind: 'default' }
    case 'isolation': return { ...base, kind: 'isolation' }
    default: return { ...base, kind: 'fixed' }
  }
}

export interface SkippedView {
  decision: Decision
  why: string
}

export interface HopView {
  key: string
  side: 'source' | 'destination'
  jail: string
  anchor: string
  direction: string
  verdict: Verdict
  decision: Decision
  /** What could not be decided (a verdict of unknown). */
  why: string
  skipped: SkippedView[]
  /** The loaded rules differ from the rendered ones. */
  drift: boolean
}

export interface CaseView {
  key: string
  family: '4' | '6'
  from: string
  to: string
  proto: string
  port: number
  icmpType: string
  verdict: Verdict
  hops: HopView[]
  /** The destination was not reached: a hop blocked or could not say. */
  stopped: boolean
}

function hopView(h: FirewallTestHop, i: number): HopView {
  return {
    key: `${h.side}-${i}`, side: h.side === 'destination' ? 'destination' : 'source', jail: h.jail, anchor: h.anchor,
    direction: h.direction, verdict: verdictOf(h.verdict),
    decision: decisionOf(h.decided_by), why: h.why ?? '',
    skipped: (h.skipped ?? []).map((k) => ({ decision: decisionOf(k.rule), why: k.why })),
    drift: h.loaded_matches_rendered === 'false',
  }
}

/** The cases of a result, one per address family, as the flow draws them. The hops are the server's, in its order. */
export function caseViews(r: FirewallTestResult): CaseView[] {
  return r.cases.map((c: FirewallTestCase, i) => {
    const hops = (c.hops ?? []).map(hopView)
    return {
      key: `${c.family}-${i}`, family: c.family === 'inet6' ? '6' : '4', from: c.from, to: c.to, proto: c.proto, port: c.port ?? 0,
      icmpType: c.icmp_type ?? '', verdict: verdictOf(c.verdict), hops, stopped: verdictOf(c.verdict) !== 'pass',
    }
  })
}

/** The line that names a case: `tcp port 5432` or `icmp echoreq`. */
export function packetOf(c: CaseView): string {
  if (c.port) return `${c.proto} port ${c.port}`
  return c.icmpType ? `${c.proto} ${c.icmpType}` : c.proto
}
