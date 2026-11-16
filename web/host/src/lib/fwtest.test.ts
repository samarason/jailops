import { describe, expect, it } from 'vitest'
import type { FirewallTestResult } from '@jailops/shared/api/types'
import { askable, blankForm, caseViews, commandOf, decisionOf, endFamilies, endKind, endValue, familyChoice, formFromQuery, formIssues, packetOf, queryOf, toRequest, verdictOf } from './fwtest'

const form = (o: Partial<ReturnType<typeof blankForm>>) => ({ ...blankForm(), ...o })

describe('the ends of a test', () => {
  it('knows a jail, an address and the host', () => {
    expect(endKind('jail:web')).toBe('jail')
    expect(endKind('jail:web-2')).toBe('jail')
    expect(endKind('web')).toBe('')
    expect(endKind('@web')).toBe('')
    expect(endKind('set:office')).toBe('')
    expect(endKind('jail:')).toBe('')
    expect(endKind('host')).toBe('host')
    expect(endKind('10.20.0.12')).toBe('address')
    expect(endKind('2001:db8::7')).toBe('address')
    expect(endKind('192.0.2.0/24')).toBe('')
    expect(endKind('@')).toBe('')
    expect(endKind('10.20.0')).toBe('')
    expect(endKind('')).toBe('')
  })
  it('keeps what was typed, without the spaces around it', () => {
    expect(endValue(' jail:web ')).toBe('jail:web')
    expect(endValue('host')).toBe('host')
    expect(endValue('10.20.0.12')).toBe('10.20.0.12')
  })
})

describe('the form', () => {
  it('needs both ends, and a port for tcp and udp', () => {
    expect(formIssues(blankForm())).toEqual({ from: 'required', to: 'required', port: 'portRequired' })
    expect(formIssues(form({ from: 'jail:web', to: 'jail:db', port: '5432' }))).toEqual({})
  })
  it('checks the port', () => {
    for (const p of ['0', '65536', '80a', '-1', '08']) expect(formIssues(form({ from: 'jail:web', to: 'jail:db', port: p })).port).toBe('portBad')
    expect(formIssues(form({ from: 'jail:web', to: 'jail:db', port: '65535' })).port).toBeUndefined()
  })
  it('does not ask for a port of a ping, and checks the ICMP type', () => {
    expect(formIssues(form({ from: 'jail:web', to: 'jail:db', proto: 'icmp' }))).toEqual({})
    expect(formIssues(form({ from: 'jail:web', to: 'jail:db', proto: 'icmp', icmpType: 'Echo Request' })).icmpType).toBe('icmpBad')
    expect(formIssues(form({ from: 'jail:web', to: 'jail:db', proto: 'icmp6', icmpType: 'echoreq' }))).toEqual({})
  })
  it('refuses the same end twice', () => {
    expect(formIssues(form({ from: ' jail:web', to: 'jail:web', port: '80' })).to).toBe('same')
  })
  it('builds the request', () => {
    expect(toRequest(form({ from: 'jail:web', to: 'jail:db', port: '5432' }))).toEqual({ from: 'jail:web', to: 'jail:db', proto: 'tcp', port: 5432 })
    expect(toRequest(form({ from: 'jail:web', to: 'host', proto: 'icmp', icmpType: 'echoreq', family: '4' }))).toEqual({ from: 'jail:web', to: 'host', proto: 'icmp', icmp_type: 'echoreq', family: '4' })
  })
})

describe('the command line', () => {
  it('is the same question', () => {
    expect(commandOf(form({ from: 'jail:web', to: 'jail:db', port: '5432' }))).toBe('jailops firewall test --from jail:web --to jail:db --port 5432')
    expect(commandOf(form({ from: '192.0.2.7', to: 'jail:web', proto: 'udp', port: '53', family: '4' }))).toBe('jailops firewall test --from 192.0.2.7 --to jail:web --proto udp --port 53 --family 4')
    expect(commandOf(form({ from: 'jail:web', to: 'jail:db', proto: 'icmp6', icmpType: 'echoreq' }))).toBe('jailops firewall test --from jail:web --to jail:db --proto icmp6 --icmp-type echoreq')
  })
})

describe('the address of the page', () => {
  it('holds only what differs from the blank form', () => {
    expect(queryOf(blankForm())).toEqual({})
    expect(queryOf(form({ from: 'jail:web', to: 'jail:db', port: '5432' }))).toEqual({ from: 'jail:web', to: 'jail:db', port: '5432' })
    expect(queryOf(form({ from: 'jail:web', to: 'jail:db', proto: 'icmp', icmpType: 'echoreq', family: '6' }))).toEqual({ from: 'jail:web', to: 'jail:db', proto: 'icmp', type: 'echoreq', family: '6' })
  })
  it('reads the form back, and ignores what it does not know', () => {
    const f = form({ from: 'jail:web', to: '10.20.0.12', proto: 'udp', port: '53', family: '4' })
    expect(formFromQuery(queryOf(f))).toEqual(f)
    expect(formFromQuery({ proto: 'gre', family: '5', from: ['a', 'b'] })).toEqual(blankForm())
  })
  it('asks at once only for a complete question', () => {
    expect(askable({ from: 'jail:web', to: 'jail:db', port: '5432' })).toBe(true)
    expect(askable({ from: 'jail:web', to: 'jail:db' })).toBe(false)
    expect(askable({ from: 'jail:web', to: 'jail:db', proto: 'icmp' })).toBe(true)
    expect(askable({})).toBe(false)
  })
})

describe('the families of the ends', () => {
  const addrs = (n: string) => ({ web: ['10.20.0.11/24', '2001:db8:10::11'], db: ['10.20.0.12/24'] } as Record<string, string[]>)[n] ?? []
  it('reads them from the jail, the address or the host', () => {
    expect(endFamilies('jail:web', addrs)).toEqual(['4', '6'])
    expect(endFamilies('jail:db', addrs)).toEqual(['4'])
    expect(endFamilies('2001:db8::1', addrs)).toEqual(['6'])
    expect(endFamilies('192.0.2.1', addrs)).toEqual(['4'])
    expect(endFamilies('host', addrs)).toEqual(['4', '6'])
    expect(endFamilies('jail:nobody', addrs)).toEqual([])
  })
  it('offers the choice only when both ends have both', () => {
    expect(familyChoice(['4', '6'], ['4', '6'])).toBe(true)
    expect(familyChoice(['4', '6'], ['4'])).toBe(false)
  })
})

const answer: FirewallTestResult = {
  verdict: 'block',
  caveats: ['the answer is for a new connection'],
  cases: [{
    family: 'inet', from: '10.20.0.11', to: '10.20.0.12', proto: 'tcp', port: 5433, verdict: 'block',
    hops: [
      { side: 'source', jail: 'web', anchor: 'jailops/main/web', direction: 'in', verdict: 'pass', decided_by: { stage: 'default', pf: 'pass in quick all' } },
      {
        side: 'destination', jail: 'db', anchor: 'jailops/main/db', direction: 'out', verdict: 'block',
        decided_by: { stage: 'policy', policy: 'no-scan', rule: 2, name: 'scanner', comment: 'a scanner', pf: 'block drop out quick' },
        skipped: [{ rule: { stage: 'policy', policy: 'postgres', rule: 1, pf: 'pass out quick' }, why: 'a deny rule wins over every allow rule' }],
        loaded_matches_rendered: 'false',
      },
    ],
  }],
}

describe('the flow of a result', () => {
  it('draws a case as hops the server gave, in its order', () => {
    const [c] = caseViews(answer)
    expect(c.family).toBe('4')
    expect(c.verdict).toBe('block')
    expect(c.stopped).toBe(true)
    expect(c.hops.map((h) => [h.side, h.direction, h.verdict])).toEqual([['source', 'in', 'pass'], ['destination', 'out', 'block']])
    expect(packetOf(c)).toBe('tcp port 5433')
  })
  it('keeps what a reviewer looks for: the rule, the rules passed over, the drift', () => {
    const h = caseViews(answer)[0].hops[1]
    expect(h.decision).toMatchObject({ kind: 'policy', policy: 'no-scan', rule: 2, comment: 'a scanner' })
    expect(h.skipped).toHaveLength(1)
    expect(h.skipped[0].why).toContain('deny rule wins')
    expect(h.drift).toBe(true)
  })
  it('says which kind of rule decided', () => {
    expect(decisionOf({ stage: 'policy', policy: 'p', project_policy: true, rule: 1, pf: '' }).kind).toBe('projectPolicy')
    expect(decisionOf({ stage: 'policy', policy: 'app-db', managed: true, rule: 1, pf: '' }).kind).toBe('managedPolicy')
    expect(decisionOf({ stage: 'default', pf: '' }).kind).toBe('default')
    expect(decisionOf({ stage: 'isolation', pf: '' }).kind).toBe('isolation')
    expect(decisionOf({ stage: 'antispoof', pf: '' }).kind).toBe('fixed')
    expect(decisionOf(undefined).kind).toBe('none')
  })
  it('treats a verdict it does not know as unknown', () => {
    expect(verdictOf('pass')).toBe('pass')
    expect(verdictOf('block')).toBe('block')
    expect(verdictOf('')).toBe('unknown')
    expect(verdictOf('maybe')).toBe('unknown')
  })
  it('names an ICMP test by its type', () => {
    const r = caseViews({ verdict: 'pass', cases: [{ family: 'inet6', from: 'a', to: 'b', proto: 'icmp6', icmp_type: 'echoreq', verdict: 'pass', hops: [] }] })[0]
    expect(packetOf(r)).toBe('icmp6 echoreq')
    expect(r.family).toBe('6')
  })
})
