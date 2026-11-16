import { describe, expect, it } from 'vitest'
import { detailToSetErrors, setMember, setNameError, setSpec, setTextOf, setUsers, validateSet } from './firewall'
import { s } from '@/i18n'
import type { AddressSet, FirewallPolicy } from '@jailops/shared/api/types'

describe('address set members as the server parses them', () => {
  it('takes addresses and CIDRs of both families, host bits included', () => {
    for (const a of ['192.0.2.1', '0.0.0.0', '192.0.2.0/24', '192.0.2.7/24', '10.0.0.0/0', '2001:db8::1', '::', '2001:db8:aa::/48', '::1.2.3.4', 'fe80::1/64', '2001:DB8::1']) expect(setMember(a), a).toBe(true)
  })
  it('refuses what netip refuses or the server rejects', () => {
    for (const a of ['', 'any', '@Office', 'tag:web', 'example.net', '192.0.2', '192.0.2.01', '256.0.0.1', '192.0.2.0/33', '192.0.2.0/024', '192.0.2.0/+8', '192.0.2.0/',
      '2001:db8::/129', 'fe80::1%em0', '::ffff:192.0.2.1', '::ffff:c000:201/120', '1::2::3', ':1', '2001:db8::12345', '192.0.2.0/24/8']) expect(setMember(a), a).toBe(false)
  })
})

describe('address set names', () => {
  it('follows the name rule (hyphens) and is not taken', () => {
    expect(setNameError('office', [], s.firewall)).toBe('')
    expect(setNameError('ops-v6', [], s.firewall)).toBe('')
    expect(setNameError('', [], s.firewall)).toBe(s.firewall.setRequired)
    expect(setNameError('a'.repeat(30), [], s.firewall)).toBe(s.firewall.setTooLong)
    expect(setNameError('a'.repeat(29), [], s.firewall)).toBe('')
    for (const n of ['Office', 'web_1', '1abc', '_x', 'a b', 'web-']) expect(setNameError(n, [], s.firewall), n).toBe(s.firewall.setBadName)
    expect(setNameError('admins', ['admins'], s.firewall)).toBe(s.firewall.setExists)
  })
})

describe('address set specs', () => {
  const others = { admins: { addresses: [{ address: '198.51.100.7' }, { address: 'set:office' }] }, office: { addresses: [{ address: '192.0.2.128/26' }] } }
  it('splits members by lines (and commas)', () => {
    expect(setSpec('192.0.2.1\n 198.51.100.0/24 ,2001:db8::1\n\n')).toEqual({ addresses: [{ address: '192.0.2.1' }, { address: '198.51.100.0/24' }, { address: '2001:db8::1' }] })
    expect(setSpec('set:office, jail:web')).toEqual({ addresses: [{ address: 'set:office' }, { address: 'jail:web' }] })
  })
  it('allows an empty set, as the server does', () => {
    expect(validateSet('empty', { addresses: [] }, others, s.firewall)).toEqual({})
  })
  it('names the first member that is no address', () => {
    expect(validateSet('x', { addresses: [{ address: '192.0.2.1' }, { address: 'nope' }, { address: 'set:office' }] }, others, s.firewall)).toEqual({ addresses: s.firewall.setMember('nope') })
  })
  it('refuses a cycle of members, with the path, and leaves a set that does not exist to the server, and allows a jail that is not there', () => {
    expect(validateSet('x', { addresses: [{ address: 'set:x' }] }, others, s.firewall).addresses).toBe(s.firewall.setCycle('x -> x'))
    // office gains the member set:admins, which has set:office as a member
    expect(validateSet('office', { addresses: [{ address: 'set:admins' }] }, { admins: others.admins }, s.firewall).addresses).toBe(s.firewall.setCycle('office -> admins -> office'))
    expect(validateSet('x', { addresses: [{ address: 'set:ghost' }] }, others, s.firewall)).toEqual({})
    expect(validateSet('x', { addresses: [{ address: 'jail:ghost' }] }, others, s.firewall)).toEqual({})
    // two paths to the same set are no cycle
    expect(validateSet('x', { addresses: [{ address: 'set:admins' }, { address: 'set:office' }] }, others, s.firewall)).toEqual({})
  })
  it('puts the server message on the field its detail names', () => {
    expect(detailToSetErrors({ message: 'address set "ghost" does not exist', detail: { field: 'addresses' } })).toEqual({ addresses: 'address set "ghost" does not exist' })
    expect(detailToSetErrors({ message: 'busy', detail: { policies: 'web' } })).toEqual({})
    expect(detailToSetErrors(null)).toEqual({})
  })
})

describe('what uses an address set', () => {
  it('finds rules with set:NAME in from or to, and sets that have it as a member', () => {
    const pol = (name: string, from: string[], to: string[] = []): FirewallPolicy => ({ metadata: { name }, spec: { rules: [{ action: 'allow', direction: 'in', from, to }] } }) as FirewallPolicy
    const set = (name: string, members: string[] = []): AddressSet => ({ metadata: { name }, spec: { addresses: members.map((address) => ({ address })) } }) as AddressSet
    const u = setUsers('office', [pol('a', ['set:office']), pol('b', [], ['set:office']), pol('c', ['set:officex', 'office', 'jail:office'])], [set('admins', ['set:office']), set('office')])
    expect(u).toEqual({ policies: ['a', 'b'], sets: ['admins'] })
  })
})

describe('setSpec reads a comment at the end of a member line', () => {
  it('takes `# text` as the comment of the one member on the line, and setTextOf writes it back', () => {
    const text = '192.0.2.9  # the office\n198.51.100.9\njail:web # the web jail\n10.0.0.1 # the lab\n10.0.0.2 # the lab, too'
    const spec = setSpec(text, 'who may connect')
    expect(spec).toEqual({
      comment: 'who may connect',
      addresses: [
        { address: '192.0.2.9', comment: 'the office' },
        { address: '198.51.100.9' },
        { address: 'jail:web', comment: 'the web jail' },
        { address: '10.0.0.1', comment: 'the lab' },
        { address: '10.0.0.2', comment: 'the lab, too' },
      ],
    })
    expect(setTextOf(setSpec(setTextOf(spec), 'who may connect'))).toBe(setTextOf(spec))
    expect(setTextOf({ addresses: [{ address: '192.0.2.9', comment: 'the office' }, { address: '198.51.100.9' }] })).toBe('192.0.2.9  # the office\n198.51.100.9')
    expect(setSpec('192.0.2.9')).toEqual({ addresses: [{ address: '192.0.2.9' }] })
    expect(setSpec('# only a comment')).toEqual({ addresses: [] })
    // two members and a comment on one line are not an address: the member check says so
    expect(validateSet('x', setSpec('10.0.0.1, 10.0.0.2  # both'), {}, s.firewall).addresses).toBe(s.firewall.setMember('10.0.0.1, 10.0.0.2'))
    expect(setSpec('192.0.2.9', '   ')).toEqual({ addresses: [{ address: '192.0.2.9' }] })
  })
})

describe('setMember accepts a jail or a set by kind', () => {
  it('takes jail:web, jail:web-2 and set:office-net, not a bad name or an @', () => {
    expect(setMember('jail:web')).toBe(true)
    expect(setMember('jail:web-2')).toBe(true)
    expect(setMember('set:office-net')).toBe(true)
    expect(setMember('jail:Web')).toBe(false)
    expect(setMember('jail:web-')).toBe(false)
    expect(setMember('jail:' + 'a'.repeat(30))).toBe(false)
    expect(setMember('set:web-2')).toBe(true)
    expect(setMember('set:web_2')).toBe(false)
    expect(setMember('@web')).toBe(false)
    expect(setMember('jail:')).toBe(false)
    expect(setMember('192.0.2.7')).toBe(true)
  })
})
