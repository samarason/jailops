import { describe, expect, it } from 'vitest'
import { allowBody, dbIssue, defaultDb, isAddressOrPrefix, isInstalledApp, isPort, sourceOf, validateAllow, type AllowForm } from './access'

const form = (o: Partial<AllowForm>): AllowForm => ({ kind: 'jail', jail: '', set: '', cidr: '', ports: '', db: '', ...o })

describe('app access: the source', () => {
  it('accepts IPv4 and IPv6 addresses and prefixes, and nothing else', () => {
    for (const ok of ['192.0.2.7', '192.0.2.0/24', '0.0.0.0/0', '2001:db8::1', '2001:db8::/64', '::/0', '::1', '2001:db8:0:0:0:0:0:1', '::ffff:192.0.2.1', 'fe80::1/10']) expect(isAddressOrPrefix(ok), ok).toBe(true)
    for (const bad of ['', 'web', '192.0.2', '192.0.2.256', '192.0.2.1/33', '192.0.2.01', '2001:db8::/129', '2001:db8:::1', '1::2::3', '1:2:3:4:5:6:7:8:9', '192.0.2.0/24/1', '@web', 'jail:web', '2001:db8::g', '192.0.2.1/']) expect(isAddressOrPrefix(bad), bad).toBe(false)
  })
  it('writes the source the way the server reads it', () => {
    expect(sourceOf(form({ kind: 'jail', jail: 'web' }))).toBe('jail:web')
    expect(sourceOf(form({ kind: 'set', set: 'office' }))).toBe('set:office')
    expect(sourceOf(form({ kind: 'cidr', cidr: ' 192.0.2.0/24 ' }))).toBe('192.0.2.0/24')
    expect(sourceOf(form({ kind: 'host' }))).toBe('host')
  })
  it('knows an installed app by its label', () => {
    expect(isInstalledApp({ metadata: { name: 'db', labels: { 'jailops.app': 'postgresql' } } } as never)).toBe(true)
    expect(isInstalledApp({ metadata: { name: 'x' } } as never)).toBe(false)
    expect(isInstalledApp(undefined)).toBe(false)
  })
})

describe('app access: the database name', () => {
  it('is strict: lower case, digits and _, never a reserved name', () => {
    expect(dbIssue('')).toBe('')
    expect(dbIssue('shop_1')).toBe('')
    expect(dbIssue('a'.repeat(63))).toBe('')
    for (const bad of ['Shop', '1shop', 'shop-db', 'a'.repeat(64), 'x"; drop', "x'y", 'a b']) expect(dbIssue(bad), bad).toBe('dbFormat')
    for (const r of ['postgres', 'public', 'template0', 'template1', 'pg_shadow']) expect(dbIssue(r), r).toBe('dbReserved')
    expect(defaultDb('web-api')).toBe('web_api')
  })
})

describe('app access: the form', () => {
  it('asks for a source of the kind chosen', () => {
    expect(validateAllow(form({ kind: 'jail' }), false).source).toBe('noJail')
    expect(validateAllow(form({ kind: 'set' }), false).source).toBe('noSet')
    expect(validateAllow(form({ kind: 'cidr', cidr: 'nope' }), false).source).toBe('cidr')
    expect(validateAllow(form({ kind: 'host' }), false)).toEqual({})
    expect(validateAllow(form({ kind: 'jail', jail: 'web' }), true)).toEqual({})
  })
  it('checks the ports', () => {
    for (const ok of ['5432', '53/udp', '80/tcp', '65535']) expect(isPort(ok), ok).toBe(true)
    for (const bad of ['0', '65536', 'http', '80/sctp', '-1']) expect(isPort(bad), bad).toBe(false)
    expect(validateAllow(form({ kind: 'host', ports: '80, 443/tcp' }), false)).toEqual({})
    expect(validateAllow(form({ kind: 'host', ports: '80,x' }), false).ports).toBe('ports')
  })
  it('needs a database name for a source that is not a jail, when the app has an access block', () => {
    expect(validateAllow(form({ kind: 'cidr', cidr: '192.0.2.7' }), true).db).toBe('dbNeeded')
    expect(validateAllow(form({ kind: 'cidr', cidr: '192.0.2.7' }), false).db).toBeUndefined()
    expect(validateAllow(form({ kind: 'jail', jail: 'web', db: 'Bad' }), true).db).toBe('dbFormat')
  })
  it('sends only what was given', () => {
    expect(allowBody(form({ kind: 'jail', jail: 'web' }), true)).toEqual({ source: 'jail:web' })
    expect(allowBody(form({ kind: 'host', ports: '80 443', db: 'x' }), false, true)).toEqual({ source: 'host', ports: ['80', '443'], dry_run: true })
    expect(allowBody(form({ kind: 'jail', jail: 'web', db: ' shop ' }), true)).toEqual({ source: 'jail:web', database: 'shop' })
  })
})
