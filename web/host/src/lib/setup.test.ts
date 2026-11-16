import { describe, expect, it } from 'vitest'
import {
  passwordProblem, validUserName, cleanToken, acmeDomainProblem, acmeEmailProblem, acmeProblems, acmeSpec, domainList, pemProblems,
  publicRemoteAddCommand, setupFirewall, setupNetwork, nextStep, skippable, STEPS, ACME_PRODUCTION, ACME_STAGING,
} from './setup'
import { remoteAddCommand } from './trust'

const CERT = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n'
const KEY = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\n'

describe('the password policy (auth.CheckPasswordPolicy)', () => {
  it.each([
    ['short', 'admin', 'at least 12 characters'],
    ['aaaaaaaaaaaaaaaa', 'admin', 'at least 5 different characters'],
    ['Password1234', 'admin', 'not a common password'],
    ['my-admin-is-great', 'admin', 'must not contain the user name'],
    ['ab-long-passphrase', 'ab', ''],
    ['correct horse battery', 'admin', ''],
    ['x'.repeat(10) + 'é'.repeat(124) + 'abcd', 'admin', 'at most 256 bytes'],
  ])('%s for %s', (pw, name, want) => {
    expect(passwordProblem(pw, name)).toBe(want)
  })
  it('counts characters, not bytes, for the minimum', () => {
    expect(passwordProblem('éèêëàâäôöûüç', 'admin')).toBe('')
  })
})

describe('names and tokens', () => {
  it('accepts the names the server accepts', () => {
    for (const n of ['admin', 'ops.team', 'a_b-c', '0']) expect(validUserName(n)).toBe(true)
    for (const n of ['', 'Admin', '.hidden', 'a b', 'x'.repeat(129), 'ä']) expect(validUserName(n)).toBe(false)
  })
  it('drops what a person adds to a token', () => {
    expect(cleanToken(' abcd-efgh ijkl\n')).toBe('ABCDEFGHIJKL')
  })
})

describe('ACME checks (api.ValidACMEDomain, api.ValidACMEEmail)', () => {
  it.each([
    ['console.example.com', ''],
    ['*.example.com', 'wildcard names need the dns-01 challenge, which JailOps does not offer'],
    ['192.0.2.10', 'an address: ACME certificates here are for DNS names only'],
    ['2001:db8::1', 'an address: ACME certificates here are for DNS names only'],
    ['localhost', 'not a fully qualified name'],
    ['bad_name.example.com', 'not a DNS name'],
    ['-x.example.com', 'not a DNS name'],
    ['example.com.', 'not a DNS name'],
  ])('domain %s', (d, want) => expect(acmeDomainProblem(d)).toBe(want))
  it.each([
    ['', ''],
    ['ops@example.com', ''],
    ['Ops <ops@example.com>', 'not an email address'],
    ['ops', 'not an email address'],
    ['ops@localhost', 'not an email address with a domain'],
    ['a@b@example.com', 'not an email address'],
  ])('email %s', (e, want) => expect(acmeEmailProblem(e)).toBe(want))
  it('needs a name and the terms, and finds a duplicate', () => {
    const f = { domains: '', email: '', challenge: 'http-01' as const, staging: false, terms: false }
    expect(Object.keys(acmeProblems(f)).sort()).toEqual(['domains', 'terms'])
    expect(acmeProblems({ ...f, domains: 'a.example.com A.example.com', terms: true }).domains).toBe('a name is listed twice')
    expect(acmeProblems({ ...f, domains: 'a.example.com *.example.com', terms: true }).domains).toMatch(/^\*\.example\.com: wildcard/)
    expect(acmeProblems({ ...f, domains: 'a.example.com', terms: true })).toEqual({})
  })
  it('builds the spec with the chosen directory', () => {
    const f = { domains: 'A.example.com, b.example.com', email: ' ops@example.com ', challenge: 'tls-alpn-01' as const, staging: true, terms: true }
    expect(acmeSpec(f)).toEqual({ enabled: true, domains: ['a.example.com', 'b.example.com'], email: 'ops@example.com', challenge: 'tls-alpn-01', directory_url: ACME_STAGING, accept_tos: true })
    expect(acmeSpec({ ...f, staging: false, email: '' }).directory_url).toBe(ACME_PRODUCTION)
    expect(domainList(' a.example.com,,b.example.com ')).toEqual(['a.example.com', 'b.example.com'])
  })
})

describe('the upload form', () => {
  it('needs a certificate block, a key block and a name', () => {
    expect(pemProblems(CERT, KEY, 'console.example.com')).toEqual({})
    expect(pemProblems(CERT, KEY, '192.0.2.10')).toEqual({})
    expect(Object.keys(pemProblems('', '', '')).sort()).toEqual(['certificate', 'hostname', 'key'])
    expect(pemProblems(KEY, KEY, 'x.example.com').certificate).toMatch(/PEM form/)
    expect(pemProblems(CERT + KEY, KEY, 'x.example.com').certificate).toMatch(/private key/)
    expect(pemProblems(CERT, '-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----', 'x.example.com')).toEqual({})
    expect(pemProblems(CERT, KEY, 'not a name').hostname).toBe('not a host name or an address')
  })
})

describe('the remote add commands', () => {
  it('pins nothing with a public certificate, and keeps the trust token form', () => {
    expect(publicRemoteAddCommand('bsd01', 'console.example.com:39110')).toBe('jailops remote add bsd01 https://console.example.com:39110 --token-file -')
    expect(remoteAddCommand('host.example:8443', 'jbc_x.y')).toBe('jailops remote add myhost host.example:8443 --token jbc_x.y')
  })
})

describe('the wizard', () => {
  it('walks the steps in order; only the account cannot be skipped', () => {
    expect(STEPS.map((s) => nextStep(s))).toEqual(['identity', 'certificate', 'firewall', 'defaults', 'image', 'done', 'done'])
    expect(STEPS.filter(skippable)).toEqual(['identity', 'certificate', 'firewall', 'defaults', 'image'])
  })
  it('proposes ssh from the browser only', () => {
    expect(setupFirewall('203.0.113.5')).toEqual({ template: 'default', ssh: { ports: [22], allow_from: ['203.0.113.5'] }, console: {}, icmp: true })
    expect(setupFirewall('').ssh).toEqual({ ports: [22] })
  })
  it('proposes a network with NAT through the uplink, for any prefix the server takes', () => {
    expect(setupNetwork('10.77.0.0/24', 'em0')).toEqual({ uplink: 'em0', ipv4: { subnet: '10.77.0.0/24', gateway: '10.77.0.1', range: '10.77.0.2-10.77.0.254', nat: true } })
    expect(setupNetwork('10.77.0.0/24', '')?.ipv4?.nat).toBe(false)
    expect(setupNetwork('10.77.0.0/16', 'em0')?.ipv4?.range).toBe('10.77.0.2-10.77.255.254')
    expect(setupNetwork('10.77.0.0/31', 'em0')).toBeNull()
    expect(setupNetwork('nonsense', '')).toBeNull()
  })
})
