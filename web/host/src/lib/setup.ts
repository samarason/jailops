// Pure helpers of the first-run wizard and the certificate panel. They catch typing mistakes early; the server's
// checks are the authority (auth.CheckPasswordPolicy, service.ValidObjectName, api.ValidACMEDomain and
// api.ValidACMEEmail) and its message is shown as it comes.
import type { ACMEChallenge, ACMESpec, HostFirewallSpec, NetworkSpec } from '@jailops/shared/api/types'
import { validDNSName, hostAddr } from './host'
import { parseV4Cidr } from './netform'

export const MIN_PASSWORD = 12
export const MAX_PASSWORD_BYTES = 256
export const MAX_ACME_DOMAINS = 20
export const ACME_PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory'
export const ACME_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
export const SETUP_CONFIRM_WITHIN = 120

// The server's list of passwords it refuses outright (internal/auth/password.go).
const COMMON = new Set(['password1234', '123456789012', 'qwertyuiopas', 'iloveyou1234', 'administrator', 'passwordpassword', 'letmein12345',
  'changeme1234', 'freebsdfreebsd', 'jailopsjailops', 'welcome12345', '123456123456'])

/** The first rule a password breaks, or '' when it passes: the server's policy. */
export function passwordProblem(pw: string, name: string): string {
  const runes = [...pw]
  if (runes.length < MIN_PASSWORD) return `at least ${MIN_PASSWORD} characters`
  if (new TextEncoder().encode(pw).length > MAX_PASSWORD_BYTES) return `at most ${MAX_PASSWORD_BYTES} bytes`
  if (new Set(runes).size < 5) return 'at least 5 different characters'
  const low = pw.toLowerCase()
  if (COMMON.has(low)) return 'not a common password'
  if (name.length >= 3 && low.includes(name.toLowerCase())) return 'must not contain the user name'
  return ''
}

/** A user name the server accepts: lower-case letters, digits, '-', '_' and '.', not starting with '.', 1 to 128. */
export function validUserName(n: string): boolean {
  return n.length >= 1 && n.length <= 128 && /^[a-z0-9._-]+$/.test(n) && !n.startsWith('.')
}

/** A setup token as the daemon prints it: base32 letters and digits (spaces and dashes a person adds are dropped). */
export function cleanToken(t: string): string {
  return t.replace(/[\s-]+/g, '').toUpperCase()
}

/** The problem of one ACME domain, or '' (mirrors api.ValidACMEDomain). */
export function acmeDomainProblem(d: string): string {
  if (d.startsWith('*.')) return 'wildcard names need the dns-01 challenge, which JailOps does not offer'
  if (hostAddr(d.replace(/^\[|\]$/g, ''))) return 'an address: ACME certificates here are for DNS names only'
  if (!validDNSName(d) || d.endsWith('.')) return 'not a DNS name'
  if (!d.includes('.')) return 'not a fully qualified name'
  return ''
}

/** The domains of a text field: split on spaces and commas, lower case. */
export const domainList = (s: string): string[] => s.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean)

/** The problem of an optional contact address, or '' (mirrors api.ValidACMEEmail). */
export function acmeEmailProblem(e: string): string {
  if (!e) return ''
  if (e.length > 254 || /[\s<>"]/.test(e)) return 'not an email address'
  const at = e.lastIndexOf('@')
  if (at < 1 || at === e.length - 1 || e.indexOf('@') !== at) return 'not an email address'
  if (!e.slice(at + 1).includes('.')) return 'not an email address with a domain'
  return ''
}

export interface AcmeForm { domains: string; email: string; challenge: ACMEChallenge; staging: boolean; terms: boolean }

/** Field problems of the ACME form; an empty object when it can be sent. */
export function acmeProblems(f: AcmeForm): Record<string, string> {
  const e: Record<string, string> = {}
  const ds = domainList(f.domains)
  if (!ds.length) e.domains = 'at least one name: the name the console is reached by'
  else if (ds.length > MAX_ACME_DOMAINS) e.domains = `at most ${MAX_ACME_DOMAINS} names`
  else {
    for (const d of ds) {
      const p = acmeDomainProblem(d)
      if (p) { e.domains = `${d}: ${p}`; break }
    }
    if (!e.domains && new Set(ds).size !== ds.length) e.domains = 'a name is listed twice'
  }
  const em = acmeEmailProblem(f.email.trim())
  if (em) e.email = em
  if (!f.terms) e.terms = "agree to the CA's terms of service first"
  return e
}

export function acmeSpec(f: AcmeForm): ACMESpec {
  return { enabled: true, domains: domainList(f.domains), ...(f.email.trim() ? { email: f.email.trim() } : {}), challenge: f.challenge,
    directory_url: f.staging ? ACME_STAGING : ACME_PRODUCTION, accept_tos: f.terms }
}

/** The PEM checks a browser can make before an upload: a certificate block first, a private key block. */
export function pemProblems(cert: string, key: string, hostname: string): Record<string, string> {
  const e: Record<string, string> = {}
  const c = cert.trim()
  if (!/^-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.test(c)) e.certificate = 'paste the certificate chain in PEM form, the server certificate first (-----BEGIN CERTIFICATE-----)'
  else if (/PRIVATE KEY-----/.test(c)) e.certificate = 'this field holds a private key: put it below, under Key'
  if (!/-----BEGIN ([A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END ([A-Z]+ )?PRIVATE KEY-----/.test(key.trim())) e.key = 'paste the private key in PEM form (-----BEGIN PRIVATE KEY-----)'
  const h = hostname.trim()
  if (!h) e.hostname = 'the name clients use to reach the console'
  else if (!validDNSName(h.replace(/^\*\./, 'x.')) && !hostAddr(h)) e.hostname = 'not a host name or an address'
  if (cert.length + key.length > 64 * 1024) e.certificate = 'at most 64 KiB together'
  return e
}

/** The command for a client when a public CA signed the certificate: an API token, nothing pinned. */
export function publicRemoteAddCommand(name: string, host: string): string {
  return `jailops remote add ${name} https://${host} --token-file -`
}

/** The firewall the wizard proposes: the default template, ssh from the browser's address, the console from anywhere. */
export function setupFirewall(clientAddress: string): HostFirewallSpec {
  return { template: 'default', ssh: { ports: [22], ...(clientAddress ? { allow_from: [clientAddress] } : {}) }, console: {}, icmp: true }
}

/** The IPv4 prefix lengths the server accepts for a network (internal/validate/network.go). */
export const V4_MIN_BITS = 8
export const V4_MAX_BITS = 30

const v4s = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')

/** The gateway (first host) and the range (every other host) of an IPv4 subnet the server accepts: a prefix of /8 to
 *  /30 without host bits set. Null otherwise. */
export function v4Plan(subnet: string): { gateway: string; range: string } | null {
  const c = parseV4Cidr(subnet)
  if (!c || c.bits < V4_MIN_BITS || c.bits > V4_MAX_BITS) return null
  const mask = (0xffffffff << (32 - c.bits)) >>> 0
  const net = (c.base & mask) >>> 0
  if (net !== c.base) return null
  const size = 2 ** (32 - c.bits)
  return { gateway: v4s(net + 1), range: `${v4s(net + 2)}-${v4s(net + size - 2)}` }
}

/** The network the wizard proposes for a subnet: the gateway is its first address, the rest is allocated. */
export function setupNetwork(subnet: string, uplink: string): NetworkSpec | null {
  const g = v4Plan(subnet)
  if (!g) return null
  return { ...(uplink.trim() ? { uplink: uplink.trim() } : {}), ipv4: { subnet: subnet.trim(), gateway: g.gateway, range: g.range, nat: !!uplink.trim() } }
}

/** The client command of the certificate panel for a host that was just renamed: the daemon builds it with the name
 *  it started with, so the old name (short and full) is swapped for the new one. A command of another host (ACME
 *  names its own domain) is left alone. */
export function retargetRemoteAdd(cmd: string, oldName: string, newName: string): string {
  if (!cmd || !oldName || !newName || oldName === newName) return cmd
  const m = /^(jailops remote add )(\S+)( https:\/\/)([^:/\s]+)(.*)$/.exec(cmd)
  if (!m || m[4] !== oldName) return cmd
  const short = newName.split('.')[0]
  return `${m[1]}${short}${m[3]}${newName}${m[5]}`
}

export const STEPS = ['account', 'identity', 'certificate', 'firewall', 'defaults', 'image', 'done'] as const
export type Step = (typeof STEPS)[number]

/** The step after one; the account cannot be skipped, so there is no way past it but creating it. */
export function nextStep(s: Step): Step {
  const i = STEPS.indexOf(s)
  return STEPS[Math.min(i + 1, STEPS.length - 1)]
}
export const skippable = (s: Step): boolean => s !== 'account' && s !== 'done'
