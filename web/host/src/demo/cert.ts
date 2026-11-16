// The certificate of the console in the demo: self-signed at first; an upload, an ACME request (which turns valid a
// moment later, like a CA that answered) and the way back behave like the daemon, with its messages.
import type { ACMESpec, CertificateInfo, HostCertificate } from '@jailops/shared/api/types'
import type { ApiErrorBody } from '@jailops/shared/api/types'
import { acmeDomainProblem, acmeEmailProblem, ACME_PRODUCTION, ACME_STAGING } from '@/lib/setup'
import { validDNSName, hostAddr } from '@/lib/host'

const HOST = 'bsd01.example.net'
const PORT = 39110
const DAY = 86400_000
const fp = (seed: string) => Array.from({ length: 64 }, (_, i) => '0123456789abcdef'[(seed.charCodeAt(i % seed.length) * (i + 7)) % 16]).join('')

export interface CertState {
  source: HostCertificate['source']
  current: CertificateInfo
  acme: (ACMESpec & { readyAt: number; issued: boolean }) | null
}

function info(names: string[], issuer: string, days: number, self: boolean, pub: boolean): CertificateInfo {
  const now = Date.now()
  return { subject: `CN=${names[0]}`, issuer, names, not_before: new Date(now - DAY).toISOString(), not_after: new Date(now + days * DAY).toISOString(),
    days_left: days, fingerprint: fp(names.join() + issuer), self_signed: self, public_ca: pub }
}

export function certState(): CertState {
  return { source: 'self-signed', current: info([HOST, 'localhost'], `CN=${HOST}`, 3650, true, false), acme: null }
}

/** Settles a request whose time has come, then answers GET /host/certificate. */
export function certificate(st: CertState, now = Date.now()): HostCertificate {
  const a = st.acme
  if (a && !a.issued && now >= a.readyAt) {
    a.issued = true
    const staging = a.directory_url === ACME_STAGING
    st.current = info(a.domains, staging ? 'CN=(STAGING) Demo Issuing CA' : 'CN=Demo Issuing CA', 90, false, !staging)
  }
  const out: HostCertificate = { kind: 'HostCertificate', source: st.source, current: structuredClone(st.current), configured: false, listener: true }
  const host = st.source === 'self-signed' ? HOST : st.current.names[0]
  out.remote_add = st.current.public_ca ? `jailops remote add bsd01 https://${host}:${PORT} --token-file -` : `jailops remote add bsd01 https://${host}:${PORT} --fingerprint ${st.current.fingerprint} --token-file -`
  if (st.source === 'acme' && a) {
    const ch = a.challenge ?? 'http-01'
    out.stored = true
    out.acme = { spec: { enabled: true, domains: a.domains, email: a.email, directory_url: a.directory_url, challenge: ch, accept_tos: true },
      state: a.issued ? 'valid' : 'requesting', challenge_port: ch === 'tls-alpn-01' ? PORT : 39080, terms_url: 'https://ca.example.com/terms.pdf',
      last_attempt: new Date(a.readyAt - 1500).toISOString(), ...(a.issued ? { last_success: new Date(a.readyAt).toISOString(), renew_at: new Date(Date.parse(st.current.not_after) - 30 * DAY).toISOString() } : {}) }
    out.redirect = { managed: true, applied: false }
  }
  if (st.source === 'uploaded') out.stored = true
  if (st.current.self_signed) out.warnings = ['the certificate is self-signed: browsers warn, and clients pin its fingerprint']
  return out
}

type Answer = HostCertificate | { status: number; error: ApiErrorBody }
const bad = (message: string, code: ApiErrorBody['code'] = 'invalid', hint?: string): Answer => ({ status: 400, error: { code, message, ...(hint ? { hint } : {}) } })

export function upload(st: CertState, b: { certificate?: string; key?: string; hostname?: string }): Answer {
  const cert = String(b.certificate ?? '')
  const key = String(b.key ?? '')
  const host = String(b.hostname ?? '').trim()
  if (!/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(cert)) return bad('the certificate chain does not parse: no PEM CERTIFICATE block')
  if (!/-----BEGIN ([A-Z]+ )?PRIVATE KEY-----[\s\S]+-----END ([A-Z]+ )?PRIVATE KEY-----/.test(key)) return bad('the key does not parse: no PEM PRIVATE KEY block')
  if (!host || (!validDNSName(host) && !hostAddr(host))) return bad(`host name "${host}" is not a DNS name or an address`)
  if (/EXPIRED/.test(cert)) return bad('the certificate expired', 'invalid', 'renew it, then upload the new one')
  if (/WRONGKEY/.test(key)) return bad('the key does not match the certificate')
  st.source = 'uploaded'
  st.acme = null
  st.current = info([host], 'CN=Example Internal CA', 365, false, false)
  return certificate(st)
}

export function useAcme(st: CertState, b: ACMESpec, speed: number): Answer {
  const domains = (b.domains ?? []).map((d) => d.toLowerCase())
  if (!domains.length) return bad('ACME needs at least one domain: the name the console is reached by')
  for (const d of domains) {
    const p = acmeDomainProblem(d)
    if (p) return bad(`"${d}" is ${p.startsWith('wildcard') ? 'a wildcard name: ' : ''}${p}`, p.startsWith('wildcard') ? 'unsupported' : 'invalid')
  }
  const em = acmeEmailProblem(b.email ?? '')
  if (em) return bad(`"${b.email}" is ${em}`)
  if (!b.accept_tos) return bad("accept_tos must be true: ACME needs your agreement to the CA's terms of service")
  const dir = b.directory_url || ACME_PRODUCTION
  if (!dir.startsWith('https://')) return bad(`directory_url "${dir}" must be an https URL`)
  st.source = 'acme'
  st.acme = { ...b, domains, directory_url: dir, readyAt: Date.now() + 1500 / speed, issued: false }
  return certificate(st)
}

export function useSelfSigned(st: CertState): HostCertificate {
  Object.assign(st, certState())
  return certificate(st)
}
