// Pure helpers of the WireGuard tab. They only catch typing mistakes early; the server's validator is the authority
// (overlaps, ports taken by another tunnel, interface names) and its message is shown as it comes.
import type { WireGuard, WireGuardPeerStatus } from '@jailops/shared/api/types'
import { parseV4Cidr, isV6Cidr } from './netform'
import { nameError } from './nameField'

export interface ServerForm {
  name: string
  /** Comma or space separated CIDRs, for example "10.99.0.1/24, fd99::1/64". */
  address: string
  port: string
  endpoint: string
  networks: string[]
  dns: string
}
export const blankServer = (): ServerForm => ({ name: '', address: '', port: '51820', endpoint: '', networks: [], dns: '' })

export const splitList = (s: string): string[] => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

const isV4 = (a: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(a) && a.split('.').every((o) => Number(o) <= 255)
const isV6 = (a: string) => a.includes(':') && /^[0-9a-fA-F:.]+$/.test(a)

/** Field -> message for what is plainly wrong; empty when the form may be sent. */
export function checkServer(f: ServerForm): Record<string, string> {
  const e: Record<string, string> = {}
  // the object name rule, at most 12 characters: the interface is wg-<name> (shared lib/names.ts, rule tunnel)
  if (f.name && nameError(f.name, 'tunnel')) e.name = nameError(f.name, 'tunnel')
  const addrs = splitList(f.address)
  if (f.address && !addrs.every((a) => parseV4Cidr(a) || isV6Cidr(a))) e.address = 'Give addresses with a prefix, for example 10.99.0.1/24 or fd99::1/64.'
  else if (addrs.filter((a) => !a.includes(':')).length > 1 || addrs.filter((a) => a.includes(':')).length > 1) e.address = 'At most one IPv4 and one IPv6 address.'
  const p = Number(f.port)
  if (!/^\d+$/.test(f.port) || p < 1 || p > 65535) e.port = 'A port from 1 to 65535.'
  if (f.endpoint && !/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):\d{1,5}$/.test(f.endpoint.trim())) e.endpoint = 'host:port, an IPv6 address in brackets.'
  if (f.dns && !splitList(f.dns).every((a) => isV4(a) || isV6(a))) e.dns = 'Addresses only.'
  return e
}

/** The body of POST /wireguard for a server. */
export function serverBody(f: ServerForm): Pick<WireGuard, 'metadata' | 'spec'> {
  return {
    metadata: { name: f.name.trim() } as WireGuard['metadata'],
    spec: {
      mode: 'server',
      address: splitList(f.address),
      listen_port: Number(f.port),
      ...(f.endpoint.trim() ? { endpoint: f.endpoint.trim() } : {}),
      ...(f.networks.length ? { networks: [...f.networks] } : {}),
      ...(splitList(f.dns).length ? { dns: splitList(f.dns) } : {}),
    },
  }
}

/** A join token as the server prints it; only its shape is checked here. */
export const looksLikeToken = (t: string): boolean => /^jwg1\.[A-Za-z0-9_-]{20,}$/.test(t.trim())

export interface PeerRow {
  name: string
  address: string
  publicKey: string
  handshake: string | undefined
  rx: number | undefined
  tx: number | undefined
  endpoint: string
}

/** The peer table: the enrolled peers of the spec joined with what the kernel reports, in the spec's order. */
export function peerRows(w: WireGuard): PeerRow[] {
  const st = new Map<string, WireGuardPeerStatus>((w.status.peers ?? []).map((p) => [p.public_key, p]))
  if (w.spec.mode === 'client') {
    return (w.status.peers ?? []).map((p) => ({
      name: 'server', address: (w.spec.allowed_ips ?? []).join(', '), publicKey: p.public_key,
      handshake: p.latest_handshake, rx: p.rx_bytes, tx: p.tx_bytes, endpoint: p.endpoint ?? w.spec.endpoint ?? '',
    }))
  }
  return (w.spec.peers ?? []).map((p) => {
    const s = st.get(p.public_key)
    return { name: p.name, address: (p.allowed_ips ?? []).join(', '), publicKey: p.public_key, handshake: s?.latest_handshake, rx: s?.rx_bytes, tx: s?.tx_bytes, endpoint: s?.endpoint ?? '' }
  })
}

/** "never" for a zero time, else what ago() renders. */
export function handshakeLabel(ts: string | undefined, ago: (t: string) => string, never: string): string {
  if (!ts || ts.startsWith('0001') || Date.parse(ts) <= 0 || Number.isNaN(Date.parse(ts))) return never
  return ago(ts)
}

/** The file name a peer's configuration downloads under. */
export const confFileName = (peer: string): string => `${peer.replace(/[^A-Za-z0-9_-]/g, '_') || 'peer'}.conf`

/** The address column of the list: listen port for a server, endpoint for a client. */
export function reach(w: WireGuard): string {
  return w.spec.mode === 'server' ? `:${w.spec.listen_port ?? 51820}${w.spec.endpoint ? ` (${w.spec.endpoint})` : ''}` : (w.spec.endpoint ?? '')
}
