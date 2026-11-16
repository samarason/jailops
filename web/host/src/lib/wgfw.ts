// Whether the host firewall that JailOps manages lets peers reach a WireGuard listen port, and the spec that adds the
// one row it needs. The template decides first: "open" passes everything, "default" passes only ssh and the console,
// "custom-rules" passes its allow list as well.
import type { HostFirewall, HostFirewallSpec } from '@jailops/shared/api/types'
import { clone } from './clone'

export type WgCover =
  | { state: 'unmanaged' }
  | { state: 'open' }
  | { state: 'allowed'; from: string[] }
  | { state: 'missing' }

/** A port list entry ("51820" or "51000-52000") that contains port. */
export function portIn(entry: string, port: number): boolean {
  const [lo, hi] = entry.split('-').map((x) => Number(x.trim()))
  if (!Number.isInteger(lo)) return false
  return hi === undefined || Number.isNaN(hi) ? lo === port : lo <= port && port <= hi
}

export function wgCover(fw: HostFirewall | undefined, port: number): WgCover {
  if (!fw || !fw.status.managed) return { state: 'unmanaged' }
  const sp = fw.status.applied ?? fw.spec
  if (sp.template === 'open') return { state: 'open' }
  if (sp.template === 'custom-rules') {
    const row = (sp.allow ?? []).find((a) => a.proto === 'udp' && a.ports.some((p) => portIn(p, port)))
    if (row) return { state: 'allowed', from: row.from ?? [] }
  }
  return { state: 'missing' }
}

/** The applied spec with an allow row for udp port; the default template becomes custom-rules (default plus the list). */
export function withWgAllow(fw: HostFirewall, port: number, comment: string): HostFirewallSpec {
  const sp = clone(fw.status.applied ?? fw.spec)
  if (sp.template === 'default') sp.template = 'custom-rules'
  sp.allow = [...(sp.allow ?? []), { proto: 'udp', ports: [String(port)], comment: comment.slice(0, 80) }]
  return sp
}
