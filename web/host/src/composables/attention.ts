import type { Jail, Network, Remote, Backup, PoolUsage, DoctorReport } from '@jailops/shared/api/types'
import { s } from '@/i18n'
import { percent, sentence } from '@jailops/shared/lib/format'
import { codeText } from '@jailops/shared/lib/describe'

export interface Attention {
  key: string
  tone: 'danger' | 'warn'
  text: string
  to?: string
}

export interface AttentionInput {
  jails?: Jail[]
  networks?: Network[]
  remotes?: Remote[]
  backups?: Backup[]
  pool?: PoolUsage
  doctor?: DoctorReport
}

/** Conditions first (danger before warn), as the operator scans top-down. */
export function attention(i: AttentionInput): Attention[] {
  const out: Attention[] = []
  for (const j of i.jails ?? []) {
    const n = j.metadata.name
    if (j.status.power === 'error') out.push({ key: 'err:' + n, tone: 'danger', text: `${n}: ${s.state.error}`, to: `/jails/${n}` })
    for (const c of j.status.conditions ?? []) {
      if (c.status === 'False') out.push({ key: `cond:${n}:${c.type}`, tone: 'danger', text: s.overview.condition(n, c.reason ? codeText(c.reason) : sentence(c.type), c.message ?? ''), to: `/jails/${n}` })
    }
    const d = j.status.drift?.length ?? 0
    if (d) out.push({ key: 'drift:' + n, tone: 'warn', text: `${n}: ${s.overview.drift(d)}`, to: `/jails/${n}` })
  }
  for (const n of i.networks ?? []) {
    const name = n.metadata.name
    const orphans = n.status.orphans?.length ?? 0
    if (orphans) out.push({ key: 'orph:' + name, tone: 'warn', text: `${name}: ${s.overview.orphans(orphans)}`, to: '/networks' })
    const total = (n.status.allocated ?? 0) + (n.status.free ?? 0)
    if (total > 0 && (n.status.free ?? 0) <= Math.max(2, total * 0.05)) out.push({ key: 'free:' + name, tone: 'warn', text: s.overview.lowAddresses(name, n.status.free ?? 0), to: '/networks' })
  }
  for (const r of i.remotes ?? []) if (!r.status.online) out.push({ key: 'rem:' + r.metadata.name, tone: 'danger', text: s.overview.hostOffline(r.metadata.name), to: '/hosts' })
  for (const b of i.backups ?? []) {
    if (b.status.failed) out.push({ key: 'bfail:' + b.metadata.name, tone: 'danger', text: s.overview.backupFailed(b.spec.jail, b.spec.snapshot), to: '/backups' })
  }
  const latest = new Map<string, Backup>()
  for (const b of [...(i.backups ?? [])].sort((x, y) => (x.metadata.created_at ?? '').localeCompare(y.metadata.created_at ?? ''))) latest.set((b.spec.kind === 'volume' ? 'volume:' : 'jail:') + b.spec.jail, b)
  for (const b of latest.values()) if (!b.status.failed && !b.status.verified) out.push({ key: 'bunver:' + (b.spec.kind === 'volume' ? 'volume:' : '') + b.spec.jail, tone: 'warn', text: s.overview.backupUnverified(b.spec.jail), to: '/backups' })
  const fails = (i.doctor?.checks ?? []).filter((c) => c.status === 'fail').length
  const warns = (i.doctor?.checks ?? []).filter((c) => c.status === 'warn').length
  if (fails) out.push({ key: 'doctor-fail', tone: 'danger', text: s.doctor.failing(fails), to: '/doctor' })
  if (warns) out.push({ key: 'doctor-warn', tone: 'warn', text: s.doctor.warning(warns), to: '/doctor' })
  if (i.pool) {
    const p = Math.round(percent(i.pool.allocated, i.pool.size))
    if (p >= 85) out.push({ key: 'pool', tone: p >= 95 ? 'danger' : 'warn', text: s.overview.poolFull(p) })
  }
  return out.sort((a, b) => (a.tone === b.tone ? 0 : a.tone === 'danger' ? -1 : 1))
}
