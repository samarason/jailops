// Demo data for projects, storage, trust, profiles, updates and provisioning.
import type { Project, Storage, Session, Identity, Profile, Certificate, Jail, UpdateReport, UpdateRecord } from '@jailops/shared/api/types'

const now = Date.now()
const ago = (s: number) => new Date(now - s * 1000).toISOString()
const ahead = (s: number) => new Date(now + s * 1000).toISOString()
const GiB = 1024 ** 3
const meta = (name: string, age = 86400 * 30) => ({ name, scope: 'host' as const, generation: 2, created_at: ago(age), updated_at: ago(age / 2) })

export function stagingJails(): Jail[] {
  const mk = (name: string, power: Jail['status']['power']): Jail => ({
    metadata: { ...meta(name, 86400 * 5), project: 'staging', labels: { env: 'staging', team: name === 'stg-db' ? 'data' : 'web' } },
    spec: { image: 'freebsd-15-1', storage: 'fast', network: [{ network: 'stg', ipv4: 'auto' }], firewall: {}, boot: {}, resources: { cpu: 1, memory: '1G' } },
    status: { power, generation: 'freebsd-15-1#g4', addresses: power === 'running' ? ['10.60.0.12/28'] : [], conditions: [{ type: 'Reconciled', status: 'True' }] },
  })
  return [mk('stg-web', 'running'), mk('stg-db', 'stopped')]
}

export function projects(counts: Record<string, number>): Project[] {
  const p = (name: string, spec: Project['spec'], status: Partial<Project['status']>, fleet = false): Project => ({
    metadata: { ...meta(name), scope: fleet ? 'fleet' : 'host', ...(fleet ? { managed_by: 'hub:6a1f0c52' } : {}) },
    spec,
    status: { jails: counts[name] ?? 0, cpu: 0, memory_used: 0, disk_used: 0, addresses: 0, conditions: [], ...status },
  })
  return [
    p('web', { comment: 'The web workloads', networks: [{ network: 'lan' }, { network: 'edge' }, { network: 'backend' }], storage: [{ storage: 'default' }], quotas: {} }, { cpu: 8, memory_used: 9 * GiB, disk_used: 120 * GiB, addresses: 7 }),
    p('shop', {
      comment: 'Web shop on two hosts', hosts: ['bsd01', 'bsd02'],
      networks: [{ network: 'shop' }],
      storage: [{ storage: 'fast', quota: '500G' }, { storage: 'default', quota: '100G' }],
      quotas: { jails: 10, cpu: 16, memory: '32G', addresses: 20 }, firewall_policies: ['web-default'], images: ['freebsd-15-1'],
    }, { cpu: 14, memory_used: 27 * GiB, disk_used: 210 * GiB, addresses: 8, conditions: [{ type: 'Host:bsd02', status: 'False', reason: 'MissingStorage', message: 'bsd02 has no storage fast' }] }, true),
    p('staging', { comment: 'Disposable tests', networks: [{ network: 'stg' }], storage: [{ storage: 'fast', quota: '50G' }], quotas: { jails: 3, memory: '4G' } }, { cpu: 2, memory_used: 1 * GiB, disk_used: 8 * GiB, addresses: 1 }),
  ]
}

export function aggregate(p: Project) {
  const st = p.status
  return {
    project: p,
    hosts: [
      { host: 'bsd01', host_uuid: '6a1f', online: true, applied: true, in_sync: true, generation: 2, status: { ...st, jails: 4, cpu: 10, memory_used: 20 * GiB } },
      { host: 'bsd02', online: true, applied: false, in_sync: false, status: undefined, conditions: [{ type: 'Host:bsd02', status: 'False', reason: 'MissingStorage', message: 'bsd02 has no storage fast' }] },
      { host: 'bsd03', online: false, applied: true, in_sync: false, error: { code: 'busy', message: 'The host did not answer.' } },
    ],
    total: { ...st, jails: 4, cpu: 10, memory_used: 20 * GiB },
  }
}

export function storages(): Storage[] {
  return [
    { metadata: meta('default'), spec: { dataset: 'tank/jailops', comment: 'First storage', compression: 'lz4' }, status: { pool: 'tank', health: 'ONLINE', size: 1800 * GiB, used: 1290 * GiB, available: 510 * GiB, fragmentation: 18 } },
    { metadata: meta('fast'), spec: { dataset: 'nvme/jailops', compression: 'zstd', encrypted: true }, status: { pool: 'nvme', health: 'DEGRADED', size: 900 * GiB, used: 300 * GiB, available: 600 * GiB, fragmentation: 4, conditions: [{ type: 'Healthy', status: 'False', reason: 'Degraded' }] } },
  ]
}

export function identity(): Identity { return { user: 'alice', kind: 'user', permission: 'admin', global: true } }

export function sessions(): Session[] {
  return [
    { id: 'ses-1', user: 'alice', remote: '203.0.113.5', created_at: ago(3600), last_seen: ago(5), expires_at: ahead(36000), current: true },
    { id: 'ses-2', user: 'bob', remote: '198.51.100.9', created_at: ago(86400), last_seen: ago(7200), expires_at: ahead(3600) },
  ]
}

export function certificates(): Certificate[] {
  const c = (name: string, kind: string, permission: Certificate['spec']['permission'], extra: Partial<Certificate['spec']>): Certificate => ({ metadata: { ...meta(name), scope: 'fleet' }, spec: { fingerprint: 'SHA256:' + name.padEnd(12, 'a').split('').map((x) => x.charCodeAt(0).toString(16)).join(':'), permission, kind, ...extra } })
  return [
    c('hub-client', 'hub', 'admin', { global: true }),
    c('laptop', 'client', 'operator', { projects: ['shop'] }),
    c('ci', 'client', 'operator', { projects: ['staging', 'shop'], expires_at: ahead(86400 * 20) }),
    c('stale-cert', 'client', 'readonly', {}),
  ]
}

export function profiles(): { project: Profile[]; host: Profile[] } {
  const p = (name: string, project: string, comment: string, config: Record<string, string>): Profile => ({ metadata: { ...meta(name), project }, spec: { comment, config } })
  return {
    project: [
      p('web-limits', 'web', 'Sensible limits for web jails', { 'limits.memory': '2G', 'limits.cpu': '2', 'boot.autostart': 'true', 'nic.eth0.mtu': '1400' }),
      p('proxy-80', 'web', 'Forward port 80', { 'proxy.http.listen': ':80', 'proxy.http.jail_port': '80' }),
    ],
    host: [p('base', 'host', 'Defaults for every project', { 'limits.pids': '4096', 'update.strategy': 'rebase', 'limits.memory': '1G' })],
  }
}

export function updateReports(jails: Jail[]): UpdateReport[] {
  return jails.map((j): UpdateReport => {
    const name = j.metadata.name
    const base = { jail: name, project: j.metadata.project ?? 'web', mode: j.spec.update?.mode ?? 'manual', checked_at: ago(3600), available: false }
    if (name === 'web') return { ...base, available: true, packages: [{ name: 'nginx', from: '1.26.1', to: '1.26.3' }, { name: 'openssl', from: '3.0.15', to: '3.0.16' }], os: { from: 'freebsd-15-1#g4', to: 'freebsd-15-1#g5' } }
    if (name === 'cache' || name === 'stg-web') return { ...base, available: true, packages: [{ name: 'redis', from: '7.2.4', to: '7.2.5' }] }
    if (name === 'build') return { ...base, error: 'the jail is stopped: its packages cannot be listed' }
    return base
  })
}

export function updateHistory(name: string): UpdateRecord[] {
  if (name !== 'web') return []
  return [
    { id: 'u2', jail: name, project: 'web', kind: 'packages', result: 'ok', started: ago(86400 * 2), finished: ago(86400 * 2 - 40), snapshot: 'pre-update-20261020', packages: [{ name: 'curl', from: '8.9.0', to: '8.9.1' }], scheduled: true },
    { id: 'u1', jail: name, project: 'web', kind: 'os', result: 'rolled_back', started: ago(86400 * 9), finished: ago(86400 * 9 - 120), snapshot: 'pre-update-20261013', from: 'freebsd-15-1#g3', to: 'freebsd-15-1#g4', root_rolled_back: true, error: 'health check /usr/local/bin/check exited 1' },
  ]
}

/** The declaration and state of provisioning, put on the jails of the demo. */
export function provisionSpec(name: string): Jail['spec']['provision'] {
  if (name === 'mail') return { packages: ['postfix', 'dovecot'], services: { enable: ['postfix'], start: ['postfix'] } }
  if (name === 'web') return { packages: ['bash', 'nginx'], files: [{ source: 'templates/nginx.conf', destination: '/usr/local/etc/nginx/nginx.conf', owner: 'root', group: 'wheel', mode: '0644' }], services: { enable: ['nginx'], start: ['nginx'] }, commands: [['/usr/local/bin/nginx', '-t']] }
  return undefined
}
export const provisionedAt = (name: string) => (name === 'mail' ? undefined : ago(86400 * 30))
