// The objects of the host API by their first path segments, with the console page of each, so the operations and
// audit pages link an object by name instead of showing its API path (shared lib/describe.ts does the parsing).
import type { KindMap } from '@jailops/shared/lib/describe'

const e = encodeURIComponent

export const hostKinds: KindMap = {
  jails: { kind: 'jail', to: (n) => `/jails/${e(n)}` },
  images: { kind: 'image', to: () => '/images' },
  apps: { kind: 'app', to: (n) => `/apps/${e(n)}` },
  networks: { kind: 'network', to: () => '/networks' },
  wireguard: { kind: 'tunnel', to: () => '/networks/wireguard' },
  'firewall/policies': { kind: 'firewall policy', to: (n) => `/firewall?policy=${e(n)}` },
  'firewall/address-sets': { kind: 'address set', to: () => '/firewall?tab=sets' },
  firewall: { kind: 'firewall' },
  projects: { kind: 'project', to: (n) => `/projects/${e(n)}` },
  storage: { kind: 'storage', to: () => '/storage' },
  profiles: { kind: 'profile', to: () => '/profiles' },
  backups: { kind: 'backup', to: () => '/backups' },
  'backup-policies': { kind: 'backup policy', to: () => '/backups?tab=policies' },
  'backup-targets': { kind: 'backup target', to: () => '/backups?tab=targets' },
  restores: { kind: 'restore', to: () => '/backups' },
  tokens: { kind: 'token', to: () => '/access?tab=tokens' },
  users: { kind: 'user', to: () => '/access?tab=users' },
  certificates: { kind: 'certificate', to: () => '/access?tab=certs' },
  sessions: { kind: 'session', to: () => '/access?tab=sessions' },
  trust: { kind: 'trust' },
  remotes: { kind: 'host', to: () => '/hosts' },
  host: { kind: 'host setting', to: () => '/host' },
  logs: { kind: 'logs', to: () => '/logs' },
  updates: { kind: 'updates', to: () => '/updates' },
  operations: { kind: 'operation', to: () => '/operations' },
}

/** Every API path of an operation's resources, flattened (the map is keyed by kind). */
export function resourcePaths(r: Record<string, string[]> | undefined): string[] {
  return Object.values(r ?? {}).flat()
}
