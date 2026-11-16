// Typed resource calls of the host console. Paths follow sdk/PROTOCOL.md. All network access
// goes through the shared client.
import { getClient } from '@jailops/shared/api/client'
import { core } from '@jailops/shared/api/core'
import type {
  Jail, JailAction, JailRollback, JailUpgrade, JailSnapshot, Image, ImageAutoUpgrade, ImageBuild, ImageUpgrade, Network, Lease,
  FirewallPolicy, AddressSet, FirewallTestRequest, FirewallTestResult, BackupTarget, BackupPolicy, Backup, RestoreRequest, RestorePreflight,
  Certificate, User, UserCreate, UserCreated, PasswordSet, Remote, Operation, AuditEntry, MutationResult, PoolUsage, DoctorReport, Token,
  Profile, JailExpanded, ConfigChange, UpdateReport, UpdateRecord, UpdateCheckRequest, UpdateApplyRequest, ProvisionRequest, ProvisionResult, ShellSetupResult,
  BackupRun, BackupRunRequest, BackupVerifyRequest, BackupKeyStatus, BackupKeyCreate, BackupKeyCreated, BackupKeyEscrow, ExecRequest,
  Project, ProjectAggregate, Storage, TrustTokenRequest, TrustToken, Session, Identity,
  AppSummary, AppDetail, AppInstall, AppInstallResult, JailLogFile, JailLogRead,
  HostIdentity, HostIdentityApply, HostChange, HostSnapshot, HostRestore,
  HostFirewall, HostFirewallApply, HostPending,
  WireGuard, WireGuardJoin, WireGuardKeys, WireGuardPeerAdd, WireGuardPeerCreated,
  AppAccess, AppAllow, AppAllowResult, AppDeny, AppDenyResult,
  LogsRead, LogForward, LogForwardSpec, LogForwardTestResult,
  HostCertificate, HostCertificateUpload, ACMESpec, SetupStatus, SetupRequest, SetupResult,
  Rename, RenameResult,
  Volume, VolumeCreate, VolumeUnlock, VolumePassphraseChange, VolumeSnapshot, VolumeRollback, VolumeAttachRequest,
} from '@jailops/shared/api/types'
import type { SnapshotBody, ExecSessionInfo, ConfigResult } from '../types'
import { logQuery, type LogQuery } from '@/lib/logs'

const e = encodeURIComponent
const c = () => getClient()

export const api = {
  ...core,
  pool: () => c().get<PoolUsage>('/resources'),
  doctor: () => c().get<DoctorReport>('/doctor'),
  tokens: {
    list: () => c().list<Token>('/tokens'),
    create: (t: Pick<Token, 'metadata' | 'spec'>) => c().mutate<Token>('POST', '/tokens', t),
    remove: (n: string) => c().mutate('DELETE', `/tokens/${e(n)}`),
  },
  jails: {
    /** The current project's jails, or those of another project named here (the Logs page of all projects). */
    list: (project?: string) => c().list<Jail>(project ? `/jails?project=${e(project)}` : '/jails'),
    get: (n: string) => c().get<Jail>(`/jails/${e(n)}`),
    create: (j: Pick<Jail, 'metadata' | 'spec'>) => c().mutate('POST', '/jails', j),
    /** Extension volumes: attach a volume of the project to the stopped jail (async, result the jail). */
    attach: (n: string, b: VolumeAttachRequest) => c().mutate<Jail>('POST', `/jails/${e(n)}/volumes`, b),
    /** The volume and its files stay. */
    detach: (n: string, volume: string) => c().mutate<Jail>('DELETE', `/jails/${e(n)}/volumes/${e(volume)}`),
    action: (n: string, a: JailAction) => c().mutate('PUT', `/jails/${e(n)}/state`, a),
    /** A merge patch of the labels only (admin in the project): a value sets a key, null removes it, the rest stays. */
    patchLabels: (n: string, labels: Record<string, string | null>) => c().mutate<Jail>('PATCH', `/jails/${e(n)}`, { metadata: { labels } }),
    /** Async: the jail and its snapshots are destroyed; the volumes it attached stay (an installed app is uninstalled this way). */
    remove: (n: string) => c().mutate('DELETE', `/jails/${e(n)}`),
    snapshots: (n: string) => c().list<JailSnapshot>(`/jails/${e(n)}/snapshots`),
    snapshot: (n: string, b: SnapshotBody) => c().mutate('POST', `/jails/${e(n)}/snapshots`, b),
    rollback: (n: string, r: JailRollback) => c().mutate('POST', `/jails/${e(n)}/rollback`, r),
    upgrade: (n: string, r: JailUpgrade) => c().mutate('POST', `/jails/${e(n)}/upgrade`, r),
  },
  /** Extension volumes: the volumes of the current project; jails attach them by name. */
  volumes: {
    list: () => c().list<Volume>('/volumes'),
    get: (n: string) => c().get<Volume>(`/volumes/${e(n)}`),
    /** The passphrase of an encrypted volume is in the body of the creation only. */
    create: (b: VolumeCreate) => c().mutate<Volume>('POST', '/volumes', b),
    /** Labels, comment and size; the owner, the mode and the storage are fixed at creation. */
    put: (v: Volume, etag?: string) => c().mutate<Volume>('PUT', `/volumes/${e(v.metadata.name)}`, v, { etag }),
    /** Async: the files and the snapshots are destroyed; a volume a jail attaches is refused (busy). */
    remove: (n: string) => c().mutate('DELETE', `/volumes/${e(n)}`),
    // encrypted volumes: the passphrase is in the body only
    unlock: (n: string, b: VolumeUnlock) => c().mutate<Volume>('POST', `/volumes/${e(n)}/unlock`, b),
    lock: (n: string) => c().mutate<Volume>('POST', `/volumes/${e(n)}/lock`),
    passphrase: (n: string, b: VolumePassphraseChange) => c().mutate<Volume>('POST', `/volumes/${e(n)}/passphrase`, b),
    snapshots: (n: string) => c().list<VolumeSnapshot>(`/volumes/${e(n)}/snapshots`),
    snapshot: (n: string, b: { metadata: { name?: string }; spec: { volume: string; comment?: string } }) => c().mutate('POST', `/volumes/${e(n)}/snapshots`, b),
    removeSnapshot: (n: string, snap: string) => c().mutate('DELETE', `/volumes/${e(n)}/snapshots/${e(snap)}`),
    rollback: (n: string, b: VolumeRollback) => c().mutate<Volume>('POST', `/volumes/${e(n)}/rollback`, b),
  },
  apps: {
    /** Extension apps: the catalog is readable by any identity, it belongs to no project. */
    list: () => c().list<AppSummary>('/apps'),
    get: (n: string) => c().get<AppDetail>(`/apps/${e(n)}`),
    /** Extension app_install: async, operator in the project. The project travels in the query like every project request. */
    install: (n: string, b: AppInstall, project: string) => c().mutate<AppInstallResult>('POST', `/apps/${e(n)}/install${project ? `?project=${e(project)}` : ''}`, b),
  },
  host: {
    /** Extension host_identity: the values read from the host and the management state (readable when not managed). */
    identity: () => c().get<HostIdentity>('/host/identity'),
    /** Global admin. With dry_run the reply is the diff and the actions, and nothing changes. */
    apply: (b: HostIdentityApply) => c().mutate<HostChange>('PUT', '/host/identity', b),
    snapshots: () => c().list<HostSnapshot>('/host/snapshots'),
    restore: (name: string, b: HostRestore = {}) => c().mutate<HostChange>('POST', `/host/snapshots/${e(name)}/restore`, b),
    /** Extension host_firewall: the last applied spec (or the default one) and the management state. */
    firewall: () => c().get<HostFirewall>('/host/firewall'),
    /** Global admin. A real apply waits for its confirmation (reply.pending) and reverts itself without one. */
    applyFirewall: (b: HostFirewallApply) => c().mutate<HostChange>('PUT', '/host/firewall', b),
    /** Extension host_pending: the change that waits for its confirmation, and how the last one ended. */
    pending: () => c().get<HostPending>('/host/pending'),
    confirm: (id?: string) => c().mutate<HostPending>('POST', '/host/pending/confirm', id ? { id } : {}),
    revert: (id?: string) => c().mutate<HostPending>('POST', '/host/pending/revert', id ? { id } : {}),
    /** Extension host_certificate: the certificate the TLS listener serves and where it comes from. */
    certificate: () => c().get<HostCertificate>('/host/certificate'),
    /** Global admin: serve this chain and key from the next handshake on. */
    uploadCertificate: (b: HostCertificateUpload) => c().mutate<HostCertificate>('PUT', '/host/certificate', b),
    /** Global admin: ACME on; the CA is asked in the background (poll certificate() until acme.state is valid or error). */
    useAcme: (b: ACMESpec) => c().mutate<HostCertificate>('POST', '/host/certificate/acme', b),
    useSelfSigned: () => c().mutate<HostCertificate>('POST', '/host/certificate/self-signed', {}),
  },
  /** Extension setup: the first administrator. Public while none exists; not_found afterwards. */
  setup: {
    status: () => c().get<SetupStatus>('/setup'),
    run: (b: SetupRequest) => c().mutate<SetupResult>('POST', '/setup', b),
  },
  appAccess: {
    /** Extension app_access: who may connect to an installed app (readonly in the project). */
    get: (n: string) => c().get<AppAccess>(`/jails/${e(n)}/access`),
    /** Operator in the project; answered at once, not as an operation: a connection string is in this answer only. */
    allow: (n: string, b: AppAllow) => c().mutate<AppAllowResult>('POST', `/jails/${e(n)}/access`, b),
    deny: (n: string, b: AppDeny) => c().mutate<AppDenyResult>('POST', `/jails/${e(n)}/access/deny`, b),
  },
  logs: {
    /** Extension jail_logs: the files below /var/log of the jail (operator in the project). */
    list: (n: string) => c().list<JailLogFile>(`/jails/${e(n)}/logs`),
    /** A file name may hold one directory ("nginx/access.log"): each segment is encoded on its own. */
    read: (n: string, file: string, q: LogQuery = {}) => c().get<JailLogRead>(`/jails/${e(n)}/logs/${file.split('/').map(e).join('/')}${logQuery(q)}`),
    /** Extension logs_unified: the ends of many jails' files merged by time (operator). The query names the project
     *  or all_projects itself (unifiedQuery), so the project filter leaves it alone. */
    unified: (query: string) => c().get<LogsRead>(`/logs${query}`),
    /** Extension log_forward (global admin): the sinks, where the list comes from, and how each one is doing. */
    forward: () => c().getWithEtag<LogForward>('/logs/forward'),
    /** Stores the list, which then replaces logging.forward of jailopsd.yaml; If-Match is the generation read. */
    putForward: (spec: LogForwardSpec, etag?: string) => c().mutate<LogForward>('PUT', '/logs/forward', spec, { etag }),
    /** Deletes the stored list: the file's list is in force again. */
    resetForward: () => c().mutate<LogForward>('DELETE', '/logs/forward'),
    /** Sends one tagged line; a failed send is a result with ok false. */
    testForward: (sink: string) => c().mutate<LogForwardTestResult>('POST', '/logs/forward/test', { sink }),
  },
  images: {
    list: () => c().list<Image>('/images'),
    /** The definition only (global admin); its first generation is a build. */
    create: (i: Pick<Image, 'metadata' | 'spec'>) => c().mutate<Image>('POST', '/images', i),
    build: (n: string, b: ImageBuild) => c().mutate('POST', `/images/${e(n)}/generations`, b),
    upgrade: (n: string, u: ImageUpgrade) => c().mutate('POST', `/images/${e(n)}/upgrade`, u),
    /** The nightly upgrade of the image (global admin): a merge patch of spec.auto_upgrade. */
    autoUpgrade: (n: string, a: ImageAutoUpgrade) => c().mutate<Image>('PATCH', `/images/${e(n)}`, { spec: { auto_upgrade: a } }),
    deleteAlias: (n: string, alias: string) => c().mutate<Image>('DELETE', `/images/${e(n)}/aliases/${e(alias)}`),
  },
  networks: {
    list: () => c().list<Network>('/networks'),
    leases: (n: string) => c().list<Lease>(`/networks/${e(n)}/leases`),
    create: (n: Pick<Network, 'metadata' | 'spec'>) => c().mutate('POST', '/networks', n),
    get: (n: string) => c().getWithEtag<Network>(`/networks/${e(n)}`),
    /** PUT replaces the spec; If-Match carries the generation read, so a concurrent edit is a 412. */
    put: (n: Pick<Network, 'metadata' | 'spec'>, etag?: string) => c().mutate<Network>('PUT', `/networks/${e(n.metadata.name)}`, n, { etag }),
    /** Refused while a jail is attached or a project grants it. */
    remove: (n: string) => c().mutate('DELETE', `/networks/${e(n)}`),
  },
  wireguard: {
    /** Extension wireguard: an operator reads, an admin changes. Keys never come back except in a peer's token, once. */
    list: () => c().list<WireGuard>('/wireguard'),
    create: (w: Pick<WireGuard, 'metadata' | 'spec'>) => c().mutate<WireGuard>('POST', '/wireguard', w),
    remove: (n: string) => c().mutate('DELETE', `/wireguard/${e(n)}`),
    join: (j: WireGuardJoin) => c().mutate<WireGuard>('POST', '/wireguard/join', j),
    addPeer: (n: string, p: WireGuardPeerAdd) => c().mutate<WireGuardPeerCreated>('POST', `/wireguard/${e(n)}/peers`, p),
    removePeer: (n: string, peer: string) => c().mutate<WireGuard>('DELETE', `/wireguard/${e(n)}/peers/${e(peer)}`),
    up: (n: string) => c().mutate<WireGuard>('POST', `/wireguard/${e(n)}/up`),
    down: (n: string) => c().mutate<WireGuard>('POST', `/wireguard/${e(n)}/down`),
    rotateKeys: (n: string) => c().mutate<WireGuardKeys>('POST', `/wireguard/${e(n)}/rotate-keys`),
  },
  firewall: {
    policies: () => c().list<FirewallPolicy>('/firewall/policies'),
    policy: (n: string) => c().getWithEtag<FirewallPolicy>(`/firewall/policies/${e(n)}`),
    addressSets: () => c().list<AddressSet>('/firewall/address-sets'),
    /** Extension firewall_test: would a new connection pass, and which rule decides (operator in the project; reads only). */
    test: (b: FirewallTestRequest) => c().mutate<FirewallTestResult>('POST', '/firewall/test', b),
    addressSet: (n: string) => c().getWithEtag<AddressSet>(`/firewall/address-sets/${e(n)}`),
    /** PUT replaces the object; If-Match carries the generation so a concurrent edit is a 412. */
    putPolicy: (p: FirewallPolicy, etag?: string) => c().mutate('PUT', `/firewall/policies/${e(p.metadata.name)}`, p, { etag }),
    putAddressSet: (a: AddressSet, etag?: string) => c().mutate('PUT', `/firewall/address-sets/${e(a.metadata.name)}`, a, { etag }),
    createAddressSet: (a: Pick<AddressSet, 'metadata' | 'spec'>) => c().mutate<AddressSet>('POST', '/firewall/address-sets', a),
    deleteAddressSet: (n: string) => c().mutate('DELETE', `/firewall/address-sets/${e(n)}`),
    createPolicy: (p: Pick<FirewallPolicy, 'metadata' | 'spec'>) => c().mutate<FirewallPolicy>('POST', '/firewall/policies', p),
    deletePolicy: (n: string) => c().mutate('DELETE', `/firewall/policies/${e(n)}`),
  },
  backups: {
    targets: () => c().list<BackupTarget>('/backup-targets'),
    policies: () => c().list<BackupPolicy>('/backup-policies'),
    list: () => c().list<Backup>('/backups'),
    /** Extension backup_run (global admin). */
    run: (b: BackupRunRequest) => c().mutate<BackupRun[]>('POST', '/backups/run', b),
    /** Extension backup_verify: depth is deep, extract or full. */
    verify: (id: string, b: BackupVerifyRequest) => c().mutate<BackupRun>('POST', `/backups/${e(id)}/verify`, b),
    /** Extension backup_key (global admin). The recovery key is in the create reply once. */
    keyStatus: () => c().get<BackupKeyStatus>('/backup/key'),
    createKey: (b: BackupKeyCreate) => c().mutate<BackupKeyCreated>('POST', '/backup/key', b),
    escrowKey: (b: BackupKeyEscrow) => c().mutate<BackupKeyStatus>('POST', '/backup/key/escrow', b),
    /** The node applies its delay before anything is deleted. */
    requestDeletion: (id: string) => c().mutate('DELETE', `/backups/${e(id)}`),
    restore: (r: RestoreRequest): Promise<MutationResult<RestorePreflight>> => c().mutate('POST', '/restores', r),
  },
  projects: {
    list: () => c().list<Project>('/projects'),
    get: (n: string) => c().getWithEtag<Project>(`/projects/${e(n)}`),
    /** Hub only: the definition and the state on every host the project lists. */
    aggregate: (n: string) => c().get<ProjectAggregate>(`/projects/${e(n)}?host=all`),
    create: (p: Pick<Project, 'metadata' | 'spec'>) => c().mutate<Project>('POST', '/projects', p),
    put: (p: Project, etag?: string) => c().mutate<Project>('PUT', `/projects/${e(p.metadata.name)}`, p, { etag }),
    remove: (n: string) => c().mutate('DELETE', `/projects/${e(n)}`),
  },
  storage: {
    list: () => c().list<Storage>('/storage'),
    create: (s: Pick<Storage, 'metadata' | 'spec'>) => c().mutate<Storage>('POST', '/storage', s),
    remove: (n: string) => c().mutate('DELETE', `/storage/${e(n)}`),
  },
  trust: {
    createToken: (r: TrustTokenRequest) => c().mutate<TrustToken>('POST', '/trust/tokens', r),
    whoami: () => c().get<Identity>('/auth/session'),
    sessions: () => c().list<Session>('/sessions'),
    revokeSession: (id: string) => c().mutate('DELETE', `/sessions/${e(id)}`),
    putCertificate: (cert: Certificate, etag?: string) => c().mutate<Certificate>('PUT', `/certificates/${e(cert.metadata.name)}`, cert, { etag }),
    getCertificate: (n: string) => c().getWithEtag<Certificate>(`/certificates/${e(n)}`),
  },
  profiles: {
    /** `project=host` selects the host-level profiles every project can use. */
    list: (project?: string) => c().list<Profile>(`/profiles${project ? `?project=${e(project)}` : ''}`),
    put: (p: Profile, etag?: string) => c().mutate<Profile>('PUT', `/profiles/${e(p.metadata.name)}`, p, { etag }),
    create: (p: Profile) => c().mutate<Profile>('POST', '/profiles', p),
    remove: (n: string) => c().mutate('DELETE', `/profiles/${e(n)}`),
  },
  jailConfig: {
    get: (n: string) => c().getWithEtag<Jail>(`/jails/${e(n)}`),
    /** The jail with its profiles merged in and the origin of every key. */
    expanded: (n: string) => c().get<JailExpanded>(`/jails/${e(n)}?expanded=true`),
    /** Never restarts the jail: the result lists the keys that need a restart. `restart` is an explicit request. */
    post: (n: string, change: ConfigChange, restart = false) => c().mutate<ConfigResult>('POST', `/jails/${e(n)}/config${restart ? '?restart=true' : ''}`, change),
  },
  updates: {
    /** The latest check of every visible jail of the project. */
    list: () => c().list<UpdateReport>('/updates'),
    check: (b: UpdateCheckRequest) => c().mutate<UpdateReport[]>('POST', '/updates/check', b),
    apply: (b: UpdateApplyRequest) => c().mutate<UpdateRecord[]>('POST', '/updates/apply', b),
    history: (n: string) => c().list<UpdateRecord>(`/jails/${e(n)}/updates`),
  },
  provision: {
    run: (n: string, b: ProvisionRequest) => c().mutate<ProvisionResult>('POST', `/jails/${e(n)}/provision`, b),
  },
  /** bash and the JailOps prompt for a running FreeBSD jail, as a new jail gets them (extension jail_shell_setup). */
  shellSetup: {
    run: (n: string) => c().mutate<ShellSetupResult>('POST', `/jails/${e(n)}/shell-setup`, {}),
  },
  /** The project filter lives with the client: composables use this and never touch the network. */
  setProjectFilter: (fn: ((path: string) => string) | null) => c().setRequestFilter(fn),
  exec: {
    /** The daemon's exec protocol is an HTTP upgrade, which a browser cannot open: the console is a session (extension jail_console). */
    open: (n: string, o: ExecRequest) => c().mutate<ExecSessionInfo>('POST', `/jails/${e(n)}/console`, o),
    input: (n: string, id: string, data: string) => c().mutate('POST', `/jails/${e(n)}/console/${e(id)}/input`, { data }),
    resize: (n: string, id: string, cols: number, rows: number) => c().mutate('POST', `/jails/${e(n)}/console/${e(id)}/resize`, { cols, rows }),
    close: (n: string, id: string) => c().mutate('DELETE', `/jails/${e(n)}/console/${e(id)}`),
    output: (n: string, id: string, h: import('@jailops/shared/api/client').StreamHandlers) => c().stream(`/jails/${e(n)}/console/${e(id)}/output`, h),
  },
  /** Extension rename: POST <object>/rename. A dry run answers the plan at once; a rename is an operation whose
   *  metadata is the same plan. If-Match is the generation of the object as the page read it. The project of a
   *  project-level object travels in the query like every project request (`host` names the host profiles). */
  rename: {
    network: (n: string, b: Rename, etag?: string) => c().mutate<RenameResult>('POST', `/networks/${e(n)}/rename`, b, { etag }),
    image: (n: string, b: Rename, etag?: string) => c().mutate<RenameResult>('POST', `/images/${e(n)}/rename`, b, { etag }),
    project: (n: string, b: Rename, etag?: string) => c().mutate<RenameResult>('POST', `/projects/${e(n)}/rename`, b, { etag }),
    jail: (n: string, b: Rename, etag?: string) => c().mutate<RenameResult>('POST', `/jails/${e(n)}/rename`, b, { etag }),
    policy: (n: string, b: Rename, etag?: string) => c().mutate<RenameResult>('POST', `/firewall/policies/${e(n)}/rename`, b, { etag }),
    addressSet: (n: string, b: Rename, etag?: string) => c().mutate<RenameResult>('POST', `/firewall/address-sets/${e(n)}/rename`, b, { etag }),
    profile: (n: string, b: Rename, etag?: string, project?: string) => c().mutate<RenameResult>('POST', `/profiles/${e(n)}/rename${project ? `?project=${e(project)}` : ''}`, b, { etag }),
  },
  remotes: { list: () => c().list<Remote>('/remotes') },
  operations: {
    list: () => c().list<Operation>('/operations'),
    cancel: (id: string) => c().cancelOperation(id),
    /** One long poll of an operation, for dialogs that follow its progress themselves. */
    wait: (id: string) => c().getOperation(id),
  },
  audit: { list: (limit = 200) => c().list<AuditEntry>(`/audit?limit=${limit}`) },
  access: {
    users: () => c().list<User>('/users'),
    createUser: (u: UserCreate) => c().mutate<UserCreated>('POST', '/users', u),
    patchUser: (n: string, spec: Partial<User['spec']>) => c().mutate<User>('PATCH', `/users/${e(n)}`, { spec }),
    setPassword: (n: string, password: string) => c().mutate<PasswordSet>('POST', `/users/${e(n)}/password`, password ? { password } : {}),
    deleteUser: (n: string) => c().mutate('DELETE', `/users/${e(n)}`),
    certificates: () => c().list<Certificate>('/certificates'),
    deleteCertificate: (n: string) => c().mutate('DELETE', `/certificates/${e(n)}`),
  },
}
