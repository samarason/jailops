package hostbackup

import (
	"context"
	"jailops.net/jailops/internal/repo/catalog"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/sdk/api"
)

// Kinds of dataset a jail record lists. They match the jailops:kind property of
// the datasets, but this package never reads that property: the record it is
// given says what each dataset is.
const (
	KindContainer  = "container"  // holds spec.json and bundle.json
	KindRoot       = "root"       // the OS root (cloned from a generation when thin)
	KindPersistent = "persistent" // a persistent path of a thin jail
	KindVolume     = "volume"     // a volume: the only dataset of a volume record
	KindState      = "state"      // the host state dataset (include_state)
)

// Dataset is one ZFS dataset of a jail as the daemon knows it.
type Dataset struct {
	// Name is the full dataset name, for example "tank/jailops/projects/web/jails/web1/etc".
	Name string
	// Kind is one of the Kind constants.
	Kind string
	// Mountpoint is the absolute mountpoint (the .zfs/snapshot directory is
	// below it).
	Mountpoint string
	// Props are ZFS properties to record with the dataset and to set again on
	// restore (for example jailops:path, jailops:class, quota, readonly). The
	// mountpoint is recorded separately, relative to the container.
	Props map[string]string
	// Skip says why the dataset is left out of this capture (SkipDelegated). The run reports it as a warning.
	Skip string
}

// SkipDelegated is Dataset.Skip of the dataset a jail manages itself (zfs_delegation): it is not mounted on the host,
// so its files cannot be read there.
const SkipDelegated = "delegated"

// SkipLocked is Dataset.Skip of an encrypted volume whose key is not loaded: its files cannot be read.
const SkipLocked = "locked"

// JailRecord is what the daemon knows about one jail, taken from its record
// (not from guesses about the dataset layout): this package never builds a
// dataset name or a mountpoint on its own.
type JailRecord struct {
	Name    string
	UUID    string
	Project string
	Labels  map[string]string
	Spec    api.JailSpec
	// Container is the jail's container dataset.
	Container string
	// Datasets lists every dataset of the jail including the container. The
	// thin root is listed but never captured (design 9.7); the root of a thick
	// jail is captured.
	Datasets []Dataset
	// Image is the generation the root was built from.
	Image api.ImageGeneration
	// SecretRefs name sealed secrets (never their values).
	SecretRefs []string
	// VolumeIDs maps the name of each volume the jail attaches to its UUID (the bundle records it).
	VolumeIDs map[string]string
	// IsState marks the host state record (include_state): its datasets are
	// all captured and it has no restore bundle.
	IsState bool
	// IsVolume marks the record of a volume. A volume is a backup unit of its own: Name and UUID are the volume's,
	// Container is its dataset (the only one), Volume is its spec and there is no restore bundle. Whatever number
	// of jails attach it, it has one record and so one copy in a run.
	IsVolume bool
	Volume   *api.VolumeSpec
}

// JailSource lists the jails of this host.
type JailSource interface {
	Jails(ctx context.Context) ([]JailRecord, error)
}

// VolumeSource lists the volumes of this host as records (IsVolume). Optional: without it no volume is backed up.
type VolumeSource interface {
	Volumes(ctx context.Context) ([]JailRecord, error)
}

// StateSource returns the host state dataset as a record, for policies with
// include_state. Optional.
type StateSource interface {
	StateRecord(ctx context.Context) (JailRecord, error)
}

// PolicySource gives the backup policies and targets of the host (the host's
// configuration objects).
type PolicySource interface {
	BackupPolicies(ctx context.Context) ([]api.BackupPolicy, error)
	BackupTargets(ctx context.Context) ([]api.BackupTarget, error)
}

// Hooks quiesce an application around the snapshot. Pre runs before the
// atomic snapshot, Post right after it (also when the snapshot failed, if Pre
// succeeded); neither is held while data is uploaded. Optional.
type Hooks interface {
	Pre(ctx context.Context, j JailRecord) error
	Post(ctx context.Context, j JailRecord) error
}

// Agents reads and writes trees on behalf of a daemon that is not root. Optional: without it the daemon
// reads and writes the directories itself (as root in development, and in tests).
type Agents interface {
	// ReadSnapshot opens a file system over a snapshot directory (<mountpoint>/.zfs/snapshot/<name>); the
	// tree is rooted at "/". The returned func ends the agent.
	ReadSnapshot(ctx context.Context, dir string) (catalog.ScanFS, func(), error)
	// WriteTree opens a sink that writes below dir, the mountpoint of a dataset being restored.
	WriteTree(ctx context.Context, dir string) (catalog.Sink, func(), error)
}

// Mounter gives access to the files of datasets.
type Mounter interface {
	// SnapshotDir returns the directory that shows snapshot snap of d
	// (<mountpoint>/.zfs/snapshot/<snap> on a real system).
	SnapshotDir(ctx context.Context, d Dataset, snap string) (string, error)
	// MountDir returns the directory a freshly created dataset is mounted on,
	// writable by the restore. It fails when the dataset is not mounted.
	MountDir(ctx context.Context, dataset string) (string, error)
}

// DatasetMounter mounts and unmounts a dataset. A backup of a jail that is stopped (or was never started) finds its
// datasets unmounted: the capture mounts them for the time it reads the snapshot and unmounts them again.
type DatasetMounter interface {
	Mount(ctx context.Context, dataset string) error
	Unmount(ctx context.Context, dataset string) error
}

// Placement is where a restored jail goes. The daemon decides it from the
// project, the name and the storage (design 8.1), so this package never
// hard-codes dataset paths.
type Placement struct {
	Container  string // container dataset
	Mountpoint string // its mountpoint
	// Root and RootMountpoint default to <Container>/root and
	// <Mountpoint>/root.
	Root           string
	RootMountpoint string
}

func (p Placement) root() string {
	if p.Root != "" {
		return p.Root
	}
	return p.Container + "/root"
}

func (p Placement) rootMP() string {
	if p.RootMountpoint != "" {
		return p.RootMountpoint
	}
	return p.Mountpoint + "/root"
}

// AdoptInput is what the daemon registers after the datasets of a restored
// jail exist.
type AdoptInput struct {
	// Jail is the final record: new name, uuid (new unless Replace), network
	// map and keep_ip applied.
	Jail api.Jail
	// Bundle is the restore bundle of the backup as it was taken.
	Bundle    api.RestoreBundle
	Placement Placement
	Backup    api.Backup
	Replace   bool
	// Generation is the image generation the root was cloned from (thin).
	Generation api.ImageGeneration
}

// Host is the host-side seam of restore: everything that is the daemon's
// (registry, networks, jail records) and not ZFS data.
type Host interface {
	// State gathers the facts of the target host for the preflight: networks,
	// policies, address sets, jails, leases and sealed secrets. KeyDomains and
	// Generations are filled in by this package.
	State(ctx context.Context, storage string) (backup.HostState, error)
	// Place decides the datasets of the jail to restore.
	Place(ctx context.Context, project, name, storage string) (Placement, error)
	// EnsureObjects creates the networks, policies and address sets of the
	// bundle that are missing from their frozen copies, honouring the
	// network map. The returned undo removes what it created.
	EnsureObjects(ctx context.Context, b api.RestoreBundle, networkMap map[string]string) (undo func(context.Context) error, err error)
	// Adopt writes spec.json and bundle.json into the container and registers
	// the jail. The returned undo unregisters it.
	Adopt(ctx context.Context, in AdoptInput) (undo func(context.Context) error, err error)
	// Running reports whether the named jail runs (a replace needs it stopped).
	Running(ctx context.Context, project, name string) (bool, error)
	// Start starts a restored jail.
	Start(ctx context.Context, project, name string) error
}

// VolumeHost is implemented by a Host that restores volumes. Without it a volume backup cannot be restored and a
// jail restore cannot bring back the volumes it attaches.
type VolumeHost interface {
	// RestoreVolume makes an empty volume of the project from the spec of a volume backup, the way volume create does
	// (owner, mode, quota, encryption with the passphrase), registers it and returns its dataset. The returned undo
	// removes it again. It fails with api.CodeAlreadyExists when the project has a volume of that name.
	RestoreVolume(ctx context.Context, project, name string, spec api.VolumeSpec, labels map[string]string, passphrase string) (dataset string, undo func(context.Context) error, err error)
	// CompleteVolume ends the restore of a volume made by RestoreVolume: until then the helper lets a file agent write
	// its dataset, and never afterwards.
	CompleteVolume(ctx context.Context, project, name string) error
}

// DrillHost is what a full restore test needs of the host besides Host. The test restores the backup as a jail of
// its own (a name nobody chose, in the project of the backup, without a network), starts it, checks it from the
// inside, then stops and deletes it. Optional: a Host that does not implement it cannot run full tests.
type DrillHost interface {
	// Stop stops the jail; a jail that is not running is not an error.
	Stop(ctx context.Context, project, name string) error
	// Delete removes the jail with its datasets; a jail that does not exist is not an error.
	Delete(ctx context.Context, project, name string) error
	// Exec runs a command in the running jail and returns what it printed and its exit status.
	Exec(ctx context.Context, project, name string, argv []string) (output string, code int, err error)
}

// ProjectHost is implemented by a Host that is project-aware. A restore into
// project P then reads the state of P (its policies, address sets and jails)
// and creates the bundle's objects in P. A Host without it sees the project
// of the backup only through Place, Running and Start.
type ProjectHost interface {
	StateIn(ctx context.Context, project, storage string) (backup.HostState, error)
	EnsureObjectsIn(ctx context.Context, project string, b api.RestoreBundle, networkMap map[string]string) (undo func(context.Context) error, err error)
}

// ProjectObjects is implemented by an ObjectSource whose policies and address
// sets belong to projects: capture resolves them in the jail's project.
type ProjectObjects interface {
	ForProject(project string) backup.ObjectSource
}

// Images resolves image generations on a storage's pool. internal/imagegen's
// Manager implements it through ImagegenImages.
type Images interface {
	// Resolve returns the generation ("<image>#g<N>") on the storage's pool,
	// or an error with api.CodeNotFound when the pool has no such generation.
	Resolve(ctx context.Context, storage, generation string) (api.ImageGeneration, error)
}

// DrillRunner runs the jail of a full restore test (an isolated network, the
// jail started from the scratch dataset, its health check). Optional: without
// it a "full" test answers api.CodeUnsupported.
type DrillRunner interface {
	backup.JailRunner
	Health(ctx context.Context, p backup.DrillPlan) error
}

// Observer is told about finished runs (status, events, metrics). Optional.
type Observer interface {
	RunFinished(ctx context.Context, r Run)
}

// Run kinds.
const (
	RunBackup = "backup"
	RunDrill  = "drill"
)

// Run is the recorded result of one backup or restore test.
type Run struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Policy   string `json:"policy,omitempty"`
	Target   string `json:"target,omitempty"`
	Project  string `json:"project,omitempty"`
	Jail     string `json:"jail"`
	JailUUID string `json:"jail_uuid"`
	// Scheduled is set for runs started by the scheduler.
	Scheduled bool      `json:"scheduled,omitempty"`
	Attempt   int       `json:"attempt"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	Code      api.Code  `json:"code,omitempty"`
	Snapshot  string    `json:"snapshot,omitempty"`
	ZFSSnap   string    `json:"zfs_snapshot,omitempty"`
	Full      bool      `json:"full,omitempty"`
	Bytes     int64     `json:"bytes,omitempty"`
	NewBytes  int64     `json:"new_bytes,omitempty"`
	Chunks    int       `json:"chunks,omitempty"`
	Files     int64     `json:"files,omitempty"`
	Warnings  []string  `json:"warnings,omitempty"`
	// Depth and Problems describe a restore test.
	Depth    string   `json:"depth,omitempty"`
	Problems []string `json:"problems,omitempty"`
}

// Catalog stores the backup objects and run results the host has seen. It is
// a cache: the repository is the truth and Service.Reindex rebuilds the
// backups from it. The daemon may supply an SQLite implementation.
type Catalog interface {
	PutBackup(ctx context.Context, b api.Backup) error
	Backups(ctx context.Context) ([]api.Backup, error)
	GetBackup(ctx context.Context, id string) (api.Backup, bool, error)
	DeleteBackup(ctx context.Context, id string) error
	PutRun(ctx context.Context, r Run) error
	Runs(ctx context.Context) ([]Run, error)
}
