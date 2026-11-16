package priv

import (
	"context"
	"io"
	"maps"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// Host is everything the helper offers. Local implements it in process and
// Client implements it over the socket, so callers do not care which they hold.
type Host interface {
	// WireGuard interfaces and their keys (wireguard.go).
	wireguard.Host

	ZFS() zfs.Client
	Jails() jailos.Jails
	PF() pfctl.Client
	Net() ifconfig.Client
	// Runner runs only the commands in CommandRules.
	Runner() run.Runner

	ReadFile(ctx context.Context, path string) ([]byte, error)
	WriteFile(ctx context.Context, q WriteFileReq) error
	MkdirAll(ctx context.Context, q MkdirReq) error
	// SetVolumeOwner sets the owner and mode of the empty root of a volume (see safefs.go).
	SetVolumeOwner(ctx context.Context, q VolumeOwnerReq) error
	// StaleMounts lists the mounts below the roots of jails that do not run, of a kind JailOps makes (stalemounts.go).
	StaleMounts(ctx context.Context) ([]StaleMount, error)
	// HealJail cleans up after one jail that does not run: the mounts below its root, and what its poststop hook removes
	// (rctl rules, the pf anchor, its links). A running jail is refused.
	HealJail(ctx context.Context, jail string) (HealJailRes, error)
	// HealNetwork destroys the interfaces of the earlier network layout (a bridge, the gateway pair of a network) that
	// no jail that runs uses (netheal.go).
	HealNetwork(ctx context.Context) (HealNetRes, error)
	// DNSUnbound writes the names of the running jails for the host's unbound (dnsunbound.go); without unbound-conf in
	// priv.conf it does nothing and says it is off.
	DNSUnbound(ctx context.Context, apply bool) (UnboundRes, error)
	// ProbeSource says whether a host directory below an admin-host-mount directory is on a mount (see safefs.go).
	ProbeSource(ctx context.Context, q SourceProbeReq) (SourceProbe, error)
	Remove(ctx context.Context, path string) error
	// RemoveAll removes a tree where that is allowed (see Config.recursiveRemovable), else it is Remove.
	RemoveAll(ctx context.Context, path string) error
	// ListLogs lists the log files of a jail (dir is <jail root>/var/log) and
	// TailFile reads a window from the end of one; see logs.go.
	ListLogs(ctx context.Context, dir string) (files []api.JailLogFile, truncated bool, err error)
	TailFile(ctx context.Context, path string, offset, limit int64) (data []byte, start, size int64, err error)

	// Mount and Unmount mount a JailOps dataset (zfs mount, zfs unmount).
	Mount(ctx context.Context, dataset string) error
	Unmount(ctx context.Context, dataset string) error
	// Sysctl reads one value from the allow-list.
	Sysctl(ctx context.Context, name string) (string, error)

	// Encrypted volumes of jails (volkeys.go). A passphrase travels on the request stream, never in arguments.
	CreateEncrypted(ctx context.Context, o zfs.CreateOpts, passphrase []byte) error
	LoadKey(ctx context.Context, dataset string, passphrase []byte) error
	UnloadKey(ctx context.Context, dataset string) error
	ChangeKey(ctx context.Context, dataset string, oldPass, newPass []byte) error
	// ReplicateRaw copies a snapshot into a new dataset with a raw send (an encrypted volume stays encrypted).
	ReplicateRaw(ctx context.Context, snapshot, dst string, props map[string]string) error
	// NDPOpen returns a read-only, locked packet capture of an approved uplink that delivers neighbor discovery
	// frames only. The caller owns the descriptor.
	NDPOpen(ctx context.Context, uplink string, promisc bool) (*os.File, error)
	// NDPAnswer sends one Neighbor Advertisement for an address inside a prefix approved for the uplink.
	NDPAnswer(ctx context.Context, q NDPAnswerReq) error

	// FSAgent starts a file agent in root and returns the caller's end of the connection to it: a read
	// agent reads a backup snapshot, a write agent writes a jail that is being restored. It needs the
	// admin assertion. See internal/fsagent.
	FSAgent(ctx context.Context, mode, root string) (*os.File, error)

	// RegisterStorage adds a storage root (a dataset that exists, carries
	// jailops:managed=on locally and does not overlap another root). It needs
	// the admin assertion (WithAdmin). UnregisterStorage removes a root
	// registered at run time. Storages lists the active roots.
	RegisterStorage(ctx context.Context, dataset string) error
	UnregisterStorage(ctx context.Context, dataset string) error
	Storages(ctx context.Context) ([]string, error)

	// CopyTree copies the directory tree src into the directory dst, both
	// inside registered storage roots, see CopyOpts. Progress is optional.
	CopyTree(ctx context.Context, src, dst string, o CopyOpts) (CopyResult, error)

	// Exec starts a command in a jail with pipes or a pseudo-terminal.
	Exec(ctx context.Context, jail string, argv []string, o ExecOpts) (ExecSession, error)

	// SeedKeys copies the host's /usr/share/keys into an image root.
	SeedKeys(ctx context.Context, root string) (CopyResult, error)

	// SetMTU sets the MTU of an interface JailOps owns.
	SetMTU(ctx context.Context, iface string, mtu int) error
	// NDPRouteAdd and NDPRouteDelete add and remove one /128 host route
	// through an interface JailOps owns (IPv6 proxy mode).
	NDPRouteAdd(ctx context.Context, addr netip.Addr, iface string) error
	NDPRouteDelete(ctx context.Context, addr netip.Addr, iface string) error

	// Host management (host.go): the identity of the host and the snapshots taken before each change.
	HostIdentityRead(ctx context.Context) (service.HostIdentityState, error)
	HostIdentityApply(ctx context.Context, spec api.HostIdentitySpec, dryRun bool) (api.HostChange, error)
	HostSnapshots(ctx context.Context) ([]api.HostSnapshot, error)
	HostSnapshotRestore(ctx context.Context, name string, dryRun bool) (api.HostChange, error)
	// The firewall module and commit confirmed (hostfw.go, hostpending.go).
	service.HostFirewallSystem
}

// Deps are the raw (unvalidated) implementations Local guards.
type Deps struct {
	ZFS    zfs.Client
	Jails  jailos.Jails
	PF     pfctl.Client
	Net    ifconfig.Client
	Runner run.Runner
	// NDP is the packet capture and sender of the IPv6 proxy; nil means unsupported.
	NDP NDPDevice
	// AgentBinary is the executable a file agent runs (default the configured helper path); tests
	// substitute their own.
	AgentBinary string
	// Jexec is the binary that enters a jail (default DefaultJexec). Tests
	// substitute a script; there is no configuration for it.
	Jexec string
	// KeysDir is the host keys directory SeedKeys copies (default
	// HostKeysDir); tests substitute one.
	KeysDir string
	// Etc is the directory host management reads and writes (default /etc); tests substitute one. There is no
	// configuration for it.
	Etc string
	// Now is the clock of host snapshot names and of the deadline of a pending change (default time.Now).
	Now func() time.Time
	// AfterFunc arms the timer of a pending change and returns its stop function (default time.AfterFunc); tests
	// substitute a timer they fire themselves.
	AfterFunc func(d time.Duration, f func()) (stop func() bool)
	// WGLocate returns the wg program (default: the first of wireguard.Binaries that is root's); tests substitute
	// their own.
	WGLocate func() string
}

// Local runs the helper's operations in process behind the validation rules.
// It is used by jailops-priv itself, by the hook subcommand, in development as
// root and in tests.
type Local struct {
	cfg  Config
	d    Deps
	conf *zfsGuard

	rootsMu sync.Mutex // serialises register, unregister and reload

	grants *grants // what the helper alone decided: datasets being restored, snapshots a backup made

	execMu    sync.Mutex
	execJail  map[string]int
	execTotal int

	noChown bool // tolerate failing chown (tests as an ordinary user)

	ndp ndpState

	hostMu   sync.Mutex                 // one host management request at a time
	pendStop func() bool                // stops the timer of the pending change (hostMu)
	hostNote func(msg string, a ...any) // logs what the timer and a restart do with a pending change

	frozenMu sync.Mutex
	// probes of host directories in flight, by path (ProbeSource), and how long a request waits for one
	probeMu   sync.Mutex
	probing   map[string]bool
	probeWait time.Duration
	probeFn   func(context.Context, SourceProbeReq) (SourceProbe, error) // tests
	frozen    map[string]int                                             // directories a running command reads its configuration from: no writes meanwhile

	wgMu sync.Mutex // one WireGuard operation at a time

	keyLim keyLimiter // wrong passphrases of encrypted volumes

	hostDirUID uint32 // the owner host-dir must have: root; the test user under WithoutChown
}

var _ Host = (*Local)(nil)

// LocalOption customises NewLocal.
type LocalOption func(*Local)

// WithoutChown makes failing chown calls non-fatal. For tests run as an
// ordinary user.
func WithoutChown() LocalOption {
	return func(l *Local) { l.noChown, l.hostDirUID = true, uint32(os.Getuid()) }
}

// NewLocal returns a Local over the given dependencies.
func NewLocal(cfg Config, d Deps, opts ...LocalOption) (*Local, error) {
	cfg, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	cfg.reg = newRootSet() // a Local never shares its roots with another
	l := &Local{cfg: cfg, d: d, grants: newGrants()}
	for _, o := range opts {
		o(l)
	}
	l.cfg.noOwnerCheck = l.noChown // tests run as an ordinary user, who owns their temporary directories
	if err := l.ReloadRoots(context.Background()); err != nil {
		return nil, err
	}
	return l, nil
}

// NewSystem returns the real implementation: commands run through
// run.Exec. UNVERIFIED on FreeBSD.
func NewSystem(cfg Config, opts ...LocalOption) (*Local, error) {
	r := run.NewExec()
	if _, err := cfg.Normalize(); err != nil {
		return nil, err
	}
	return NewLocal(cfg, Deps{
		ZFS: zfs.NewClient(r), Jails: jailos.NewCommand(r), PF: pfctl.NewCommand(r),
		Net:    ifconfig.NewCommand(r, ifconfig.Options{}),
		Runner: r, NDP: systemNDP{},
	}, opts...)
}

// Config returns the normalised configuration.
func (l *Local) Config() Config { return l.cfg }

func (l *Local) ZFS() zfs.Client      { return zfsGuard{l} }
func (l *Local) Jails() jailos.Jails  { return jailGuard{l} }
func (l *Local) PF() pfctl.Client     { return pfGuard{l} }
func (l *Local) Net() ifconfig.Client { return netGuard{l} }
func (l *Local) Runner() run.Runner   { return runGuard{l} }

// ---- ZFS ----

type zfsGuard struct{ l *Local }

var _ zfs.Client = zfsGuard{}

func (g zfsGuard) managed(ctx context.Context, name string) error {
	ds := dsPart(name)
	p, err := g.l.d.ZFS.Get(ctx, ds, "jailops:managed")
	if err != nil {
		return err
	}
	// The property must be set on the dataset itself: user properties are
	// inherited, so a child of the root is not owned just by living there.
	if v := p["jailops:managed"]; v.Value != "on" || v.Source != "local" {
		return forbidden("dataset %s is not managed by JailOps", ds)
	}
	return nil
}

func (g zfsGuard) notRoot(name string) error {
	if g.l.cfg.isRootDataset(name) {
		return forbidden("a storage root cannot be changed through the helper (use storage.unregister)")
	}
	return nil
}

// rootMountProps are the properties that decide where and whether a storage root is mounted, and what it lets
// through: the helper verified the root's directory (root, mode 0700) and keeps it that way, so neither the root's
// mountpoint nor its mounting is changed through the helper.
var rootMountProps = []string{"mountpoint", "canmount", "devices"}

func (g zfsGuard) rootProps(name string, props []string) error {
	if !g.l.cfg.isRootDataset(dsPart(name)) {
		return nil
	}
	for _, p := range props {
		if slices.Contains(rootMountProps, p) {
			return forbidden("%s of a storage root cannot be changed through the helper", p)
		}
	}
	return nil
}

var zfsTypes = []string{"filesystem", "volume", "snapshot", "bookmark"}

func (g zfsGuard) List(ctx context.Context, o zfs.ListOpts) ([]zfs.Dataset, error) {
	c := g.l.cfg
	if o.Root == "" {
		// An unrooted listing is the union of the registered roots.
		var out []zfs.Dataset
		for _, r := range c.Roots() {
			o.Root = r
			part, err := g.List(ctx, o)
			if err != nil {
				return nil, err
			}
			out = append(out, part...)
		}
		return out, nil
	}
	if _, err := c.zfsName(o.Root); err != nil {
		return nil, err
	}
	for _, t := range o.Types {
		if !slices.Contains(zfsTypes, t) {
			return nil, invalid("invalid dataset type %q", t)
		}
	}
	if o.Depth < 0 || o.Depth > 32 {
		return nil, invalid("invalid depth")
	}
	if err := c.zfsPropNames(o.Props); err != nil {
		return nil, err
	}
	return g.l.d.ZFS.List(ctx, o)
}

func (g zfsGuard) Get(ctx context.Context, name string, props ...string) (map[string]zfs.Prop, error) {
	if _, err := g.l.cfg.zfsName(name); err != nil {
		return nil, err
	}
	if err := g.l.cfg.zfsPropNames(props); err != nil {
		return nil, err
	}
	return g.l.d.ZFS.Get(ctx, name, props...)
}

func (g zfsGuard) Exists(ctx context.Context, name string) (bool, error) {
	if _, err := g.l.cfg.zfsName(name); err != nil {
		return false, err
	}
	return g.l.d.ZFS.Exists(ctx, name)
}

func (g zfsGuard) Set(ctx context.Context, name string, props map[string]string) error {
	if _, err := g.l.cfg.zfsName(name); err != nil {
		return err
	}
	if len(props) == 0 {
		return invalid("no properties")
	}
	if _, ok := props["jailed"]; ok {
		return g.setJailed(ctx, name, props)
	}
	if err := g.l.cfg.zfsProps(ctx, props); err != nil {
		return err
	}
	if err := g.rootProps(name, slices.Collect(maps.Keys(props))); err != nil {
		return err
	}
	if err := g.managed(ctx, name); err != nil {
		return err
	}
	if err := g.l.d.ZFS.Set(ctx, name, props); err != nil {
		return err
	}
	if props[propComplete] == "on" {
		g.l.grants.endRestore(name)
	}
	return nil
}

func (g zfsGuard) Inherit(ctx context.Context, name string, props ...string) error {
	if _, err := g.l.cfg.zfsName(name); err != nil {
		return err
	}
	if len(props) == 0 {
		return invalid("no properties")
	}
	if err := g.l.cfg.zfsPropNames(props); err != nil {
		return err
	}
	for _, p := range props {
		if neverProps[p] {
			return forbidden("property %s cannot be changed through the helper", p)
		}
	}
	if err := g.rootProps(name, props); err != nil {
		return err
	}
	if err := g.managed(ctx, name); err != nil {
		return err
	}
	return g.l.d.ZFS.Inherit(ctx, name, props...)
}

func (g zfsGuard) Create(ctx context.Context, o zfs.CreateOpts) error {
	c := g.l.cfg
	if err := c.zfsDataset(o.Name); err != nil {
		return err
	}
	if err := c.zfsProps(ctx, o.Props); err != nil {
		return err
	}
	if o.VolumeSize != "" {
		if err := c.checkSize("volume size", o.VolumeSize); err != nil {
			return err
		}
	}
	if err := g.l.d.ZFS.Create(ctx, o); err != nil {
		return err
	}
	// A dataset created incomplete is a jail being built or restored: file agents may write it until it is
	// marked complete (Set below) or destroyed. Only a creation starts this; no property set later does.
	if o.Props[propComplete] == "off" {
		g.l.grants.beginRestore(o.Name)
	}
	return nil
}

func (g zfsGuard) Clone(ctx context.Context, snapshot, target string, props map[string]string, parents bool) error {
	c := g.l.cfg
	if err := c.zfsSnapshot(snapshot); err != nil {
		return err
	}
	if err := c.zfsDataset(target); err != nil {
		return err
	}
	if err := c.zfsProps(ctx, props); err != nil {
		return err
	}
	return g.l.d.ZFS.Clone(ctx, snapshot, target, props, parents)
}

func (g zfsGuard) Snapshot(ctx context.Context, o zfs.SnapshotOpts) error {
	c := g.l.cfg
	if len(o.Names) == 0 || len(o.Names) > c.Limits.MaxNames {
		return invalid("expected between 1 and %d snapshot names", c.Limits.MaxNames)
	}
	for _, n := range o.Names {
		if err := c.zfsSnapshot(n); err != nil {
			return err
		}
	}
	if err := c.zfsProps(ctx, o.Props); err != nil {
		return err
	}
	if err := g.l.d.ZFS.Snapshot(ctx, o); err != nil {
		return err
	}
	// a backup's snapshots may be read by a file agent: the helper remembers that it was asked for them
	if o.Props["jailops:managed"] == "on" {
		for _, n := range o.Names {
			if _, snap, ok := strings.Cut(n, "@"); ok && strings.HasPrefix(snap, backupSnap) {
				g.l.grants.addSnapshot(n)
			}
		}
	}
	return nil
}

func (g zfsGuard) Destroy(ctx context.Context, name string, o zfs.DestroyOpts) error {
	if _, err := g.l.cfg.zfsName(name); err != nil {
		return err
	}
	if err := g.notRoot(name); err != nil {
		return err
	}
	if err := g.managed(ctx, name); err != nil {
		return err
	}
	if err := g.l.d.ZFS.Destroy(ctx, name, o); err != nil {
		return withHolders(ctx, g.l.d.Runner, err)
	}
	g.l.grants.forget(name)
	return nil
}

func (g zfsGuard) Rename(ctx context.Context, from, to string, o zfs.RenameOpts) error {
	c := g.l.cfg
	k1, err := c.zfsName(from)
	if err != nil {
		return err
	}
	k2, err := c.zfsName(to)
	if err != nil {
		return err
	}
	if k1 != k2 {
		return invalid("cannot rename a %v to a %v", k1, k2)
	}
	if err := g.notRoot(from); err != nil {
		return err
	}
	if err := g.notRoot(to); err != nil {
		return err
	}
	if err := g.managed(ctx, from); err != nil {
		return err
	}
	if err := g.l.d.ZFS.Rename(ctx, from, to, o); err != nil {
		return err
	}
	g.l.grants.forget(from)
	return nil
}

func (g zfsGuard) Rollback(ctx context.Context, snapshot string, o zfs.RollbackOpts) error {
	if err := g.l.cfg.zfsSnapshot(snapshot); err != nil {
		return err
	}
	if err := g.managed(ctx, snapshot); err != nil {
		return err
	}
	return g.l.d.ZFS.Rollback(ctx, snapshot, o)
}

func (g zfsGuard) Hold(ctx context.Context, tag string, snapshots ...string) error {
	if err := zfs.ValidateTag(tag); err != nil {
		return err
	}
	if len(snapshots) == 0 || len(snapshots) > g.l.cfg.Limits.MaxNames {
		return invalid("expected between 1 and %d snapshots", g.l.cfg.Limits.MaxNames)
	}
	for _, s := range snapshots {
		if err := g.l.cfg.zfsSnapshot(s); err != nil {
			return err
		}
	}
	return g.l.d.ZFS.Hold(ctx, tag, snapshots...)
}

func (g zfsGuard) Release(ctx context.Context, tag string, snapshots ...string) error {
	if err := zfs.ValidateTag(tag); err != nil {
		return err
	}
	if len(snapshots) == 0 || len(snapshots) > g.l.cfg.Limits.MaxNames {
		return invalid("expected between 1 and %d snapshots", g.l.cfg.Limits.MaxNames)
	}
	for _, s := range snapshots {
		if err := g.l.cfg.zfsSnapshot(s); err != nil {
			return err
		}
	}
	return g.l.d.ZFS.Release(ctx, tag, snapshots...)
}

func (g zfsGuard) Holds(ctx context.Context, snapshot string) ([]zfs.Hold, error) {
	if err := g.l.cfg.zfsSnapshot(snapshot); err != nil {
		return nil, err
	}
	return g.l.d.ZFS.Holds(ctx, snapshot)
}

func (g zfsGuard) Bookmark(ctx context.Context, snapshot, bookmark string) error {
	if err := g.l.cfg.zfsSnapshot(snapshot); err != nil {
		return err
	}
	if err := zfs.ValidateBookmark(bookmark); err != nil {
		return err
	}
	if err := g.l.cfg.inRoot(dsPart(bookmark)); err != nil {
		return err
	}
	return g.l.d.ZFS.Bookmark(ctx, snapshot, bookmark)
}

func (g zfsGuard) Written(ctx context.Context, dataset, since string) (uint64, error) {
	if err := g.l.cfg.zfsDataset(dataset); err != nil {
		return 0, err
	}
	if since != "" {
		if err := g.l.cfg.zfsSnapshot(since); err != nil {
			return 0, err
		}
	}
	return g.l.d.ZFS.Written(ctx, dataset, since)
}

func (g zfsGuard) GUID(ctx context.Context, name string) (uint64, error) {
	if _, err := g.l.cfg.zfsName(name); err != nil {
		return 0, err
	}
	return g.l.d.ZFS.GUID(ctx, name)
}

func (g zfsGuard) Clones(ctx context.Context, snapshot string) ([]string, error) {
	if err := g.l.cfg.zfsSnapshot(snapshot); err != nil {
		return nil, err
	}
	return g.l.d.ZFS.Clones(ctx, snapshot)
}

func (g zfsGuard) Origin(ctx context.Context, dataset string) (string, error) {
	if err := g.l.cfg.zfsDataset(dataset); err != nil {
		return "", err
	}
	return g.l.d.ZFS.Origin(ctx, dataset)
}

func (g zfsGuard) Send(ctx context.Context, o zfs.SendOpts, w io.Writer) error {
	c := g.l.cfg
	if o.ResumeToken != "" {
		// A resume token names its dataset inside an opaque blob the helper
		// cannot read, so it can point anywhere.
		if !(isAdmin(ctx) && c.Admin.ResumeSend) {
			return forbidden("resuming a send from a token needs the admin assertion and AdminPolicy.ResumeSend")
		}
		if err := zfs.ValidateResumeToken(o.ResumeToken); err != nil {
			return err
		}
		return g.l.d.ZFS.Send(ctx, o, w)
	}
	if err := c.zfsSnapshot(o.Snapshot); err != nil {
		return err
	}
	if o.From != "" {
		k, err := c.zfsName(o.From)
		if err != nil {
			return err
		}
		if k == zfs.KindDataset {
			return invalid("incremental source must be a snapshot or bookmark")
		}
	}
	return g.l.d.ZFS.Send(ctx, o, w)
}

// neverReceived are properties a received stream must not carry: a stream
// from another host could set a mountpoint over a host directory, export the
// data, or turn on device nodes, setuid or exec where the storage root has
// them off. Excluded, they are inherited from the dataset's parent (devices
// off from the root). The list holds only properties this ZFS knows: an
// unknown name makes zfs receive fail.
var neverReceived = []string{"mountpoint", "sharenfs", "sharesmb", "jailed", "keylocation", "devices", "setuid", "exec"}

func (g zfsGuard) Receive(ctx context.Context, o zfs.ReceiveOpts, r io.Reader) error {
	c := g.l.cfg
	// -F rolls the target back and destroys its newer snapshots, and a resumable receive leaves state behind that
	// only an administrator should have to manage; nothing in JailOps asks for either.
	if (o.Force || o.Resumable) && !isAdmin(ctx) {
		return forbidden("zfs receive with force or resume needs the admin assertion")
	}
	if err := c.zfsDataset(o.Target); err != nil {
		return err
	}
	if err := c.zfsProps(ctx, o.Props); err != nil {
		return err
	}
	if err := c.zfsPropNames(o.Exclude); err != nil {
		return err
	}
	if err := g.notRoot(o.Target); err != nil {
		return err
	}
	if ok, err := g.l.d.ZFS.Exists(ctx, o.Target); err != nil {
		return err
	} else if ok {
		if err := g.managed(ctx, o.Target); err != nil {
			return err
		}
	}
	ex := slices.Clone(o.Exclude)
	for _, p := range neverReceived {
		if _, set := o.Props[p]; !set && !slices.Contains(ex, p) {
			ex = append(ex, p)
		}
	}
	o.Exclude = ex
	return g.l.d.ZFS.Receive(ctx, o, r)
}

// Replicate is zfs send | zfs receive with the same checks as each of them, over a kernel pipe: the data never
// passes through this process or the caller.
func (g zfsGuard) Replicate(ctx context.Context, snapshot, dst string, props map[string]string) error {
	return g.replicate(ctx, snapshot, dst, props, false)
}

func (g zfsGuard) replicate(ctx context.Context, snapshot, dst string, props map[string]string, raw bool) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sent := make(chan error, 1)
	go func() {
		err := g.Send(ctx, zfs.SendOpts{Snapshot: snapshot, Raw: raw}, pw)
		pw.Close()
		sent <- err
	}()
	rerr := g.Receive(ctx, zfs.ReceiveOpts{Target: dst, Props: props}, pr)
	if rerr != nil {
		cancel()
	}
	serr := <-sent
	if rerr != nil {
		return rerr
	}
	return serr
}

func (g zfsGuard) ReceiveAbort(ctx context.Context, dataset string) error {
	if err := g.l.cfg.zfsDataset(dataset); err != nil {
		return err
	}
	if err := g.managed(ctx, dataset); err != nil {
		return err
	}
	return g.l.d.ZFS.ReceiveAbort(ctx, dataset)
}

func (g zfsGuard) ListPools(ctx context.Context) ([]zfs.Pool, error) {
	return g.l.d.ZFS.ListPools(ctx)
}

func (g zfsGuard) ActiveFeatures(ctx context.Context, pool string) ([]string, error) {
	if !slices.Contains(g.l.cfg.Pools(), pool) {
		return nil, forbidden("pool %q holds no registered storage root", pool)
	}
	return g.l.d.ZFS.ActiveFeatures(ctx, pool)
}

// Mount mounts a JailOps dataset.
func (l *Local) Mount(ctx context.Context, dataset string) error {
	return l.mountOp(ctx, "mount", dataset)
}

// Unmount unmounts a JailOps dataset (never forced).
func (l *Local) Unmount(ctx context.Context, dataset string) error {
	return l.mountOp(ctx, "unmount", dataset)
}

func (l *Local) mountOp(ctx context.Context, verb, dataset string) error {
	if err := l.cfg.zfsDataset(dataset); err != nil {
		return err
	}
	// unmounted, a root would leave its datasets to be mounted below a directory the helper did not check
	if err := (zfsGuard{l}).notRoot(dataset); err != nil {
		return err
	}
	if err := (zfsGuard{l}).managed(ctx, dataset); err != nil {
		return err
	}
	if verb == "unmount" {
		// What an earlier stop left below the root of a jail that does not run (a devfs under root/dev, stacked by each
		// failed stop) keeps the dataset busy for good: it comes off first.
		l.cleanStaleMountsOfDataset(ctx, dataset)
	}
	_, err := l.d.Runner.Run(ctx, run.Cmd{Name: "zfs", Args: []string{verb, dataset}, Timeout: 60 * time.Second})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			return mapZFSMount(ee)
		}
		return err
	}
	return nil
}

var sysctlNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,6}$`)

// Sysctl reads one allow-listed sysctl through the rule in CommandRules.
func (l *Local) Sysctl(ctx context.Context, name string) (string, error) {
	rule, argv, err := l.cfg.CheckCommandCtx(ctx, []string{"sysctl", "-n", name})
	if err != nil {
		return "", err
	}
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: argv[0], Args: argv[1:], Timeout: time.Duration(rule.MaxTimeoutSeconds) * time.Second})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func mapZFSMount(ee *run.ExitError) error {
	low := strings.ToLower(ee.Stderr)
	switch {
	case strings.Contains(low, "already mounted"):
		return nil
	case strings.Contains(low, "not currently mounted"):
		return nil
	case strings.Contains(low, "busy"):
		return api.Errorf(api.CodeBusy, "%s", strings.TrimSpace(ee.Stderr))
	case strings.Contains(low, "does not exist"):
		return api.Errorf(api.CodeNotFound, "%s", strings.TrimSpace(ee.Stderr))
	}
	return api.Errorf(api.CodeInternal, "zfs: %s", strings.TrimSpace(ee.Stderr))
}
