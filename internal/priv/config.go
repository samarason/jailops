package priv

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Default locations on a FreeBSD host.
const (
	// DefaultSocket is the helper's socket. Its directory belongs to root (mode 0710, group jailops): the daemon may
	// reach the socket but cannot put anything in its place.
	DefaultSocket     = "/var/run/jailops-priv/priv.sock"
	DefaultConfDir    = "/usr/local/etc/jailops/jails"
	DefaultHelperPath = "/usr/local/libexec/jailops-priv"
	// DefaultStorageFile persists the storage roots registered at run time.
	DefaultStorageFile = "/usr/local/etc/jailops/priv.d/storage.conf"
	// AnchorPrefix is the pf anchor tree owned by JailOps.
	AnchorPrefix = "jailops/"
)

// Limits bound what one request can ask for.
type Limits struct {
	MaxFileBytes     int           // WriteFile and ReadFile payload
	MaxArgv          int           // arguments of a command
	MaxArgvBytes     int           // total size of a command line
	MaxNames         int           // dataset names in one request
	MaxProps         int           // properties in one request
	MaxVolumeBytes   uint64        // volsize, quota, reservation
	MaxExecPerJail   int           // exec sessions per jail
	MaxExecTotal     int           // exec sessions in total
	MaxInflight      int           // concurrent requests per connection (an exec session is one for as long as it runs: room for MaxExecTotal sessions and the calls beside them)
	MaxConns         int           // concurrent connections
	DefaultTimeout   time.Duration // applied when the request has no deadline
	MaxTimeout       time.Duration // cap for ordinary requests
	MaxStreamTimeout time.Duration // cap for send, receive and exec
}

// DefaultLimits returns the limits used when a field is zero.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes: 4 << 20, MaxArgv: 256, MaxArgvBytes: 128 << 10,
		MaxNames: 256, MaxProps: 64, MaxVolumeBytes: 16 << 40,
		MaxInflight: 96, MaxConns: 32, MaxExecPerJail: 8, MaxExecTotal: 64,
		DefaultTimeout: 5 * time.Minute, MaxTimeout: time.Hour, MaxStreamTimeout: 24 * time.Hour,
	}
}

func (l Limits) fill() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes > 0 {
		d.MaxFileBytes = l.MaxFileBytes
	}
	if l.MaxArgv > 0 {
		d.MaxArgv = l.MaxArgv
	}
	if l.MaxArgvBytes > 0 {
		d.MaxArgvBytes = l.MaxArgvBytes
	}
	if l.MaxNames > 0 {
		d.MaxNames = l.MaxNames
	}
	if l.MaxProps > 0 {
		d.MaxProps = l.MaxProps
	}
	if l.MaxVolumeBytes > 0 {
		d.MaxVolumeBytes = l.MaxVolumeBytes
	}
	if l.MaxExecPerJail > 0 {
		d.MaxExecPerJail = l.MaxExecPerJail
	}
	if l.MaxExecTotal > 0 {
		d.MaxExecTotal = l.MaxExecTotal
	}
	if l.MaxInflight > 0 {
		d.MaxInflight = l.MaxInflight
	}
	if l.MaxConns > 0 {
		d.MaxConns = l.MaxConns
	}
	if l.DefaultTimeout > 0 {
		d.DefaultTimeout = l.DefaultTimeout
	}
	if l.MaxTimeout > 0 {
		d.MaxTimeout = l.MaxTimeout
	}
	if l.MaxStreamTimeout > 0 {
		d.MaxStreamTimeout = l.MaxStreamTimeout
	}
	return d
}

// AdminPolicy is the allow-list for dangerous parameters. A request carrying
// an admin assertion may use only what is listed here; an empty list allows
// nothing. An API admin is root on the host when these are allowed, and the
// documentation says so.
type AdminPolicy struct {
	// RawJailParams are jail.conf parameter names accepted beyond the fixed
	// set the renderer emits (for example "cpuset", "children.max").
	RawJailParams []string
	// AllowFlags are the "allow.*" flags accepted, without the prefix.
	AllowFlags []string
	// DevfsRulesets are the devfs ruleset numbers accepted besides the default.
	DevfsRulesets []int
	// HostMountRoots are host directories a jail fstab may mount from.
	HostMountRoots []string
	// ZFSProps are native ZFS properties accepted beyond the fixed set.
	ZFSProps []string
	// Routes lets an admin add routes through a gateway.
	Routes bool
	// RawPF lets an admin load rulesets containing include, file tables and
	// other constructs the helper otherwise refuses.
	RawPF bool
	// ResumeSend lets an admin resume a send from an opaque token.
	ResumeSend bool
	// ZFSDelegation lets an admin hand a jail one dataset of its own, `<container>/delegated`: the jailed property
	// of that dataset, `zfs.dataset` with that name, allow.mount, allow.mount.zfs and enforce_statfs=1 in the jail's
	// jail.conf. The jail's root can then create datasets, snapshots and mounts below it.
	ZFSDelegation bool
}

// Config configures validation and the Local implementation.
type Config struct {
	// StorageRoots are the storage roots fixed by the operator in priv.conf,
	// for example "tank/jailops". Roots registered at run time
	// (storage.register) are added from StorageFile. Every dataset name must
	// be one registered root or live below exactly one of them. A root is
	// active only when it exists, lives on an imported pool and carries
	// jailops:managed=on locally; a root that fails this is listed as
	// inactive and allows nothing.
	StorageRoots []string
	// RootDataset is deprecated: it is added to StorageRoots.
	RootDataset string
	// StorageFile persists the roots registered at run time (default
	// DefaultStorageFile). It is root-owned, mode 0600, and reread on SIGHUP.
	StorageFile string
	// AllowPoolRoot lets a pool's top dataset be registered as a root.
	AllowPoolRoot bool
	// AllowStartWithoutPF lets a jail with a network link start while pf is disabled; by default the start is refused.
	AllowStartWithoutPF bool
	// FetchHosts are the hosts fetch may download from (default
	// DefaultFetchHosts).
	FetchHosts []string
	// ImageMirrors are directories fs.read_file may read besides the storage
	// roots (a local mirror of image archives). Reading is all that is allowed.
	ImageMirrors []string
	// MountBase is optional. It only supplies the default StateDir
	// (<MountBase>/state); file and mount paths are checked against the
	// mountpoints of the registered roots, not against it.
	MountBase string
	// ConfDir holds the rendered jail.conf and fstab files.
	ConfDir string
	// StateDir is the state directory (objects/<Kind>/<uuid>.json, rendered/).
	StateDir string
	// WorkDir is the daemon's scratch directory (image builds). Empty: none.
	WorkDir string
	// PkgKeysDir holds the key directories (fingerprints) that a pkg repository configuration written by the daemon
	// may name besides the base system's /usr/share/keys (default DefaultPkgKeysDir). KeyringDir holds the keyrings
	// that debootstrap may check a release with (default DefaultKeyringDir). Both belong to root, are not
	// writable by others and lie outside every directory the daemon writes: the daemon never chooses what the
	// helper trusts. Their contents are checked every time they are used.
	PkgKeysDir, KeyringDir string
	// UnboundConf is the one file the helper writes the names of the running jails into for the host's resolver
	// (dns.unbound, docs/dns.md). The helper binary's default is DefaultUnboundConf, the conf.d of the base system's
	// local-unbound, which counts only when that directory exists; empty (also the zero Config): off. Its directory
	// belongs to root and is closed to others, and lies outside every directory the daemon writes.
	UnboundConf string
	// DNSSuffix is the zone under which the names of the jails live: NAME.PROJECT.<suffix> (dns-suffix; default
	// DefaultDNSSuffix). One or more DNS labels; `local` (multicast DNS) is refused. A suffix of the administrator's own
	// (corp.example) is the clean choice.
	DNSSuffix string
	// WireGuardDir holds the keys of WireGuard interfaces, one directory per object (default
	// DefaultWireGuardDir). It belongs to root with mode 0700 and lies outside every directory the daemon writes.
	WireGuardDir string
	// WireGuardRoutes are networks a WireGuard tunnel may route into itself although they are wider than a /8 or /16,
	// or cover an address of the host, its gateway, a resolver, loopback, link-local or multicast (wireguard-routes).
	WireGuardRoutes []netip.Prefix
	// noOwnerCheck skips the check that the helper's own directories belong to root (tests).
	noOwnerCheck bool
	// HelperPath is the path jail.conf hooks call; only the exact hook
	// command lines are accepted in a jail.conf.
	HelperPath string
	// Sysctls extends the read allow-list.
	Sysctls []string
	// HostManage lists the host management modules the helper changes (host-manage; docs/appliance.md). Empty:
	// the host operations only read.
	HostManage []string
	// HostDir holds the snapshots of host files and the record of what was applied (default DefaultHostDir). It
	// belongs to root, mode 0700: the daemon can neither read nor change it.
	HostDir string
	Admin   AdminPolicy
	Limits  Limits

	reg *rootSet // registered storage roots, shared by copies of the Config
}

// DefaultSysctls is the sysctl read allow-list.
var DefaultSysctls = []string{
	"kern.osrelease", "kern.osreldate", "kern.ostype", "kern.version", "kern.boottime",
	"kern.features.vimage",
	"net.inet.ip.forwarding", "net.inet6.ip6.forwarding", "net.inet6.icmp6.nd6_onlink_ns_rfc4861", "net.inet6.ip6.use_stableaddr", "security.jail.jailed",
	"security.jail.vnet", "kern.racct.enable", "hw.ncpu", "hw.physmem",
}

// Normalize fills defaults and cleans paths. It returns an error when the
// configuration cannot enforce its own rules.
func (c Config) Normalize() (Config, error) {
	if c.ConfDir == "" {
		c.ConfDir = DefaultConfDir
	}
	if c.HelperPath == "" {
		c.HelperPath = DefaultHelperPath
	}
	c.StorageRoots = append([]string(nil), c.StorageRoots...)
	if c.RootDataset != "" && !slices.Contains(c.StorageRoots, c.RootDataset) {
		c.StorageRoots = append(c.StorageRoots, c.RootDataset)
	}
	c.RootDataset = ""
	for _, r := range c.StorageRoots {
		if err := c.checkRootName(r); err != nil {
			return c, err
		}
	}
	if err := checkRootOverlap(c.StorageRoots); err != nil {
		return c, err
	}
	if c.StorageFile == "" {
		c.StorageFile = DefaultStorageFile
	}
	if !filepath.IsAbs(c.StorageFile) || filepath.Clean(c.StorageFile) != c.StorageFile {
		return c, api.Errorf(api.CodeInvalid, "storage file %q must be a clean absolute path", c.StorageFile)
	}
	if c.reg == nil {
		c.reg = newRootSet()
	}
	if c.MountBase != "" {
		if !filepath.IsAbs(c.MountBase) {
			return c, api.Errorf(api.CodeInvalid, "mount base must be an absolute path")
		}
		c.MountBase = filepath.Clean(c.MountBase)
		if c.MountBase == "/" {
			return c, api.Errorf(api.CodeInvalid, "mount base must not be /")
		}
		if c.StateDir == "" {
			c.StateDir = filepath.Join(c.MountBase, "state")
		}
	}
	if c.StateDir == "" {
		return c, api.Errorf(api.CodeInvalid, "state directory is required (state-dir)")
	}
	if c.WorkDir != "" {
		if !filepath.IsAbs(c.WorkDir) || filepath.Clean(c.WorkDir) == "/" {
			return c, api.Errorf(api.CodeInvalid, "work directory %q must be an absolute path other than /", c.WorkDir)
		}
		c.WorkDir = filepath.Clean(c.WorkDir)
	}
	for _, p := range []*string{&c.ConfDir, &c.StateDir, &c.HelperPath} {
		if !filepath.IsAbs(*p) {
			return c, api.Errorf(api.CodeInvalid, "path %q must be absolute", *p)
		}
		*p = filepath.Clean(*p)
	}
	for _, h := range c.FetchHosts {
		if !reHostName.MatchString(strings.TrimPrefix(h, "http://")) {
			return c, api.Errorf(api.CodeInvalid, "fetch host %q is not a lower case host name (http://<host> allows plain http for that host)", h)
		}
	}
	if c.PkgKeysDir == "" {
		c.PkgKeysDir = DefaultPkgKeysDir
	}
	if c.KeyringDir == "" {
		c.KeyringDir = DefaultKeyringDir
	}
	for _, p := range []struct{ key, dir string }{{"pkg-keys-dir", c.PkgKeysDir}, {"keyring-dir", c.KeyringDir}} {
		if !filepath.IsAbs(p.dir) || filepath.Clean(p.dir) != p.dir || filepath.Dir(p.dir) == "/" {
			return c, api.Errorf(api.CodeInvalid, "%s %q must be a clean absolute path at least two levels deep", p.key, p.dir)
		}
		for _, d := range []string{c.StateDir, c.ConfDir, c.WorkDir, c.MountBase, c.WireGuardDir} {
			if d != "" && (within(d, p.dir) || within(p.dir, d)) {
				return c, api.Errorf(api.CodeInvalid, "%s %q must not overlap %s: the daemon writes there, and the helper trusts what is in this directory", p.key, p.dir, d)
			}
		}
	}
	if c.DNSSuffix == "" {
		c.DNSSuffix = DefaultDNSSuffix
	}
	if err := validate.Hostname("dns-suffix", c.DNSSuffix); err != nil || c.DNSSuffix == "local" || strings.HasSuffix(c.DNSSuffix, ".local") || len(c.DNSSuffix) > 100 {
		return c, api.Errorf(api.CodeInvalid, "dns-suffix %q must be DNS labels and not `local` (multicast DNS)", c.DNSSuffix)
	}
	if c.UnboundConf != "" {
		if !filepath.IsAbs(c.UnboundConf) || filepath.Clean(c.UnboundConf) != c.UnboundConf || filepath.Dir(c.UnboundConf) == "/" || !strings.HasSuffix(c.UnboundConf, ".conf") {
			return c, api.Errorf(api.CodeInvalid, "unbound-conf %q must be a clean absolute path of a .conf file at least two levels deep", c.UnboundConf)
		}
		for _, d := range []string{c.StateDir, c.ConfDir, c.WorkDir, c.MountBase} {
			if d != "" && within(d, c.UnboundConf) {
				return c, api.Errorf(api.CodeInvalid, "unbound-conf %q must not lie in %s: the daemon writes there", c.UnboundConf, d)
			}
		}
	}
	if c.WireGuardDir == "" {
		c.WireGuardDir = DefaultWireGuardDir
	}
	if !filepath.IsAbs(c.WireGuardDir) || filepath.Clean(c.WireGuardDir) != c.WireGuardDir || filepath.Dir(c.WireGuardDir) == "/" {
		return c, api.Errorf(api.CodeInvalid, "wireguard directory %q must be a clean absolute path at least two levels deep", c.WireGuardDir)
	}
	for _, d := range []string{c.StateDir, c.ConfDir, c.WorkDir, c.MountBase} {
		if d != "" && (within(d, c.WireGuardDir) || within(c.WireGuardDir, d)) {
			return c, api.Errorf(api.CodeInvalid, "wireguard directory %q must not overlap %s", c.WireGuardDir, d)
		}
	}
	c.ImageMirrors = append([]string(nil), c.ImageMirrors...)
	for i, m := range c.ImageMirrors {
		if !filepath.IsAbs(m) || filepath.Clean(m) == "/" {
			return c, api.Errorf(api.CodeInvalid, "image mirror %q is not acceptable", m)
		}
		c.ImageMirrors[i] = filepath.Clean(m)
	}
	c.Admin.HostMountRoots = append([]string(nil), c.Admin.HostMountRoots...)
	for i, r := range c.Admin.HostMountRoots {
		if !filepath.IsAbs(r) || filepath.Clean(r) == "/" {
			return c, api.Errorf(api.CodeInvalid, "host mount root %q is not acceptable", r)
		}
		c.Admin.HostMountRoots[i] = filepath.Clean(r)
	}
	if err := c.checkHostManage(); err != nil {
		return c, err
	}
	c.HostManage = append([]string(nil), c.HostManage...)
	if c.HostDir == "" {
		c.HostDir = DefaultHostDir
	}
	if !filepath.IsAbs(c.HostDir) || filepath.Clean(c.HostDir) == "/" {
		return c, api.Errorf(api.CodeInvalid, "host directory %q must be an absolute path other than /", c.HostDir)
	}
	c.HostDir = filepath.Clean(c.HostDir)
	c.Limits = c.Limits.fill()
	return c, nil
}

// roots returns the allow-listed file roots: the mountpoints of the active
// storage roots, the conf directory and the state directory.
func (c Config) roots() []string {
	// The state directory is the daemon's own (it writes there itself): the helper never writes in a directory the
	// daemon owns, which would let the daemon swap a component for a symlink between a check and the use.
	r := append(c.reg.mounts(), c.ConfDir)
	if c.WorkDir != "" {
		r = append(r, c.WorkDir) // image builds write their repository configuration and tarballs here
	}
	return r
}
