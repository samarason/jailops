// Package daemon wires jailopsd: configuration, start order, listeners,
// reconciler and graceful shutdown. It holds no business logic.
package daemon

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/sdk/api"
)

// DefaultConfigPath is where jailopsd looks for its configuration.
const DefaultConfigPath = "/usr/local/etc/jailops/jailopsd.yaml"

// Config is jailopsd.yaml. Unknown keys are an error.
type Config struct {
	// Role is "host" (the only role of this binary). The backup node is a
	// separate daemon.
	Role string `yaml:"role"`
	// Hub turns the daemon into a hub: it keeps a registry of remotes and
	// forwards ?host= requests over pinned mTLS.
	Hub bool `yaml:"hub"`

	Pool string `yaml:"pool"`
	// Dataset is the JailOps dataset; default "<pool>/jailops".
	Dataset string `yaml:"dataset"`
	// MountBase is where the dataset is mounted; default "/usr/local/jailops".
	MountBase string `yaml:"mount_base"`
	// StateDir defaults to <data_dir>/state, which is where jailops-priv init mounts the state dataset. It must lie
	// outside the storage root: the root is owned by the helper and not writable by the daemon.
	StateDir string `yaml:"state_dir"`
	// DataDir holds the SQLite database, the seal key, TLS material and the
	// operation journal; default /var/db/jailops.
	DataDir string `yaml:"data_dir"`
	// ConfDir is where rendered jail.conf files go (the conf_dir of jailops-priv).
	ConfDir string `yaml:"conf_dir"`
	WorkDir string `yaml:"work_dir"`

	Listen Listen `yaml:"listen"`
	// Web switches the embedded management console. The API does not depend on it.
	Web  Web  `yaml:"web"`
	Priv Priv `yaml:"priv"`
	Log  Log  `yaml:"log"`

	Reconcile Reconcile `yaml:"reconcile"`
	ZFS       ZFSConf   `yaml:"zfs"`
	Limits    Limits    `yaml:"limits"`
	Projects  Projects  `yaml:"projects"`
	Lifecycle Lifecycle `yaml:"lifecycle"`
	// Backup, when present, enables host-side backups (design 9): the key,
	// capture, the schedule, restore and restore tests, against one backup
	// node. Absent, every backup call answers unsupported.
	Backup *BackupConf `yaml:"backup"`
	// Updates configures the update scheduler.
	Updates UpdatesConf `yaml:"updates"`
	// Jails holds the defaults of new jails: their shell and bash prompt (docs/shell.md).
	Jails JailsConf `yaml:"jails"`
	// Apps configures the application catalog (docs/apps.md).
	Apps AppsConf `yaml:"apps"`
	// Host configures host management (docs/appliance.md).
	Host HostConf `yaml:"host"`
	// Logging configures log forwarding (docs/logging.md).
	Logging LoggingConf `yaml:"logging"`
	// Audit configures how long the audit log keeps its entries.
	Audit AuditConf `yaml:"audit"`
	// Devd configures reading the kernel's notifications from devd(8) (docs/operations.md).
	Devd DevdConf `yaml:"devd"`

	// Appliance are the modules rc.conf turned on (ApplyAppliance); never read from the file.
	Appliance []string `yaml:"-"`
}

// AuditConf bounds the audit log. Once a day the daemon deletes the entries older than Retention and the oldest
// beyond MaxEntries; the newest 1000 entries are never deleted.
type AuditConf struct {
	// Retention is how long an entry is kept (default 90d; at least 1d).
	Retention Duration `yaml:"retention"`
	// MaxEntries bounds the number of entries (default 1000000; at least 1000).
	MaxEntries int `yaml:"max_entries"`
}

// LoggingConf configures where the logs of the jails go. Forward is the
// sink list in force until an administrator stores one through the API.
type LoggingConf struct {
	Forward []api.LogSink `yaml:"forward"`
	// SecretsDir is the only directory the CA and token files of a sink set through the API may lie in (default
	// DefaultLogSecretsDir; root-owned, 0750 root:jailops). The files of Forward may lie anywhere.
	SecretsDir string `yaml:"secrets_dir"`
}

// DefaultLogSecretsDir is the default of logging.secrets_dir.
const DefaultLogSecretsDir = "/usr/local/etc/jailops/sinks"

// HostConf configures host management: JailOps changes the host itself only for the modules listed here (and in
// host-manage of priv.conf).
type HostConf struct {
	Manage HostManage `yaml:"manage"`
}

// HostManage lists the modules JailOps manages. Empty (the default): none.
type HostManage struct {
	Modules []string `yaml:"modules"`
}

// AppsConf configures the application catalog: definitions the daemon reads
// from local files, installed by the jailops-apps package.
type AppsConf struct {
	// CatalogDir holds the *.yaml definitions (default
	// /usr/local/share/jailops/apps). A missing directory is an empty catalog.
	CatalogDir string `yaml:"catalog_dir"`
	// LocalDir holds the operator's own definitions (default
	// /usr/local/etc/jailops/apps), read with the catalog; one of the same
	// name as a packaged one wins. A missing directory is empty.
	LocalDir string `yaml:"local_dir"`
}

// DevdConf configures the events the host raises from the kernel's notifications: ZFS errors, the link of the uplink,
// a limit a jail hit.
type DevdConf struct {
	// Enable turns reading devd's socket on or off; the default is on for FreeBSD and off elsewhere.
	Enable *bool `yaml:"enable"`
	// Pipe is the seqpacket socket of devd; default /var/run/devd.seqpacket.pipe.
	Pipe string `yaml:"pipe"`
}

// On reports whether the daemon reads devd's socket.
func (d DevdConf) On() bool {
	if d.Enable != nil {
		return *d.Enable
	}
	return runtime.GOOS == "freebsd"
}

// UpdatesConf configures managed updates (design 8.4). Updates are off for
// every jail until a user sets its updates.mode.
type UpdatesConf struct {
	// Tick is how often schedules are evaluated (default 1m).
	Tick Duration `yaml:"tick"`
	// ProjectFilesDir holds the provisioning files, one directory per project
	// (default <state_dir>/project-files).
	ProjectFilesDir string `yaml:"project_files_dir"`
}

// DefaultMaxStates is the default of jails.max_states: the pf states each pass rule of a jail may create. Ten thousand
// keeps a jail far from the 100000 states of pf's default table, and is above what a busy DNS or web server of a
// jail keeps open at once; a jail that needs more has limits.states.
const DefaultMaxStates = 10000

// JailsConf holds the defaults a new FreeBSD jail gets when its request (and its profiles) leave the shell and
// prompt keys empty. They apply to jails created from now on; an existing jail gets them only through
// `jailops jail shell-setup`.
type JailsConf struct {
	// Shell is bash (the default: installed at the jail's first start and started by `jailops shell` and the
	// console) or sh (FreeBSD's own shell; nothing is installed).
	Shell string `yaml:"shell"`
	// Prompt is the bash prompt of a jail whose shell is bash: default (the default), short, none, or a PS1 text.
	Prompt string `yaml:"prompt"`
	// PromptColor is the 256-colour number of the default prompt, 1 to 255 (default 39, a light blue).
	PromptColor *int `yaml:"prompt_color"`
	// MaxStates is the pf state limit of a jail whose limits.states is 0: each pass rule of its anchor may create that
	// many states (default 10000; 0 sets no limit).
	MaxStates *int `yaml:"max_states"`
}

// BackupConf configures internal/hostbackup.
type BackupConf struct {
	// KeyPath is the host key file (default /var/db/jailops/backup.key).
	KeyPath string `yaml:"key_path"`
	// PassphraseFile, when set, holds the passphrase (first line) that wraps
	// the key file; empty relies on the file mode, which unattended
	// schedules need.
	PassphraseFile string `yaml:"passphrase_file"`
	// Node is the backup node this host pushes to.
	Node BackupNode `yaml:"node"`
	// RecoveryRecipients are age public keys the key is escrowed to.
	RecoveryRecipients []string `yaml:"recovery_recipients"`
	// AllowUnescrowed lets backups run while the key is not escrowed.
	AllowUnescrowed bool `yaml:"allow_unescrowed"`
	// Concurrency bounds the jobs that run at once (default 2).
	Concurrency int `yaml:"concurrency"`
	// ScratchDir and ScratchDataset are where restore tests restore.
	ScratchDir     string `yaml:"scratch_dir"`
	ScratchDataset string `yaml:"scratch_dataset"`
}

// BackupNode names the node and pins its certificate.
type BackupNode struct {
	Name        string `yaml:"name"`
	Address     string `yaml:"address"`     // host:port
	Fingerprint string `yaml:"fingerprint"` // hex SHA-256 of the node certificate
	CertFile    string `yaml:"cert_file"`   // this host's client certificate
	KeyFile     string `yaml:"key_file"`
}

// Lifecycle configures thin jails.
type Lifecycle struct {
	// Persistent replaces the list of paths of a thin jail that survive a
	// generation switch (each in its own dataset). Empty keeps the default:
	// /etc, /usr/local, /var/db (UNVERIFIED: pkg database persistence),
	// /var/log, /var/mail, /var/spool, /home and /root.
	Persistent []PersistentPath `yaml:"persistent"`
}

// PersistentPath is one entry of Lifecycle.Persistent.
type PersistentPath struct {
	Dataset string `yaml:"dataset"`
	Path    string `yaml:"path"`
	Class   string `yaml:"class"` // system or data
	Merge   bool   `yaml:"merge"`
	NoSeed  bool   `yaml:"no_seed"`
}

// Projects configures project creation. NetworkPool is the pool of subnets
// that `project create --new-network` carves dedicated networks from; without
// it that option answers unsupported.
type Projects struct {
	// NetworkPool is an IPv4 prefix such as "10.64.0.0/12".
	NetworkPool string `yaml:"network_pool"`
	// NetworkBits is the size of each project subnet (24 when zero).
	NetworkBits int `yaml:"network_bits"`
	// Uplink and NAT apply to the dedicated networks.
	Uplink string `yaml:"uplink"`
	NAT    bool   `yaml:"nat"`
}

// Web configures the embedded web console of the host. The console is always in the binary and off until the operator
// turns it on: with enabled false (the default) the daemon serves the API only, every path outside /api/v1 and /healthz
// answers 404, and nothing else changes.
type Web struct {
	// Enabled defaults to false.
	Enabled *bool `yaml:"enabled"`
}

// UI reports whether the embedded console is served.
func (c Config) UI() bool { return c.Web.Enabled != nil && *c.Web.Enabled }

// DefaultHTTPSAddress is the port of JailOps on the network (docs/ports.md).
const DefaultHTTPSAddress = ":39110"

// ApplyWebOverride is what the -web and -no-web flags (and the rc.conf knob jailopsd_web) do to a configuration. -no-web
// switches the console off. -web switches it on, and, when no TLS listener is configured, opens the default one
// (DefaultHTTPSAddress): asking for the console from the command line or from rc.conf means asking to see it in a
// browser. A console switched on only in the file (web.enabled: true) opens no listener by itself.
func ApplyWebOverride(c Config, force, no bool) Config {
	if !force && !no {
		return c
	}
	on := force && !no
	c.Web.Enabled = &on
	if on && c.Listen.HTTPS.Address == "" {
		c.Listen.HTTPS.Address = DefaultHTTPSAddress
	}
	return c
}

// Listen configures the listeners.
type Listen struct {
	Unix  UnixListen  `yaml:"unix"`
	HTTPS HTTPSListen `yaml:"https"`
}

// UnixListen is the local socket. The kernel-reported peer uid decides one thing: uid 0 (root) is a global
// administrator, the host's recovery access. Every other peer is anonymous, exactly like an unauthenticated
// remote client, and authenticates like one (API token, session login). There is no mapping of Unix users or groups
// to roles. Mode 0666 is therefore safe: who may connect is not what decides who may do something.
type UnixListen struct {
	Path string `yaml:"path"`
	Mode uint32 `yaml:"mode"`
}

// HTTPSListen is the network listener: pinned mTLS, API tokens and the web UI
// login. An empty address disables it.
type HTTPSListen struct {
	Address string `yaml:"address"`
	// Cert and Key default to <data_dir>/tls/server.{crt,key}, generated on
	// first start.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// Names are extra DNS names and IPs for a generated certificate.
	Names []string `yaml:"names"`
	// ACME obtains and renews the certificate from a public CA (docs/exposure.md). A choice made through the API
	// (POST /api/v1/host/certificate/...) replaces it.
	ACME ACMEConf `yaml:"acme"`
}

// ACMEConf is listen.https.acme: api.ACMESpec and the address of the challenge listener.
type ACMEConf struct {
	Enabled      bool     `yaml:"enabled"`
	Email        string   `yaml:"email"`
	Domains      []string `yaml:"domains"`
	DirectoryURL string   `yaml:"directory_url"`
	Challenge    string   `yaml:"challenge"`
	AcceptTOS    bool     `yaml:"accept_tos"`
	// ChallengeAddress is the plain-http listener that answers http-01 challenges and nothing else (default
	// DefaultChallengeAddress); port 80 is redirected to it, on the loopback addresses.
	ChallengeAddress string `yaml:"challenge_address"`
}

// DefaultChallengeAddress is the listener of http-01 challenges (docs/ports.md).
const DefaultChallengeAddress = ":39080"

// Spec is the setting as the API sees it.
func (a ACMEConf) Spec() api.ACMESpec {
	return api.ACMESpec{Enabled: a.Enabled, Email: a.Email, Domains: a.Domains, DirectoryURL: a.DirectoryURL,
		Challenge: api.ACMEChallenge(a.Challenge), AcceptTOS: a.AcceptTOS}.Canonical()
}

// Priv says how jailopsd reaches the root helper.
type Priv struct {
	Socket string `yaml:"socket"`
}

// Log configures logging to stderr.
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text or json
}

// Reconcile tunes the loop.
type Reconcile struct {
	Interval  Duration `yaml:"interval"`
	Autostart *bool    `yaml:"autostart"`
}

// ZFSConf holds ZFS compatibility settings.
type ZFSConf struct {
	// CompatFile is the OpenZFS compatibility file name of the target release
	// line, for example "openzfs-2.2-freebsd".
	CompatFile string `yaml:"compat_file"`
	CompatDir  string `yaml:"compat_dir"`
}

// Limits bounds requests.
type Limits struct {
	MaxBodyBytes   int64    `yaml:"max_body_bytes"`
	RequestTimeout Duration `yaml:"request_timeout"`
	// AuthFailureThreshold is the number of failed authentications from one
	// source (bad token, untrusted certificate, forged requestor claim)
	// before that source is locked out (default 5).
	AuthFailureThreshold int `yaml:"auth_failure_threshold"`
	// ExecSessionsPerJail, ExecIdle and ExecMax bound exec sessions
	// (defaults 8, 30m and 12h).
	ExecSessionsPerJail int      `yaml:"exec_sessions_per_jail"`
	ExecIdle            Duration `yaml:"exec_idle"`
	ExecMax             Duration `yaml:"exec_max"`
}

// Duration is a time.Duration that reads "30s" in YAML.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	// whole days are written "90d"
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 {
			return fmt.Errorf("invalid duration %q", s)
		}
		*d = Duration(time.Duration(days) * 24 * time.Hour)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(v)
	return nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Defaults returns the configuration with every default filled in.
func Defaults() Config {
	t := true
	return Config{
		Role: "host", MountBase: "/usr/local/jailops", DataDir: "/var/db/jailops",
		ConfDir: "/usr/local/etc/jailops/jails", WorkDir: "/var/tmp/jailops",
		Listen:    Listen{Unix: UnixListen{Path: "/var/run/jailops/jailops.sock", Mode: 0o666}},
		Priv:      Priv{Socket: priv.DefaultSocket},
		Log:       Log{Level: "info", Format: "text"},
		Reconcile: Reconcile{Interval: Duration(60 * time.Second), Autostart: &t},
		Limits:    Limits{MaxBodyBytes: 4 << 20, RequestTimeout: Duration(60 * time.Second)},
		Apps:      AppsConf{CatalogDir: apps.DefaultDir, LocalDir: apps.DefaultLocalDir},
		Audit:     AuditConf{Retention: Duration(90 * 24 * time.Hour), MaxEntries: 1000000},
		Logging:   LoggingConf{SecretsDir: DefaultLogSecretsDir},
	}
}

// Decode reads a configuration, rejecting unknown keys, and fills defaults.
func Decode(r io.Reader) (Config, error) {
	cfg := Defaults()
	raw, err := io.ReadAll(r)
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && err != io.EOF {
		return cfg, fmt.Errorf("config: %w", err)
	}
	return cfg.finish()
}

// Load reads the file at path.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	cfg, err := Decode(bytes.NewReader(b))
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) finish() (Config, error) {
	if c.Role == "" {
		c.Role = "host"
	}
	if c.Role != "host" {
		return c, fmt.Errorf("config: role %q is not supported by jailopsd: the backup node is a separate daemon (jailops-backupd)", c.Role)
	}
	if c.Pool == "" {
		return c, fmt.Errorf("config: pool is required")
	}
	if c.Dataset == "" {
		c.Dataset = c.Pool + "/jailops"
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Join(c.DataDir, "state")
	}
	if c.Audit.Retention == 0 {
		c.Audit.Retention = Duration(90 * 24 * time.Hour)
	}
	if c.Audit.MaxEntries == 0 {
		c.Audit.MaxEntries = 1000000
	}
	if c.Audit.Retention.Std() < 24*time.Hour || c.Audit.MaxEntries < 1000 {
		return c, fmt.Errorf("config: audit.retention must be at least 1d and audit.max_entries at least 1000")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return c, fmt.Errorf("config: log.level %q must be debug, info, warn or error", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return c, fmt.Errorf("config: log.format %q must be text or json", c.Log.Format)
	}
	if c.Apps.CatalogDir == "" {
		c.Apps.CatalogDir = apps.DefaultDir
	}
	switch c.Jails.Shell {
	case "":
		c.Jails.Shell = api.ShellBash
	case api.ShellBash, api.ShellSh:
	default:
		return c, fmt.Errorf("config: jails.shell %q must be bash or sh", c.Jails.Shell)
	}
	if c.Jails.Prompt == "" {
		c.Jails.Prompt = api.PromptDefault
	}
	if err := api.CheckPrompt(c.Jails.Prompt); err != nil {
		return c, fmt.Errorf("config: jails.prompt: %v", err)
	}
	if c.Jails.PromptColor == nil {
		n := api.DefaultPromptColor
		c.Jails.PromptColor = &n
	}
	if err := api.CheckPromptColor(*c.Jails.PromptColor); err != nil || *c.Jails.PromptColor == 0 {
		return c, fmt.Errorf("config: jails.prompt_color %d must be a 256-colour number between 1 and 255 (16 is black)", *c.Jails.PromptColor)
	}
	if c.Jails.MaxStates == nil {
		n := DefaultMaxStates
		c.Jails.MaxStates = &n
	}
	if *c.Jails.MaxStates < 0 || *c.Jails.MaxStates > 10000000 {
		return c, fmt.Errorf("config: jails.max_states %d must be between 0 and 10000000", *c.Jails.MaxStates)
	}
	if c.Apps.LocalDir == "" {
		c.Apps.LocalDir = apps.DefaultLocalDir
	}
	for name, p := range map[string]string{"mount_base": c.MountBase, "state_dir": c.StateDir, "data_dir": c.DataDir, "conf_dir": c.ConfDir,
		"work_dir": c.WorkDir, "listen.unix.path": c.Listen.Unix.Path, "priv.socket": c.Priv.Socket, "apps.catalog_dir": c.Apps.CatalogDir,
		"apps.local_dir": c.Apps.LocalDir} {
		if name == "listen.unix.path" && p == "" {
			continue // the socket is disabled
		}
		if !filepath.IsAbs(p) {
			return c, fmt.Errorf("config: %s must be an absolute path", name)
		}
	}
	if a := c.Listen.HTTPS.Address; a != "" {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			return c, fmt.Errorf("config: listen.https.address %q must be host:port or :port (for example \":39110\" or \"127.0.0.1:39110\"): %v", a, err)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			return c, fmt.Errorf("config: listen.https.address %q has an invalid port", a)
		}
		if host != "" {
			if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil && !validHostname(host) {
				return c, fmt.Errorf("config: listen.https.address %q: %q is neither an IP address nor a host name", a, host)
			}
		}
	}
	if err := c.checkACME(); err != nil {
		return c, err
	}
	if (c.Listen.HTTPS.Cert == "") != (c.Listen.HTTPS.Key == "") {
		return c, fmt.Errorf("config: listen.https.cert and listen.https.key go together: give both (your certificate) or neither (a generated, self-signed one)")
	}
	for name, p := range map[string]string{"listen.https.cert": c.Listen.HTTPS.Cert, "listen.https.key": c.Listen.HTTPS.Key} {
		if p != "" && !filepath.IsAbs(p) {
			return c, fmt.Errorf("config: %s must be an absolute path", name)
		}
	}
	if c.Projects.NetworkPool != "" {
		p, err := netip.ParsePrefix(c.Projects.NetworkPool)
		if err != nil || !p.Addr().Is4() {
			return c, fmt.Errorf("config: projects.network_pool %q must be an IPv4 prefix such as 10.64.0.0/12", c.Projects.NetworkPool)
		}
		if bits := c.Projects.NetworkBits; bits != 0 && (bits <= p.Bits() || bits > 29) {
			return c, fmt.Errorf("config: projects.network_bits %d does not fit %s", bits, p)
		}
	}
	if b := c.Backup; b != nil {
		if b.Node.Address == "" || b.Node.Fingerprint == "" {
			return c, fmt.Errorf("config: backup.node.address and backup.node.fingerprint are required (the node's certificate is pinned)")
		}
		if b.Node.CertFile == "" || b.Node.KeyFile == "" {
			return c, fmt.Errorf("config: backup.node.cert_file and backup.node.key_file are required (this host's client certificate)")
		}
		for name, p := range map[string]string{"key_path": b.KeyPath, "passphrase_file": b.PassphraseFile, "node.cert_file": b.Node.CertFile,
			"node.key_file": b.Node.KeyFile, "scratch_dir": b.ScratchDir} {
			if p != "" && !filepath.IsAbs(p) {
				return c, fmt.Errorf("config: backup.%s must be an absolute path", name)
			}
		}
		if b.Concurrency < 0 || b.Concurrency > 32 {
			return c, fmt.Errorf("config: backup.concurrency must be between 0 and 32")
		}
	}
	seenDS := map[string]bool{}
	for i, p := range c.Lifecycle.Persistent {
		if p.Dataset == "" || strings.ContainsAny(p.Dataset, "/@ ") || seenDS[p.Dataset] {
			return c, fmt.Errorf("config: lifecycle.persistent[%d].dataset %q must be a unique single dataset name", i, p.Dataset)
		}
		seenDS[p.Dataset] = true
		if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || p.Path == "/" {
			return c, fmt.Errorf("config: lifecycle.persistent[%d].path %q must be a clean absolute path below /", i, p.Path)
		}
		if p.Class != "system" && p.Class != "data" {
			return c, fmt.Errorf("config: lifecycle.persistent[%d].class must be system or data", i)
		}
	}
	var seenMod []string
	for _, m := range c.Host.Manage.Modules {
		if !slices.Contains(api.HostModules, m) {
			return c, fmt.Errorf("config: host.manage.modules: %q is not a module (known: %s)", m, strings.Join(api.HostModules, ", "))
		}
		if slices.Contains(seenMod, m) {
			return c, fmt.Errorf("config: host.manage.modules lists %q twice", m)
		}
		seenMod = append(seenMod, m)
	}
	if err := (api.LogForwardSpec{Sinks: c.Logging.Forward}).Validate(); err != nil {
		return c, fmt.Errorf("config: logging.forward: %v", err)
	}
	if d := c.Logging.SecretsDir; d == "" || !filepath.IsAbs(d) || filepath.Clean(d) != d || d == "/" {
		return c, fmt.Errorf("config: logging.secrets_dir %q must be a clean absolute path other than /", d)
	}
	if c.Devd.Pipe == "" {
		c.Devd.Pipe = "/var/run/devd.seqpacket.pipe"
	}
	if p := c.Devd.Pipe; !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsRune(p, 0) {
		return c, fmt.Errorf("config: devd.pipe %q must be a clean absolute path", p)
	}
	if c.Reconcile.Interval.Std() < time.Second {
		return c, fmt.Errorf("config: reconcile.interval must be at least 1s")
	}
	if c.Reconcile.Autostart == nil {
		t := true
		c.Reconcile.Autostart = &t
	}
	return c, nil
}

// checkACME validates listen.https.acme: the setting itself, the challenge listener, and that it does not meet
// certificate files of the operator. That a TLS listener exists is checked after the -web flag (CheckListeners).
func (c *Config) checkACME() error {
	a := &c.Listen.HTTPS.ACME
	if a.ChallengeAddress == "" {
		a.ChallengeAddress = DefaultChallengeAddress
	}
	if err := a.Spec().Validate(); err != nil {
		return fmt.Errorf("config: listen.https.acme: %v", err)
	}
	if _, err := redirectTarget(a.ChallengeAddress); err != nil {
		return fmt.Errorf("config: listen.https.acme.challenge_address: %v", err)
	}
	if a.Enabled && c.Listen.HTTPS.Cert != "" {
		return fmt.Errorf("config: listen.https.acme and listen.https.cert exclude each other: give your certificate files or let ACME obtain one")
	}
	return nil
}

// CheckListeners checks what depends on the listeners after the flags changed them: ACME needs the TLS listener,
// and with tls-alpn-01 the redirect of port 443 reaches it on the loopback addresses.
func (c Config) CheckListeners() error {
	a := c.Listen.HTTPS.ACME
	if !a.Enabled {
		return nil
	}
	if c.Listen.HTTPS.Address == "" {
		return fmt.Errorf("config: listen.https.acme needs the TLS listener: set listen.https.address, or jailopsd_web=\"YES\" in /etc/rc.conf")
	}
	if a.Spec().Challenge == api.ACMETLSALPN01 {
		if _, err := redirectTarget(c.Listen.HTTPS.Address); err != nil {
			return fmt.Errorf("config: listen.https.address with tls-alpn-01: %v", err)
		}
	}
	return nil
}

// redirectTarget checks a listener the host redirects a challenge port to: host:port with a port of 1024 or more, on
// all addresses or on a loopback address (the redirect targets 127.0.0.1 and ::1). It returns the port.
func redirectTarget(addr string) (int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("%q must be host:port or :port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || (n != 0 && n < 1024) || n > 65535 {
		return 0, fmt.Errorf("%q: the port must be 1024 to 65535 (the daemon is not root; the host redirects the CA's port to it)", addr)
	}
	if host != "" {
		ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil || !(ip.IsUnspecified() || ip.IsLoopback()) {
			return 0, fmt.Errorf("%q: listen on all addresses or a loopback address: the redirect of the CA's port targets 127.0.0.1 and ::1", addr)
		}
	}
	return n, nil
}

// ApplyAppliance adds the modules rc.conf turns on (jailops_appliance, the -appliance-modules flag) to
// host.manage.modules: the daemon manages the union. "all" is every module. The helper decides with its own list.
func ApplyAppliance(c Config, mods []string) (Config, error) {
	var add []string
	for _, m := range mods {
		names := []string{m}
		if m == "all" {
			names = api.HostModules
		} else if !slices.Contains(api.HostModules, m) {
			return c, fmt.Errorf("jailops_appliance_modules: %q is not a module (known: %s, or all)", m, strings.Join(api.HostModules, ", "))
		}
		for _, n := range names {
			if !slices.Contains(add, n) {
				add = append(add, n)
			}
		}
	}
	out := slices.Clone(c.Host.Manage.Modules)
	for _, m := range add {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	c.Host.Manage.Modules = out
	c.Appliance = add
	return c, nil
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func validHostname(h string) bool { return len(h) <= 253 && hostnameRE.MatchString(h) }
