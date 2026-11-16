package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/internal/supervise"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/hostbackup"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/logfwd"
	"jailops.net/jailops/internal/ndproxy"
	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/server"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/service/zfsadapt"
	"jailops.net/jailops/internal/state"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// Options are the inputs of Start that are not in the configuration file.
type Options struct {
	// Config is used as is when set; otherwise ConfigPath is read.
	Config     *Config
	ConfigPath string
	// Dev runs the privileged operations in process as root.
	Dev     bool
	Version string
	// ForceWeb serves the web console and NoWeb serves none, whatever web.enabled says (the -web and -no-web flags, the
	// rc.conf knob jailopsd_web="YES" or "NO"). Neither set: web.enabled decides, and it defaults to off.
	ForceWeb, NoWeb bool
	// ApplianceModules are the modules rc.conf turns on (jailops_appliance, the -appliance-modules flag): added to
	// host.manage.modules. The helper's own list decides what it changes.
	ApplianceModules []string
	// LogOutput receives the log (default os.Stderr).
	LogOutput io.Writer
	// Clients builds the operating system clients (default DefaultClients).
	Clients ClientFactory
	// Clock and Now are injectable for tests.
	Now func() time.Time
	// Hostname overrides os.Hostname.
	Hostname string
	// Env overrides the environment reported by GET /api/v1.
	Env *api.Environment
	// NoListen skips opening listeners (tests use Handler directly).
	NoListen bool
	// Backups wires a host-side backup backend.
	Backups service.Backups
	// Execer replaces how commands run in jails (tests; by default the helper
	// client, else jexec in process under --dev).
	Execer service.JailExecer
	// Registrar replaces how storage datasets are registered with the root
	// helper (tests; by default the helper client itself, else in process).
	Registrar service.StorageRegistrar
	// BackupTLS replaces the pinned node certificate and the client
	// certificate files of the backup section, and BackupMounter replaces how
	// dataset snapshots are read (tests).
	BackupTLS     *tls.Config
	BackupMounter hostbackup.Mounter
	// LogForwardTune adjusts the log forwarder (tests: poll interval, file check).
	LogForwardTune func(*logfwd.Env)
	// KeepAlive and ReadTimeout replace the keepalive interval of long requests (15s) and the read timeout of the
	// listeners (2m) (tests).
	KeepAlive, ReadTimeout time.Duration
	// ACMEHTTPClient talks to the ACME CA (tests: a CA of their own); TLSRoots decide whether a certificate comes
	// from a public CA (nil: the host's roots); ListenChallenge opens the http-01 listener (tests: a free port).
	ACMEHTTPClient  *http.Client
	TLSRoots        *x509.CertPool
	ListenChallenge func(addr string) (net.Listener, error)
	// ACMEAttempted hears how each ACME request ended (tests).
	ACMEAttempted func(error)
}

// Daemon is a running jailopsd.
type Daemon struct {
	cfg  Config
	log  *slog.Logger
	opts Options

	state   *state.Store
	db      *store.Store
	clients *Clients
	svc     *service.Service
	backups *hostBackups
	rec     *reconcile.Reconciler
	srv     *server.Server

	unixLn, httpsLn net.Listener
	servers         []*http.Server
	cert            tls.Certificate
	certs           *certReloader
	certMgr         *certManager

	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	failed chan error
}

// Run starts the daemon, waits for ctx to end and shuts down gracefully.
func Run(ctx context.Context, opts Options) error {
	d, err := Start(ctx, opts)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case err := <-d.failed:
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = d.Shutdown(sctx)
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return d.Shutdown(sctx)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// Start runs the start order: configuration, state (flock), store and
// migrations, operating system clients, service, route verification, then the
// listeners and background loops. Any failure undoes what was opened.
func Start(ctx context.Context, opts Options) (*Daemon, error) {
	var cfg Config
	switch {
	case opts.Config != nil:
		var err error
		if cfg, err = opts.Config.finish(); err != nil {
			return nil, err
		}
	default:
		path := opts.ConfigPath
		if path == "" {
			path = DefaultConfigPath
		}
		var err error
		if cfg, err = Load(path); err != nil {
			return nil, err
		}
	}
	cfg = ApplyWebOverride(cfg, opts.ForceWeb, opts.NoWeb)
	cfg, err := ApplyAppliance(cfg, opts.ApplianceModules)
	if err != nil {
		return nil, err
	}
	if err := cfg.CheckListeners(); err != nil {
		return nil, err
	}
	if opts.LogOutput == nil {
		opts.LogOutput = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Clients == nil {
		opts.Clients = DefaultClients
	}
	log := server.NewLogger(opts.LogOutput, cfg.Log.Format, parseLevel(cfg.Log.Level))
	d := &Daemon{cfg: cfg, log: log, opts: opts, failed: make(chan error, 4)}
	bg, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d.cancel = cancel
	ok := false
	defer func() {
		if !ok {
			d.teardown()
		}
	}()

	for _, dir := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "journal"), filepath.Join(cfg.DataDir, "tls"), cfg.WorkDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("daemon: %w", err)
		}
	}
	// 1. Operating system clients and the dataset layout.
	clients, err := opts.Clients(ctx, &cfg, opts.Dev)
	if err != nil {
		return nil, err
	}
	d.clients = clients
	if err := ensureLayout(ctx, clients.ZFS, cfg); err != nil {
		return nil, err
	}
	// 2. State, with the single-writer flock.
	st, err := state.Open(cfg.StateDir, state.Options{Hooks: state.Hooks{BeforeDestructive: d.snapshotState}})
	if err != nil {
		return nil, fmt.Errorf("daemon: opening state %s: %w", cfg.StateDir, err)
	}
	d.state = st
	// 3. Operational store and its migrations.
	db, err := store.Open(filepath.Join(cfg.DataDir, "jailops.db"), store.Options{Now: opts.Now})
	if err != nil {
		return nil, fmt.Errorf("daemon: opening database: %w", err)
	}
	d.db = db
	hostUUID, err := hostIdentity(ctx, db)
	if err != nil {
		return nil, err
	}
	sealKey, err := loadOrCreateKey(filepath.Join(cfg.DataDir, "seal.key"))
	if err != nil {
		return nil, err
	}
	secretsID, err := loadOrCreateSecretsKey(filepath.Join(cfg.DataDir, "secrets.key"))
	if err != nil {
		return nil, err
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	certPath := firstNonEmpty(cfg.Listen.HTTPS.Cert, filepath.Join(cfg.DataDir, "tls", "server.crt"))
	keyPath := firstNonEmpty(cfg.Listen.HTTPS.Key, filepath.Join(cfg.DataDir, "tls", "server.key"))
	d.cert, err = loadOrCreateCert(certPath, keyPath, cfg.Listen.HTTPS.Cert != "", hostname, cfg.Listen.HTTPS.Names, opts.Now())
	if err != nil {
		return nil, err
	}
	d.certs = newCertReloader(certPath, keyPath, d.cert, log, opts.Now)
	d.certMgr = &certManager{tlsDir: filepath.Join(cfg.DataDir, "tls"), identity: d.certs, configured: cfg.Listen.HTTPS.Cert != "",
		https: cfg.Listen.HTTPS.Address, fileACME: cfg.Listen.HTTPS.ACME, log: log, now: opts.Now, roots: opts.TLSRoots,
		acmeHTTP: opts.ACMEHTTPClient, listenChallenge: opts.ListenChallenge, tlsAddr: d.HTTPSAddr, onAttempt: opts.ACMEAttempted}
	d.certMgr.begin(bg)
	// 4. Service.
	env := api.Environment{OS: "FreeBSD", Arch: goArch(), Pool: cfg.Pool, PF: true}
	if opts.Env != nil {
		env = *opts.Env
	}
	zad := zfsadapt.New(clients.ZFS, clients.Runner)
	zad.MountFn, zad.UnmountFn = clients.Mount, clients.Unmount
	deps := service.Deps{
		Now: opts.Now, Log: log, Version: opts.Version, Hostname: hostname, HostUUID: hostUUID, Role: api.RoleHost, Hub: cfg.Hub, Env: env,
		Pool: cfg.Pool, Root: cfg.Dataset, MountBase: cfg.MountBase, ConfDir: cfg.ConfDir, StateDir: cfg.StateDir,
		WorkDir: cfg.WorkDir, JournalDir: filepath.Join(cfg.DataDir, "journal"),
		State: st, DB: db, SealKey: sealKey, SecretsIdentity: secretsID, SecretsRecipient: secretsID.Recipient().String(),
		ZFS: zad, ImageZFS: zad, Exec: runExec{clients.Runner}, Files: clients.Files, Logs: clients.Logs, Jails: clients.Jails,
		PF: clients.PF, Net: clients.Net, Run: clients.Runner, Sysctl: clients.Sysctl, ZClient: clients.ZFS, WG: clients.WG,
		CompatFile: cfg.ZFS.CompatFile, CompatDir: cfg.ZFS.CompatDir, Backups: opts.Backups, Keys: clients.Keys,
		NetworkPool: cfg.Projects.NetworkPool, NetworkPoolBits: cfg.Projects.NetworkBits, NetworkUplink: cfg.Projects.Uplink, NetworkNAT: cfg.Projects.NAT,
		ServerFingerprint: fingerprintOf(d.cert),
	}
	switch {
	case opts.Execer != nil:
		deps.Execer = opts.Execer
	case func() bool { _, ok := any(clients.Host).(service.JailExecer); return ok && clients.Host != nil }():
		deps.Execer = any(clients.Host).(service.JailExecer)
	case opts.Dev:
		deps.Execer = service.LocalExecer{Prefix: []string{"jexec", "-l"}}
	}
	for _, p := range cfg.Lifecycle.Persistent {
		deps.Persistent = append(deps.Persistent, lifecycle.PersistentPath{Dataset: p.Dataset, Path: p.Path, Class: lifecycle.Class(p.Class), Merge: p.Merge, NoSeed: p.NoSeed})
	}
	deps.UpdateTick, deps.ProjectFilesDir = cfg.Updates.Tick.Std(), cfg.Updates.ProjectFilesDir
	deps.JailShell, deps.JailPrompt = cfg.Jails.Shell, cfg.Jails.Prompt
	if cfg.Jails.PromptColor != nil {
		deps.JailPromptColor = *cfg.Jails.PromptColor
	}
	if cfg.Jails.MaxStates != nil {
		deps.JailMaxStates = *cfg.Jails.MaxStates
	}
	deps.AppsDir = cfg.Apps.CatalogDir
	deps.Host, deps.HostModules = clients.HostSystem, cfg.Host.Manage.Modules
	deps.ConsolePort = consolePort(cfg.Listen.HTTPS.Address)
	deps.Certificates, deps.ApplianceModules = d.certMgr, cfg.Appliance
	deps.ConsoleURLs = func() []string {
		return consoleURLs(firstNonEmpty(d.HTTPSAddr(), cfg.Listen.HTTPS.Address), hostname, net.InterfaceAddrs)
	}
	deps.AppsLocalDir = cfg.Apps.LocalDir
	deps.LogForward, deps.LogForwardTune, deps.LogSecretsDir = cfg.Logging.Forward, opts.LogForwardTune, cfg.Logging.SecretsDir
	deps.LogOwnPorts = func() []int {
		// the console's listener (the port it got when it was 0) and the ACME challenge listener
		ports := []int{consolePort(firstNonEmpty(d.HTTPSAddr(), cfg.Listen.HTTPS.Address)), consolePort(firstNonEmpty(cfg.Listen.HTTPS.ACME.ChallengeAddress, DefaultChallengeAddress))}
		return slices.DeleteFunc(ports, func(p int) bool { return p == 0 })
	}
	deps.DialJail = clients.Dial
	deps.HostFile = clients.HostFile
	deps.ExecLimits = service.ExecLimits{PerJail: cfg.Limits.ExecSessionsPerJail, Idle: cfg.Limits.ExecIdle.Std(), Max: cfg.Limits.ExecMax.Std()}
	if opts.Registrar != nil {
		deps.Registrar = opts.Registrar
	} else if r, ok := any(clients.Host).(service.StorageRegistrar); ok && clients.Host != nil {
		deps.Registrar = r
	}
	if cfg.Hub {
		prober := &server.SDKProber{Cert: &d.cert}
		deps.Remotes = prober
		deps.Dial = prober.Dial
	}
	if deps.Backups == nil {
		var agents hostbackup.Agents
		if !opts.Dev && clients.Host != nil {
			agents = privAgents{clients.Host} // not root: files are read and written by agents of the helper
		}
		var mounts hostbackup.DatasetMounter
		if m, ok := any(clients.Host).(hostbackup.DatasetMounter); ok && clients.Host != nil {
			mounts = m // a stopped jail's datasets are mounted by the helper for the time of the backup
		}
		hb, err := buildHostBackups(cfg, hostUUID, clients.ZFS, log, opts, agents, mounts)
		if err != nil {
			return nil, err
		}
		if hb != nil {
			d.backups = hb
			deps.Backups = hb.svc
			deps.BackupAdmin = backupAdmin{hb.svc}
		}
	}
	svc, err := service.New(deps)
	if err != nil {
		return nil, err
	}
	d.svc = svc
	if d.backups != nil {
		d.backups.late.s = svc
	}
	// 5. Reconciler.
	autostart := cfg.Reconcile.Autostart != nil && *cfg.Reconcile.Autostart
	rcfg := reconcile.Config{Interval: cfg.Reconcile.Interval.Std(), Autostart: autostart, NDP: d.ndpFactory(),
		BootStateFile: filepath.Join(cfg.StateDir, "boot-id")}
	trigger := make(chan struct{}, 1)
	d.rec = reconcile.New(rcfg, reconcile.Env{Source: svc, Sink: svc, Actions: svc, Net: clients.Net, PF: clients.PF, Jails: clients.Jails,
		Run: clients.Runner, Sysctl: clients.Sysctl, Routes: func(context.Context) ([]ifconfig.RouteEntry, error) { return priv.ReadRoutes() },
		Log: log, Trigger: trigger, WG: clients.WG, AfterPass: func(ctx context.Context) { svc.SyncDNS(ctx) }})
	svc.SetReconciler(d.rec)
	// 6. Routes are verified against the permission table here.
	srv, err := server.New(server.Config{
		Svc: svc, Log: log, ClientCert: &d.cert, NoUI: !cfg.UI(),
		MaxBody: cfg.Limits.MaxBodyBytes, RequestTimeout: cfg.Limits.RequestTimeout.Std(), KeepAlive: opts.KeepAlive,
		Lockout: auth.LockoutConfig{Threshold: cfg.Limits.AuthFailureThreshold, Now: opts.Now},
		HSTS:    d.certMgr.HSTS,
	})
	if err != nil {
		return nil, err
	}
	d.srv = srv
	// Found on FreeBSD: startup work (registering the default storage) and the reconcile loop act for the
	// host administrator who configured the daemon; the helper needs the admin assertion for them.
	if err := svc.Start(priv.WithAdmin(ctx, systemActor)); err != nil {
		return nil, err
	}
	// 7. Listeners.
	if !opts.NoListen {
		if err := d.listen(); err != nil {
			return nil, err
		}
	}
	// 8. Background work.
	admin := priv.WithAdmin(bg, systemActor)
	d.loop(bg, "reconcile", func(context.Context) { _ = d.rec.Run(admin) })
	d.loop(bg, "state-events", func(ctx context.Context) { d.stateEvents(ctx, trigger) })
	d.loop(bg, "housekeeping", d.housekeeping)
	if cfg.Devd.On() {
		d.loop(bg, "devd", func(ctx context.Context) { svc.RunDevd(ctx, cfg.Devd.Pipe) })
	}
	if d.backups != nil {
		d.loop(bg, "backup", func(context.Context) { d.backupLoop(admin) })
	}
	if cfg.Hub {
		d.loop(bg, "hub-probe", d.probeLoop)
		d.loop(bg, "hub-fleet", d.fleetLoop)
	}
	ok = true
	svc.MarkStarted() // GET /readyz answers from here on
	if st, err := svc.SetupStatus(ctx); err == nil && st.Required {
		log.Info("no administrator yet: the console asks for the setup token, which `jailops-priv setup-token` (as root) prints")
	}
	if len(cfg.Appliance) > 0 {
		log.Info("appliance mode: rc.conf turns host management on", "modules", strings.Join(cfg.Appliance, ","), "managed", strings.Join(cfg.Host.Manage.Modules, ","))
	}
	log.Info("jailopsd started", "version", opts.Version, "host", hostUUID, "pool", cfg.Pool, "hub", cfg.Hub,
		"unix", d.UnixPath(), "https", d.HTTPSAddr(), "fingerprint", fingerprintOf(d.cert))
	return d, nil
}

// backupLoop rebuilds the catalog from the repository when it is empty and
// the host holds a key (a new host restoring), then runs the scheduler until
// the daemon stops.
func (d *Daemon) backupLoop(ctx context.Context) {
	hb := d.backups.svc
	if l, err := hb.List(ctx); err == nil && len(l) == 0 {
		if st, err := d.backups.admin().KeyStatus(ctx); err == nil && st.Status != "none" {
			if n, err := hb.Reindex(ctx, ""); err != nil {
				d.log.Warn("backup: the catalog could not be rebuilt from the repository", "err", err)
			} else if n > 0 {
				d.log.Info("backup: the catalog was rebuilt from the repository", "backups", n)
			}
		}
	}
	if err := hb.Run(ctx); err != nil && ctx.Err() == nil {
		d.log.Error("backup scheduler stopped", "err", err)
	}
}

func (h *hostBackups) admin() backupAdmin { return backupAdmin{h.svc} }

func (d *Daemon) go_(f func()) {
	d.wg.Add(1)
	go func() { defer d.wg.Done(); f() }()
}

// loop runs a background loop of the daemon under the supervisor: a panic in it is logged and counted and the loop
// starts again after a delay; it does not end the daemon.
func (d *Daemon) loop(ctx context.Context, name string, f func(context.Context)) {
	d.wg.Add(1)
	go func() { defer d.wg.Done(); supervise.Run(ctx, d.log, name, f) }()
}

// Handler returns the full HTTP handler (for tests that do not listen).
func (d *Daemon) Handler() http.Handler { return d.srv.Handler() }

// Server returns the API server.
func (d *Daemon) Server() *server.Server { return d.srv }

// Service returns the service layer.
func (d *Daemon) Service() *service.Service { return d.svc }

// Reconciler returns the reconcile loop.
func (d *Daemon) Reconciler() *reconcile.Reconciler { return d.rec }

// Fingerprint is the pin of the server certificate.
func (d *Daemon) Fingerprint() string { return fingerprintOf(d.cert) }

// Certificate is the server (and hub client) certificate.
func (d *Daemon) Certificate() tls.Certificate { return d.cert }

// UnixPath is the socket path, "" when not listening.
func (d *Daemon) UnixPath() string {
	if d.unixLn == nil {
		return ""
	}
	return d.unixLn.Addr().String()
}

// HTTPSAddr is the address of the HTTPS listener, "" when not listening.
func (d *Daemon) HTTPSAddr() string {
	if d.httpsLn == nil {
		return ""
	}
	return d.httpsLn.Addr().String()
}

// Shutdown stops accepting, drains requests, cancels operations (the plan
// executor rolls the running step back through its journal) and closes the
// stores.
func (d *Daemon) Shutdown(ctx context.Context) error {
	var err error
	d.once.Do(func() {
		d.log.Info("jailopsd stopping")
		if d.svc != nil {
			d.svc.MarkStopping()
		}
		for _, s := range d.servers {
			if e := s.Shutdown(ctx); e != nil {
				_ = s.Close()
				err = errors.Join(err, e)
			}
		}
		d.teardown()
		d.log.Info("jailopsd stopped")
	})
	return err
}

func (d *Daemon) teardown() {
	if d.cancel != nil {
		d.cancel()
	}
	if d.certMgr != nil {
		d.certMgr.end()
	}
	if d.svc != nil {
		d.svc.Close()
	}
	d.wg.Wait()
	if d.backups != nil {
		d.backups.svc.Close()
	}
	if d.rec != nil {
		d.rec.Close()
	}
	for _, l := range []net.Listener{d.unixLn, d.httpsLn} {
		if l != nil {
			_ = l.Close()
		}
	}
	if d.unixLn != nil {
		_ = os.Remove(d.cfg.Listen.Unix.Path)
	}
	if d.clients != nil && d.clients.Closer != nil {
		_ = d.clients.Closer.Close()
	}
	if d.db != nil {
		_ = d.db.Close()
	}
	if d.state != nil {
		_ = d.state.Close()
	}
}

// snapshotState takes a ZFS snapshot of the state dataset before a delete,
// when that dataset exists.
func (d *Daemon) snapshotState(kind api.Kind, name string) error {
	if d.clients == nil || d.clients.ZFS == nil {
		return nil
	}
	ds := d.cfg.Dataset + "/state"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ok, err := d.clients.ZFS.Exists(ctx, ds); err != nil || !ok {
		return nil
	}
	snap := fmt.Sprintf("%s@jo-pre-delete-%d", ds, d.opts.Now().UnixNano())
	if err := d.clients.ZFS.Snapshot(ctx, zfs.SnapshotOpts{Names: []string{snap}, Props: map[string]string{"jailops:comment": "before deleting " + string(kind) + " " + name}}); err != nil {
		return fmt.Errorf("snapshot of the state dataset before deleting %s %s: %w", kind, name, err)
	}
	return nil
}

func (d *Daemon) stateEvents(ctx context.Context, trigger chan<- struct{}) {
	ch, cancel := d.state.Watch(64)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			select {
			case trigger <- struct{}{}:
			default:
			}
		}
	}
}

// fleetLoop applies fleet projects to their hosts: when a project changes and
// every FleetInterval, which is how a host that was offline catches up.
func (d *Daemon) fleetLoop(ctx context.Context) {
	t := time.NewTicker(service.FleetInterval)
	defer t.Stop()
	for {
		d.svc.FleetReconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.svc.FleetKicks():
		}
	}
}

func (d *Daemon) probeLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		d.svc.ProbeRemotes(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// housekeeping purges expired sessions and tokens, prunes old operations and
// copies the database with VACUUM INTO daily (users, tokens and the audit log
// are the only rows that cannot be rebuilt).
func (d *Daemon) housekeeping(ctx context.Context) {
	var audited time.Time
	run := func() {
		_, _ = d.db.Sessions.PurgeExpired(ctx)
		_, _ = d.db.Tokens.DeleteExpired(ctx)
		_, _ = d.db.Operations.Prune(ctx, d.opts.Now().Add(-30*24*time.Hour))
		if now := d.opts.Now(); now.Sub(audited) >= 24*time.Hour {
			audited = now
			if n, err := d.PruneAudit(ctx); err != nil {
				d.log.Warn("audit log: pruning failed", "err", err)
			} else if n > 0 {
				d.log.Info("audit log: old entries deleted", "entries", n, "retention", d.cfg.Audit.Retention.Std().String(), "max_entries", d.cfg.Audit.MaxEntries)
			}
		}
		d.backupDB(ctx)
		d.svc.Housekeeping(ctx)
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// PruneAudit deletes the audit entries that audit.retention and audit.max_entries no longer keep (never one of the
// newest 1000) and returns how many it deleted. The daemon runs it once a day.
func (d *Daemon) PruneAudit(ctx context.Context) (int64, error) {
	keep, rows := d.cfg.Audit.Retention.Std(), d.cfg.Audit.MaxEntries
	if keep <= 0 {
		keep = 90 * 24 * time.Hour
	}
	if rows <= 0 {
		rows = 1000000
	}
	return d.db.Audit.Prune(ctx, d.opts.Now().Add(-keep), rows)
}

func (d *Daemon) backupDB(ctx context.Context) {
	dir := filepath.Join(d.cfg.DataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	name := filepath.Join(dir, "jailops-"+d.opts.Now().UTC().Format("20060102")+".db")
	if _, err := os.Stat(name); err == nil {
		return
	}
	if err := d.db.VacuumInto(ctx, name); err != nil {
		d.log.Warn("database backup failed", "err", err)
		return
	}
	// Keep the newest seven.
	ents, _ := os.ReadDir(dir)
	for i := 0; i < len(ents)-7; i++ {
		_ = os.Remove(filepath.Join(dir, ents[i].Name()))
	}
}

// ndpFactory builds the neighbor discovery proxy. In production it works through the root helper: the
// helper hands over a locked, read-only capture of the uplink and sends the advertisements itself, for the subnets of the
// networks in proxy mode. With --dev it runs in process as root.
func (d *Daemon) ndpFactory() reconcile.NDPFactory {
	return func(uplink string) (reconcile.NDP, error) {
		if !d.opts.Dev {
			if d.clients == nil || d.clients.Host == nil {
				return nil, api.Errorf(api.CodeUnsupported, "the IPv6 proxy needs the root helper")
			}
			return newHelperNDP(d.clients.Host, d.clients.Net, uplink, func(format string, args ...any) { d.log.Warn(fmt.Sprintf(format, args...)) })
		}
		bpf := ndproxy.NewBPF(uplink)
		p, err := ndproxy.New(ndproxy.Config{Uplink: uplink}, ndproxy.Deps{
			Capture: bpf, Injector: bpf, Routes: ndproxy.RouteManager{Exec: ndExec{run.NewExec()}},
			Joiner: ndproxy.NewMulticastJoiner(), Clock: reconcile.SystemClock{},
		})
		if err != nil {
			return nil, err
		}
		return p, nil
	}
}

type ndExec struct{ r run.Runner }

func (e ndExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	res, err := e.r.Run(ctx, run.Cmd{Name: name, Args: args, Timeout: 20 * time.Second})
	return append(res.Stdout, res.Stderr...), err
}

// runExec adapts run.Runner to the Exec interfaces of the lifecycle and the
// image builder.
type runExec struct{ r run.Runner }

func (e runExec) Run(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	res, err := e.r.Run(ctx, run.Cmd{Name: argv[0], Args: argv[1:], Timeout: 30 * time.Minute})
	return append(res.Stdout, res.Stderr...), err
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// systemActor names the daemon itself in the helper's audit log for work it starts on its own.
const systemActor = "jailopsd"
