package backupd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"jailops.net/jailops/internal/supervise"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/sdk/api"
)

// Version is the daemon version: cmd/jailops-backupd sets it from the build's -X main.version.
var Version = "dev"

// Server is a running backup node: the node library plus its listeners.
type Server struct {
	Cfg  *Config
	Node *node.Node
	DB   *ctl.DB
	Log  *slog.Logger

	hosts *hostResolver
	mgmt  *Mgmt
	cert  tls.Certificate

	mu        sync.Mutex
	hostLn    net.Listener
	adminLn   net.Listener
	servers   []*http.Server
	ownsDB    bool
	scheduler *Scheduler
}

// Options for New.
type Options struct {
	// Adopt takes over a repository owned by another node.
	Adopt bool
	Log   *slog.Logger
	// Backend replaces the configured datastore (tests).
	Backend datastore.Backend
	// DB replaces the configured database (tests).
	DB *ctl.DB
	// Now replaces the clock of the node and the scheduler (tests).
	Now func() time.Time
	// WebHandler serves the UI files on the listener (internal/backupui in production).
	WebHandler http.Handler
	// Tune adjusts the node configuration after the configuration file was applied (tests).
	Tune func(*node.Config)
	// PasswordParams replaces the argon2id cost (tests).
	PasswordParams *auth.PasswordParams
}

// New opens the datastore and the database and builds the node. Nothing listens yet.
func New(ctx context.Context, cfg *Config, o Options) (*Server, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{Cfg: cfg, Log: o.Log}
	db := o.DB
	if db == nil {
		var err error
		if db, err = cfg.OpenDB(ctx); err != nil {
			return nil, err
		}
		s.ownsDB = true
	}
	s.DB = db
	fail := func(err error) (*Server, error) {
		if s.ownsDB {
			db.Close()
		}
		return nil, err
	}
	be := o.Backend
	if be == nil {
		var err error
		if be, err = cfg.OpenBackend(); err != nil {
			return fail(err)
		}
	}
	if err := cfg.SyncStaticHosts(ctx, db); err != nil {
		return fail(err)
	}
	nc := cfg.NodeConfig(be, db, o.Adopt)
	nc.Now = o.Now
	nc.Audit = func(ev node.AuditEvent) {
		s.Log.Info("audit", "actor", ev.Actor, "action", ev.Action, "target", ev.Target)
	}
	if o.Tune != nil {
		o.Tune(&nc)
	}
	n, err := node.Open(ctx, nc)
	if err != nil {
		return fail(err)
	}
	s.Node = n
	s.hosts = newHostResolver(db, 2*time.Second)
	pp := auth.DefaultPasswordParams
	if o.PasswordParams != nil {
		pp = *o.PasswordParams
	}
	s.mgmt = newMgmt(s, o.WebHandler, pp)
	s.scheduler = newScheduler(n, cfg.Schedule, o.Now, s.Log)
	return s, nil
}

// HostAddr is the address of the listener (host API, and the management API and console when enabled) once Serve runs.
func (s *Server) HostAddr() string { return s.addr(&s.hostLn) }

// AdminSocket is the path of the admin socket.
func (s *Server) AdminSocket() string { return s.Cfg.AdminSocket }

// WebAddr is the address the management API and the console are served on: the same as HostAddr, and empty when they are off.
func (s *Server) WebAddr() string {
	if !s.Cfg.Web.Enabled {
		return ""
	}
	return s.addr(&s.hostLn)
}

func (s *Server) addr(l *net.Listener) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if *l == nil {
		return ""
	}
	return (*l).Addr().String()
}

// FingerprintOfServerCert is the fingerprint hosts pin.
func (s *Server) ServerFingerprint() string { return auth.Fingerprint(s.cert.Certificate[0]) }

// Listen opens the listener (TLS 1.3 on Config.Listen: one port for the host API, the management API and, when enabled, the
// console) and the admin unix socket.
func (s *Server) Listen() error {
	cert, err := s.Cfg.LoadServerCert()
	if err != nil {
		return err
	}
	s.cert = cert
	hl, err := tls.Listen("tcp", s.Cfg.Listen, s.hosts.hostTLS(cert))
	if err != nil {
		return fmt.Errorf("backupd: host listener: %w", err)
	}
	al, err := listenUnix(s.Cfg.AdminSocket)
	if err != nil {
		hl.Close()
		return err
	}
	s.mu.Lock()
	s.hostLn, s.adminLn = hl, al
	s.mu.Unlock()
	return nil
}

// listenUnix creates the admin socket: mode 0600, so only root can connect (the peer check admits only uid 0 as well).
func listenUnix(path string) (net.Listener, error) {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("backupd: %s exists and is not a socket", path)
		}
		// a socket nobody answers on is a leftover of a crash
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("backupd: another process is serving %s", path)
		}
		_ = os.Remove(path)
	}
	old := setUmask(0o117)
	ln, err := net.Listen("unix", path)
	setUmask(old)
	if err != nil {
		return nil, fmt.Errorf("backupd: admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve serves until ctx ends, then shuts down gracefully. Listen must have been called.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	hl, al := s.hostLn, s.adminLn
	s.mu.Unlock()
	if hl == nil || al == nil {
		return errors.New("backupd: Listen was not called")
	}
	// large HTTP/2 flow-control windows: with the default ones an upload is capped at one window per
	// round trip, which limits throughput on a long path
	hostSrv := &http.Server{Handler: s.listenerHandler(), ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		ErrorLog: slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
		HTTP2:    &http.HTTP2Config{MaxReceiveBufferPerConnection: 32 << 20, MaxReceiveBufferPerStream: 8 << 20, MaxConcurrentStreams: 256}}
	adminSrv := &http.Server{Handler: s.adminHandler(), ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uc, ok := c.(*net.UnixConn); ok {
				if cred, err := auth.PeerCred(uc); err == nil {
					return context.WithValue(ctx, credKey{}, cred)
				}
			}
			return ctx
		}}
	srvs := []*http.Server{hostSrv, adminSrv}
	errc := make(chan error, 2)
	go func() { errc <- hostSrv.Serve(hl) }()
	go func() { errc <- adminSrv.Serve(al) }()
	s.mu.Lock()
	s.servers = srvs
	s.mu.Unlock()
	schedCtx, stopSched := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		supervise.Run(schedCtx, nil, "backup-scheduler", func(c context.Context) { s.scheduler.Run(c) })
		close(done)
	}()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	stopSched()
	<-done
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, sv := range srvs {
		_ = sv.Shutdown(sctx)
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// Close stops the node and releases the database.
func (s *Server) Close() {
	s.mu.Lock()
	for _, sv := range s.servers {
		_ = sv.Close()
	}
	for _, l := range []net.Listener{s.hostLn, s.adminLn} {
		if l != nil {
			_ = l.Close()
		}
	}
	s.mu.Unlock()
	if s.Node != nil {
		s.Node.Close()
	}
	_ = os.Remove(s.Cfg.AdminSocket)
	if s.ownsDB && s.DB != nil {
		s.DB.Close()
	}
}

// adminHandler serves the administration API on the unix socket. Only root
// (uid 0) gets in; everybody else is refused before any handler runs.
func (s *Server) adminHandler() http.Handler {
	return adminPolicy(testAdminUID, s.Node.AdminHandler)
}

// adminPolicy checks the peer credentials of the connection, then calls the inner handler with the administrator attached.
func adminPolicy(extra *uint32, inner func() http.Handler) http.Handler {
	h := inner()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, ok := r.Context().Value(credKey{}).(auth.Cred)
		if !ok {
			writeError(w, api.Errorf(api.CodeUnauthorized, "the peer credentials of the socket are unavailable"))
			return
		}
		perm := peerPermission(cred)
		if extra != nil && cred.UID == *extra {
			perm = api.PermAdmin
		}
		if perm == "" {
			writeError(w, api.Errorf(api.CodeForbidden, "uid %d may not administer the backup node", cred.UID))
			return
		}
		a := node.Actor{Name: fmt.Sprintf("unix:uid=%d", cred.UID), Perm: perm, Remote: "unix"}
		h.ServeHTTP(w, r.WithContext(node.WithActor(r.Context(), a)))
	})
}

// testAdminUID, when non-nil, makes the admin socket treat that uid as an administrator as well. It is unexported and
// only export_test.go can set it, because tests do not run as root; nothing in the daemon assigns it.
var testAdminUID *uint32

type credKey struct{}

// WebHandler returns the management API and UI handler (tests mount it without a listener).
func (s *Server) WebHandler() http.Handler { return s.mgmt.Handler() }
