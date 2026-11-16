// Package server is the HTTP API of jailopsd, exactly as sdk/PROTOCOL.md
// specifies it. Handlers translate requests into calls on internal/service and
// hold no business logic.
//
// The route table lives in one place (routes.go) and is verified against the
// permission table of internal/auth when the server is built.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/webui"
	"jailops.net/jailops/sdk/api"
)

// Config configures a Server.
type Config struct {
	Svc *service.Service
	Log *slog.Logger
	// ClientCert is presented to remotes when this daemon forwards requests
	// in hub mode.
	ClientCert *tls.Certificate
	// Remotes overrides how a forwarding transport to a remote is built
	// (tests); the default pins the remote's certificate by fingerprint.
	Remotes func(ctx context.Context, r api.Remote) (http.RoundTripper, error)
	// MaxBody bounds request bodies (default 4 MiB).
	MaxBody int64
	// RequestTimeout bounds ordinary requests (default 60s).
	RequestTimeout time.Duration
	// KeepAlive is the SSE comment interval (default 15s).
	KeepAlive time.Duration
	// Lockout tunes the failed bearer token limiter.
	Lockout auth.LockoutConfig
	// NoUI leaves the embedded web UI out.
	NoUI bool
	// HSTS reports whether the certificate served now is one a browser trusts by itself (ACME, or an uploaded or
	// configured certificate that verifies against the host's roots). Only then is Strict-Transport-Security sent:
	// a browser that remembered it would refuse the self-signed certificate without a way to click through. Nil: never.
	HSTS func() bool
}

// Server is the HTTP handler of one daemon.
type Server struct {
	cfg    Config
	svc    *service.Service
	log    *slog.Logger
	authz  *auth.Authorizer
	routes []route
	mux    *http.ServeMux
	shape  *auth.Registry
	tokLim *auth.Lockout

	userMu    sync.Mutex
	userNames map[uint32]string

	hubMu sync.Mutex
	hubTr map[string]*hubTransport

	consoles  consoleRegistry
	streams   streamCounter
	lockedAud lockedAudit
}

// New builds a Server and verifies that every route has a permission entry.
func New(cfg Config) (*Server, error) {
	if cfg.Svc == nil {
		return nil, errors.New("server: a service is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 4 << 20
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 60 * time.Second
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = 15 * time.Second
	}
	s := &Server{cfg: cfg, svc: cfg.Svc, log: cfg.Log, authz: auth.NewAuthorizer(), userNames: map[uint32]string{},
		hubTr: map[string]*hubTransport{}, tokLim: auth.NewLockout(cfg.Lockout)}
	s.routes = s.routeTable()
	keys := s.RouteKeys()
	if err := auth.VerifyComplete(keys); err != nil {
		return nil, fmt.Errorf("server: refusing to start: %w", err)
	}
	s.shape = s.authz.Reg
	s.mux = http.NewServeMux()
	for _, r := range s.routes {
		s.mux.HandleFunc(r.method+" "+r.pattern, s.wrap(r))
	}
	// GET /healthz is liveness: the process answers HTTP. It checks nothing else (GET /readyz does).
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	s.mux.HandleFunc("/api/v1/", s.fallback)
	if !cfg.NoUI {
		s.mux.Handle("/", webui.Handler())
	}
	return s, nil
}

// RouteKeys returns "METHOD pattern" for every registered API route.
func (s *Server) RouteKeys() []string {
	out := make([]string, len(s.routes))
	for i, r := range s.routes {
		out[i] = r.method + " " + r.pattern
	}
	return out
}

// Handler returns the full handler (API and UI) behind the panic guard, the
// request id and the access log.
func (s *Server) Handler() http.Handler {
	return s.outer(s.mux)
}

type peerKey struct{}

// ConnContext attaches the kernel-reported credentials of unix socket peers
// to the connection context. Use it as http.Server.ConnContext.
func (s *Server) ConnContext(ctx context.Context, c net.Conn) context.Context {
	if uc, ok := c.(*net.UnixConn); ok {
		if cred, err := auth.PeerCred(uc); err == nil {
			return context.WithValue(ctx, peerKey{}, cred)
		} else {
			s.log.Warn("peer credentials unavailable", "err", err)
		}
	}
	return ctx
}

func (s *Server) fallback(w http.ResponseWriter, r *http.Request) {
	rc := newRC(s, w, r, route{})
	// A known path with another method is 405, anything else 404.
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if _, ok := s.shape.Match(m, r.URL.Path); ok && m != r.Method {
			rc.fail(api.Errorf(api.CodeUnsupported, "method %s is not allowed on %s", r.Method, r.URL.Path))
			w.Header().Set("Allow", m)
			return
		}
	}
	rc.fail(api.Errorf(api.CodeNotFound, "no such route %s %s", r.Method, r.URL.Path))
}

// remoteAddr is the peer address without the port; "unix:<uid>" for sockets, so that the failed-login limiter and the
// audit log tell local users apart and one of them cannot lock the others out.
func remoteAddr(r *http.Request) (string, netip.Addr) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if cred, ok := r.Context().Value(peerKey{}).(auth.Cred); ok {
			return "unix:" + strconv.FormatUint(uint64(cred.UID), 10), netip.Addr{}
		}
		return "unix", netip.Addr{}
	}
	a, _ := netip.ParseAddr(host)
	return host, a
}

// ---- authentication ----

type authResult struct {
	actor   service.Actor
	method  string // "", unix, cert, hub, token, session
	csrf    string
	session string
	// unknownCert is set when the caller presented a client certificate that
	// is not trusted and no other credential.
	unknownCert bool
}

func (s *Server) uname(uid uint32) string {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if n, ok := s.userNames[uid]; ok {
		return n
	}
	n := "uid:" + strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		n = u.Username
	}
	s.userNames[uid] = n
	return n
}

// authenticate finds who the caller is. A credential that is present but bad
// is an error (401, or 429 while locked out); no credential is anonymous.
func (s *Server) authenticate(r *http.Request) (authResult, error) {
	var res authResult
	remote, ip := remoteAddr(r)
	claim := r.Header.Get(auth.RequestorHeader)
	if cred, ok := r.Context().Value(peerKey{}).(auth.Cred); ok {
		if claim != "" {
			return res, api.Errorf(api.CodeForbidden, "requestor claims are not accepted on the unix socket")
		}
		// Root is the host's recovery access: a global administrator. Every other peer is anonymous and falls
		// through to the credentials below (token, session cookie), like a remote client.
		if cred.UID == 0 {
			res.actor = service.Actor{Name: s.uname(cred.UID), Kind: "unix", Perm: api.PermAdmin, Remote: "unix", Global: true}
			res.method = "unix"
			return res, nil
		}
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		fp := auth.CertFingerprint(leaf)
		// The listener only requests a client certificate and pins by fingerprint, so what chain building would
		// check on the leaf (validity period, key usage) is checked here.
		if err := auth.CheckPeerLeaf(leaf, s.svc.Clock(), x509.ExtKeyUsageClientAuth); err != nil {
			return res, api.Errorf(api.CodeUnauthorized, "client certificate: %v", err)
		}
		if a, ok := s.svc.CertActor(fp, remote); ok {
			if claim == "" {
				res.actor, res.method = a, "cert"
				return res, nil
			}
			if a.Kind != "hub" {
				return res, api.Errorf(api.CodeForbidden, "only a hub certificate may carry a requestor claim")
			}
			// A hub forwards what a requestor may do to resources, never a login, a credential change or a session:
			// those belong to the host's own users, and a forwarded claim has no password or second factor.
			if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || strings.HasPrefix(r.URL.Path, "/api/v1/sessions") {
				return res, api.Errorf(api.CodeForbidden, "%s cannot be reached through a hub", r.URL.Path)
			}
			// failures are counted per source, but a claim that verifies is never refused for what others did
			key := "claim|" + auth.SourceKey(remote)
			c, err := auth.VerifyRequestor(leaf, claim, auth.RequestorExpect{Audience: s.svc.HostUUID(), Method: r.Method, Path: r.URL.Path, Now: s.svc.Clock()})
			if err == nil {
				var act service.Actor
				if act, err = s.svc.HubActor(fp, c, remote); err == nil {
					s.tokLim.Success(key)
					res.actor, res.method = act, "hub"
					return res, nil
				}
			}
			if lerr := s.tokLim.Fail(key); lerr != nil {
				return res, lerr
			}
			return res, err
		}
		res.unknownCert = true
	}
	if claim != "" {
		return res, api.Errorf(api.CodeForbidden, "requestor claims are accepted from hub certificates only")
	}
	bearer := ""
	if h := r.Header.Get("Authorization"); h != "" {
		if scheme, tok, ok := strings.Cut(h, " "); ok && strings.EqualFold(scheme, "Bearer") {
			bearer = strings.TrimSpace(tok)
		} else {
			return res, api.Errorf(api.CodeUnauthorized, "unsupported authorization scheme")
		}
	}
	if bearer != "" {
		// A token is not guessable (256 bits), so a valid one is never refused because of what others at the same address
		// tried: the failures of a source are counted, and a wrong token is answered with the lock in force.
		key := "tok|" + auth.SourceKey(remote)
		a, err := s.svc.AuthenticateToken(r.Context(), bearer, ip)
		if err != nil {
			if api.IsCode(err, api.CodeUnauthorized) {
				if lerr := s.tokLim.Fail(key); lerr != nil {
					return res, lerr
				}
			}
			return res, err
		}
		s.tokLim.Success(key)
		res.actor, res.method, res.unknownCert = a, "token", false
		return res, nil
	}
	if id, ok := auth.SessionIDFromRequest(r); ok {
		a, csrf, err := s.svc.AuthenticateSession(r.Context(), id, remote)
		if err != nil {
			return res, err
		}
		res.actor, res.method, res.csrf, res.session, res.unknownCert = a, "session", csrf, id, false
		return res, nil
	}
	return res, nil
}

func isMutation(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}
