package backupd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

const sessionTTL = 12 * time.Hour

// Mgmt is the management API of the backup node and the host of its web UI. It
// has its own users, API tokens and browser sessions (all in PostgreSQL); a
// browser session needs a CSRF token on every state-changing request.
type Mgmt struct {
	s    *Server
	reg  *auth.Registry
	ui   http.Handler
	pp   auth.PasswordParams
	lock *auth.Lockout
	// ipLock limits the logins of one source address over all users, ten times looser than lock.
	ipLock *auth.Lockout
	mux    *http.ServeMux
	// hashSem bounds the password hashes that run at once. Every login attempt, valid user or not, costs an argon2id hash
	// (64 MiB, several passes), and the lockout only counts a failure after the hash is done: without a bound one client
	// could start hundreds of hashes in parallel before it is locked out.
	hashSem chan struct{}
}

// readDeadline is how long a management request may take to arrive (a variable for the tests).
var readDeadline = 15 * time.Second

// hashSlot takes a slot for one password hash and returns what releases it; false answers the request with 429.
func (m *Mgmt) hashSlot(w http.ResponseWriter) (func(), bool) {
	select {
	case m.hashSem <- struct{}{}:
		return func() { <-m.hashSem }, true
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, api.Errorf(api.CodeRateLimited, "too many sign-in attempts at once, try again in a moment"))
		return nil, false
	}
}

type identity struct {
	User string
	Role string
	Perm api.Permission
	Via  string // "token" or "session"
	CSRF string
}

func newMgmt(s *Server, ui http.Handler, pp auth.PasswordParams) *Mgmt {
	reg, err := Registry()
	if err != nil {
		panic(err) // a malformed static table is a programming error caught by tests
	}
	m := &Mgmt{s: s, reg: reg, ui: ui, pp: pp, lock: auth.NewLockout(auth.LockoutConfig{}), ipLock: auth.NewLockout(auth.LockoutConfig{Threshold: 50}), mux: http.NewServeMux(),
		hashSem: make(chan struct{}, max(1, runtime.NumCPU()))}
	var routes []string
	h := func(method, pattern string, fn func(http.ResponseWriter, *http.Request, *identity)) {
		routes = append(routes, method+" "+pattern)
		m.mux.HandleFunc(method+" "+pattern, m.wrap(method, pattern, fn))
	}
	h("GET", "/api/v1", m.info)
	h("POST", "/api/v1/auth/login", m.login)
	h("POST", "/api/v1/auth/logout", m.logout)
	h("GET", "/api/v1/auth/session", m.session)
	h("POST", "/api/v1/auth/password", m.password)
	h("GET", "/api/v1/repository", m.repository)
	h("GET", "/api/v1/certificate", m.certificate)
	h("GET", "/api/v1/hosts", m.hostList)
	h("POST", "/api/v1/hosts", m.hostEnroll)
	h("PUT", "/api/v1/hosts/{name}", m.hostUpdate)
	h("DELETE", "/api/v1/hosts/{name}", m.hostRevoke)
	h("GET", "/api/v1/groups", m.groups)
	h("GET", "/api/v1/groups/{group}/snapshots", m.snapshots)
	h("GET", "/api/v1/groups/{group}/snapshots/{snap}", m.snapshot)
	h("PUT", "/api/v1/groups/{group}/snapshots/{snap}/protected", m.protect)
	h("POST", "/api/v1/groups/{group}/snapshots/{snap}/deletion", m.requestDeletion)
	h("DELETE", "/api/v1/groups/{group}/snapshots/{snap}/deletion", m.cancelDeletion)
	h("POST", "/api/v1/groups/{group}/snapshots/{snap}/deletion/execute", m.executeDeletion)
	h("GET", "/api/v1/sessions", m.sessions)
	h("GET", "/api/v1/jobs", m.jobs)
	h("GET", "/api/v1/jobs/{id}", m.job)
	h("POST", "/api/v1/jobs/{id}/cancel", m.cancelJob)
	h("POST", "/api/v1/jobs/gc", m.startGC)
	h("POST", "/api/v1/jobs/verify", m.startVerify)
	h("POST", "/api/v1/jobs/retention", m.startRetention)
	h("POST", "/api/v1/jobs/reconcile", m.startReconcile)
	h("GET", "/api/v1/maintenance", m.getMaintenance)
	h("PUT", "/api/v1/maintenance", m.setMaintenance)
	h("GET", "/api/v1/quarantine", m.quarantine)
	h("POST", "/api/v1/quarantine/purge", m.purgeQuarantine)
	h("POST", "/api/v1/quarantine/{id}", m.quarantineChunk)
	h("GET", "/api/v1/escrow", m.escrowList)
	h("DELETE", "/api/v1/escrow/{domain}", m.deleteEscrow)
	h("GET", "/api/v1/retention-policies", m.policies)
	h("PUT", "/api/v1/retention-policies/{scope}", m.setPolicy)
	h("DELETE", "/api/v1/retention-policies/{scope}", m.deletePolicy)
	h("GET", "/api/v1/audit", m.auditLog)
	h("GET", "/api/v1/users", m.userList)
	h("POST", "/api/v1/users", m.userCreate)
	h("PUT", "/api/v1/users/{name}", m.userUpdate)
	h("DELETE", "/api/v1/users/{name}", m.userDelete)
	h("GET", "/api/v1/tokens", m.tokenList)
	h("POST", "/api/v1/tokens", m.tokenCreate)
	h("DELETE", "/api/v1/tokens/{name}", m.tokenDelete)
	if err := reg.VerifyComplete(routes); err != nil {
		panic(err)
	}
	// anything else under /api/v1 is an API 404; everything else is the UI
	m.mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, api.Errorf(api.CodeNotFound, "no such endpoint"))
	})
	// the console is the only thing web.enabled switches: the management API is always served (a token, a session or a
	// user logs in to it), and without the console "/" is a plain 404
	if ui != nil && s.Cfg.Web.Enabled {
		m.mux.Handle("/", ui)
	}
	return m
}

// Routes returns the "METHOD pattern" keys of the management API (for the documentation test).
func MgmtRoutes() []string {
	var out []string
	for _, e := range Perms {
		out = append(out, e.Key())
	}
	sort.Strings(out)
	return out
}

// Handler returns the management API and UI handler.
func (m *Mgmt) Handler() http.Handler {
	return securityHeaders(m.mux)
}

// permissionsPolicy turns off the browser features the console does not use.
const permissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), midi=(), " +
	"accelerometer=(), gyroscope=(), magnetometer=(), display-capture=()"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		// no Strict-Transport-Security: the node's certificate is self-signed and pinned by its clients, and a browser
		// that remembered the header could no longer be told to accept it
		h.Set("Permissions-Policy", permissionsPolicy)
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a
}

// wrap authenticates and authorises one route, then calls fn.
func (m *Mgmt) wrap(method, pattern string, fn func(http.ResponseWriter, *http.Request, *identity)) http.HandlerFunc {
	e, _ := m.reg.Lookup(method, pattern)
	return func(w http.ResponseWriter, r *http.Request) {
		// the management API is reachable by clients that have not proved anything yet: a body that never arrives must not
		// hold a handler for ever (the host API keeps its long uploads, it is another handler)
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(readDeadline))
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if e.Public {
			fn(w, r, nil)
			return
		}
		id, err := m.identify(r)
		if err != nil {
			writeError(w, err)
			return
		}
		if !node.Satisfies(id.Perm, e.Perm) {
			writeError(w, api.Errorf(api.CodeForbidden, "the %s role cannot %s %s", id.Role, method, pattern).WithDetail("required", string(e.Perm)))
			return
		}
		if id.Via == "session" && method != http.MethodGet && method != http.MethodHead {
			if !auth.CSRFValid(id.CSRF, r.Header.Get("X-CSRF-Token")) {
				writeError(w, api.Errorf(api.CodeForbidden, "missing or wrong CSRF token"))
				return
			}
			if err := auth.CheckOrigin(r); err != nil {
				writeError(w, err)
				return
			}
		}
		fn(w, r, id)
	}
}

// loginKey is one limiter key of a login and the limiter that holds it.
type loginKey struct {
	lim *auth.Lockout
	key string
}

func (m *Mgmt) identify(r *http.Request) (*identity, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || !auth.TokenWellFormed(tok) {
			return nil, api.Errorf(api.CodeUnauthorized, "malformed bearer token")
		}
		// failures are counted per source (an IPv6 source is its /64); a token is not guessable, so a valid one is never
		// refused for what others at the same address tried
		tokKey := "tok|" + auth.SourceKey(remoteAddr(r).String())
		t, err := m.s.DB.TokenByHash(ctx, auth.HashToken(tok))
		if err != nil {
			if lerr := m.lock.Fail(tokKey); lerr != nil {
				return nil, api.Errorf(api.CodeRateLimited, "too many failed attempts")
			}
			return nil, api.Errorf(api.CodeUnauthorized, "unknown token")
		}
		var exp time.Time
		if t.ExpiresAt != nil {
			exp = *t.ExpiresAt
		}
		if err := auth.CheckTokenUse(exp, t.AllowFrom, time.Now(), remoteAddr(r)); err != nil {
			return nil, err
		}
		m.s.DB.TouchToken(ctx, t.ID)
		return &identity{User: "token:" + t.Name, Role: t.Role, Perm: roleToPerm[t.Role], Via: "token"}, nil
	}
	sid, ok := auth.SessionIDFromRequest(r)
	if !ok {
		return nil, api.Errorf(api.CodeUnauthorized, "authentication required")
	}
	ss, err := m.s.DB.UISessionByHash(ctx, auth.HashSessionID(sid))
	if err != nil {
		return nil, api.Errorf(api.CodeUnauthorized, "the session expired")
	}
	u, err := m.s.DB.User(ctx, ss.User)
	if err != nil || u.Disabled {
		return nil, api.Errorf(api.CodeUnauthorized, "the account is disabled")
	}
	return &identity{User: u.Name, Role: u.Role, Perm: roleToPerm[u.Role], Via: "session", CSRF: ss.CSRF}, nil
}

func (m *Mgmt) actor(id *identity, r *http.Request) node.Actor {
	return node.Actor{Name: id.User, Perm: id.Perm, Remote: r.RemoteAddr}
}

func decodeBody(r *http.Request, v any) error {
	if r.ContentLength != 0 {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
			return api.Errorf(api.CodeInvalid, "the request body must be application/json")
		}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return api.Errorf(api.CodeInvalid, "malformed request body: %v", err)
	}
	return nil
}

func (m *Mgmt) audit(ctx context.Context, id *identity, r *http.Request, action, target string, detail map[string]any) {
	_ = m.s.DB.Audit(ctx, id.User, action, target, detail, r.RemoteAddr)
}

// ---- server and session ---------------------------------------------------------------

func (m *Mgmt) info(w http.ResponseWriter, r *http.Request, id *identity) {
	host := m.s.Cfg.Hostname
	if host == "" {
		host, _ = osHostname()
	}
	authState := "untrusted"
	if _, err := m.identify(r); err == nil {
		authState = "trusted"
	}
	info := api.ServerInfo{APIVersion: "1.0", APIExtensions: []string{"backup_node", "backup_node_management", "backup_node_two_step_deletion", "backup_node_maintenance_modes"},
		Version: Version, HostUUID: m.s.Node.ServerID(), Hostname: host, Role: api.RoleBackup, Auth: authState,
		Environment: api.Environment{OS: runtime.GOOS, Arch: runtime.GOARCH}}
	if authState != "trusted" {
		info = info.ForUntrusted()
	}
	writeJSON(w, 200, info)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SessionBody is the answer of login and of GET /api/v1/auth/session.
type SessionBody struct {
	User string `json:"user"`
	Role string `json:"role"`
	CSRF string `json:"csrf,omitempty"`
}

func (m *Mgmt) login(w http.ResponseWriter, r *http.Request, _ *identity) {
	var req loginRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, err)
		return
	}
	// A browser login is a form post: when the browser says where it comes from, it must be this site (login CSRF
	// would sign the victim in as the attacker). Clients that send no Origin (curl, the CLI) are not browsers.
	if r.Header.Get("Origin") != "" {
		if err := auth.CheckOrigin(r); err != nil {
			writeError(w, err)
			return
		}
	}
	// Two keys: the pair (one user from one place) and the source (a spray over many names). A key for the user
	// from anywhere would let a stranger lock the administrator out.
	ip := auth.SourceKey(remoteAddr(r).String()) // an IPv6 source is its /64
	keys := []loginKey{{m.lock, strings.ToLower(req.Username) + "|" + ip}, {m.ipLock, "ip|" + ip}}
	for _, k := range keys {
		if err := k.lim.Check(k.key); err != nil {
			var le *auth.LockedError
			if errors.As(err, &le) {
				w.Header().Set("Retry-After", le.RetryAfterSeconds())
			}
			writeError(w, api.Errorf(api.CodeRateLimited, "too many failed attempts"))
			return
		}
	}
	u, err := m.s.DB.User(r.Context(), req.Username)
	release, ok := m.hashSlot(w)
	if !ok {
		return
	}
	valid := false
	if err == nil && !u.Disabled {
		valid, _ = auth.VerifyPassword(req.Password, u.PasswordHash)
	} else {
		auth.BurnPasswordTime(req.Password, m.pp) // the time must not tell whether the user exists
	}
	release()
	if !valid {
		for _, k := range keys {
			_ = k.lim.Fail(k.key)
		}
		_ = m.s.DB.Audit(r.Context(), "anonymous", "auth.login.failed", req.Username, nil, r.RemoteAddr)
		writeError(w, api.Errorf(api.CodeUnauthorized, "wrong user name or password"))
		return
	}
	for _, k := range keys {
		k.lim.Success(k.key)
	}
	sid, hash, err := auth.NewSessionID()
	if err == nil {
		var csrf string
		if csrf, err = auth.NewCSRFToken(); err == nil {
			if err = m.s.DB.CreateUISession(r.Context(), hash, u.Name, csrf, sessionTTL); err == nil {
				http.SetCookie(w, auth.SessionCookie(sid, r.TLS != nil, sessionTTL))
				_ = m.s.DB.Audit(r.Context(), u.Name, "auth.login", "", nil, r.RemoteAddr)
				writeJSON(w, 200, SessionBody{User: u.Name, Role: u.Role, CSRF: csrf})
				return
			}
		}
	}
	writeError(w, api.Errorf(api.CodeInternal, "creating the session: %v", err))
}

func (m *Mgmt) logout(w http.ResponseWriter, r *http.Request, id *identity) {
	if sid, ok := auth.SessionIDFromRequest(r); ok {
		_ = m.s.DB.DeleteUISession(r.Context(), auth.HashSessionID(sid))
	}
	http.SetCookie(w, auth.ClearSessionCookie(r.TLS != nil))
	writeJSON(w, 200, nil)
}

func (m *Mgmt) session(w http.ResponseWriter, r *http.Request, id *identity) {
	writeJSON(w, 200, SessionBody{User: id.User, Role: id.Role, CSRF: id.CSRF})
}

func (m *Mgmt) password(w http.ResponseWriter, r *http.Request, id *identity) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if id.Via != "session" {
		writeError(w, api.Errorf(api.CodeForbidden, "a token cannot change a password"))
		return
	}
	u, err := m.s.DB.User(r.Context(), id.User)
	if err != nil {
		writeError(w, api.Errorf(api.CodeNotFound, "no such user"))
		return
	}
	pwKey := "pw|" + strings.ToLower(u.Name)
	if err := m.lock.Check(pwKey); err != nil {
		writeError(w, api.Errorf(api.CodeRateLimited, "too many failed attempts"))
		return
	}
	release, slot := m.hashSlot(w)
	if !slot {
		return
	}
	ok, _ := auth.VerifyPassword(req.Current, u.PasswordHash)
	release()
	if !ok {
		_ = m.lock.Fail(pwKey)
		writeError(w, api.Errorf(api.CodeUnauthorized, "the current password is wrong"))
		return
	}
	m.lock.Success(pwKey)
	if err := auth.CheckPasswordPolicy(req.New, u.Name); err != nil {
		writeError(w, err)
		return
	}
	hash, err := auth.HashPassword(req.New, m.pp)
	if err == nil {
		err = m.s.DB.UpdateUser(r.Context(), u.Name, u.Role, u.Disabled, hash)
	}
	if err != nil {
		writeError(w, api.Errorf(api.CodeInternal, "%v", err))
		return
	}
	// A changed password ends every other session of the user: whoever held the old one is out.
	var keep []byte
	if sid, ok := auth.SessionIDFromRequest(r); ok {
		keep = auth.HashSessionID(sid)
	}
	_ = m.s.DB.EndUserSessions(r.Context(), u.Name, keep)
	m.audit(r.Context(), id, r, "user.password", u.Name, nil)
	writeJSON(w, 200, nil)
}

// ---- repository ---------------------------------------------------------------------------

func (m *Mgmt) repository(w http.ResponseWriter, r *http.Request, id *identity) {
	st, err := m.s.Node.Status(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, 200, struct {
		node.RepositoryStatus
		Wire api.RepositoryStatus `json:"status"`
		Next map[string]time.Time `json:"next_runs"`
	}{st, st.API(), m.s.scheduler.Next()})
}

func (m *Mgmt) certificate(w http.ResponseWriter, r *http.Request, id *identity) {
	writeJSON(w, 200, map[string]string{"fingerprint": m.s.ServerFingerprint()})
}

// ---- hosts -----------------------------------------------------------------------------------

// HostBody is the body of POST /api/v1/hosts.
type HostBody struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Certificate string   `json:"certificate,omitempty"` // PEM, as an alternative to the fingerprint
	Scopes      []string `json:"scopes,omitempty"`      // default: backup-push, backup-pull
	Note        string   `json:"note,omitempty"`
}

// EnrollHost validates and stores a host. It is shared by the CLI and the API.
func EnrollHost(ctx context.Context, db *ctl.DB, b HostBody) (ctl.Host, error) {
	if !api.IsName(b.Name, api.MaxName) {
		return ctl.Host{}, api.Errorf(api.CodeInvalid, "a host needs a name: lower case letters, digits and hyphens, starting with a letter, at most %d characters", api.MaxName)
	}
	fp := b.Fingerprint
	if fp == "" && b.Certificate != "" {
		var err error
		if fp, err = FingerprintOfPEM([]byte(b.Certificate)); err != nil {
			return ctl.Host{}, api.Errorf(api.CodeInvalid, "certificate: %v", err)
		}
	}
	fp, err := auth.NormalizeFingerprint(fp)
	if err != nil {
		return ctl.Host{}, api.Errorf(api.CodeInvalid, "%v", err)
	}
	if len(b.Scopes) == 0 {
		b.Scopes = []string{string(api.PermBackupPush), string(api.PermBackupPull)}
	}
	if err := checkScopes(b.Scopes); err != nil {
		return ctl.Host{}, api.Errorf(api.CodeInvalid, "%v", err)
	}
	h, err := db.EnrollHost(ctx, b.Name, fp, b.Scopes, b.Note, "")
	if errors.Is(err, ctl.ErrConflict) {
		return h, api.Errorf(api.CodeAlreadyExists, "a host with this name or fingerprint is already enrolled")
	}
	return h, err
}

func (m *Mgmt) hostList(w http.ResponseWriter, r *http.Request, id *identity) {
	h, err := m.s.DB.Hosts(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if h == nil {
		h = []ctl.Host{}
	}
	writeJSON(w, 200, h)
}

func (m *Mgmt) hostEnroll(w http.ResponseWriter, r *http.Request, id *identity) {
	var b HostBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	h, err := EnrollHost(r.Context(), m.s.DB, b)
	if err != nil {
		writeError(w, err)
		return
	}
	m.s.hosts.forget()
	m.audit(r.Context(), id, r, "host.enroll", h.Name, map[string]any{"fingerprint": h.Fingerprint, "scopes": h.Scopes})
	writeJSON(w, http.StatusCreated, h)
}

func (m *Mgmt) hostUpdate(w http.ResponseWriter, r *http.Request, id *identity) {
	var b struct {
		Scopes []string `json:"scopes"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	if err := checkScopes(b.Scopes); err != nil {
		writeError(w, api.Errorf(api.CodeInvalid, "%v", err))
		return
	}
	if err := m.s.DB.SetHostScopes(r.Context(), r.PathValue("name"), b.Scopes); err != nil {
		writeError(w, notFoundOr(err, "no such host"))
		return
	}
	m.s.hosts.forget()
	m.audit(r.Context(), id, r, "host.scopes", r.PathValue("name"), map[string]any{"scopes": b.Scopes})
	writeJSON(w, 200, nil)
}

func (m *Mgmt) hostRevoke(w http.ResponseWriter, r *http.Request, id *identity) {
	h, err := m.s.DB.RevokeHost(r.Context(), r.PathValue("name"))
	if err != nil {
		writeError(w, notFoundOr(err, "no such host"))
		return
	}
	m.s.hosts.forget()
	m.s.Node.Sweep(r.Context())
	m.audit(r.Context(), id, r, "host.revoke", h.Name, map[string]any{"fingerprint": h.Fingerprint})
	writeJSON(w, 200, h)
}

func notFoundOr(err error, msg string) error {
	if errors.Is(err, ctl.ErrNotFound) {
		return api.Errorf(api.CodeNotFound, "%s", msg)
	}
	return err
}

// ---- groups and snapshots ---------------------------------------------------------------------

func (m *Mgmt) groups(w http.ResponseWriter, r *http.Request, id *identity) {
	g, err := m.s.Node.Groups(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	snaps, err := m.s.DB.Snapshots(r.Context(), "")
	if err != nil {
		writeError(w, err)
		return
	}
	type row struct {
		ctl.Group
		Snapshots int       `json:"snapshots"`
		Failed    int       `json:"failed"`
		Protected int       `json:"protected"`
		Pending   int       `json:"pending_deletion"`
		Latest    time.Time `json:"latest,omitzero"`
	}
	idx := map[string]*row{}
	out := make([]*row, 0, len(g))
	for _, x := range g {
		rw := &row{Group: x}
		idx[x.GroupID] = rw
		out = append(out, rw)
	}
	for _, s := range snaps {
		if rw := idx[s.GroupID]; rw != nil {
			rw.Snapshots++
			if s.VerifyState == "failed" {
				rw.Failed++
			}
			if s.Protected {
				rw.Protected++
			}
			if s.PendingDeletionAfter != nil {
				rw.Pending++
			}
			if s.CommittedAt.After(rw.Latest) {
				rw.Latest = s.CommittedAt
			}
		}
	}
	writeJSON(w, 200, out)
}

func (m *Mgmt) snapshots(w http.ResponseWriter, r *http.Request, id *identity) {
	s, err := m.s.Node.Snapshots(r.Context(), r.PathValue("group"))
	if err != nil {
		writeError(w, err)
		return
	}
	if s == nil {
		s = []ctl.Snapshot{}
	}
	writeJSON(w, 200, s)
}

func (m *Mgmt) snapshot(w http.ResponseWriter, r *http.Request, id *identity) {
	s, err := m.s.Node.SnapshotState(r.Context(), r.PathValue("group"), r.PathValue("snap"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, 200, s)
}

func (m *Mgmt) protect(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.ProtectBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	if err := m.s.Node.SetProtected(r.Context(), r.PathValue("group"), r.PathValue("snap"), b.Protected, id.User); err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, b)
}

func apiErr(err error) error {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae
	}
	return api.Errorf(api.CodeInternal, "%v", err)
}

func (m *Mgmt) requestDeletion(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.DeletionBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	var d time.Duration
	if b.Delay != "" {
		var err error
		if d, err = time.ParseDuration(b.Delay); err != nil {
			writeError(w, api.Errorf(api.CodeInvalid, "malformed delay"))
			return
		}
	}
	del, err := m.s.Node.RequestDeletion(r.Context(), r.PathValue("group"), r.PathValue("snap"), id.User, d)
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, http.StatusCreated, del)
}

func (m *Mgmt) cancelDeletion(w http.ResponseWriter, r *http.Request, id *identity) {
	if err := m.s.Node.CancelDeletion(r.Context(), r.PathValue("group"), r.PathValue("snap"), id.User); err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, nil)
}

func (m *Mgmt) executeDeletion(w http.ResponseWriter, r *http.Request, id *identity) {
	if err := m.s.Node.ExecuteDeletion(r.Context(), r.PathValue("group"), r.PathValue("snap"), id.User); err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, nil)
}

// ---- jobs ----------------------------------------------------------------------------------------

func (m *Mgmt) sessions(w http.ResponseWriter, r *http.Request, id *identity) {
	s, err := m.s.DB.OpenSessions(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if s == nil {
		s = []ctl.Session{}
	}
	writeJSON(w, 200, s)
}

func (m *Mgmt) jobs(w http.ResponseWriter, r *http.Request, id *identity) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	j, err := m.s.DB.Jobs(r.Context(), r.URL.Query().Get("kind"), limit)
	if err != nil {
		writeError(w, err)
		return
	}
	if j == nil {
		j = []ctl.Job{}
	}
	writeJSON(w, 200, j)
}

func parseJobID(r *http.Request) (int64, error) {
	n, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || n <= 0 {
		return 0, api.Errorf(api.CodeInvalid, "malformed job id")
	}
	return n, nil
}

func (m *Mgmt) job(w http.ResponseWriter, r *http.Request, id *identity) {
	n, err := parseJobID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	j, err := m.s.DB.Job(r.Context(), n)
	if err != nil {
		writeError(w, notFoundOr(err, "no such job"))
		return
	}
	writeJSON(w, 200, j)
}

func (m *Mgmt) cancelJob(w http.ResponseWriter, r *http.Request, id *identity) {
	n, err := parseJobID(r)
	if err == nil {
		err = m.s.Node.CancelJob(r.Context(), n, id.User)
	}
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, http.StatusAccepted, nil)
}

func (m *Mgmt) answerJob(w http.ResponseWriter, j ctl.Job, err error) {
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

func (m *Mgmt) startGC(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.GCRequest
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	var d time.Duration
	if b.Grace != "" {
		var err error
		if d, err = time.ParseDuration(b.Grace); err != nil {
			writeError(w, api.Errorf(api.CodeInvalid, "malformed grace duration"))
			return
		}
	}
	j, err := m.s.Node.StartGC(node.GCOptions{Grace: d, DryRun: b.DryRun}, id.User)
	m.answerJob(w, j, err)
}

func (m *Mgmt) startVerify(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.VerifyOptions
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	j, err := m.s.Node.StartVerify(b, id.User)
	m.answerJob(w, j, err)
}

func (m *Mgmt) startRetention(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.RetentionOptions
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	j, err := m.s.Node.StartRetention(b, id.User)
	m.answerJob(w, j, err)
}

func (m *Mgmt) startReconcile(w http.ResponseWriter, r *http.Request, id *identity) {
	j, err := m.s.Node.StartReconcile(id.User)
	m.answerJob(w, j, err)
}

func (m *Mgmt) getMaintenance(w http.ResponseWriter, r *http.Request, id *identity) {
	writeJSON(w, 200, node.ModeBody{Mode: m.s.Node.Mode().String()})
}

func (m *Mgmt) setMaintenance(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.ModeBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	mode, ok := parseMode(b.Mode)
	if !ok {
		writeError(w, api.Errorf(api.CodeInvalid, "mode must be online, read-only or offline"))
		return
	}
	if err := m.s.Node.SetMode(r.Context(), mode, id.User); err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, node.ModeBody{Mode: mode.String()})
}

func (m *Mgmt) quarantine(w http.ResponseWriter, r *http.Request, id *identity) {
	q, err := m.s.Node.ListQuarantine(r.Context())
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	if q == nil {
		q = []node.QuarantinedChunk{}
	}
	writeJSON(w, 200, q)
}

func (m *Mgmt) purgeQuarantine(w http.ResponseWriter, r *http.Request, id *identity) {
	c, err := m.s.Node.PurgeQuarantine(r.Context(), 24*time.Hour)
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	m.audit(r.Context(), id, r, "quarantine.purge", "", map[string]any{"removed": c})
	writeJSON(w, 200, map[string]int{"removed": c})
}

func (m *Mgmt) quarantineChunk(w http.ResponseWriter, r *http.Request, id *identity) {
	cid, err := format.ParseID(r.PathValue("id"))
	if err != nil {
		writeError(w, api.Errorf(api.CodeInvalid, "malformed chunk id"))
		return
	}
	moved, err := m.s.Node.QuarantineChunk(r.Context(), cid, id.User, r.RemoteAddr)
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, map[string]bool{"moved": moved})
}

func (m *Mgmt) escrowList(w http.ResponseWriter, r *http.Request, id *identity) {
	d, err := m.s.Node.ListEscrow(r.Context())
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, map[string][]string{"domains": d})
}

func (m *Mgmt) deleteEscrow(w http.ResponseWriter, r *http.Request, id *identity) {
	if err := m.s.Node.DeleteEscrow(r.Context(), r.PathValue("domain"), id.User, r.RemoteAddr); err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, nil)
}

func (m *Mgmt) policies(w http.ResponseWriter, r *http.Request, id *identity) {
	p, err := m.s.DB.RetentionPolicies(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if p == nil {
		p = []ctl.RetentionPolicyRow{}
	}
	writeJSON(w, 200, p)
}

func (m *Mgmt) setPolicy(w http.ResponseWriter, r *http.Request, id *identity) {
	var b node.PolicyBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	if err := m.s.Node.SetRetentionPolicy(r.Context(), r.PathValue("scope"), b.Policy, b.Timezone, id.User); err != nil {
		writeError(w, apiErr(err))
		return
	}
	writeJSON(w, 200, b)
}

func (m *Mgmt) deletePolicy(w http.ResponseWriter, r *http.Request, id *identity) {
	if err := m.s.DB.DeleteRetentionPolicy(r.Context(), r.PathValue("scope")); err != nil {
		writeError(w, notFoundOr(err, "no such policy"))
		return
	}
	m.audit(r.Context(), id, r, "retention.policy.delete", r.PathValue("scope"), nil)
	writeJSON(w, 200, nil)
}

func (m *Mgmt) auditLog(w http.ResponseWriter, r *http.Request, id *identity) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	l, err := m.s.DB.AuditLog(r.Context(), q.Get("action"), limit, before)
	if err != nil {
		writeError(w, err)
		return
	}
	if l == nil {
		l = []ctl.AuditEntry{}
	}
	writeJSON(w, 200, l)
}

// ---- users and tokens -----------------------------------------------------------------------

func validRole(r string) bool { _, ok := roleToPerm[r]; return ok }

// UserBody is the body of POST /api/v1/users and PUT /api/v1/users/{name}.
type UserBody struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

func (m *Mgmt) userList(w http.ResponseWriter, r *http.Request, id *identity) {
	u, err := m.s.DB.Users(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if u == nil {
		u = []ctl.User{}
	}
	writeJSON(w, 200, u)
}

// CreateUser adds a user with a checked password. It is shared by the CLI and the API.
func CreateUser(ctx context.Context, db *ctl.DB, name, password, role string, pp auth.PasswordParams) error {
	if !api.IsName(name, api.MaxName) {
		return api.Errorf(api.CodeInvalid, "a user needs a name: lower case letters, digits and hyphens, starting with a letter, at most %d characters", api.MaxName)
	}
	if !validRole(role) {
		return api.Errorf(api.CodeInvalid, "role must be readonly, backup-admin or admin")
	}
	if err := auth.CheckPasswordPolicy(password, name); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password, pp)
	if err != nil {
		return err
	}
	err = db.CreateUser(ctx, name, hash, role)
	if errors.Is(err, ctl.ErrConflict) {
		return api.Errorf(api.CodeAlreadyExists, "the user exists")
	}
	if err != nil {
		return api.Errorf(api.CodeInvalid, "%v", err)
	}
	return nil
}

func (m *Mgmt) userCreate(w http.ResponseWriter, r *http.Request, id *identity) {
	var b UserBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	if err := CreateUser(r.Context(), m.s.DB, b.Name, b.Password, b.Role, m.pp); err != nil {
		writeError(w, apiErr(err))
		return
	}
	m.audit(r.Context(), id, r, "user.create", b.Name, map[string]any{"role": b.Role})
	writeJSON(w, http.StatusCreated, nil)
}

func (m *Mgmt) userUpdate(w http.ResponseWriter, r *http.Request, id *identity) {
	var b UserBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	name := r.PathValue("name")
	u, err := m.s.DB.User(r.Context(), name)
	if err != nil {
		writeError(w, notFoundOr(err, "no such user"))
		return
	}
	if b.Role == "" {
		b.Role = u.Role
	}
	if !validRole(b.Role) {
		writeError(w, api.Errorf(api.CodeInvalid, "role must be readonly, backup-admin or admin"))
		return
	}
	hash := ""
	if b.Password != "" {
		if err := auth.CheckPasswordPolicy(b.Password, name); err != nil {
			writeError(w, err)
			return
		}
		if hash, err = auth.HashPassword(b.Password, m.pp); err != nil {
			writeError(w, apiErr(err))
			return
		}
	}
	if u.Role == RoleAdmin && !u.Disabled && (b.Role != RoleAdmin || b.Disabled) {
		if n, _ := m.s.DB.CountAdmins(r.Context()); n <= 1 {
			writeError(w, api.Errorf(api.CodeBusy, "this is the last enabled administrator"))
			return
		}
	}
	if err := m.s.DB.UpdateUser(r.Context(), name, b.Role, b.Disabled, hash); err != nil {
		writeError(w, apiErr(err))
		return
	}
	if hash != "" || b.Disabled || b.Role != u.Role {
		_ = m.s.DB.EndUserSessions(r.Context(), name, nil)
	}
	m.audit(r.Context(), id, r, "user.update", name, map[string]any{"role": b.Role, "disabled": b.Disabled, "password_changed": hash != ""})
	writeJSON(w, 200, nil)
}

func (m *Mgmt) userDelete(w http.ResponseWriter, r *http.Request, id *identity) {
	name := r.PathValue("name")
	u, err := m.s.DB.User(r.Context(), name)
	if err != nil {
		writeError(w, notFoundOr(err, "no such user"))
		return
	}
	if u.Role == RoleAdmin && !u.Disabled {
		if n, _ := m.s.DB.CountAdmins(r.Context()); n <= 1 {
			writeError(w, api.Errorf(api.CodeBusy, "this is the last enabled administrator"))
			return
		}
	}
	if err := m.s.DB.DeleteUser(r.Context(), name); err != nil {
		writeError(w, notFoundOr(err, "no such user"))
		return
	}
	m.audit(r.Context(), id, r, "user.delete", name, nil)
	writeJSON(w, 200, nil)
}

// TokenBody is the body of POST /api/v1/tokens.
type TokenBody struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	AllowFrom []string   `json:"allow_from,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (m *Mgmt) tokenList(w http.ResponseWriter, r *http.Request, id *identity) {
	t, err := m.s.DB.Tokens(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if t == nil {
		t = []ctl.Token{}
	}
	writeJSON(w, 200, t)
}

func (m *Mgmt) tokenCreate(w http.ResponseWriter, r *http.Request, id *identity) {
	var b TokenBody
	if err := decodeBody(r, &b); err != nil {
		writeError(w, err)
		return
	}
	if !api.IsName(b.Name, api.MaxName) || !validRole(b.Role) {
		writeError(w, api.Errorf(api.CodeInvalid, "a token needs a name (lower case letters, digits and hyphens, starting with a letter) and a role (readonly, backup-admin or admin)"))
		return
	}
	if err := auth.ValidateAllowFrom(b.AllowFrom); err != nil {
		writeError(w, err)
		return
	}
	secret, hash, err := auth.GenerateToken()
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	t, err := m.s.DB.CreateToken(r.Context(), b.Name, hash, b.Role, b.AllowFrom, b.ExpiresAt)
	if errors.Is(err, ctl.ErrConflict) {
		writeError(w, api.Errorf(api.CodeAlreadyExists, "a token with this name exists"))
		return
	}
	if err != nil {
		writeError(w, apiErr(err))
		return
	}
	m.audit(r.Context(), id, r, "token.create", b.Name, map[string]any{"role": b.Role})
	// the secret is shown once
	writeJSON(w, http.StatusCreated, struct {
		ctl.Token
		Secret string `json:"secret"`
	}{t, secret})
}

func (m *Mgmt) tokenDelete(w http.ResponseWriter, r *http.Request, id *identity) {
	if err := m.s.DB.DeleteToken(r.Context(), r.PathValue("name")); err != nil {
		writeError(w, notFoundOr(err, "no such token"))
		return
	}
	m.audit(r.Context(), id, r, "token.delete", r.PathValue("name"), nil)
	writeJSON(w, 200, nil)
}
