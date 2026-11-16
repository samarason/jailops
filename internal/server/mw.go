package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// route is one row of the route table.
type route struct {
	method, pattern string
	h               func(*rc) error
	// long routes (events, operation wait, hub streams) have no request deadline.
	long bool
	// local routes answer for this daemon only: ?host= is never forwarded (GET /readyz).
	local bool
}

// rc is the per-request context handed to handlers.
type rc struct {
	s   *Server
	w   http.ResponseWriter
	r   *http.Request
	rt  route
	rid string

	actor   service.Actor
	method  string // how the caller authenticated
	csrf    string
	session string

	status         int
	statusOverride int
	code           api.Code
	// object is the resource named in the audit entry.
	object string
	// project is the project of the request, for the audit entry.
	project string
	// detail is added to the audit entry.
	detail string
}

func newRC(s *Server, w http.ResponseWriter, r *http.Request, rt route) *rc {
	return &rc{s: s, w: w, r: r, rt: rt, rid: ridFrom(r.Context())}
}

type ridKey struct{}
type infoKey struct{}

// reqInfo is filled in by wrap so the outer logger can report the actor.
type reqInfo struct{ actor, route string }

func ridFrom(ctx context.Context) string {
	s, _ := ctx.Value(ridKey{}).(string)
	return s
}

var ridRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

func newRID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// statusWriter records the status and bytes written and forwards Flush.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijacking is not supported")
}

// PermissionsPolicy turns off the browser features neither console uses.
const PermissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), midi=(), " +
	"accelerometer=(), gyroscope=(), magnetometer=(), display-capture=()"

// outer is the guard around everything: request id, headers, panic recovery,
// access log.
func (s *Server) outer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := r.Header.Get("X-Request-ID")
		if !ridRe.MatchString(rid) {
			rid = newRID()
		}
		w.Header().Set("X-Request-ID", rid)
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if isAPIPath(r.URL.Path) {
			// API answers carry secrets (a new token, a generated password, recovery codes): never cached.
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
			h.Set("Expires", "0")
		} else {
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		}
		// the consoles use no camera, microphone, location, payment or sensors
		h.Set("Permissions-Policy", PermissionsPolicy)
		if r.TLS != nil && s.cfg.HSTS != nil && s.cfg.HSTS() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		info := &reqInfo{}
		ctx := context.WithValue(context.WithValue(r.Context(), ridKey{}, rid), infoKey{}, info)
		r = r.WithContext(ctx)
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic in handler", "rid", rid, "panic", p, "stack", string(debug.Stack()))
				if sw.status == 0 {
					writeJSON(sw, http.StatusInternalServerError, api.Response{Type: api.ResponseError, Status: "Failure", StatusCode: 500,
						Error: api.Errorf(api.CodeInternal, "internal error").WithHint("see the daemon log for request " + rid)})
				}
			}
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				return // probes, every few seconds
			}
			st := sw.status
			if st == 0 {
				st = 200
			}
			_, remote := remoteString(r)
			s.log.Info("request", "rid", rid, "method", r.Method, "path", redactConsolePath(r.URL.Path), "query", redactQuery(r.URL.Query()),
				"status", st, "ms", time.Since(start).Milliseconds(), "bytes", sw.bytes, "actor", info.actor, "route", info.route, "remote", remote)
		}()
		next.ServeHTTP(sw, r)
	})
}

// isAPIPath reports a path of the API (/api/v1 and below), as opposed to the console's static files.
func isAPIPath(p string) bool { return p == "/api/v1" || strings.HasPrefix(p, "/api/v1/") }

func remoteString(r *http.Request) (string, string) {
	h, _ := remoteAddr(r)
	return h, h
}

// redactQuery renders the query string for the log with credentials hidden.
func redactQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		switch k {
		case "access_token", "token", "password", "secret":
			parts = append(parts, k+"=[redacted]")
		default:
			for _, v := range q[k] {
				parts = append(parts, k+"="+v)
			}
		}
	}
	return strings.Join(parts, "&")
}

// wrap builds the handler of a route: authenticate, authorise (role, then
// scope), CSRF, hub forwarding, deadline, handler, audit.
func (s *Server) wrap(rt route) http.HandlerFunc {
	ent, _ := s.authz.Reg.Lookup(rt.method, rt.pattern)
	return func(w http.ResponseWriter, r *http.Request) {
		c := newRC(s, w, r, rt)
		if info, ok := r.Context().Value(infoKey{}).(*reqInfo); ok {
			info.route = rt.method + " " + rt.pattern
			defer func() { info.actor = c.actor.Name }()
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBody)
		}
		ar, aerr := s.authenticate(r)
		if aerr != nil && !ent.Public {
			c.fail(aerr)
			s.auditAuthFailure(c, aerr)
			return
		}
		var locked *auth.LockedError
		if aerr != nil && errors.As(aerr, &locked) {
			c.fail(aerr)
			s.auditAuthFailure(c, aerr)
			return
		}
		if aerr == nil {
			c.actor, c.method, c.csrf, c.session = ar.actor, ar.method, ar.csrf, ar.session
		}
		if ar.unknownCert && !ent.Public {
			var err error = api.Errorf(api.CodeUnauthorized, "the client certificate is not trusted").
				WithHint("ask a global administrator for a trust token (jailops cert enroll)")
			if lerr := s.tokLim.Fail("cert|" + auth.SourceKey(c.remote())); lerr != nil {
				err = lerr
			}
			c.fail(err)
			s.auditAuthFailure(c, err)
			return
		}
		// The project the request names. A name that cannot be a project is
		// as unknown as any other.
		if p := r.URL.Query().Get("project"); p != "" {
			if !hostProfiles(r, p) && validate.ProjectName(p) != nil {
				c.fail(api.Errorf(api.CodeNotFound, "project %q not found", p))
				return
			}
			r = r.WithContext(service.WithProject(r.Context(), p))
			c.r = r
		}
		switch ent.Class {
		case auth.ClassProject:
			c.project = service.ProjectFrom(r.Context())
		case auth.ClassVisible:
			c.project = r.URL.Query().Get("project")
		}
		if err := s.authz.Check(c.actor.Perm, rt.method, rt.pattern); err != nil {
			c.fail(err)
			if isMutation(r.Method) && c.actor.Name != "" {
				s.audit(c, "denied")
			}
			return
		}
		if err := s.checkScope(c, ent); err != nil {
			c.fail(err)
			if isMutation(r.Method) {
				s.audit(c, "denied")
			}
			return
		}
		if ent.Class == auth.ClassProject && service.ProjectFrom(r.Context()) == "" {
			// There is no default project: a request for a project-level resource names its project.
			c.fail(service.ErrProjectRequired())
			if isMutation(r.Method) {
				s.audit(c, "error")
			}
			return
		}
		if ent.Class == auth.ClassProject && !hostProfiles(r, service.ProjectFrom(r.Context())) {
			// A project the caller may not use is not_found, before any handler runs.
			if err := s.svc.AccessProject(service.WithActor(r.Context(), c.actor)); err != nil {
				c.fail(err)
				if isMutation(r.Method) {
					s.audit(c, "error")
				}
				return
			}
		}
		if c.method == "session" && isMutation(r.Method) {
			if !auth.CSRFValid(c.csrf, r.Header.Get("X-CSRF-Token")) {
				c.fail(api.Errorf(api.CodeForbidden, "missing or invalid CSRF token").WithHint("send the X-CSRF-Token header"))
				s.audit(c, "denied")
				return
			}
			if err := auth.CheckOrigin(r); err != nil {
				c.fail(api.Errorf(api.CodeForbidden, "%v", err))
				s.audit(c, "denied")
				return
			}
		}
		if host := r.URL.Query().Get("host"); host != "" && !rt.local {
			if host == "all" {
				if rt.method == "GET" && rt.pattern == "/api/v1/projects/{name}" {
					if err := s.aggregateProject(c); err != nil {
						c.fail(err)
					}
					return
				}
				c.fail(api.Errorf(api.CodeInvalid, "host=all is only valid for GET /api/v1/projects/<name>"))
				return
			}
			if s.forward(c, host) {
				if isMutation(r.Method) {
					s.audit(c, "ok")
				}
				return
			}
		}
		ctx := service.WithActor(r.Context(), c.actor)
		if !rt.long {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, s.cfg.RequestTimeout)
			defer cancel()
		}
		c.r = r.WithContext(ctx)
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("panic in handler", "rid", c.rid, "route", rt.method+" "+rt.pattern, "panic", p, "stack", string(debug.Stack()))
					c.fail(api.Errorf(api.CodeInternal, "internal error").WithHint("see the daemon log for request " + c.rid))
				}
			}()
			if err := rt.h(c); err != nil {
				c.fail(err)
			}
		}()
		if isMutation(r.Method) {
			result := "ok"
			switch {
			case c.status == 401 || c.status == 403 || c.status == 429:
				result = "denied"
			case c.status >= 400:
				result = "error"
			}
			s.audit(c, result)
		}
	}
}

// checkScope is the second authorization check, after the role: the
// scope of the identity against the class of the route. The service layer
// repeats these rules and adds the per-object ones (a project the caller may
// not use is not_found there), so a handler that forgot one is still safe.
func (s *Server) checkScope(c *rc, ent auth.Entry) error {
	switch ent.Class {
	case auth.ClassPublic, auth.ClassSelf:
		return nil
	}
	a := c.actor
	if !a.HasScope() {
		return api.Errorf(api.CodeForbidden, "this identity has no projects and is not global").
			WithHint("an identity needs a non-empty projects list or global: true")
	}
	switch ent.Class {
	case auth.ClassGlobal:
		if !a.Global {
			return api.Errorf(api.CodeForbidden, "%s %s needs a global administrator", ent.Method, ent.Pattern)
		}
	case auth.ClassGranted:
		if isMutation(ent.Method) && !a.Global {
			return api.Errorf(api.CodeForbidden, "%s %s needs a global administrator", ent.Method, ent.Pattern)
		}
	}
	return nil
}

func (c *rc) remote() string {
	h, _ := remoteAddr(c.r)
	return h
}

// auditAuthFailure records a failed authentication (bad token, forged claim,
// untrusted certificate, lockout). Nothing about the credential is stored.
func (s *Server) auditAuthFailure(c *rc, err error) {
	code := ""
	var ae *api.Error
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		code = string(api.CodeRateLimited)
	case errors.As(err, &ae):
		code = string(ae.Code)
	}
	remote := c.remote()
	s.writeAudit(context.WithoutCancel(c.r.Context()), store.AuditEntry{Actor: "-", ActorKind: "anonymous", Method: c.rt.method, Route: c.rt.pattern,
		Object: redactConsolePath(c.r.URL.Path), Result: "denied", Status: c.status, Remote: remote, Detail: "authentication failed: " + code})
}

// maxAuditValue bounds one value a client sent in an audit detail.
const maxAuditValue = 200

// auditValue makes text a client sent safe for an audit detail: quoted with Go's escapes (no line break, and no
// space or "=" that could pass for another key=value) and cut at maxAuditValue bytes. Every value of a request
// body that goes into a detail goes through it, also when the request is refused later.
func auditValue(s string) string {
	cut := len(s) > maxAuditValue
	if cut {
		s = strings.ToValidUTF8(s[:maxAuditValue], "")
	}
	q := strconv.Quote(s)
	if cut {
		q += "..."
	}
	return q
}

// audit records a state-changing request. It never contains bodies or secrets.
func (s *Server) audit(c *rc, result string) {
	name, kind := c.actor.Name, c.actor.Kind
	if name == "" {
		name, kind = "-", "anonymous"
	}
	obj := c.object
	if obj == "" {
		obj = redactConsolePath(c.r.URL.Path)
	}
	e := store.AuditEntry{Actor: name, ActorKind: kind, Method: c.rt.method, Route: c.rt.pattern, Object: obj, Project: c.project,
		Result: result, Status: c.status, Remote: c.actor.Remote}
	if e.Remote == "" {
		e.Remote, _ = remoteAddr(c.r)
	}
	if c.code != "" {
		e.Detail = string(c.code)
	}
	if c.detail != "" {
		e.Detail = strings.TrimSpace(e.Detail + " " + c.detail)
	}
	if c.r.URL.Query().Get("host") != "" {
		e.Detail = "host=" + auditValue(c.r.URL.Query().Get("host")) + " " + e.Detail
	}
	s.writeAudit(context.WithoutCancel(c.r.Context()), e)
}

// withActor returns the request context carrying the caller, for service calls
// made outside the normal handler path.
func withActor(c *rc) context.Context {
	return service.WithActor(c.r.Context(), c.actor)
}

func contextTimeout(c *rc, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.r.Context(), d)
}

func asAPIError(err error) *api.Error {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae
	}
	return api.Errorf(api.CodeInternal, "%v", err)
}

// hostProfiles reports a request for the host-level profiles (?project=host),
// which the service authorises itself: anyone with a scope reads, a global
// admin writes.
func hostProfiles(r *http.Request, project string) bool {
	return project == api.HostProfileProject && strings.HasPrefix(r.URL.Path, "/api/v1/profiles")
}

// storeEntry builds an audit entry for an event inside a request.
func storeEntry(c *rc, method, project, detail string) store.AuditEntry {
	name, kind := c.actor.Name, c.actor.Kind
	if name == "" {
		name, kind = "-", "anonymous"
	}
	remote := c.actor.Remote
	if remote == "" {
		remote, _ = remoteAddr(c.r)
	}
	return store.AuditEntry{Actor: name, ActorKind: kind, Method: method, Route: c.rt.pattern, Object: c.object, Project: project,
		Result: "ok", Remote: remote, Detail: detail}
}
