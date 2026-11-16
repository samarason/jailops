package fake

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Identity is a caller known to the fake: a bearer token maps to one.
type Identity struct {
	Name       string
	Permission api.Permission
	Projects   []string
	Global     bool
	// AllRoles makes the identity hold every role, the narrow backup roles
	// included. The token of WithToken and an open server have it; a daemon
	// admin does not (deleting backups needs backup-admin).
	AllRoles bool
}

// reqInfo is what the server knows about one request.
type reqInfo struct {
	id      Identity
	kind    string // token, certificate, anonymous
	authed  bool
	project string
	// aggregate marks GET /api/v1/projects/<n>?host=all on a hub.
	aggregate bool
}

type infoKey struct{}

func (s *Server) info(r *http.Request) *reqInfo {
	if v, ok := r.Context().Value(infoKey{}).(*reqInfo); ok {
		return v
	}
	return &reqInfo{id: Identity{Name: "anonymous", Permission: api.PermAdmin, Global: true, AllRoles: true}, kind: "anonymous", authed: true}
}

func (rc *reqInfo) canProject(p string) bool {
	return rc.id.Global || slices.Contains(rc.id.Projects, p)
}

// canSee says whether objects of a project ("" for host-level) are visible.
func (rc *reqInfo) canSee(project string) bool {
	if project == "" {
		return rc.id.Global
	}
	return rc.canProject(project)
}

func (rc *reqInfo) hasScope() bool { return rc.id.Global || len(rc.id.Projects) > 0 }

// Route scopes.
const (
	scopePublic  = "public"
	scopeSelf    = "self"
	scopeProject = "project"
	scopeList    = "list"
	scopeHost    = "host"
	scopeGlobal  = "global"
)

// classify returns the role a route needs and its scope. pattern is
// "METHOD /path" as registered.
func classify(pattern string) (api.Permission, string) {
	method, path, _ := strings.Cut(pattern, " ")
	read := method == http.MethodGet
	rw := func(scope string) (api.Permission, string) {
		if read {
			return api.PermReadonly, scope
		}
		return api.PermAdmin, scope
	}
	switch {
	case pattern == "GET /api/v1", pattern == "POST /api/v1/trust/clients":
		return "", scopePublic
	case path == "/api/v1/auth/session":
		return api.PermReadonly, scopeSelf
	case strings.HasPrefix(path, "/api/v1/apps/") && strings.HasSuffix(path, "/install"):
		return api.PermOperator, scopeProject
	case path == "/api/v1/config-keys", strings.HasPrefix(path, "/api/v1/apps"):
		return api.PermReadonly, scopeSelf
	case strings.HasPrefix(path, "/api/v1/sessions"):
		return api.PermReadonly, scopeSelf
	case path == "/api/v1/trust/tokens", strings.HasPrefix(path, "/api/v1/users"), strings.HasPrefix(path, "/api/v1/tokens"),
		strings.HasPrefix(path, "/api/v1/certificates"):
		return api.PermAdmin, scopeGlobal
	case strings.HasPrefix(path, "/api/v1/remotes"), strings.HasPrefix(path, "/api/v1/backup-targets"), strings.HasPrefix(path, "/api/v1/host/"):
		return rw(scopeGlobal)
	case strings.HasPrefix(path, "/api/v1/wireguard"):
		if read {
			return api.PermOperator, scopeGlobal
		}
		return api.PermAdmin, scopeGlobal
	case strings.HasPrefix(path, "/api/v1/networks"), strings.HasPrefix(path, "/api/v1/images"),
		strings.HasPrefix(path, "/api/v1/storage"), strings.HasPrefix(path, "/api/v1/projects"):
		return rw(scopeHost)
	case path == "/api/v1/firewall/test":
		return api.PermOperator, scopeProject
	case path == "/api/v1/events", path == "/api/v1/updates", path == "/api/v1/boot":
		return api.PermReadonly, scopeList
	case path == "/api/v1/logs":
		// the logs of many jails: the role that may read one jail's
		return api.PermOperator, scopeList
	case strings.HasPrefix(path, "/api/v1/logs/forward"):
		return api.PermAdmin, scopeGlobal
	case path == "/api/v1/updates/check", path == "/api/v1/updates/apply":
		return api.PermOperator, scopeProject
	case strings.HasPrefix(path, "/api/v1/operations"):
		if method == http.MethodDelete {
			return api.PermOperator, scopeList
		}
		return api.PermReadonly, scopeList
	case strings.HasPrefix(path, "/api/v1/backup/key"), path == "/api/v1/backups/run":
		return api.PermAdmin, scopeGlobal
	case strings.HasPrefix(path, "/api/v1/backups/") && strings.HasSuffix(path, "/verify"):
		return api.PermOperator, scopeList
	case strings.HasPrefix(path, "/api/v1/backups"):
		if method == http.MethodDelete {
			return api.PermBackupAdmin, scopeList
		}
		return rw(scopeList)
	case path == "/api/v1/restores":
		return api.PermRestore, scopeProject
	case strings.HasPrefix(path, "/api/v1/jails/"):
		switch {
		case strings.HasSuffix(path, "/console"), strings.Contains(path, "/console/"):
			return api.PermOperator, scopeProject
		case strings.HasSuffix(path, "/logs"), strings.Contains(path, "/logs/"):
			// logs hold secrets: the role that may exec into the jail
			return api.PermOperator, scopeProject
		case strings.HasSuffix(path, "/app-draft"):
			// it runs commands in the jail: the role that may exec
			return api.PermOperator, scopeProject
		case read:
			return api.PermReadonly, scopeProject
		case strings.HasSuffix(path, "/state"), strings.HasSuffix(path, "/snapshots"), strings.Contains(path, "/snapshots/"),
			strings.HasSuffix(path, "/rollback"), strings.HasSuffix(path, "/upgrade"), strings.HasSuffix(path, "/config"), strings.HasSuffix(path, "/exec"),
			strings.HasSuffix(path, "/access"), strings.HasSuffix(path, "/access/deny"),
			strings.HasSuffix(path, "/unlock"), strings.HasSuffix(path, "/lock"), strings.HasSuffix(path, "/shell-setup"):
			return api.PermOperator, scopeProject
		}
		return api.PermAdmin, scopeProject
	}
	if strings.HasPrefix(path, "/api/v1/volumes") {
		switch {
		case read:
			return api.PermReadonly, scopeProject
		case strings.HasSuffix(path, "/unlock"), strings.HasSuffix(path, "/lock"), strings.HasSuffix(path, "/snapshots"), strings.Contains(path, "/snapshots/"):
			return api.PermOperator, scopeProject
		}
		return api.PermAdmin, scopeProject
	}
	return rw(scopeProject)
}

// RoutePerms returns the role every route of the fake needs, keyed by
// "METHOD pattern", so a test can cross-check it against a real daemon.
func RoutePerms() map[string]api.Permission {
	s := New()
	defer s.Close()
	out := map[string]api.Permission{}
	for _, p := range s.patterns {
		if !strings.Contains(p, " ") {
			continue // the catch-all
		}
		perm, scope := classify(p)
		if scope == scopePublic {
			continue
		}
		out[p] = perm
	}
	return out
}

func (s *Server) projectOK(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.projects.items[p] != nil
}

func fingerprintOf(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func normFP(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "sha256:", "").Replace(s))
}

// authenticate identifies the caller. A presented credential that is bad is
// an unauthorized error; no credential is anonymous.
func (s *Server) authenticate(r *http.Request) (*reqInfo, *api.Error) {
	rc := &reqInfo{}
	if p := r.URL.Query().Get("project"); p != "" {
		rc.project = p
	}
	if h := r.Header.Get("Authorization"); h != "" {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		s.mu.Lock()
		id, known := s.identities[tok]
		s.mu.Unlock()
		if !ok || !known {
			return rc, api.Errorf(api.CodeUnauthorized, "missing or invalid token")
		}
		rc.id, rc.kind, rc.authed = id, "token", true
		return rc, nil
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if id, ok := s.certIdentity(r.TLS); ok {
			rc.id, rc.kind, rc.authed = id, "certificate", true
			return rc, nil
		}
	}
	s.mu.Lock()
	need := s.requireAuth
	s.mu.Unlock()
	if need {
		return rc, api.Errorf(api.CodeUnauthorized, "missing or invalid token")
	}
	rc.id = Identity{Name: "anonymous", Permission: api.PermAdmin, Global: true, AllRoles: true}
	rc.kind, rc.authed = "anonymous", true
	return rc, nil
}

func (s *Server) certIdentity(cs *tls.ConnectionState) (Identity, bool) {
	fp := fingerprintOf(cs.PeerCertificates[0].Raw)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.certs.items {
		if normFP(c.Spec.Fingerprint) != fp {
			continue
		}
		if !c.Spec.ExpiresAt.IsZero() && !now.Before(c.Spec.ExpiresAt) {
			return Identity{}, false
		}
		return Identity{Name: "cert:" + c.Metadata.Name, Permission: c.Spec.Permission, Projects: slices.Clone(c.Spec.Projects), Global: c.Spec.Global}, true
	}
	return Identity{}, false
}

// authorize applies the two checks of PROTOCOL.md: the role (forbidden), then
// the object's project (not_found). pattern is the matched route.
func (s *Server) authorize(rc *reqInfo, pattern string, r *http.Request, authErr *api.Error) *api.Error {
	if !strings.Contains(pattern, " ") {
		return nil // the catch-all answers unknown paths with 404
	}
	perm, scope := classify(pattern)
	if scope == scopePublic {
		return nil
	}
	if authErr != nil {
		return authErr
	}
	if !rc.id.AllRoles && !rc.id.Permission.Satisfies(perm) {
		return api.Errorf(api.CodeForbidden, "the %s role cannot call %s", rc.id.Permission, pattern).WithDetail("required", string(perm))
	}
	if scope != scopeSelf && !rc.hasScope() {
		return api.Errorf(api.CodeForbidden, "this identity has no projects and is not global: it can do nothing").
			WithHint("grant it projects or global access")
	}
	notFoundProject := func(p string) *api.Error {
		return api.Errorf(api.CodeNotFound, "project %q not found", p)
	}
	switch scope {
	case scopeProject:
		if rc.project == api.HostProfileProject && strings.HasPrefix(r.URL.Path, "/api/v1/profiles") {
			if r.Method != http.MethodGet && !rc.id.Global {
				return api.Errorf(api.CodeForbidden, "host-level profiles need a global admin")
			}
			return nil
		}
		if rc.project == "" {
			return api.Errorf(api.CodeInvalid, "a project is required").
				WithHint("name one with --project NAME (list them with 'jailops project list')")
		}
		if !s.projectOK(rc.project) || !rc.canProject(rc.project) {
			return notFoundProject(rc.project)
		}
	case scopeList:
		if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") {
			// one operation is looked up by its id, as the daemon does: the project of the request does not have to
			// exist (a project rename is followed under the old name)
			break
		}
		if q := r.URL.Query().Get("project"); q != "" && (!s.projectOK(q) || !rc.canProject(q)) {
			return notFoundProject(q)
		}
	case scopeHost:
		if r.Method != http.MethodGet && !rc.id.Global {
			return api.Errorf(api.CodeForbidden, "host-level objects need a global admin")
		}
	case scopeGlobal:
		if !rc.id.Global {
			return api.Errorf(api.CodeForbidden, "this route needs a global admin")
		}
	}
	return nil
}

func validIdentityScope(projects []string, global bool) *api.Error {
	if !global && len(projects) == 0 {
		return api.Errorf(api.CodeInvalid, "an identity needs a non-empty projects list or global: true").
			WithHint("an empty projects list never means all projects")
	}
	return nil
}

var _ = time.Second
