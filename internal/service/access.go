package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/sdk/api"
)

func validPerm(p api.Permission) bool {
	switch p {
	case api.PermReadonly, api.PermOperator, api.PermAdmin, api.PermBackupPush, api.PermBackupPull, api.PermRestore, api.PermBackupAdmin:
		return true
	}
	return false
}

// canGrant stops a caller from creating credentials stronger than their own.
func canGrant(ctx context.Context, p api.Permission) error {
	have := ActorFrom(ctx).Perm
	// An admin may hand out any role, including the narrow transport roles.
	if have != api.PermAdmin && !have.Satisfies(p) {
		return api.Errorf(api.CodeForbidden, "you cannot grant the %s role with a %s credential", p, ActorFrom(ctx).Perm)
	}
	return nil
}

// checkScope validates the scope of a new identity: a non-empty project list
// or global, never neither; the projects must exist, and a caller cannot hand
// out more scope than they have. It returns the normalised scope.
func (s *Service) checkScope(ctx context.Context, projects []string, global bool) (auth.Scope, error) {
	sc, err := auth.Scope{Projects: projects, Global: global}.Normalize()
	if err != nil {
		return sc, invalid("%v", err)
	}
	if err := sc.Validate(); err != nil {
		return sc, err
	}
	a := ActorFrom(ctx)
	if sc.Global && !a.Global {
		return sc, api.Errorf(api.CodeForbidden, "only a global administrator grants global access")
	}
	for _, p := range sc.Projects {
		if !a.CanProject(p) {
			return sc, api.Errorf(api.CodeForbidden, "you cannot grant access to project %q", p)
		}
		if _, err := s.projKind.get(p); err != nil {
			return sc, invalid("project %q does not exist", p)
		}
	}
	return sc, nil
}

// ---- tokens ----

func tokenToAPI(t *store.Token) api.Token {
	return api.Token{
		Metadata: api.ObjectMeta{Name: t.Name, UUID: t.ID, Scope: api.ScopeFleet, Generation: 1, CreatedAt: t.CreatedAt, UpdatedAt: t.CreatedAt},
		Spec: api.TokenSpec{Permission: t.Permission, ExpiresAt: t.ExpiresAt, AllowFrom: t.AllowFrom,
			Projects: t.Projects, Global: t.Global},
	}
}

func (s *Service) findToken(ctx context.Context, name string) (*store.Token, error) {
	l, err := s.d.DB.Tokens.List(ctx)
	if err != nil {
		return nil, internal(err)
	}
	for _, t := range l {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, notFound("token", name)
}

// ListTokens lists tokens without secrets or hashes.
func (s *Service) ListTokens(ctx context.Context, labels map[string]string) ([]api.Token, error) {
	if err := requireGlobal(ctx, "listing tokens"); err != nil {
		return nil, err
	}
	l, err := s.d.DB.Tokens.List(ctx)
	if err != nil {
		return nil, internal(err)
	}
	out := []api.Token{}
	for _, t := range l {
		if len(labels) == 0 {
			out = append(out, tokenToAPI(t))
		}
	}
	return out, nil
}

// GetToken returns a token record (never the secret).
func (s *Service) GetToken(ctx context.Context, name string) (api.Token, error) {
	if err := requireGlobal(ctx, "reading a token"); err != nil {
		return api.Token{}, err
	}
	t, err := s.findToken(ctx, name)
	if err != nil {
		return api.Token{}, err
	}
	return tokenToAPI(t), nil
}

// CreateToken makes a token. The secret is in the reply and nowhere else.
func (s *Service) CreateToken(ctx context.Context, in api.Token) (api.Token, error) {
	p := in.Spec.Permission
	sc, err := s.checkScope(ctx, in.Spec.Projects, in.Spec.Global)
	if err != nil {
		return api.Token{}, err
	}
	if !validPerm(p) {
		return api.Token{}, invalid("token permission is required (readonly, operator, admin, ...)")
	}
	if err := canGrant(ctx, p); err != nil {
		return api.Token{}, err
	}
	name := in.Metadata.Name
	if name == "" {
		name = "token-" + randHex(4)
	}
	if err := ValidObjectName(name); err != nil {
		return api.Token{}, err
	}
	if err := auth.ValidateAllowFrom(in.Spec.AllowFrom); err != nil {
		return api.Token{}, err
	}
	now := s.now().UTC()
	if !in.Spec.ExpiresAt.IsZero() && !in.Spec.ExpiresAt.After(now) {
		return api.Token{}, invalid("expires_at is in the past")
	}
	if _, err := s.findToken(ctx, name); err == nil {
		return api.Token{}, api.Errorf(api.CodeAlreadyExists, "token %q already exists", name)
	}
	secret, hash, err := auth.GenerateToken()
	if err != nil {
		return api.Token{}, internal(err)
	}
	rec := store.Token{ID: newOpID(), Name: name, Hash: hash, Permission: p, ExpiresAt: in.Spec.ExpiresAt.UTC(),
		AllowFrom: in.Spec.AllowFrom, CreatedAt: now, Projects: sc.Projects, Global: sc.Global}
	if err := s.d.DB.Tokens.Create(ctx, rec); err != nil {
		return api.Token{}, internal(err)
	}
	s.emit(ctx, "token-created", "/api/v1/tokens/"+name)
	out := tokenToAPI(&rec)
	out.Secret = secret
	return out, nil
}

// DeleteToken revokes a token.
func (s *Service) DeleteToken(ctx context.Context, name string) error {
	if err := requireGlobal(ctx, "revoking a token"); err != nil {
		return err
	}
	t, err := s.findToken(ctx, name)
	if err != nil {
		return err
	}
	if err := s.keepAdmin(ctx, "token:"+t.Name); err != nil {
		return err
	}
	if err := s.d.DB.Tokens.Delete(ctx, t.ID); err != nil {
		return internal(err)
	}
	s.emit(ctx, "token-deleted", "/api/v1/tokens/"+name)
	return nil
}

// AuthenticateToken checks a presented bearer token.
func (s *Service) AuthenticateToken(ctx context.Context, secret string, remote netip.Addr) (Actor, error) {
	bad := api.Errorf(api.CodeUnauthorized, "missing or invalid token")
	if !auth.TokenWellFormed(secret) {
		return Actor{}, bad
	}
	t, err := s.d.DB.Tokens.GetByHash(ctx, auth.HashToken(secret))
	if err != nil {
		return Actor{}, bad
	}
	if err := auth.CheckTokenUse(t.ExpiresAt, t.AllowFrom, s.now(), remote); err != nil {
		return Actor{}, err
	}
	_ = s.d.DB.Tokens.TouchUsed(ctx, t.ID)
	return Actor{Name: t.Name, Kind: "token", Perm: t.Permission, Remote: remote.String(), Projects: t.Projects, Global: t.Global}, nil
}

// ---- certificates ----

type certInfo struct {
	name    string
	perm    api.Permission
	kind    string
	scope   auth.Scope
	expires time.Time
}

func (s *Service) warmCerts() {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	s.rebuildCerts()
}

func (s *Service) rebuildCerts() {
	m := map[string]certInfo{}
	if objs, err := s.certKind.list(); err == nil {
		for _, o := range objs {
			m[o.Spec.Fingerprint] = certInfo{name: o.Meta.Name, perm: o.Spec.Permission, kind: o.Spec.Kind,
				scope: auth.Scope{Projects: o.Spec.Projects, Global: o.Spec.Global}, expires: o.Spec.ExpiresAt}
		}
	}
	s.certCache = m
}

// CertActor returns the caller a pinned client certificate stands for.
func (s *Service) CertActor(fingerprint, remote string) (Actor, bool) {
	fp, err := auth.NormalizeFingerprint(fingerprint)
	if err != nil {
		return Actor{}, false
	}
	s.certMu.Lock()
	defer s.certMu.Unlock()
	ci, ok := s.certCache[fp]
	if !ok || (!ci.expires.IsZero() && !s.now().Before(ci.expires)) {
		return Actor{}, false
	}
	kind := "certificate"
	if ci.kind == "hub" {
		kind = "hub"
	}
	return Actor{Name: "cert:" + ci.name, Kind: kind, Perm: ci.perm, Remote: remote, Projects: ci.scope.Projects, Global: ci.scope.Global}, true
}

// HubActor turns a verified requestor claim of a hub certificate into the
// caller it stands for. The claim is limited by the certificate's own entry:
// its role cannot exceed the certificate's, and the projects it names must
// lie inside the certificate's scope (global needs a global certificate).
func (s *Service) HubActor(fingerprint string, c auth.RequestorClaim, remote string) (Actor, error) {
	fp, err := auth.NormalizeFingerprint(fingerprint)
	if err != nil {
		return Actor{}, api.Errorf(api.CodeUnauthorized, "unknown certificate")
	}
	s.certMu.Lock()
	ci, ok := s.certCache[fp]
	s.certMu.Unlock()
	if !ok || ci.kind != "hub" || (!ci.expires.IsZero() && !s.now().Before(ci.expires)) {
		return Actor{}, api.Errorf(api.CodeForbidden, "only a hub certificate may forward a requestor")
	}
	perm, sc, err := c.Clamp(ci.perm, ci.scope)
	if err != nil {
		return Actor{}, err
	}
	kind := c.Kind
	if kind == "" {
		kind = "user"
	}
	return Actor{Name: c.Name, Kind: kind, Perm: perm, Remote: remote + " via hub:" + ci.name, Projects: sc.Projects, Global: sc.Global}, nil
}

// IsHubCertificate reports whether the fingerprint is a trusted, current
// certificate of kind hub.
func (s *Service) IsHubCertificate(fingerprint string) bool {
	fp, err := auth.NormalizeFingerprint(fingerprint)
	if err != nil {
		return false
	}
	s.certMu.Lock()
	defer s.certMu.Unlock()
	ci, ok := s.certCache[fp]
	return ok && ci.kind == "hub" && (ci.expires.IsZero() || s.now().Before(ci.expires))
}

func certToAPI(o object[api.CertificateSpec]) api.Certificate {
	return api.Certificate{Metadata: o.Meta, Spec: o.Spec}
}

func (s *Service) findCert(key string) (object[api.CertificateSpec], error) {
	if o, err := s.certKind.get(key); err == nil {
		return o, nil
	}
	if fp, err := auth.NormalizeFingerprint(key); err == nil {
		objs, _ := s.certKind.list()
		for _, o := range objs {
			if o.Spec.Fingerprint == fp {
				return o, nil
			}
		}
	}
	return object[api.CertificateSpec]{}, notFound("certificate", key)
}

func (s *Service) checkCert(ctx context.Context, c *api.Certificate, self string) error {
	fp, err := auth.NormalizeFingerprint(c.Spec.Fingerprint)
	if err != nil {
		return invalid("invalid fingerprint: %v", err)
	}
	c.Spec.Fingerprint = fp
	if !validPerm(c.Spec.Permission) {
		return invalid("certificate permission is required")
	}
	if err := canGrant(ctx, c.Spec.Permission); err != nil {
		return err
	}
	switch c.Spec.Kind {
	case "client", "host", "hub", "backup":
	case "":
		c.Spec.Kind = "client"
	default:
		return invalid("certificate kind must be client, host, hub or backup")
	}
	sc, err := s.checkScope(ctx, c.Spec.Projects, c.Spec.Global)
	if err != nil {
		return err
	}
	c.Spec.Projects, c.Spec.Global = sc.Projects, sc.Global
	if c.Metadata.Name == "" {
		c.Metadata.Name = c.Spec.Kind + "-" + fp[:12]
	}
	if err := ValidObjectName(c.Metadata.Name); err != nil {
		return err
	}
	objs, _ := s.certKind.list()
	for _, o := range objs {
		if o.Spec.Fingerprint == fp && o.Meta.Name != self {
			return api.Errorf(api.CodeAlreadyExists, "certificate %s is already trusted as %q", fp[:12], o.Meta.Name)
		}
	}
	return nil
}

// ListCertificates lists trusted certificates.
func (s *Service) ListCertificates(ctx context.Context, labels map[string]string) ([]api.Certificate, error) {
	if err := requireGlobal(ctx, "listing certificates"); err != nil {
		return nil, err
	}
	objs, err := s.certKind.list()
	if err != nil {
		return nil, err
	}
	out := []api.Certificate{}
	for _, o := range objs {
		if MatchLabels(o.Meta.Labels, labels) {
			out = append(out, certToAPI(o))
		}
	}
	return out, nil
}

// GetCertificate returns a certificate by name or fingerprint.
func (s *Service) GetCertificate(ctx context.Context, key string) (api.Certificate, error) {
	if err := requireGlobal(ctx, "reading a certificate"); err != nil {
		return api.Certificate{}, err
	}
	o, err := s.findCert(key)
	return certToAPI(o), err
}

// CreateCertificate trusts a certificate fingerprint.
func (s *Service) CreateCertificate(ctx context.Context, c api.Certificate) (api.Certificate, error) {
	if err := requireGlobal(ctx, "trusting a certificate"); err != nil {
		return api.Certificate{}, err
	}
	if err := s.checkCert(ctx, &c, ""); err != nil {
		return api.Certificate{}, err
	}
	o, err := s.certKind.create(ctx, c.Metadata, c.Spec)
	if err != nil {
		return api.Certificate{}, err
	}
	s.warmCerts()
	return certToAPI(o), nil
}

// UpdateCertificate replaces a certificate entry.
func (s *Service) UpdateCertificate(ctx context.Context, key string, c api.Certificate, expect int64) (api.Certificate, error) {
	if err := requireGlobal(ctx, "changing a certificate"); err != nil {
		return api.Certificate{}, err
	}
	cur, err := s.findCert(key)
	if err != nil {
		return api.Certificate{}, err
	}
	if c.Metadata.Name == "" {
		c.Metadata.Name = cur.Meta.Name
	}
	if c.Metadata.Name != cur.Meta.Name {
		return api.Certificate{}, invalid("renaming is not supported")
	}
	if err := s.checkCert(ctx, &c, cur.Meta.Name); err != nil {
		return api.Certificate{}, err
	}
	if c.Spec.Permission != api.PermAdmin || !c.Spec.Global || (!c.Spec.ExpiresAt.IsZero() && !s.now().Before(c.Spec.ExpiresAt)) {
		if err := s.keepAdmin(ctx, "certificate:"+cur.Meta.Name); err != nil {
			return api.Certificate{}, err
		}
	}
	o, err := s.certKind.update(ctx, cur.Meta.Name, expect, c.Metadata.Labels, &c.Metadata.ManagedBy, c.Spec)
	if err != nil {
		return api.Certificate{}, err
	}
	s.warmCerts()
	return certToAPI(o), nil
}

// PatchCertificate applies a merge patch.
func (s *Service) PatchCertificate(ctx context.Context, key string, patch map[string]any, expect int64) (api.Certificate, error) {
	cur, err := s.GetCertificate(ctx, key)
	if err != nil {
		return cur, err
	}
	if expect != AnyGeneration && expect != cur.Metadata.Generation {
		return cur, api.Errorf(api.CodeConflict, "certificate %q changed: current generation is %d", key, cur.Metadata.Generation)
	}
	var out api.Certificate
	if err := MergePatch(cur, patch, &out); err != nil {
		return out, err
	}
	return s.UpdateCertificate(ctx, key, out, cur.Metadata.Generation)
}

// DeleteCertificate stops trusting a certificate.
func (s *Service) DeleteCertificate(ctx context.Context, key string, expect int64) error {
	if err := requireGlobal(ctx, "revoking a certificate"); err != nil {
		return err
	}
	cur, err := s.findCert(key)
	if err != nil {
		return err
	}
	if err := s.keepAdmin(ctx, "certificate:"+cur.Meta.Name); err != nil {
		return err
	}
	if err := s.certKind.delete(ctx, cur.Meta.Name, expect); err != nil {
		return err
	}
	s.warmCerts()
	s.emit(ctx, "certificate-revoked", "/api/v1/certificates/"+cur.Meta.Name)
	return nil
}

// ---- users ----

func userToAPI(u *store.User) api.User {
	return api.User{
		Metadata: api.ObjectMeta{Name: u.Name, UUID: u.ID, Scope: api.ScopeFleet, Generation: u.UpdatedAt.UnixMilli(), CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt},
		Spec:     api.UserSpec{Permission: u.Permission, Disabled: u.Disabled, TOTP: u.TOTPEnabled, Projects: u.Projects, Global: u.Global},
	}
}

// ListUsers lists users without any credential material.
func (s *Service) ListUsers(ctx context.Context, labels map[string]string) ([]api.User, error) {
	if err := requireGlobal(ctx, "listing users"); err != nil {
		return nil, err
	}
	l, err := s.d.DB.Users.List(ctx)
	if err != nil {
		return nil, internal(err)
	}
	out := []api.User{}
	for _, u := range l {
		if len(labels) == 0 {
			out = append(out, userToAPI(u))
		}
	}
	return out, nil
}

// GetUser returns one user.
func (s *Service) GetUser(ctx context.Context, name string) (api.User, error) {
	if err := requireGlobal(ctx, "reading a user"); err != nil {
		return api.User{}, err
	}
	u, err := s.d.DB.Users.GetByName(ctx, name)
	if err != nil {
		return api.User{}, notFound("user", name)
	}
	return userToAPI(u), nil
}

const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generatePassword(user string) (string, error) {
	for i := 0; i < 50; i++ {
		b := make([]byte, 20)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		for j := range b {
			b[j] = passwordAlphabet[int(b[j])%len(passwordAlphabet)]
		}
		if auth.CheckPasswordPolicy(string(b), user) == nil {
			return string(b), nil
		}
	}
	return "", errors.New("could not generate a password")
}

// CreateUser creates a user; a generated password is returned once.
func (s *Service) CreateUser(ctx context.Context, in api.UserCreate) (api.UserCreated, error) {
	if err := requireGlobal(ctx, "creating a user"); err != nil {
		return api.UserCreated{}, err
	}
	sc, err := s.checkScope(ctx, in.Spec.Projects, in.Spec.Global)
	if err != nil {
		return api.UserCreated{}, err
	}
	name := in.Metadata.Name
	if err := ValidObjectName(name); err != nil {
		return api.UserCreated{}, err
	}
	if !validPerm(in.Spec.Permission) {
		return api.UserCreated{}, invalid("user permission is required")
	}
	if err := canGrant(ctx, in.Spec.Permission); err != nil {
		return api.UserCreated{}, err
	}
	if in.Spec.TOTP {
		return api.UserCreated{}, invalid("two-factor authentication is enrolled by the user after the first login")
	}
	if _, err := s.d.DB.Users.GetByName(ctx, name); err == nil {
		return api.UserCreated{}, api.Errorf(api.CodeAlreadyExists, "user %q already exists", name)
	}
	pw, generated := in.Password, false
	if pw == "" {
		var err error
		if pw, err = generatePassword(name); err != nil {
			return api.UserCreated{}, internal(err)
		}
		generated = true
	} else if err := auth.CheckPasswordPolicy(pw, name); err != nil {
		return api.UserCreated{}, invalid("%v", err)
	}
	hash, err := auth.HashPassword(pw, s.d.PasswordParams)
	if err != nil {
		return api.UserCreated{}, internal(err)
	}
	now := s.now().UTC()
	u := store.User{ID: newOpID(), Name: name, PasswordHash: hash, Permission: in.Spec.Permission, Disabled: in.Spec.Disabled, CreatedAt: now, UpdatedAt: now,
		Projects: sc.Projects, Global: sc.Global}
	if err := s.d.DB.Users.Create(ctx, u); err != nil {
		return api.UserCreated{}, internal(err)
	}
	s.emit(ctx, "user-created", "/api/v1/users/"+name)
	out := api.UserCreated{User: userToAPI(&u)}
	if generated {
		out.Password = pw
	}
	return out, nil
}

// UpdateUser changes a user's role and disabled flag.
func (s *Service) UpdateUser(ctx context.Context, name string, in api.User, expect int64) (api.User, error) {
	if err := requireGlobal(ctx, "changing a user"); err != nil {
		return api.User{}, err
	}
	u, err := s.d.DB.Users.GetByName(ctx, name)
	if err != nil {
		return api.User{}, notFound("user", name)
	}
	if expect != AnyGeneration && expect != u.UpdatedAt.UnixMilli() {
		return api.User{}, api.Errorf(api.CodeConflict, "user %q changed: current generation is %d", name, u.UpdatedAt.UnixMilli())
	}
	if in.Metadata.Name != "" && in.Metadata.Name != name {
		return api.User{}, invalid("renaming is not supported")
	}
	if !validPerm(in.Spec.Permission) {
		return api.User{}, invalid("user permission is required")
	}
	if err := canGrant(ctx, in.Spec.Permission); err != nil {
		return api.User{}, err
	}
	if in.Spec.TOTP && !u.TOTPEnabled {
		return api.User{}, invalid("two-factor authentication is enrolled by the user")
	}
	sc, err := s.checkScope(ctx, in.Spec.Projects, in.Spec.Global)
	if err != nil {
		return api.User{}, err
	}
	if in.Spec.Permission != api.PermAdmin || !sc.Global {
		if err := s.keepAdmin(ctx, "user:"+u.Name); err != nil {
			return api.User{}, err
		}
	}
	changed := false
	if sc.Global != u.Global || !slices.Equal(sc.Projects, u.Projects) {
		if err := s.d.DB.Users.SetScope(ctx, u.ID, sc.Projects, sc.Global); err != nil {
			return api.User{}, internal(err)
		}
		changed = true
	}
	if in.Spec.Permission != u.Permission {
		if err := s.d.DB.Users.SetPermission(ctx, u.ID, in.Spec.Permission); err != nil {
			return api.User{}, internal(err)
		}
		changed = true
	}
	if in.Spec.Disabled != u.Disabled {
		if err := s.d.DB.Users.SetDisabled(ctx, u.ID, in.Spec.Disabled); err != nil {
			return api.User{}, internal(err)
		}
		changed = true
	}
	if !in.Spec.TOTP && u.TOTPEnabled {
		if err := s.d.DB.Users.SetTOTP(ctx, u.ID, nil, false); err != nil {
			return api.User{}, internal(err)
		}
		changed = true
	}
	if changed {
		s.emit(ctx, "user-updated", "/api/v1/users/"+name)
	}
	return s.GetUser(ctx, name)
}

// SetUserPassword replaces a user's password without knowing the old one: the recovery path for a global
// administrator (the host's root reaches it over the socket). The user's sessions end. An empty password asks for a
// generated one, returned once.
func (s *Service) SetUserPassword(ctx context.Context, name, password string) (api.PasswordSet, error) {
	if err := requireGlobal(ctx, "setting a user's password"); err != nil {
		return api.PasswordSet{}, err
	}
	u, err := s.d.DB.Users.GetByName(ctx, name)
	if err != nil {
		return api.PasswordSet{}, notFound("user", name)
	}
	var out api.PasswordSet
	if password == "" {
		if password, err = generatePassword(name); err != nil {
			return out, internal(err)
		}
		out.Password = password
	} else if err := auth.CheckPasswordPolicy(password, name); err != nil {
		return out, invalid("%v", err)
	}
	hash, err := auth.HashPassword(password, s.d.PasswordParams)
	if err != nil {
		return api.PasswordSet{}, internal(err)
	}
	if err := s.d.DB.Users.SetPasswordHash(ctx, u.ID, hash); err != nil {
		return api.PasswordSet{}, internal(err)
	}
	s.emit(ctx, "user-updated", "/api/v1/users/"+name)
	return out, nil
}

// DeleteUser removes a user and their sessions.
func (s *Service) DeleteUser(ctx context.Context, name string) error {
	if err := requireGlobal(ctx, "deleting a user"); err != nil {
		return err
	}
	u, err := s.d.DB.Users.GetByName(ctx, name)
	if err != nil {
		return notFound("user", name)
	}
	if err := s.keepAdmin(ctx, "user:"+u.Name); err != nil {
		return err
	}
	if err := s.d.DB.Users.Delete(ctx, u.ID); err != nil {
		return internal(err)
	}
	s.emit(ctx, "user-deleted", "/api/v1/users/"+name)
	return nil
}

// ---- login, sessions, second factor ----

// Session is a freshly created web session.
type Session struct {
	ID        string // cookie value; shown once
	CSRF      string
	User      string
	Perm      api.Permission
	Projects  []string
	Global    bool
	Ref       string
	ExpiresAt time.Time
}

// loginKey is one limiter key of a login attempt and the limiter that holds it.
type loginKey struct {
	lim *auth.Lockout
	key string
}

// loginKeys are the limiter keys of a login: one per user and source (tight: five failures lock that user at that
// source), and one per source alone (ten times looser: it stops one address from trying many users, but several people
// behind one address are not locked out by a stranger's few wrong passwords).
func (s *Service) loginKeys(user, remote string) []loginKey {
	src := auth.SourceKey(remote)
	return []loginKey{{s.login, "u|" + strings.ToLower(user) + "|" + src}, {s.loginIP, "ip|" + src}}
}

var errBadLogin = api.Errorf(api.CodeUnauthorized, "invalid user name or password")

// Login verifies a password (and TOTP when enrolled) and opens a session.
// Every attempt counts toward an exponential lockout per user and source (an IPv6 source is its /64) before the
// password is derived, so a locked source costs no derivation and attempts sent at once cannot pass the threshold
// together; a locked key returns *auth.LockedError. Guesses for one account from many sources are slowed down
// (auth.AccountDelay), and at most auth.DeriveSlots derivations run at once.
func (s *Service) Login(ctx context.Context, user, password, totp, remote string) (Session, error) {
	keys := s.loginKeys(user, remote)
	for i, k := range keys {
		if err := k.lim.Begin(k.key); err != nil {
			for _, b := range keys[:i] {
				b.lim.Abort(b.key)
			}
			return Session{}, err
		}
	}
	decided := false
	defer func() {
		if !decided {
			for _, k := range keys {
				k.lim.Abort(k.key)
			}
		}
	}()
	if err := auth.AdmitDerivation(); err != nil {
		return Session{}, err
	}
	endAcct, err := s.acct.Begin(ctx, strings.ToLower(user))
	if err != nil {
		return Session{}, err
	}
	fail := func() error {
		decided = true
		endAcct(false)
		var locked error
		for _, k := range keys {
			if err := k.lim.End(k.key, false); err != nil && locked == nil {
				locked = err
			}
		}
		if locked != nil {
			return locked
		}
		return errBadLogin
	}
	u, err := s.d.DB.Users.GetByName(ctx, user)
	if err != nil {
		auth.BurnPasswordTime(password, s.d.PasswordParams)
		return Session{}, fail()
	}
	ok, verr := auth.VerifyPassword(password, u.PasswordHash)
	if verr != nil || !ok || u.Disabled {
		return Session{}, fail()
	}
	if u.TOTPEnabled {
		if strings.TrimSpace(totp) == "" {
			// the password was right: not a failure, and the account is not slowed for it
			endAcct(true)
			return Session{}, api.Errorf(api.CodeUnauthorized, "a second factor is required").WithDetail("totp", "required")
		}
		if !s.checkSecondFactor(ctx, u, totp) {
			return Session{}, fail()
		}
	}
	decided = true
	endAcct(true)
	for _, k := range keys {
		_ = k.lim.End(k.key, true)
	}
	_ = s.d.DB.Users.TouchLogin(ctx, u.ID)
	if auth.NeedsRehash(u.PasswordHash, s.d.PasswordParams) {
		if h, err := auth.HashPassword(password, s.d.PasswordParams); err == nil {
			_ = s.d.DB.Users.SetPasswordHash(ctx, u.ID, h) // also ends other sessions
		}
	}
	id, hash, err := auth.NewSessionID()
	if err != nil {
		return Session{}, internal(err)
	}
	csrf, err := auth.NewCSRFToken()
	if err != nil {
		return Session{}, internal(err)
	}
	sess, err := s.d.DB.Sessions.Create(ctx, hash, u.ID, csrf, remote)
	if err != nil {
		return Session{}, internal(err)
	}
	return Session{ID: id, CSRF: csrf, User: u.Name, Perm: u.Permission, Projects: u.Projects, Global: u.Global,
		Ref: store.SessionRef(hash), ExpiresAt: sess.MaxExpires}, nil
}

func (s *Service) checkSecondFactor(ctx context.Context, u *store.User, code string) bool {
	code = strings.TrimSpace(code)
	if len(s.d.SealKey) == auth.SealKeySize && len(u.TOTPSealed) > 0 {
		if secret, err := auth.Unseal(s.d.SealKey, u.TOTPSealed, []byte(u.ID)); err == nil {
			s.totpMu.Lock()
			defer s.totpMu.Unlock()
			key := "totp_last/" + u.ID
			var last int64
			if v, err := s.d.DB.Meta.Get(ctx, key); err == nil {
				last, _ = strconv.ParseInt(v, 10, 64)
			}
			if n, ok := auth.TOTPValidate(secret, code, s.now(), 1, last, auth.TOTPConfig{}); ok {
				_ = s.d.DB.Meta.Set(ctx, key, strconv.FormatInt(n, 10))
				return true
			}
		}
	}
	for _, entry := range u.RecoveryHashes {
		if auth.MatchRecoveryCode(code, entry) {
			ok, _ := s.d.DB.Users.ConsumeRecoveryHash(ctx, u.ID, entry)
			return ok
		}
	}
	return false
}

// AuthenticateSession resolves a session cookie value to its caller and CSRF token.
func (s *Service) AuthenticateSession(ctx context.Context, id, remote string) (Actor, string, error) {
	sess, err := s.d.DB.Sessions.Validate(ctx, auth.HashSessionID(id))
	if err != nil {
		return Actor{}, "", api.Errorf(api.CodeUnauthorized, "the session has expired")
	}
	u, err := s.d.DB.Users.GetByID(ctx, sess.UserID)
	if err != nil || u.Disabled {
		return Actor{}, "", api.Errorf(api.CodeUnauthorized, "the session has expired")
	}
	return Actor{Name: u.Name, Kind: "user", Perm: u.Permission, Remote: remote, Projects: u.Projects, Global: u.Global,
		SessionRef: store.SessionRef(auth.HashSessionID(id))}, sess.CSRF, nil
}

// Logout ends a session.
func (s *Service) Logout(ctx context.Context, id string) error {
	defer s.credGen.Add(1)
	return internal(s.d.DB.Sessions.Delete(ctx, auth.HashSessionID(id)))
}

// SessionInfo describes the current session for the UI.
type SessionInfo struct {
	User       string         `json:"user"`
	Permission api.Permission `json:"permission"`
	TOTP       bool           `json:"totp"`
}

// WhoAmI returns the user record of a session caller.
func (s *Service) WhoAmI(ctx context.Context, name string) (SessionInfo, error) {
	u, err := s.d.DB.Users.GetByName(ctx, name)
	if err != nil {
		return SessionInfo{}, notFound("user", name)
	}
	return SessionInfo{User: u.Name, Permission: u.Permission, TOTP: u.TOTPEnabled}, nil
}

// guard rate-limits an operation that verifies a secret for a signed-in user (the current password, a second
// factor code): too many failures for the user lock it for a while, like login does. The attempt is counted before
// the secret is checked (Begin), so attempts sent at once cannot all pass the threshold together, and it waits for a
// derivation slot like a login does. It returns the function to call with the outcome.
func (s *Service) guard(kind, user string) (done func(ok bool) error, err error) {
	key := kind + "|" + strings.ToLower(user)
	if err := s.login.Begin(key); err != nil {
		return nil, err
	}
	if err := auth.AdmitDerivation(); err != nil {
		s.login.Abort(key)
		return nil, err
	}
	decided := false
	return func(ok bool) error {
		if decided {
			return nil
		}
		decided = true
		return s.login.End(key, ok)
	}, nil
}

// ChangePassword sets a new password after checking the current one; all the
// user's sessions end.
func (s *Service) ChangePassword(ctx context.Context, user, current, next string) error {
	u, err := s.d.DB.Users.GetByName(ctx, user)
	if err != nil {
		return notFound("user", user)
	}
	done, err := s.guard("pw", user)
	if err != nil {
		return err
	}
	ok, _ := auth.VerifyPassword(current, u.PasswordHash)
	if lerr := done(ok); !ok {
		if lerr != nil {
			return lerr
		}
		return api.Errorf(api.CodeUnauthorized, "the current password is wrong")
	}
	if err := auth.CheckPasswordPolicy(next, user); err != nil {
		return invalid("%v", err)
	}
	h, err := auth.HashPassword(next, s.d.PasswordParams)
	if err != nil {
		return internal(err)
	}
	defer s.credGen.Add(1) // the user's other sessions end
	return internal(s.d.DB.Users.SetPasswordHash(ctx, u.ID, h))
}

// TOTPEnrollment is shown once while enrolling.
type TOTPEnrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// StartTOTP creates a pending TOTP secret for the user.
func (s *Service) StartTOTP(ctx context.Context, user, password string) (TOTPEnrollment, error) {
	if len(s.d.SealKey) != auth.SealKeySize {
		return TOTPEnrollment{}, api.Errorf(api.CodeUnsupported, "two-factor authentication needs a seal key")
	}
	u, err := s.d.DB.Users.GetByName(ctx, user)
	if err != nil {
		return TOTPEnrollment{}, notFound("user", user)
	}
	if err := s.confirmPassword(u, password); err != nil {
		return TOTPEnrollment{}, err
	}
	if u.TOTPEnabled {
		return TOTPEnrollment{}, api.Errorf(api.CodeAlreadyExists, "two-factor authentication is already enabled")
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		return TOTPEnrollment{}, internal(err)
	}
	sealed, err := auth.Seal(s.d.SealKey, secret, []byte(u.ID))
	if err != nil {
		return TOTPEnrollment{}, internal(err)
	}
	if err := s.d.DB.Users.SetTOTP(ctx, u.ID, sealed, false); err != nil {
		return TOTPEnrollment{}, internal(err)
	}
	return TOTPEnrollment{Secret: auth.EncodeTOTPSecret(secret), URI: auth.TOTPProvisioningURI("JailOps", u.Name, secret)}, nil
}

// ConfirmTOTP enables the pending secret once a valid code is presented and
// returns recovery codes, shown once.
func (s *Service) ConfirmTOTP(ctx context.Context, user, code string) ([]string, error) {
	u, err := s.d.DB.Users.GetByName(ctx, user)
	if err != nil {
		return nil, notFound("user", user)
	}
	if u.TOTPEnabled || len(u.TOTPSealed) == 0 {
		return nil, invalid("there is no pending two-factor enrollment")
	}
	secret, err := auth.Unseal(s.d.SealKey, u.TOTPSealed, []byte(u.ID))
	if err != nil {
		return nil, internal(err)
	}
	done, err := s.guard("totp", user)
	if err != nil {
		return nil, err
	}
	s.totpMu.Lock()
	n, ok := auth.TOTPValidate(secret, strings.TrimSpace(code), s.now(), 1, 0, auth.TOTPConfig{})
	if lerr := done(ok); !ok {
		s.totpMu.Unlock()
		if lerr != nil {
			return nil, lerr
		}
		return nil, api.Errorf(api.CodeUnauthorized, "the code is not valid")
	}
	s.totpMu.Unlock()
	_ = s.d.DB.Meta.Set(ctx, "totp_last/"+u.ID, strconv.FormatInt(n, 10))
	if err := s.d.DB.Users.SetTOTP(ctx, u.ID, u.TOTPSealed, true); err != nil {
		return nil, internal(err)
	}
	return s.newRecoveryCodes(ctx, u.ID)
}

func (s *Service) newRecoveryCodes(ctx context.Context, id string) ([]string, error) {
	codes, hashes, err := auth.GenerateRecoveryCodes(10)
	if err != nil {
		return nil, internal(err)
	}
	if err := s.d.DB.Users.SetRecoveryHashes(ctx, id, hashes); err != nil {
		return nil, internal(err)
	}
	return codes, nil
}

// RecoveryCodes replaces the recovery codes of a user with TOTP enabled.
func (s *Service) RecoveryCodes(ctx context.Context, user, password string) ([]string, error) {
	u, err := s.d.DB.Users.GetByName(ctx, user)
	if err != nil {
		return nil, notFound("user", user)
	}
	if !u.TOTPEnabled {
		return nil, invalid("recovery codes need two-factor authentication")
	}
	if err := s.confirmPassword(u, password); err != nil {
		return nil, err
	}
	return s.newRecoveryCodes(ctx, u.ID)
}

// DisableTOTP removes the second factor after the password is confirmed.
func (s *Service) DisableTOTP(ctx context.Context, user, password string) error {
	u, err := s.d.DB.Users.GetByName(ctx, user)
	if err != nil {
		return notFound("user", user)
	}
	if err := s.confirmPassword(u, password); err != nil {
		return err
	}
	return internal(s.d.DB.Users.SetTOTP(ctx, u.ID, nil, false))
}

// confirmPassword asks a signed-in user for the password again before a change of the second factor, so that a
// session someone else holds cannot change it. Wrong passwords count toward the user's lockout.
func (s *Service) confirmPassword(u *store.User, password string) error {
	if password == "" {
		return api.Errorf(api.CodeUnauthorized, "the password is required").WithDetail("password", "required")
	}
	done, err := s.guard("pw", u.Name)
	if err != nil {
		return err
	}
	ok, _ := auth.VerifyPassword(password, u.PasswordHash)
	if lerr := done(ok); !ok {
		if lerr != nil {
			return lerr
		}
		return api.Errorf(api.CodeUnauthorized, "the password is wrong")
	}
	return nil
}

// ---- audit ----

// AuditQuery filters the audit log.
type AuditQuery struct {
	Actor    string
	Since    time.Time
	BeforeID int64
	Limit    int
}

// ListAudit returns the audit entries the caller may see, newest first: all of
// them for a global identity, the entries of their projects otherwise, and
// those of the project named in the request when there is one.
func (s *Service) ListAudit(ctx context.Context, q AuditQuery) ([]api.AuditEntry, error) {
	all, projects, err := s.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}
	q.Limit = min(q.Limit, 1000)
	l, err := s.d.DB.Audit.List(ctx, store.AuditFilter{Actor: q.Actor, Since: q.Since, BeforeID: q.BeforeID, Limit: q.Limit,
		ProjectFilter: !all, Projects: projects})
	if err != nil {
		return nil, internal(err)
	}
	out := []api.AuditEntry{}
	for _, e := range l {
		out = append(out, api.AuditEntry{ID: strconv.FormatInt(e.ID, 10), Timestamp: e.Time, Requestor: e.Actor,
			Action: strings.TrimSpace(e.Method + " " + e.Route), Resource: e.Object, Project: e.Project, SourceIP: e.Remote, Result: e.Result, Detail: e.Detail})
	}
	return out, nil
}

// Audit appends one entry (the server records every mutating request).
func (s *Service) Audit(ctx context.Context, e store.AuditEntry) {
	if e.Time.IsZero() {
		e.Time = s.now().UTC()
	}
	if _, err := s.d.DB.Audit.Append(ctx, e); err != nil {
		s.log.Error("audit append failed", "err", err)
	}
}

var _ = fmt.Sprint
