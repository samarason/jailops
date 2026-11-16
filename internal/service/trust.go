package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/sdk/api"
)

// The trust workflow (design 8.2): a global admin asks for a single-use trust
// token bound to a name; the client presents it with its certificate and the
// server records the certificate's fingerprint with the role and the scope the
// token was issued for. No trust on first use, no copying of certificates.

const (
	defaultTrustTTL = time.Hour
	trustLimitKey   = "trust|"
)

// trustKey derives the HMAC key of trust tokens from the seal key, so the
// key never needs a file of its own and never equals the key that seals TOTP
// secrets.
func (s *Service) trustKey() ([]byte, error) {
	if len(s.d.SealKey) < 16 {
		return nil, api.Errorf(api.CodeUnsupported, "trust tokens need the daemon's seal key")
	}
	h := sha256.New()
	h.Write([]byte("jailops-trust-key\x00"))
	h.Write(s.d.SealKey)
	return h.Sum(nil), nil
}

// CreateTrustToken issues a trust token. The token is returned once; only its
// grant (role, scope, expiry) is stored.
func (s *Service) CreateTrustToken(ctx context.Context, req api.TrustTokenRequest) (api.TrustToken, error) {
	if err := requireGlobal(ctx, "issuing a trust token"); err != nil {
		return api.TrustToken{}, err
	}
	name := req.Name
	if err := ValidObjectName(name); err != nil {
		return api.TrustToken{}, err
	}
	if !validPerm(req.Permission) {
		return api.TrustToken{}, invalid("permission is required (readonly, operator, admin, ...)")
	}
	if err := canGrant(ctx, req.Permission); err != nil {
		return api.TrustToken{}, err
	}
	sc, err := s.checkScope(ctx, req.Projects, req.Global)
	if err != nil {
		return api.TrustToken{}, err
	}
	now := s.now().UTC()
	if !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(now) {
		return api.TrustToken{}, invalid("expires_at is in the past")
	}
	ttl := defaultTrustTTL
	if req.TTLSeconds < 0 {
		return api.TrustToken{}, invalid("ttl_seconds must not be negative")
	}
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl > auth.MaxTrustTTL {
		return api.TrustToken{}, invalid("a trust token lives at most %s", auth.MaxTrustTTL)
	}
	fp := s.servingFingerprint()
	if fp == "" {
		return api.TrustToken{}, api.Errorf(api.CodeUnsupported, "this daemon has no server certificate to pin")
	}
	if s.certKind.exists(name) {
		return api.TrustToken{}, api.Errorf(api.CodeAlreadyExists, "certificate %q already exists", name)
	}
	key, err := s.trustKey()
	if err != nil {
		return api.TrustToken{}, err
	}
	tok, claims, err := auth.NewTrustToken(key, name, fp, ttl, now)
	if err != nil {
		return api.TrustToken{}, err
	}
	rec := store.TrustToken{ID: claims.ID, Name: name, Permission: req.Permission, Projects: sc.Projects, Global: sc.Global,
		CertExpiresAt: req.ExpiresAt.UTC(), ExpiresAt: time.Unix(claims.Expires, 0).UTC(), CreatedAt: now, CreatedBy: ActorFrom(ctx).Name}
	if err := s.d.DB.TrustTokens.Create(ctx, rec); err != nil {
		return api.TrustToken{}, internal(err)
	}
	s.emit(ctx, "trust-token-created", "/api/v1/trust/tokens/"+name)
	return api.TrustToken{Name: name, Token: tok, ExpiresAt: rec.ExpiresAt}, nil
}

// RedeemTrustToken is POST /api/v1/trust/clients: the caller is not
// authenticated, the token is the only credential. Every failure of the token
// is the same unauthorized answer, failures are counted per source and
// locked out, and the token is consumed atomically, so it works once.
func (s *Service) RedeemTrustToken(ctx context.Context, req api.TrustClientRequest, remote string) (api.Certificate, error) {
	key := trustLimitKey + auth.SourceKey(remote)
	if err := s.trustLim.Check(key); err != nil {
		return api.Certificate{}, err
	}
	fail := func(err error) (api.Certificate, error) {
		if lerr := s.trustLim.Fail(key); lerr != nil {
			return api.Certificate{}, lerr
		}
		return api.Certificate{}, err
	}
	block, _ := pem.Decode([]byte(req.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return api.Certificate{}, invalid("certificate must be one PEM encoded CERTIFICATE")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return api.Certificate{}, invalid("certificate: %v", err)
	}
	now := s.now().UTC()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return api.Certificate{}, invalid("the certificate is outside its validity period")
	}
	fp := auth.CertFingerprint(leaf)
	hmacKey, err := s.trustKey()
	if err != nil {
		return api.Certificate{}, err
	}
	claims, err := auth.VerifyTrustToken(hmacKey, req.Token, s.d.ServerFingerprint, now)
	if err != nil {
		return fail(err)
	}
	grant, err := s.d.DB.TrustTokens.Get(ctx, claims.ID)
	if err != nil || grant.Name != claims.Name || !grant.ConsumedAt.IsZero() {
		return fail(store.ErrTrustTokenUnusable)
	}
	// Refuse before the token is spent when the certificate cannot be recorded.
	if _, ok := s.CertActor(fp, remote); ok {
		return api.Certificate{}, api.Errorf(api.CodeAlreadyExists, "this certificate is already trusted")
	}
	if s.certKind.exists(grant.Name) {
		return api.Certificate{}, api.Errorf(api.CodeAlreadyExists, "certificate %q already exists", grant.Name)
	}
	grant, err = s.d.DB.TrustTokens.Consume(ctx, claims.ID, fp, now)
	if err != nil {
		return fail(err)
	}
	s.trustLim.Success(key)
	sys := WithActor(ctx, Actor{Name: "trust:" + grant.Name, Kind: "system", Perm: api.PermAdmin, Global: true, Remote: remote})
	o, err := s.certKind.create(sys, api.ObjectMeta{Name: grant.Name, Labels: map[string]string{"jailops.trust": "token"}}, api.CertificateSpec{
		Fingerprint: fp, Permission: grant.Permission, Kind: "client", Projects: grant.Projects, Global: grant.Global, ExpiresAt: grant.CertExpiresAt})
	if err != nil {
		return api.Certificate{}, err
	}
	s.warmCerts()
	s.Audit(sys, store.AuditEntry{Actor: "trust:" + grant.Name, ActorKind: "certificate", Method: "POST", Route: "/api/v1/trust/clients",
		Object: "/api/v1/certificates/" + grant.Name, Result: "ok", Remote: remote, Detail: "trust token consumed for " + fp[:12]})
	return certToAPI(o), nil
}

// PruneTrust removes expired trust tokens and expired certificate entries'
// stale sessions; the daemon calls it with the other housekeeping.
func (s *Service) PruneTrust(ctx context.Context) {
	_, _ = s.d.DB.TrustTokens.PruneExpired(ctx, s.now().Add(-24*time.Hour))
}

// ---- sessions ----

func sessionToAPI(si store.SessionInfo, current string) api.Session {
	return api.Session{ID: si.Ref, User: si.UserName, Remote: si.Remote, CreatedAt: si.CreatedAt, LastSeen: si.LastSeen,
		ExpiresAt: minTime(si.IdleExpires, si.MaxExpires), Current: si.Ref == current}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// isGlobalAdmin reports a global identity with the admin role: only it may see and end other users' sessions.
func isGlobalAdmin(a Actor) bool { return a.Global && a.Perm.Satisfies(api.PermAdmin) }

// ListSessions lists the caller's sessions; a global admin sees every session.
func (s *Service) ListSessions(ctx context.Context) ([]api.Session, error) {
	a := ActorFrom(ctx)
	l, err := s.d.DB.Sessions.List(ctx)
	if err != nil {
		return nil, internal(err)
	}
	out := []api.Session{}
	for _, si := range l {
		if isGlobalAdmin(a) || (a.Kind == "user" && si.UserName == a.Name) {
			out = append(out, sessionToAPI(si, a.SessionRef))
		}
	}
	return out, nil
}

// RevokeSession ends a session: the caller's own, or any for a global admin.
// Someone else's session is not_found.
func (s *Service) RevokeSession(ctx context.Context, id string) error {
	a := ActorFrom(ctx)
	l, err := s.d.DB.Sessions.List(ctx)
	if err != nil {
		return internal(err)
	}
	for _, si := range l {
		if si.Ref != id {
			continue
		}
		if !isGlobalAdmin(a) && !(a.Kind == "user" && si.UserName == a.Name) {
			break
		}
		if _, err := s.d.DB.Sessions.DeleteByRef(ctx, id); err != nil {
			return internal(err)
		}
		s.emit(ctx, "session-revoked", "/api/v1/sessions/"+id)
		return nil
	}
	return notFound("session", id)
}
