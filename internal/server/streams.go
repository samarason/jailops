package server

import (
	"slices"
	"strings"
	"sync"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// Long requests (the event stream, a console's output, an exec session) outlive the moment their credential was
// checked. They check it again at every keepalive tick and end when the token, user, session or certificate was
// deleted, disabled or changed in role or scope since the request began.

// maxStreamsPerIdentity bounds the open event streams of one identity.
const maxStreamsPerIdentity = 16

// streamCounter counts the open event streams per identity.
type streamCounter struct {
	mu sync.Mutex
	n  map[string]int
}

// acquire takes a slot for key and returns its release, or rate_limited when the identity holds its maximum.
func (sc *streamCounter) acquire(key string) (func(), error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.n == nil {
		sc.n = map[string]int{}
	}
	if sc.n[key] >= maxStreamsPerIdentity {
		return nil, api.Errorf(api.CodeRateLimited, "this identity already has %d event streams open", maxStreamsPerIdentity).
			WithHint("close one first")
	}
	sc.n[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			sc.mu.Lock()
			defer sc.mu.Unlock()
			if sc.n[key]--; sc.n[key] <= 0 {
				delete(sc.n, key)
			}
		})
	}, nil
}

// identityKey names the identity of a request: the kind of credential and its name.
func identityKey(a service.Actor) string { return a.Kind + ":" + a.Name }

// stillAuthorized checks the credential of a long request again: it must still authenticate the same identity with
// the same role and scope. Root on the socket and a forwarded hub claim keep the check of their certificate or peer.
func (s *Server) stillAuthorized(c *rc) bool {
	r := c.r
	ctx := r.Context()
	remote, ip := remoteAddr(r)
	var now service.Actor
	switch c.method {
	case "unix":
		return true
	case "cert", "hub":
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return false
		}
		a, ok := s.svc.CertActor(auth.CertFingerprint(r.TLS.PeerCertificates[0]), remote)
		if !ok {
			return false
		}
		if c.method == "hub" {
			// the claim was checked when the request began; the hub's own certificate must still be trusted
			return a.Kind == "hub"
		}
		now = a
	case "token":
		h := r.Header.Get("Authorization")
		_, tok, _ := strings.Cut(h, " ")
		a, err := s.svc.AuthenticateToken(ctx, strings.TrimSpace(tok), ip)
		if err != nil {
			return false
		}
		now = a
	case "session":
		id, ok := auth.SessionIDFromRequest(r)
		if !ok {
			return false
		}
		a, _, err := s.svc.AuthenticateSession(ctx, id, remote)
		if err != nil {
			return false
		}
		now = a
	default:
		// anonymous requests never reach a long route
		return false
	}
	was := c.actor
	return now.Name == was.Name && now.Kind == was.Kind && now.Perm == was.Perm && now.Global == was.Global &&
		slices.Equal(now.Projects, was.Projects)
}
