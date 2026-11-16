package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/sdk/api"
)

// First-run setup (docs/appliance.md): while no global administrator exists, root issues a one-time setup token
// (POST /api/v1/setup/token, which `jailops-priv setup-token` and the rc script of jailopsd call over the unix
// socket), and whoever holds it creates the first administrator in the console (POST /api/v1/setup). Only the
// SHA-256 of the token is stored, in <state_dir>/setup/token.json; it expires after api.SetupTokenTTL and is gone once
// it was used. Wrong tokens count toward a lockout per source, like failed logins. Once an administrator exists,
// every setup route answers not_found.

const setupLimitKey = "setup|"

// setupTokenFile is the stored hash of the setup token.
type setupTokenFile struct {
	SHA256    string    `json:"sha256"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) setupTokenPath() string { return filepath.Join(s.d.StateDir, "setup", "token.json") }

// adminIdentities lists the global administrators of the host as "user:NAME", "token:NAME" and "certificate:NAME":
// users (disabled ones count: disabling the last one does not open the setup again), and API tokens and client
// certificates that have not expired. Root on the socket is not one of them: it is the host's recovery access.
func (s *Service) adminIdentities(ctx context.Context) ([]string, error) {
	var out []string
	us, err := s.d.DB.Users.List(ctx)
	if err != nil {
		return nil, internal(err)
	}
	for _, u := range us {
		if u.Permission == api.PermAdmin && u.Global {
			out = append(out, "user:"+u.Name)
		}
	}
	now := s.now()
	live := func(exp time.Time) bool { return exp.IsZero() || now.Before(exp) }
	ts, err := s.d.DB.Tokens.List(ctx)
	if err != nil {
		return nil, internal(err)
	}
	for _, t := range ts {
		if t.Permission == api.PermAdmin && t.Global && live(t.ExpiresAt) {
			out = append(out, "token:"+t.Name)
		}
	}
	cs, err := s.certKind.list()
	if err != nil {
		return nil, internal(err)
	}
	for _, c := range cs {
		if c.Spec.Permission == api.PermAdmin && c.Spec.Global && live(c.Spec.ExpiresAt) {
			out = append(out, "certificate:"+c.Meta.Name)
		}
	}
	return out, nil
}

// adminExists reports whether a global administrator exists. When one does, a setup token left over (one issued
// before the administrator was made another way) is removed: it can never be used, and it must not wait on disk.
func (s *Service) adminExists(ctx context.Context) (bool, error) {
	ids, err := s.adminIdentities(ctx)
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		return false, nil
	}
	if err := os.Remove(s.setupTokenPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Error("setup: a setup token left over could not be removed", "err", err)
	}
	return true, nil
}

// keepAdmin refuses a change that removes or demotes the identity drop ("user:NAME", "token:NAME",
// "certificate:NAME") when it is the host's last global administrator: the first-run setup would open again, and
// the setup token every start of jailopsd prints on the console would let whoever reads it create a new one.
func (s *Service) keepAdmin(ctx context.Context, drop string) error {
	ids, err := s.adminIdentities(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(ids, drop) || len(ids) > 1 {
		return nil
	}
	kind, name, _ := strings.Cut(drop, ":")
	return api.Errorf(api.CodeConflict, "%s %q is the last global administrator of this host", kind, name).
		WithHint("make another global administrator first (as root on the host: jailops user create NAME --admin), then change or remove this one")
}

func errSetupDone() error {
	return api.Errorf(api.CodeNotFound, "setup is complete: an administrator exists").
		WithHint("sign in; root resets a lost password with `jailops user set-password NAME`")
}

func (s *Service) readSetupToken() (*setupTokenFile, error) {
	b, err := os.ReadFile(s.setupTokenPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, internal(err)
	}
	var t setupTokenFile
	if err := json.Unmarshal(b, &t); err != nil || len(t.SHA256) != 64 {
		return nil, nil // a broken file is no token: root issues a new one
	}
	return &t, nil
}

// normalSetupToken lets a person type the token with spaces, dashes or in lower case.
func normalSetupToken(t string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(t)))
}

func setupHash(t string) string {
	h := sha256.Sum256([]byte(normalSetupToken(t)))
	return hex.EncodeToString(h[:])
}

// SetupStatus answers GET /api/v1/setup: anyone may ask while no administrator exists.
func (s *Service) SetupStatus(ctx context.Context) (api.SetupStatus, error) {
	if ok, err := s.adminExists(ctx); err != nil || ok {
		if err == nil {
			err = errSetupDone()
		}
		return api.SetupStatus{}, err
	}
	out := api.SetupStatus{Required: true}
	t, err := s.readSetupToken()
	if err != nil {
		return out, err
	}
	if t != nil && s.now().Before(t.ExpiresAt) {
		exp := t.ExpiresAt.UTC()
		out.TokenIssued, out.ExpiresAt = true, &exp
	}
	return out, nil
}

// IssueSetupToken answers POST /api/v1/setup/token (a global administrator: root on the socket before anyone else
// exists). The new token replaces the one before and is returned once.
func (s *Service) IssueSetupToken(ctx context.Context) (api.SetupToken, error) {
	if err := requireGlobal(ctx, "issuing a setup token"); err != nil {
		return api.SetupToken{}, err
	}
	if ok, err := s.adminExists(ctx); err != nil || ok {
		if err == nil {
			err = errSetupDone()
		}
		return api.SetupToken{}, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return api.SetupToken{}, internal(err)
	}
	tok := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	exp := s.now().UTC().Add(api.SetupTokenTTL).Truncate(time.Second)
	b, _ := json.Marshal(setupTokenFile{SHA256: setupHash(tok), ExpiresAt: exp})
	s.setupMu.Lock()
	err := os.MkdirAll(filepath.Dir(s.setupTokenPath()), 0o700)
	if err == nil {
		err = writeFileAtomic(s.setupTokenPath(), b)
	}
	s.setupMu.Unlock()
	if err != nil {
		return api.SetupToken{}, internal(err)
	}
	out := api.SetupToken{Token: tok, ExpiresAt: exp, URLs: []string{}}
	if s.d.ConsoleURLs != nil {
		out.URLs = append(out.URLs, s.d.ConsoleURLs()...)
	}
	if len(out.URLs) == 0 {
		out.Hint = "turn it on with jailopsd_web=\"YES\" in /etc/rc.conf and restart jailopsd (service jailopsd restart)"
	}
	// the token itself never goes to the daemon's log
	s.log.Info("setup token issued: open the console and create the first administrator with it", "valid_until", exp.Format(time.RFC3339), "urls", strings.Join(out.URLs, " "))
	s.emit(ctx, "setup-token-issued", "/api/v1/setup")
	return out, nil
}

var errBadSetupToken = api.Errorf(api.CodeUnauthorized, "the setup token is not valid").
	WithHint("use the token the host printed last (on its console, or in /var/log/auth.log); as root, jailops-priv setup-token prints a new one")

// Setup answers POST /api/v1/setup: the token is the only credential. It creates the first global administrator and
// consumes the token. Wrong, expired and missing tokens get the same answer and count toward the lockout of the
// source; once an administrator exists the answer is not_found.
func (s *Service) Setup(ctx context.Context, in api.SetupRequest, remote string) (api.SetupResult, error) {
	key := setupLimitKey + auth.SourceKey(remote)
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if ok, err := s.adminExists(ctx); err != nil || ok {
		if err == nil {
			err = errSetupDone()
		}
		return api.SetupResult{}, err
	}
	if err := s.setupLim.Check(key); err != nil {
		return api.SetupResult{}, err
	}
	t, err := s.readSetupToken()
	if err != nil {
		return api.SetupResult{}, err
	}
	if t == nil || !s.now().Before(t.ExpiresAt) || subtle.ConstantTimeCompare([]byte(setupHash(in.Token)), []byte(t.SHA256)) != 1 {
		if lerr := s.setupLim.Fail(key); lerr != nil {
			return api.SetupResult{}, lerr
		}
		return api.SetupResult{}, errBadSetupToken
	}
	if in.Password == "" {
		return api.SetupResult{}, invalid("a password is required: the first administrator chooses one")
	}
	sys := WithActor(ctx, Actor{Name: "setup", Kind: "system", Perm: api.PermAdmin, Global: true, Remote: remote})
	created, err := s.CreateUser(sys, api.UserCreate{Metadata: api.ObjectMeta{Name: in.Name},
		Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}, Password: in.Password})
	if err != nil {
		return api.SetupResult{}, err
	}
	s.setupLim.Success(key)
	if err := os.Remove(s.setupTokenPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Error("setup: the used token could not be removed", "err", err)
	}
	s.Audit(sys, store.AuditEntry{Actor: "setup", ActorKind: "system", Method: "POST", Route: "/api/v1/setup",
		Object: "/api/v1/users/" + in.Name, Result: "ok", Remote: remote, Detail: "first administrator created with the setup token"})
	s.log.Info("setup: the first administrator was created; the setup token is used up", "user", in.Name, "remote", remote)
	out := api.SetupResult{User: created.User}
	if !strings.HasPrefix(remote, "unix") {
		out.ClientAddress = remote
	}
	return out, nil
}
