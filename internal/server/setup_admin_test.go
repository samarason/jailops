package server_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

func rootCtx() context.Context {
	return service.WithActor(context.Background(), service.Actor{Name: "root", Kind: "unix", Perm: api.PermAdmin, Global: true})
}

const testFingerprint = "a3f1c0de0123456789abcdef0123456789abcdef0123456789abcdef01234567"

// Only root on the socket issues a setup token: a local user of the socket is anonymous and is refused, and no
// token file is written for it.
func TestSetupTokenOnlyFromRoot(t *testing.T) {
	e := dtest.New(t, dtest.Options{NoAdmin: true})
	file := filepath.Join(e.Cfg.StateDir, "setup", "token.json")
	for peer, cred := range ordinaryPeers {
		if code, body := serveAs(e, cred, "POST", "/api/v1/setup/token", "", "{}"); code != 401 && code != 403 {
			t.Errorf("%s: %d %s", peer, code, body)
		}
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("a refused request wrote %s: %v", file, err)
	}
	if code, body := serveAs(e, auth.Cred{UID: 0, GID: 0}, "POST", "/api/v1/setup/token", "", "{}"); code != 200 || !strings.Contains(body, `"token"`) {
		t.Fatalf("root: %d %s", code, body)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
}

// A global administrator that is an API token or a client certificate closes the setup like a user does, and the
// setup token issued before it is removed; one that has expired does not count.
func TestSetupClosedByAdminTokenOrCertificate(t *testing.T) {
	for _, kind := range []string{"token", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			var mu sync.Mutex
			now := time.Now()
			e := dtest.New(t, dtest.Options{NoAdmin: true, Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
			s := e.D.Service()
			file := filepath.Join(e.Cfg.StateDir, "setup", "token.json")
			tok, err := s.IssueSetupToken(rootCtx())
			if err != nil {
				t.Fatal(err)
			}
			exp := now.Add(time.Hour)
			switch kind {
			case "token":
				_, err = s.CreateToken(rootCtx(), api.Token{Metadata: api.ObjectMeta{Name: "automation"}, Spec: api.TokenSpec{Permission: api.PermAdmin, Global: true, ExpiresAt: exp}})
			case "certificate":
				_, err = s.CreateCertificate(rootCtx(), api.Certificate{Metadata: api.ObjectMeta{Name: "laptop"}, Spec: api.CertificateSpec{Fingerprint: testFingerprint, Permission: api.PermAdmin, Global: true, ExpiresAt: exp}})
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(file); err != nil {
				t.Fatalf("the token file went before anyone asked: %v", err)
			}
			if code, body := e.Raw("GET", "/api/v1/setup", "", ""); code != 404 {
				t.Errorf("setup status with an admin %s: %d %s", kind, code, body)
			}
			if _, err := os.Stat(file); !os.IsNotExist(err) {
				t.Errorf("the setup token left over was not removed: %v", err)
			}
			if _, err := s.Setup(context.Background(), api.SetupRequest{Token: tok.Token, Name: "late", Password: "a long enough passphrase 42"}, "192.0.2.1"); !api.IsCode(err, api.CodeNotFound) {
				t.Errorf("setup with the old token: %v", err)
			}
			if _, err := s.IssueSetupToken(rootCtx()); !api.IsCode(err, api.CodeNotFound) {
				t.Errorf("a new token: %v", err)
			}
			// expired, it is no administrator: the setup is open again
			mu.Lock()
			now = now.Add(2 * time.Hour)
			mu.Unlock()
			if code, body := e.Raw("GET", "/api/v1/setup", "", ""); code != 200 || !strings.Contains(body, `"required":true`) {
				t.Errorf("after the expiry: %d %s", code, body)
			}
		})
	}
}

// The last global administrator is not deleted or demoted while no other one (a user, a token, a certificate)
// exists; with another one it is.
func TestLastGlobalAdministratorIsKept(t *testing.T) {
	e := dtest.New(t, dtest.Options{NoAdmin: true})
	s := e.D.Service()
	ctx := rootCtx()
	tok, err := s.IssueSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Setup(context.Background(), api.SetupRequest{Token: tok.Token, Name: "admin", Password: "a long enough passphrase 42"}, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	last := func(what string, err error) {
		t.Helper()
		if !api.IsCode(err, api.CodeConflict) || !strings.Contains(err.Error(), "last global administrator") {
			t.Errorf("%s: %v, want the refusal", what, err)
		}
	}
	ok := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	last("delete the only admin", s.DeleteUser(ctx, "admin"))
	_, err = s.UpdateUser(ctx, "admin", api.User{Spec: api.UserSpec{Permission: api.PermOperator, Global: true}}, service.AnyGeneration)
	last("demote it to operator", err)
	if _, err := s.CreateProject(ctx, api.Project{Metadata: api.ObjectMeta{Name: "p"}}); err != nil {
		t.Fatal(err)
	}
	_, err = s.UpdateUser(ctx, "admin", api.User{Spec: api.UserSpec{Permission: api.PermAdmin, Projects: []string{"p"}}}, service.AnyGeneration)
	last("take its global scope", err)
	if _, err := s.UpdateUser(ctx, "admin", api.User{Spec: api.UserSpec{Permission: api.PermAdmin, Global: true, Disabled: true}}, service.AnyGeneration); err != nil {
		t.Errorf("disabling (it still counts, and root re-enables it): %v", err)
	}
	// with an admin token as well, the user may go; then the token is the last one
	_, err = s.CreateToken(ctx, api.Token{Metadata: api.ObjectMeta{Name: "ci"}, Spec: api.TokenSpec{Permission: api.PermAdmin, Global: true}})
	ok("an admin token", err)
	_, err = s.UpdateUser(ctx, "admin", api.User{Spec: api.UserSpec{Permission: api.PermReadonly, Global: true}}, service.AnyGeneration)
	ok("demote the user while a token remains", err)
	last("delete the only admin token", s.DeleteToken(ctx, "ci"))
	_, err = s.CreateCertificate(ctx, api.Certificate{Metadata: api.ObjectMeta{Name: "laptop"}, Spec: api.CertificateSpec{Fingerprint: testFingerprint, Permission: api.PermAdmin, Global: true}})
	ok("an admin certificate", err)
	ok("delete the token while a certificate remains", s.DeleteToken(ctx, "ci"))
	_, err = s.UpdateCertificate(ctx, "laptop", api.Certificate{Spec: api.CertificateSpec{Fingerprint: testFingerprint, Permission: api.PermOperator, Global: true}}, service.AnyGeneration)
	last("demote the only admin certificate", err)
	last("delete the only admin certificate", s.DeleteCertificate(ctx, "laptop", service.AnyGeneration))
	// the operator token of another role does not count
	_, err = s.CreateToken(ctx, api.Token{Metadata: api.ObjectMeta{Name: "ops"}, Spec: api.TokenSpec{Permission: api.PermOperator, Global: true}})
	ok("an operator token", err)
	last("still the last admin", s.DeleteCertificate(ctx, "laptop", service.AnyGeneration))
	if code, _ := e.Raw("GET", "/api/v1/setup", "", ""); code != 404 {
		t.Errorf("the setup opened: %d", code)
	}
}
