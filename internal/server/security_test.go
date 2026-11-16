package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/server"
	"jailops.net/jailops/sdk/api"
)

func TestAuditTrail(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	// A denied and a failed mutation.
	op := e.Client(api.PermOperator)
	if _, err := op.Networks().Create(c, dtest.LAN()); !api.IsCode(err, api.CodeForbidden) {
		t.Fatal(err)
	}
	if _, err := e.Admin.Networks().Create(c, dtest.LAN()); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatal(err)
	}
	entries, err := e.Global().Audit(c, 200)
	if err != nil {
		t.Fatal(err)
	}
	var created, denied, failed, opdone bool
	for _, en := range entries {
		if en.Requestor == "" || en.Timestamp.IsZero() || en.ID == "" {
			t.Fatalf("incomplete entry %+v", en)
		}
		switch {
		case en.Action == "POST /api/v1/jails" && en.Result == "ok" && en.Resource == "/api/v1/jails/web":
			created = true
		case en.Action == "POST /api/v1/networks" && en.Result == "denied" && strings.HasPrefix(en.Requestor, "t-operator"):
			denied = true
		case en.Action == "POST /api/v1/networks" && en.Result == "error" && strings.HasPrefix(en.Requestor, "t-admin"):
			failed = true
		case strings.HasPrefix(en.Action, "OPERATION") && strings.Contains(en.Detail, "Create jail web") && en.Result == "ok":
			opdone = true
		}
	}
	if !created || !denied || !failed || !opdone {
		t.Fatalf("created=%v denied=%v failed=%v op=%v\n%+v", created, denied, failed, opdone, entries)
	}
	// Reads are not audited; only admins read the log.
	if _, err := op.Audit(c, 10); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("%v", err)
	}
	for _, en := range entries {
		if en.Action == "GET /api/v1/jails" {
			t.Fatalf("a read was audited: %+v", en)
		}
	}
}

var tokenShape = regexp.MustCompile(`jo[tj]_[A-Za-z0-9]{16,}`)

func TestSecretsNeverLeak(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	tok, err := e.Admin.Tokens().Create(c, api.Token{Metadata: api.ObjectMeta{Name: "leaky"}, Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	made, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	chosen := "Ch0sen-Password-xyz"
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "bob"}, Spec: api.UserSpec{Permission: api.PermReadonly, Global: true}, Password: chosen}); err != nil {
		t.Fatal(err)
	}
	hc := jarClient(t)
	st, out := login(t, e, hc, "ann", made.Password, "")
	if st != 200 {
		t.Fatal(st)
	}
	csrf, _ := out["csrf"].(string)
	var sessionID string
	for _, ck := range hc.Jar.Cookies(mustURL(e.HTTP.URL)) {
		if strings.Contains(ck.Name, "session") {
			sessionID = ck.Value
		}
	}
	// A failed login, a bad token and a token in the query string.
	login(t, e, nil, "ann", "wrong-password-value", "")
	e.Raw("GET", "/api/v1/jails?project=alpha", "jot_"+strings.Repeat("z", 52), "")
	req, _ := http.NewRequest("GET", e.HTTP.URL+"/api/v1/events?access_token="+tok.Secret, nil)
	ectx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	if resp, err := http.DefaultClient.Do(req.WithContext(ectx)); err == nil {
		resp.Body.Close()
	}
	cancel()
	time.Sleep(2 * time.Second) // the access log line is written when the stream ends (a slow CI machine takes its time)

	// Everything that can be read back.
	var all strings.Builder
	for _, p := range []string{"/api/v1/tokens", "/api/v1/tokens/leaky", "/api/v1/users", "/api/v1/users/ann", "/api/v1/users/bob", "/api/v1/audit?limit=500", "/api/v1/operations", "/api/v1/auth/session"} {
		code, body := e.Raw("GET", p, e.Token(api.PermAdmin), "")
		if code != 200 {
			t.Fatalf("%s: %d %s", p, code, body)
		}
		all.WriteString(body)
	}
	events := e.Raw
	_ = events
	code, body := e.RawHdr("GET", "/api/v1/doctor", e.Token(api.PermAdmin), "", nil)
	if code != 200 {
		t.Fatal(code)
	}
	all.WriteString(body)
	readback := all.String()
	logs := e.Log()
	secrets := map[string]string{"token secret": tok.Secret, "generated password": made.Password, "chosen password": chosen, "session id": sessionID, "csrf token": csrf}
	for what, s := range secrets {
		if s == "" {
			t.Fatalf("no %s captured", what)
		}
		if strings.Contains(readback, s) {
			t.Errorf("%s appears in a response", what)
		}
		if strings.Contains(logs, s) {
			t.Errorf("%s appears in the log", what)
		}
	}
	for _, needle := range []string{"$argon2", "password_hash", "PasswordHash", "totp_sealed"} {
		if strings.Contains(readback, needle) || strings.Contains(logs, needle) {
			t.Errorf("%q leaked", needle)
		}
	}
	// No credential-shaped string at all in the log, except none.
	if m := tokenShape.FindString(logs); m != "" {
		t.Errorf("token-shaped string in the log: %s", m)
	}
	if !strings.Contains(logs, "[redacted]") {
		t.Error("the query token was not redacted in the access log")
	}
	// The audit log holds no bodies.
	entries, _ := e.Admin.Audit(c, 500)
	b, _ := json.Marshal(entries)
	for what, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Errorf("%s in the audit log", what)
		}
	}
}

func mustURL(s string) *urlT { u, _ := parseURL(s); return u }

func TestLoggerRedaction(t *testing.T) {
	var buf bytes.Buffer
	l := server.NewLogger(&buf, "text", slog.LevelDebug)
	secret := "jot_" + strings.Repeat("q", 52)
	l.Info("got "+secret, "password", "hunter2", "note", "has "+secret+" inside", "token_name", "ci",
		slog.Group("req", slog.String("authorization", "Bearer "+secret), slog.String("method", "GET")), "err", errString("failed with "+secret))
	l.With("cookie", "abc").Warn("ok")
	out := buf.String()
	for _, bad := range []string{secret, "hunter2", "abc"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q leaked: %s", bad, out)
		}
	}
	if !strings.Contains(out, "method=GET") {
		t.Errorf("ordinary fields were lost: %s", out)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// Two networks may not share addresses, whatever their projects.
func TestOverlappingNetworkIsRefused(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	n := dtest.LAN()
	n.Metadata.Name = "other"
	n.Spec.IPv4 = &api.IPv4Net{Subnet: "10.20.0.128/25", Gateway: "10.20.0.129", Range: "10.20.0.130-10.20.0.140"}
	if _, err := e.Admin.Networks().Create(c, n); !api.IsCode(err, api.CodeConflict) || !strings.Contains(err.Error(), `network "lan"`) {
		t.Fatalf("%v", err)
	}
	n.Spec.IPv4 = &api.IPv4Net{Subnet: "10.99.0.0/24", Gateway: "10.99.0.1", Range: "10.99.0.2-10.99.0.9"}
	if _, err := e.Admin.Networks().Create(c, n); err != nil {
		t.Fatal(err)
	}
}

// The jail's anti-spoofing table holds its own link-local address (formed from the MAC JailOps sets), not fe80::/10.
func TestJailAnchorHoldsTheJailsOwnLinkLocalAddress(t *testing.T) {
	e := seeded(t)
	startJailIn(t, e.Admin, dtest.WebJailOn("ll1", "lan"))
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_ll1.conf")
	m := regexp.MustCompile(`table <jail_addrs> persist \{ ([^}]*) \}`).FindStringSubmatch(rs)
	if m == nil {
		t.Fatalf("no table:\n%s", rs)
	}
	if strings.Contains(m[1], "fe80::/10") || !strings.Contains(m[1], "fe80::") {
		t.Errorf("table %q must hold the jail's own link-local address and not the whole range", m[1])
	}
}

// A token in the query string authenticates nothing on the upgrade of an exec session or on a console route either:
// clients send it in the Authorization header (the SDK does for exec), the web console uses its session cookie.
func TestQueryTokenOnExecAndConsoleIsRefused(t *testing.T) {
	e := seeded(t)
	mustJail(t, e, "web")
	tok := e.Token(api.PermAdmin)
	up := map[string]string{"Connection": "Upgrade", "Upgrade": api.ExecProtocol}
	for _, q := range []string{"token", "access_token"} {
		if code, body := e.RawHdr("POST", "/api/v1/jails/web/exec?project=alpha&"+q+"="+tok, "", `{"argv":["id"]}`, up); code != http.StatusUnauthorized {
			t.Errorf("exec with ?%s=: %d %s", q, code, body)
		}
		for _, m := range []string{"GET", "POST"} {
			if code, body := e.RawHdr(m, "/api/v1/jails/web/console?project=alpha&"+q+"="+tok, "", "", nil); code != http.StatusUnauthorized {
				t.Errorf("%s console with ?%s=: %d %s", m, q, code, body)
			}
		}
	}
	// the same token in the header is accepted (the exec itself answers 101 or an ordinary error, never 401)
	if code, body := e.RawHdr("GET", "/api/v1/jails/web/console?project=alpha", tok, "", nil); code == http.StatusUnauthorized {
		t.Errorf("console with the header: %d %s", code, body)
	}
}
