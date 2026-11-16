package server_test

import (
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// Text a client sends reaches an audit detail quoted and cut: a line break, a forged key=value or a long value
// cannot make one entry look like two, or like another result. The request is audited even when it is refused.
func TestAuditDetailEscapesClientText(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	tok := e.Token(api.PermAdmin)
	evil := "192.0.2.1\r\nresult=ok actor=root db=x " + strings.Repeat("A", 500)
	for _, r := range []struct{ path, body string }{
		{"/api/v1/jails/nope/access/deny?project=" + dtest.SeedProject, mustJSON(api.AppDeny{Source: evil})},
		{"/api/v1/jails/nope/access?project=" + dtest.SeedProject, mustJSON(api.AppAllow{Source: evil, Ports: []string{"5432\nx=y"}, Database: "d b"})},
		{"/api/v1/logs/forward/test", mustJSON(api.LogForwardTest{Sink: evil})},
	} {
		if code, _ := e.Raw("POST", r.path, tok, r.body); code < 400 {
			t.Fatalf("%s accepted: %d", r.path, code)
		}
	}
	code, body := e.Raw("GET", "/api/v1/audit?limit=50", tok, "")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var env api.Response
	var entries []api.AuditEntry
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env.Metadata, &entries); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, a := range entries {
		if !strings.Contains(a.Detail, "192.0.2.1") {
			continue
		}
		seen++
		if strings.ContainsAny(a.Detail, "\r\n") || strings.Contains(a.Detail, " result=ok") || len(a.Detail) > 3*250 {
			t.Errorf("%s: detail %q", a.Action, a.Detail)
		}
		if !strings.Contains(a.Detail, `"192.0.2.1\r\nresult=ok actor=root db=x AAAA`) || !strings.Contains(a.Detail, `A"...`) {
			t.Errorf("%s: not quoted and cut: %q", a.Action, a.Detail)
		}
	}
	if seen != 3 {
		t.Errorf("%d of 3 refused requests audited with their detail: %+v", seen, entries)
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
