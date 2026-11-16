package server_test

import (
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// What a failing doctor check says can be a raw error with the host's paths: a global administrator reads it, a
// global reader gets the status without the text.
func TestDoctorShowsRawErrorsToAdministratorsOnly(t *testing.T) {
	e := seeded(t)
	report := func(tok string) api.DoctorReport {
		code, body := rawDo(t, e, "GET", "/api/v1/doctor", tok, "", nil)
		var env struct{ Metadata api.DoctorReport }
		if code != 200 || json.Unmarshal([]byte(body), &env) != nil {
			t.Fatalf("%d %s", code, trunc(body))
		}
		return env.Metadata
	}
	admin, ro := report(e.Token(api.PermAdmin)), report(e.IdentityToken(api.PermReadonly, true))
	// the configuration directory of the test does not exist: a warning with the raw error of stat
	raw := ""
	for _, c := range admin.Checks {
		if c.Name == "conf.dir" {
			raw = c.Message
		}
	}
	if !strings.Contains(raw, "/etc/jailops/jails") {
		t.Fatalf("the admin's conf.dir check: %q", raw)
	}
	if len(ro.Checks) != len(admin.Checks) || ro.Status != admin.Status {
		t.Fatalf("a reader's report differs in its checks: %d/%d %s/%s", len(ro.Checks), len(admin.Checks), ro.Status, admin.Status)
	}
	for _, c := range ro.Checks {
		if c.Status != api.DoctorOK && c.Status != api.DoctorInfo && (strings.Contains(c.Message, "/") || c.Hint != "" || len(c.Detail) > 0) {
			t.Errorf("a reader sees %s: %q %q %v", c.Name, c.Message, c.Hint, c.Detail)
		}
	}
}

// A caller that proved nothing learns the API version, the extensions and the role, not the host's name, id,
// software version or pool.
func TestAnonymousServerInfoIsMinimal(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	code, body := rawDo(t, e, "GET", "/api/v1", "", "", nil)
	var env struct{ Metadata map[string]any }
	if code != 200 || json.Unmarshal([]byte(body), &env) != nil {
		t.Fatalf("%d %s", code, body)
	}
	for k := range env.Metadata {
		switch k {
		case "api_version", "api_extensions", "role", "auth", "environment", "version", "host_uuid", "hostname":
		default:
			t.Errorf("anonymous answer carries %q", k)
		}
	}
	if env.Metadata["auth"] != "untrusted" || env.Metadata["hostname"] != "" || env.Metadata["host_uuid"] != "" || env.Metadata["version"] != "" ||
		len(env.Metadata["api_extensions"].([]any)) == 0 || strings.Contains(body, "tank") || strings.Contains(body, "testhost") {
		t.Errorf("anonymous answer: %s", body)
	}
	code, body = rawDo(t, e, "GET", "/api/v1", e.Token(api.PermReadonly), "", nil)
	if code != 200 || !strings.Contains(body, `"hostname":"testhost"`) || !strings.Contains(body, `"pool":"tank"`) {
		t.Errorf("trusted answer: %d %s", code, body)
	}
}
