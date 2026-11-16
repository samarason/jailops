package server_test

import (
	"fmt"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// Request bodies are strict: a member the type does not know (a misspelled option above all), a member in other
// cases, a member twice and data after the value are refused with invalid, and the message names the member.
func TestRequestBodiesAreStrict(t *testing.T) {
	e := seeded(t)
	tok := e.Token(api.PermAdmin)
	sets := "/api/v1/firewall/address-sets?project=" + dtest.SeedProject
	for _, c := range []struct{ name, method, path, body, want string }{
		{"unknown member", "POST", sets, `{"metadata":{"name":"unk"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]},"bogus":{"x":1}}`, `unknown member \"bogus\"`},
		{"unknown nested member", "POST", sets, `{"metadata":{"name":"unk","nmae":"x"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}}`, `unknown member \"metadata.nmae\"`},
		{"duplicate member", "POST", sets, `{"metadata":{"name":"dupa","name":"dupb"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}}`, `member \"metadata.name\" appears twice`},
		{"trailing data", "POST", sets, `{"metadata":{"name":"trail"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}} GARBAGE`, "after the JSON value"},
		{"two values", "POST", sets, `{"metadata":{"name":"two"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}}{}`, "after the JSON value"},
		{"other cases", "POST", sets, `{"METADATA":{"name":"fold"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}}`, `the name is \"metadata\"`},
		{"misspelled dry_run", "PUT", "/api/v1/host/identity", `{"spec":{"hostname":"h1"},"dryrun":true}`, `unknown member \"dryrun\"`},
		{"deep nesting", "POST", sets, strings.Repeat("[", 5000), "nested deeper"},
		{"misspelled exec option", "POST", "/api/v1/jails/web/console?project=" + dtest.SeedProject, `{"argv":["id"],"tty":true,"usr":"root"}`, `unknown member \"usr\"`},
	} {
		code, body := rawDo(t, e, c.method, c.path, tok, c.body, nil)
		if code != 400 || errorCode(body) != string(api.CodeInvalid) || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s", c.name, code, trunc(body))
		}
	}
	// an object read and sent back carries its status, which is ignored; maps take any key
	ok := `{"metadata":{"name":"ok","labels":{"Any.Key":"v"}},"spec":{"addresses":[{"address":"10.0.0.0/8"}]},"status":{"whatever":1}}`
	if code, body := rawDo(t, e, "POST", sets, tok, ok, nil); code != 201 {
		t.Errorf("status member: %d %s", code, body)
	}
	if code, body := rawDo(t, e, "PATCH", "/api/v1/firewall/address-sets/ok?project="+dtest.SeedProject, tok, `{"spec":{"anything":true}}`, map[string]string{"Content-Type": "application/merge-patch+json"}); code == 400 && strings.Contains(body, "unknown member") {
		t.Errorf("a merge patch is checked like a typed body: %s", body)
	}
}

// Labels have a charset, a size and a count; descriptions and comments refuse control and invisible characters.
// What JailOps itself sets (the app labels) passes the same rules.
func TestLabelsAndFreeTextAreChecked(t *testing.T) {
	e := seeded(t)
	tok := e.Token(api.PermAdmin)
	sets := "/api/v1/firewall/address-sets?project=" + dtest.SeedProject
	set := func(name, labels string) string {
		return `{"metadata":{"name":"` + name + `","labels":{` + labels + `}},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}}`
	}
	many := make([]string, api.MaxLabels+1)
	for i := range many {
		many[i] = fmt.Sprintf(`"k%d":"v"`, i)
	}
	for _, c := range []struct{ name, body string }{
		{"escape in a value", set("c1", `"k":"\u001b]0;pwned\u0007\u001b[2J"`)},
		{"NUL in a value", set("c2", `"k":"a\u0000b"`)},
		{"bidi override in a value", set("c3", `"k":"abc\u202edef"`)},
		{"zero width in a value", set("c4", `"k":"ab\u200bc"`)},
		{"escape in a key", set("c5", `"\u001b[31mk":"v"`)},
		{"space in a key", set("c6", `"a b":"v"`)},
		{"key ends with a dot", set("c7", `"a.":"v"`)},
		{"long key", set("c8", `"`+strings.Repeat("k", 64)+`":"v"`)},
		{"long value", set("c9", `"k":"`+strings.Repeat("x", api.MaxLabelValue+1)+`"`)},
		{"too many labels", set("c10", strings.Join(many, ","))},
	} {
		if code, body := rawDo(t, e, "POST", sets, tok, c.body, nil); code != 400 || errorCode(body) != string(api.CodeInvalid) {
			t.Errorf("%s: %d %s", c.name, code, trunc(body))
		}
	}
	for _, c := range []struct{ name, body string }{
		{"app labels", set("ok1", `"jailops.app":"postgresql","jailops.app.hash":"sha256-abc","jailops.app.version":"16.4_1"`)},
		{"prefixed key and text value", set("ok2", `"example.org/tier":"front end, café","Env_1":""`)},
	} {
		if code, body := rawDo(t, e, "POST", sets, tok, c.body, nil); code != 201 {
			t.Errorf("%s: %d %s", c.name, code, trunc(body))
		}
	}
	for _, c := range []struct{ name, method, path, body string }{
		{"project comment", "POST", "/api/v1/projects", `{"metadata":{"name":"pctl"},"spec":{"comment":"\u001b]52;c;cHduZWQ=\u0007"}}`},
		{"long project comment", "POST", "/api/v1/projects", `{"metadata":{"name":"plong"},"spec":{"comment":"` + strings.Repeat("d", api.MaxFreeText+1) + `"}}`},
		{"project comment of two lines", "POST", "/api/v1/projects", `{"metadata":{"name":"p2l"},"spec":{"comment":"two lines\nand a tab\there"}}`},
		{"snapshot comment", "POST", "/api/v1/jails/web/snapshots?project=" + dtest.SeedProject, `{"comment":"\u001b[2J"}`},
	} {
		if c.path != "/api/v1/projects" {
			mustJail(t, e, "web")
		}
		if code, body := rawDo(t, e, c.method, c.path, tok, c.body, nil); code != 400 || errorCode(body) != string(api.CodeInvalid) {
			t.Errorf("%s: %d %s", c.name, code, trunc(body))
		}
	}
	if code, body := rawDo(t, e, "POST", "/api/v1/projects", tok, `{"metadata":{"name":"pok"},"spec":{"comment":"one line, with a café"}}`, nil); code != 201 {
		t.Errorf("a comment of one line: %d %s", code, body)
	}
}
