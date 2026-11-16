package cli_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// Who may connect to an installed app: allow, again, rotate, access, deny, and
// the refusals of the server, as a person sees them; the password is in the
// allow output only.
func TestAppAccess(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	tr := h.transcript()
	tr.ok("app", "install", "postgresql", "db", "--image", "freebsd-151@stable")
	tr.ok("app", "install", "nginx", "web", "--image", "freebsd-151@stable")
	tr.ok("app", "access")
	tr.ok("app", "allow", "db", "--from", "jail:web", "--dry-run")
	out := tr.ok("app", "allow", "db", "--from", "jail:web")
	pw := regexp.MustCompile(`postgres://web:([A-Za-z0-9]{32})@`).FindStringSubmatch(out)
	if pw == nil {
		t.Fatalf("no connection string: %s", out)
	}
	tr.ok("app", "allow", "db", "--from", "jail:web")
	tr.ok("app", "allow", "db", "--from", "jail:web", "--rotate")
	tr.ok("app", "allow", "db", "--from", "192.0.2.0/24", "--db", "shop")
	tr.ok("app", "allow", "web", "--from", "host")
	tr.ok("app", "allow", "web", "--from", "198.51.100.7", "--port", "80", "--port", "443")
	tr.ok("app", "access")
	tr.ok("app", "access", "db")
	tr.ok("app", "deny", "db", "--from", "jail:web", "--dry-run")
	tr.ok("app", "deny", "db", "--from", "jail:web")
	tr.ok("app", "deny", "db", "--from", "jail:web")
	tr.ok("app", "deny", "db", "--from", "192.0.2.0/24", "--drop-role", "-y")
	tr.do("", "app", "allow", "db", "--from", "192.0.2.0/24")
	tr.do("", "app", "allow", "db", "--from", "jail:nobody")
	tr.do("", "app", "allow", "db", "to", "jail:web")
	tr.do("", "app", "allow", "db")
	tr.do("", "app", "allow", "missing", "--from", "jail:web")
	tr.golden("app_access")

	// the password was shown once: nothing reads it back
	for _, args := range [][]string{{"app", "access", "db", "-o", "json"}, {"app", "access", "-o", "yaml"}, {"app", "access", "web"}} {
		o, _, code := h.run("", args...)
		if code != 0 || strings.Contains(o, pw[1]) {
			t.Fatalf("%v: %d %s", args, code, o)
		}
	}
	o, _, code := h.run("", "app", "allow", "db", "--from", "jail:web", "-o", "json")
	var res api.AppAllowResult
	if code != 0 || json.Unmarshal([]byte(o), &res) != nil || res.Grant.Source != "jail:web" || !strings.HasPrefix(res.ConnectionString, "postgres://web:") {
		t.Fatalf("%d %s", code, o)
	}
}

// SOURCE completes in two levels: the kinds (jail:, set:, host), then the jails or the address sets of the project;
// APP from the installed apps; the word in between is from.
func TestAppAccessCompletion(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	for _, args := range [][]string{
		{"app", "install", "postgresql", "db", "--image", "freebsd-151@stable"},
		{"app", "install", "nginx", "web", "--image", "freebsd-151@stable"},
		{"firewall", "address-set", "create", "office", "--address", "198.51.100.0/24"},
	} {
		if o, e, code := h.run("", args...); code != 0 {
			t.Fatalf("%v: %s %s", args, o, e)
		}
	}
	for _, c := range []struct {
		args       []string
		want, none []string
	}{
		{[]string{"app", "allow", ""}, []string{"db", "web"}, []string{"--from"}},
		{[]string{"app", "allow", "db", "--from", ""}, []string{"jail:", "set:", "host"}, []string{"db"}},
		{[]string{"app", "allow", "db", "--from", ""}, []string{"jail:", "set:", "host"}, []string{"tag:", "any", "jail:web", "@web"}},
		{[]string{"app", "allow", "db", "--from", "j"}, []string{"jail:"}, []string{"set:", "host"}},
		{[]string{"app", "allow", "db", "--from", "jail:"}, []string{"jail:web"}, []string{"jail:db", "set:office"}},
		{[]string{"app", "allow", "db", "--from", "set:"}, []string{"set:office"}, []string{"jail:web"}},
		{[]string{"app", "deny", "web", "--from", "jail:"}, []string{"jail:db"}, []string{"jail:web"}},
		{[]string{"app", "access", ""}, []string{"db", "web"}, []string{"--from"}},
		{[]string{"firewall", "address-set", "create", "pg_allow", "--address", ""}, []string{"jail:", "set:"}, []string{"host", "tag:", "any"}},
		{[]string{"firewall", "address-set", "create", "pg_allow", "--address", "jail:"}, []string{"jail:web", "jail:db"}, []string{"set:office"}},
		{[]string{"firewall", "address-set", "create", "pg_allow", "--address", "set:"}, []string{"set:office"}, nil},
		{[]string{"firewall", "address-set", "create", "office", "--address", "set:"}, nil, []string{"set:office"}},
	} {
		out, _, code := h.run("", append([]string{"__complete"}, c.args...)...)
		lines := strings.Split(out, "\n")
		has := func(s string) bool {
			for _, l := range lines {
				if l == s {
					return true
				}
			}
			return false
		}
		if code != 0 {
			t.Fatalf("%v: %d", c.args, code)
		}
		for _, w := range c.want {
			if !has(w) {
				t.Errorf("complete %v: %q missing in %q", c.args, w, out)
			}
		}
		for _, w := range c.none {
			if has(w) {
				t.Errorf("complete %v: %q offered in %q", c.args, w, out)
			}
		}
	}
}
