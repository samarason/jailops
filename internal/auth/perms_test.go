package auth

import (
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestPermsTableWellFormed(t *testing.T) {
	reg, err := NewRegistry(Perms)
	if err != nil {
		t.Fatal(err)
	}
	if len(Perms) < 100 {
		t.Fatalf("table suspiciously small: %d", len(Perms))
	}
	valid := map[api.Permission]bool{api.PermReadonly: true, api.PermOperator: true, api.PermAdmin: true,
		api.PermBackupPush: true, api.PermBackupPull: true, api.PermRestore: true, api.PermBackupAdmin: true}
	for _, e := range Perms {
		if !e.Public && !valid[e.Perm] {
			t.Errorf("%s: invalid permission %q", e.Key(), e.Perm)
		}
		if _, ok := reg.Lookup(e.Method, e.Pattern); !ok {
			t.Errorf("%s not found by Lookup", e.Key())
		}
		// Every entry must be reachable: a representative concrete path maps to itself or a more specific entry.
		path := strings.NewReplacer("{path...}", "a/b", "{name}", "x", "{id}", "x", "{gen}", "x", "{snapshot}", "x",
			"{volume}", "x", "{fingerprint}", "x").Replace(e.Pattern)
		if _, ok := reg.Match(e.Method, path); !ok {
			t.Errorf("%s: concrete path %s does not match anything", e.Key(), path)
		}
	}
}

func TestMutatingRoutesAreNeverReadonlyExceptAccountSelfService(t *testing.T) {
	self := map[string]bool{
		"POST /api/v1/auth/logout": true, "POST /api/v1/auth/password": true, "POST /api/v1/auth/totp": true,
		"DELETE /api/v1/auth/totp": true, "POST /api/v1/auth/recovery-codes": true, "DELETE /api/v1/sessions/{id}": true,
	}
	for _, e := range Perms {
		if e.Method != "GET" && !e.Public && e.Perm == api.PermReadonly && !self[e.Key()] {
			t.Errorf("%s is a mutation open to readonly", e.Key())
		}
		if e.Method == "GET" && e.Perm == api.PermReadonly {
			for _, secret := range []string{"/users", "/tokens", "/certificates", "/audit"} {
				if strings.Contains(e.Pattern, secret) {
					t.Errorf("%s exposes identity data to readonly", e.Key())
				}
			}
		}
	}
}

func TestNewRegistryRejects(t *testing.T) {
	tests := []struct {
		name string
		e    []Entry
	}{
		{"bad method", []Entry{{Method: "FETCH", Pattern: "/x", Perm: api.PermAdmin, Class: ClassGlobal}}},
		{"no leading slash", []Entry{{Method: "GET", Pattern: "x", Perm: api.PermAdmin, Class: ClassGlobal}}},
		{"no perm", []Entry{{Method: "GET", Pattern: "/x", Class: ClassGlobal}}},
		{"duplicate", []Entry{{Method: "GET", Pattern: "/x", Perm: api.PermAdmin, Class: ClassGlobal}, {Method: "GET", Pattern: "/x", Perm: api.PermAdmin, Class: ClassGlobal}}},
		{"empty segment", []Entry{{Method: "GET", Pattern: "/x//y", Perm: api.PermAdmin, Class: ClassGlobal}}},
		{"rest wildcard not last", []Entry{{Method: "GET", Pattern: "/{a...}/y", Perm: api.PermAdmin, Class: ClassGlobal}}},
		{"unknown class", []Entry{{Method: "GET", Pattern: "/x", Perm: api.PermAdmin, Class: "everything"}}},
		{"public with class", []Entry{{Method: "GET", Pattern: "/x", Public: true, Class: ClassGlobal}}},
		{"non-public public class", []Entry{{Method: "GET", Pattern: "/x", Perm: api.PermAdmin, Class: ClassPublic}}},
		{"partial wildcard", []Entry{{Method: "GET", Pattern: "/x{a}", Perm: api.PermAdmin, Class: ClassGlobal}}},
	}
	for _, tc := range tests {
		if _, err := NewRegistry(tc.e); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// A table kept outside this package (the backup node's) has no classes: its
// routes are host-level, and a public one stays public.
func TestEntriesWithoutAClassAreHostLevel(t *testing.T) {
	reg, err := NewRegistry([]Entry{{Method: "GET", Pattern: "/x", Perm: api.PermAdmin}, {Method: "GET", Pattern: "/y", Public: true}})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := reg.Class("GET", "/x"); c != ClassGlobal {
		t.Fatal(c)
	}
	if c, _ := reg.Class("GET", "/y"); c != ClassPublic {
		t.Fatal(c)
	}
}

func TestVerifyComplete(t *testing.T) {
	if err := VerifyComplete([]string{"GET /api/v1/jails", "POST /api/v1/jails/{name}/exec"}); err != nil {
		t.Fatal(err)
	}
	err := VerifyComplete([]string{"GET /api/v1/jails", "GET /api/v1/zz", "DELETE /api/v1/jails"})
	if err == nil || !strings.Contains(err.Error(), "GET /api/v1/zz") || !strings.Contains(err.Error(), "DELETE /api/v1/jails") ||
		strings.Contains(err.Error(), "GET /api/v1/jails;") {
		t.Fatalf("got %v", err)
	}
	if VerifyComplete(nil) != nil {
		t.Fatal("empty route list must pass")
	}
}

func TestCheck(t *testing.T) {
	a := NewAuthorizer()
	type P = api.Permission
	tests := []struct {
		held          P
		method, route string
		want          api.Code // "" = allowed
	}{
		{api.PermReadonly, "GET", "/api/v1/jails", ""},
		{api.PermReadonly, "POST", "/api/v1/jails", api.CodeForbidden},
		{api.PermOperator, "PUT", "/api/v1/jails/{name}/state", ""},
		{api.PermOperator, "POST", "/api/v1/jails", api.CodeForbidden},
		{api.PermOperator, "POST", "/api/v1/jails/{name}/snapshots", ""},
		{api.PermAdmin, "POST", "/api/v1/jails", ""},
		{api.PermAdmin, "PUT", "/api/v1/jails/{name}/state", ""},
		{api.PermAdmin, "GET", "/api/v1/users", ""},
		{api.PermOperator, "GET", "/api/v1/users", api.CodeForbidden},
		{api.PermAdmin, "POST", "/api/v1/backups/{id}/restore", ""},   // admin covers restore
		{api.PermRestore, "POST", "/api/v1/backups/{id}/restore", ""}, //
		{api.PermRestore, "GET", "/api/v1/jails", api.CodeForbidden},  // narrow roles are narrow
		{api.PermBackupPush, "POST", "/api/v1/backups/receive", ""},   //
		{api.PermBackupPush, "GET", "/api/v1/backups/{id}/stream", api.CodeForbidden},
		{api.PermBackupPull, "GET", "/api/v1/backups/{id}/stream", ""},
		{api.PermBackupPull, "POST", "/api/v1/backups/receive", api.CodeForbidden},
		{api.PermAdmin, "DELETE", "/api/v1/backups/{id}", api.CodeForbidden}, // only backup-admin deletes backups
		{api.PermBackupAdmin, "DELETE", "/api/v1/backups/{id}", ""},
		{api.PermBackupAdmin, "POST", "/api/v1/jails", api.CodeForbidden},
		{"", "GET", "/api/v1", ""}, // public
		{"", "POST", "/api/v1/auth/login", ""},
		{"", "GET", "/api/v1/jails", api.CodeUnauthorized},
		{api.PermAdmin, "GET", "/api/v1/unlisted", api.CodeForbidden}, // unlisted is never open
		{api.PermAdmin, "TRACE", "/api/v1/jails", api.CodeForbidden},
		{"bogus", "GET", "/api/v1/jails", api.CodeForbidden},
	}
	for _, tc := range tests {
		err := a.Check(tc.held, tc.method, tc.route)
		if tc.want == "" && err != nil || tc.want != "" && !api.IsCode(err, tc.want) {
			t.Errorf("%q %s %s: got %v want %q", tc.held, tc.method, tc.route, err, tc.want)
		}
	}
}

func TestCheckPathMostSpecificWins(t *testing.T) {
	a := NewAuthorizer()
	tests := []struct {
		held         api.Permission
		method, path string
		want         api.Code
	}{
		{api.PermBackupPush, "POST", "/api/v1/backups/receive", ""},
		{api.PermBackupPull, "GET", "/api/v1/backups/chains", ""},
		{api.PermReadonly, "GET", "/api/v1/backups/abc123", ""},
		{api.PermReadonly, "GET", "/api/v1/backups/chains", api.CodeForbidden}, // literal beats {id}
		{api.PermOperator, "GET", "/api/v1/jails/web/files/etc/rc.conf", ""},
		{api.PermReadonly, "GET", "/api/v1/jails/web/files/etc/rc.conf", api.CodeForbidden},
		{api.PermReadonly, "GET", "/api/v1/jails/web/files/", api.CodeForbidden}, // empty rest does not match -> unlisted
		{api.PermAdmin, "GET", "/api/v1/jails/web/nothing", api.CodeForbidden},
		{api.PermAdmin, "GET", "/api/v1/jails/web/state/extra", api.CodeForbidden},
		{api.PermAdmin, "GET", "/api/v1/nothing", api.CodeForbidden},
		{api.PermReadonly, "GET", "/api/v1/jails/web", ""},
	}
	for _, tc := range tests {
		err := a.CheckPath(tc.held, tc.method, tc.path)
		if tc.want == "" && err != nil || tc.want != "" && !api.IsCode(err, tc.want) {
			t.Errorf("%q %s %s: got %v want %q", tc.held, tc.method, tc.path, err, tc.want)
		}
	}
}

func TestForbiddenErrorNamesRequirement(t *testing.T) {
	err := NewAuthorizer().Check(api.PermReadonly, "POST", "/api/v1/jails")
	var e *api.Error
	if !asAPI(err, &e) || e.Detail["required"] != "admin" {
		t.Fatalf("%v", err)
	}
}

func asAPI(err error, target **api.Error) bool {
	e, ok := err.(*api.Error)
	if ok {
		*target = e
	}
	return ok
}

func TestRouteClasses(t *testing.T) {
	reg := DefaultRegistry()
	want := map[string]Class{
		"GET /api/v1":                           ClassPublic,
		"POST /api/v1/trust/clients":            ClassPublic,
		"POST /api/v1/trust/tokens":             ClassGlobal,
		"GET /api/v1/sessions":                  ClassSelf,
		"DELETE /api/v1/sessions/{id}":          ClassSelf,
		"POST /api/v1/auth/password":            ClassSelf,
		"GET /api/v1/networks":                  ClassGranted,
		"DELETE /api/v1/projects/{name}":        ClassGranted,
		"PUT /api/v1/storage/{name}":            ClassGranted,
		"GET /api/v1/images/{name}/generations": ClassGranted,
		"POST /api/v1/jails":                    ClassProject,
		"GET /api/v1/jails/{name}/snapshots":    ClassProject,
		"GET /api/v1/firewall/policies":         ClassProject,
		"GET /api/v1/backup-policies/{name}":    ClassProject,
		"GET /api/v1/backup-targets":            ClassGlobal,
		"GET /api/v1/backups":                   ClassVisible,
		"GET /api/v1/backups/{id}":              ClassObject,
		"DELETE /api/v1/backups/{id}":           ClassObject,
		"POST /api/v1/backups/{id}/restore":     ClassProject,
		"POST /api/v1/restores":                 ClassProject,
		"GET /api/v1/operations":                ClassVisible,
		"GET /api/v1/operations/{id}/wait":      ClassObject,
		"DELETE /api/v1/operations/{id}":        ClassObject,
		"GET /api/v1/events":                    ClassVisible,
		"GET /api/v1/audit":                     ClassVisible,
		"GET /api/v1/users":                     ClassGlobal,
		"GET /api/v1/doctor":                    ClassGlobal,
		"GET /api/v1/remotes":                   ClassGlobal,
	}
	for k, c := range want {
		m, p, _ := strings.Cut(k, " ")
		got, ok := reg.Class(m, p)
		if !ok || got != c {
			t.Errorf("%s: class %q, want %q", k, got, c)
		}
	}
	for _, e := range Perms {
		if !e.Class.valid() {
			t.Errorf("%s has no class", e.Key())
		}
		if (e.Class == ClassPublic) != e.Public {
			t.Errorf("%s: public/class mismatch", e.Key())
		}
	}
}

// The routes an anonymous caller reaches are a fixed list: adding one is a decision this test records.
func TestPublicRoutesAreExactlyThese(t *testing.T) {
	want := []string{"GET /api/v1", "GET /readyz", "POST /api/v1/auth/login", "POST /api/v1/cluster/join",
		"POST /api/v1/trust/clients", "GET /api/v1/setup", "POST /api/v1/setup"}
	var got []string
	for _, e := range Perms {
		if e.Public {
			got = append(got, e.Key())
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("public routes %v, want %v", got, want)
	}
}
