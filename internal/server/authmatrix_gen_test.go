package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// memBackups is a backup backend with one backup per project.
type memBackups struct{ items map[string]api.Backup }

func (m *memBackups) List(context.Context) ([]api.Backup, error) {
	var out []api.Backup
	for _, b := range m.items {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata.Name < out[j].Metadata.Name })
	return out, nil
}
func (m *memBackups) Get(_ context.Context, id string) (api.Backup, error) {
	if b, ok := m.items[id]; ok {
		return b, nil
	}
	return api.Backup{}, api.Errorf(api.CodeNotFound, "backup %q not found", id)
}
func (m *memBackups) Delete(context.Context, string) error { return nil }
func (m *memBackups) Preflight(context.Context, api.RestoreRequest) (api.RestorePreflight, error) {
	return api.RestorePreflight{OK: true}, nil
}
func (m *memBackups) Restore(context.Context, api.RestoreRequest) (api.Jail, error) {
	return api.Jail{}, nil
}
func (m *memBackups) RestoreVolume(context.Context, api.RestoreRequest) (api.Volume, error) {
	return api.Volume{}, nil
}

// who is one identity of the matrix.
type who struct {
	name   string
	global bool
	// projects is the project list; nil with global false is the identity with neither.
	projects []string
	anon     bool
}

// Result classes of the matrix.
type result string

const (
	allowed      result = "allowed"
	forbidden    result = "forbidden"
	notFound     result = "not_found"
	unauthorized result = "unauthorized"
)

// fixtureOwner says which projects see an object that the route table calls
// "granted": host-level objects project users read only when a project of
// theirs is granted them. It is the object model of the fixture below.
var fixtureOwner = map[string][]string{
	"networks/lan":    {"alpha"},
	"images/fb":       {"alpha", "beta"},
	"storage/default": {"alpha", "beta"},
	"projects/alpha":  {"alpha"},
}

// expect derives the result of a request from the route table (class and
// role) and the object model, never from the daemon.
func expect(ent auth.Entry, role api.Permission, id who, param map[string]string, objPath string, withProject bool) result {
	if ent.Public {
		return allowed
	}
	if id.anon {
		return unauthorized
	}
	if !role.Satisfies(ent.Perm) {
		return forbidden
	}
	if ent.Class == auth.ClassSelf {
		return allowed
	}
	if !id.global && len(id.projects) == 0 {
		return forbidden
	}
	in := func(p string) bool { return id.global || hasStr(id.projects, p) }
	switch ent.Class {
	case auth.ClassGlobal:
		if id.global {
			return allowed
		}
		return forbidden
	case auth.ClassGranted:
		if ent.Method != "GET" {
			if id.global {
				return allowed
			}
			return forbidden
		}
		owners, item := fixtureOwner[objPath]
		if !item || id.global {
			return allowed
		}
		for _, p := range owners {
			if hasStr(id.projects, p) {
				return allowed
			}
		}
		return notFound
	case auth.ClassProject:
		if in("alpha") {
			return allowed
		}
		return notFound
	case auth.ClassVisible:
		if withProject && !in("alpha") {
			return notFound
		}
		return allowed
	case auth.ClassObject:
		if in("alpha") {
			return allowed
		}
		return notFound
	}
	panic("unclassified route " + ent.Key())
}

func hasStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// objectPath returns the "kind/name" of the first path parameter of a
// granted route, the key into fixtureOwner.
func objectPath(path string) string {
	p := strings.TrimPrefix(path, "/api/v1/")
	parts := strings.Split(p, "/")
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return ""
}

// TestAuthorizationMatrix is generated from the route table and the object
// model: for every route, every role and each kind of identity (global admin,
// project-restricted in its project, project-restricted in another project,
// neither, anonymous) the expected result is derived and compared with the
// running daemon.
func TestAuthorizationMatrix(t *testing.T) {
	bk := &memBackups{items: map[string]api.Backup{
		"b-alpha": {Metadata: api.ObjectMeta{Name: "b-alpha", Project: "alpha"}},
		"b-beta":  {Metadata: api.ObjectMeta{Name: "b-beta", Project: "beta"}},
	}}
	// The catalog holds an app named like the jails of the fixture, so an allowed install request reaches the
	// service and is refused there as already_exists, never as not_found.
	catalog := t.TempDir()
	if err := os.WriteFile(filepath.Join(catalog, "web.yaml"), []byte(strings.ReplaceAll(appDemo, "name: demo", "name: web")), 0o644); err != nil {
		t.Fatal(err)
	}
	e := dtest.New(t, dtest.Options{Hub: true, Backups: bk, Mutate: func(c *daemon.Config) { c.Apps.CatalogDir = catalog }})
	e.Seed()
	c := ctxT(t)
	// Fixture: two projects (alpha from Seed holds lan, beta holds lan-beta); the same jail name in both.
	bn := dtest.LAN()
	bn.Metadata.Name = "lan-beta"
	bn.Spec.IPv4 = &api.IPv4Net{Subnet: "10.21.0.0/24", Gateway: "10.21.0.1", Range: "10.21.0.10-10.21.0.50"}
	if _, err := e.Admin.Networks().Create(c, bn); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Storage: []api.ProjectStorage{{Storage: "default"}}, Networks: []api.ProjectNetwork{{Network: "lan-beta"}}}}); err != nil {
		t.Fatal(err)
	}
	var opAlpha string
	for _, p := range []string{"alpha", "beta"} {
		pc := e.Admin.Project(p)
		sp := webSpecIn(p)
		vop, err := pc.Volumes().Create(c, sdk.NewVolume("vol", api.VolumeSpec{Storage: "default"}), "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vop.Wait(c); err != nil {
			t.Fatalf("%s volume: %v\n%s", p, err, e.Log())
		}
		vsn, err := pc.Volumes().Snapshots("vol").Create(c, "s1", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vsn.Wait(c); err != nil {
			t.Fatal(err)
		}
		sp.Volumes = []api.VolumeAttach{{Name: "vol", Mount: "/srv/vol"}}
		op, err := pc.Jails().Create(c, sdk.NewJail("web", sp))
		if err != nil {
			t.Fatal(err)
		}
		if p == "alpha" {
			opAlpha = op.ID()
		}
		if _, err := op.Wait(c); err != nil {
			t.Fatalf("%s: %v\n%s", p, err, e.Log())
		}
		sn, err := pc.Jails().Snapshots("web").Create(c, "s1", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sn.Wait(c); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "pol"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.Profiles().Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "prof"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.memory": "1G"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "set"}, Spec: api.AddressSetSpec{Addresses: api.Entries("10.0.0.0/8")}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Admin.Backups().Targets().Create(c, api.BackupTarget{Metadata: api.ObjectMeta{Name: "tgt"}, Spec: api.BackupTargetSpec{Kind: "directory", Path: "/backup"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Project("alpha").Backups().Policies().Create(c, api.BackupPolicy{Metadata: api.ObjectMeta{Name: "bp"},
		Spec: api.BackupPolicySpec{Targets: []string{"tgt"}, Schedule: "0 3 * * *"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "u1"}, Spec: api.UserSpec{Permission: api.PermReadonly, Global: true}}); err != nil {
		t.Fatal(err)
	}
	tk, err := e.Admin.Tokens().Create(c, api.Token{Metadata: api.ObjectMeta{Name: "tk1"}, Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	_ = tk
	fp := strings.Repeat("cd", 32)
	if _, err := e.Admin.Certificates().Create(c, api.Certificate{Spec: api.CertificateSpec{Fingerprint: fp, Permission: api.PermReadonly, Kind: "host", Global: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Remotes().Create(c, api.Remote{Metadata: api.ObjectMeta{Name: "r1"}, Spec: api.RemoteSpec{Address: "127.0.0.1:1", Fingerprint: strings.Repeat("ab", 32)}}); err != nil {
		t.Fatal(err)
	}
	params := map[string]string{"name": "web", "snapshot": "s1", "volume": "vol", "gen": "1", "path...": "etc/x", "file...": "messages", "id": opAlpha,
		"fingerprint": fp, "member": "m"}
	// The {name} parameter depends on the family.
	nameFor := func(pattern string) string {
		switch {
		case strings.HasPrefix(pattern, "/api/v1/images"):
			return "fb"
		case strings.HasPrefix(pattern, "/api/v1/networks"):
			return "lan"
		case strings.HasPrefix(pattern, "/api/v1/storage"):
			return "default"
		case strings.HasPrefix(pattern, "/api/v1/volumes"):
			return "vol"
		case strings.HasPrefix(pattern, "/api/v1/projects"):
			return "alpha"
		case strings.HasPrefix(pattern, "/api/v1/firewall/policies"):
			return "pol"
		case strings.HasPrefix(pattern, "/api/v1/firewall/address-sets"):
			return "set"
		case strings.HasPrefix(pattern, "/api/v1/profiles"):
			return "prof"
		case strings.HasPrefix(pattern, "/api/v1/backup-targets"):
			return "tgt"
		case strings.HasPrefix(pattern, "/api/v1/backup-policies"):
			return "bp"
		case strings.HasPrefix(pattern, "/api/v1/users"):
			return "u1"
		case strings.HasPrefix(pattern, "/api/v1/tokens"):
			return "tk1"
		case strings.HasPrefix(pattern, "/api/v1/remotes"):
			return "r1"
		}
		return "web"
	}
	concretize := func(pattern string) string {
		out := pattern
		for {
			i := strings.Index(out, "{")
			if i < 0 {
				return out
			}
			j := strings.Index(out[i:], "}")
			key := out[i+1 : i+j]
			val := params[key]
			if key == "name" {
				val = nameFor(pattern)
			}
			if val == "" {
				val = "x"
			}
			if strings.HasPrefix(pattern, "/api/v1/backups/{id}") && key == "id" {
				val = "b-alpha"
			}
			out = out[:i] + val + out[i+j+1:]
		}
	}
	// Identities: one token per role and scope kind.
	roles := []api.Permission{api.PermReadonly, api.PermOperator, api.PermAdmin, api.PermBackupPush, api.PermBackupPull, api.PermRestore, api.PermBackupAdmin}
	whos := []who{{name: "global", global: true}, {name: "alpha-user", projects: []string{"alpha"}}, {name: "beta-user", projects: []string{"beta"}},
		{name: "neither"}, {name: "anonymous", anon: true}}
	tokens := map[string]string{}
	for _, w := range whos {
		for _, r := range roles {
			key := w.name + "/" + string(r)
			switch {
			case w.anon:
			case w.global:
				tokens[key] = e.IdentityToken(r, true)
			case len(w.projects) > 0:
				tokens[key] = e.IdentityToken(r, false, w.projects...)
			default:
				tokens[key] = e.ScopelessToken(r)
			}
		}
	}
	reg := auth.DefaultRegistry()
	keys := e.D.Server().RouteKeys()
	rank := map[string]int{"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}
	sort.SliceStable(keys, func(i, j int) bool {
		mi, pi, _ := strings.Cut(keys[i], " ")
		mj, pj, _ := strings.Cut(keys[j], " ")
		if rank[mi] != rank[mj] {
			return rank[mi] < rank[mj]
		}
		if mi == "DELETE" {
			return len(pi) > len(pj) // children before parents
		}
		return false
	})
	client := &http.Client{Timeout: 8 * time.Second}
	do := func(method, path, token string) (int, string) {
		req, _ := http.NewRequest(method, e.HTTP.URL+path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		return resp.StatusCode, string(buf[:n])
	}
	checked, localChecked := 0, 0
	counts := map[result]int{}
	for _, key := range keys {
		method, pattern, _ := strings.Cut(key, " ")
		ent, ok := reg.Lookup(method, pattern)
		if !ok {
			t.Fatalf("%s has no entry", key)
		}
		base := concretize(pattern)
		if strings.Contains(pattern, "/events") {
			base += "?type=lifecycle"
		}
		withProjectVariants := []bool{true}
		if ent.Class == auth.ClassVisible {
			withProjectVariants = []bool{false, true}
		}
		deleted := false
		// Requests that are not allowed first, so a destructive route is not
		// spent before the identities that must be refused have been tried.
		type probe struct {
			w    who
			role api.Permission
			wp   bool
			want result
		}
		var probes []probe
		for _, wp := range withProjectVariants {
			for _, w := range whos {
				for _, r := range roles {
					probes = append(probes, probe{w, r, wp, expect(ent, r, w, params, objectPath(base), wp)})
				}
			}
		}
		sort.SliceStable(probes, func(i, j int) bool {
			return (probes[i].want == allowed) != (probes[j].want == allowed) && probes[j].want == allowed
		})
		for _, pr := range probes {
			path := base
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			switch ent.Class {
			case auth.ClassProject, auth.ClassObject:
				if pr.wp || ent.Class == auth.ClassProject {
					path += sep + "project=alpha"
				}
			case auth.ClassVisible:
				if pr.wp {
					path += sep + "project=alpha"
				}
			}
			code, body := do(method, path, tokens[pr.w.name+"/"+string(pr.role)])
			// The "anonymous local" column: a non-root peer of the unix socket is exactly an anonymous remote client.
			if pr.w.anon && pr.role == api.PermReadonly {
				for peer, cred := range ordinaryPeers {
					lc, lb := serveAs(e, cred, method, path, "", "{}")
					if code == 429 {
						continue // the remote source is locked out by the login probes; the lockout is per source, not a different right
					}
					if lc != code || errorCode(lb) != errorCode(body) {
						t.Errorf("%s (project param %v): anonymous local (%s) got %d %s, anonymous remote got %d %s", key, pr.wp, peer, lc, errorCode(lb), code, errorCode(body))
					}
					localChecked++
				}
			}
			var got result
			switch {
			case code == 401 && ent.Public:
				got = allowed // a public route checks its own credential (login)
			case code == 401:
				got = unauthorized
			case code == 403 && errorCode(body) == "not_managed":
				got = allowed // a host module that is off here: the caller was authorized
			case code == 403:
				got = forbidden
			case code == 404 && pr.want == notFound:
				got = notFound
			default:
				got = allowed
			}
			// A console session id that was never opened: the request passed authorization and found no session.
			if got == allowed && code == 404 && strings.Contains(body, "console session") {
				continue
			}
			// The setup routes answer not_found once a global administrator exists (the matrix's admin tokens are):
			// the request passed authorization.
			if got == allowed && code == 404 && strings.Contains(body, "setup is complete") {
				continue
			}
			// A destructive route answers not_found to whoever comes after the first success.
			if got == allowed && code == 404 && (deleted || ent.Class == auth.ClassSelf || ent.Class == auth.ClassGlobal) {
				continue
			}
			if got == allowed && code == 404 {
				got = notFound
			}
			if pr.want == allowed && method == "DELETE" && code/100 == 2 || code == 202 {
				deleted = true
			}
			counts[pr.want]++
			checked++
			if got != pr.want {
				t.Errorf("%s as %s/%s (project param %v): got %d %s want %s\n  %s", key, pr.w.name, pr.role, pr.wp, code, got, pr.want, strings.TrimSpace(body))
			}
		}
	}
	t.Logf("%d requests checked over %d routes: %v", checked, len(keys), counts)
	if checked < 2000 {
		t.Fatalf("only %d checks", checked)
	}
	if localChecked < len(keys)*len(ordinaryPeers) {
		t.Fatalf("only %d anonymous-local checks over %d routes", localChecked, len(keys))
	}
	for _, r := range []result{allowed, forbidden, notFound, unauthorized} {
		if counts[r] == 0 {
			t.Fatalf("the matrix never expects %s", r)
		}
	}
}

// errorCode is the API error code of a response body, "" for a success.
func errorCode(body string) string {
	var env api.Response
	if json.Unmarshal([]byte(body), &env) != nil || env.Error == nil {
		return ""
	}
	return string(env.Error.Code)
}

var _ = fmt.Sprint
