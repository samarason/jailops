package server_test

// Cross-project leak detector. Project alpha holds objects whose names carry the marker "zalpha"; identities
// restricted to project beta call every GET route of the server with the interesting ?project= forms and names, and
// no successful answer may carry the marker. Events streamed to beta identities while alpha changes must not carry
// it either, and mutating routes tried with alpha's names must never succeed.

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

const leakMarker = "zalpha"

type leakFixture struct {
	e       *dtest.Env
	opAlpha string
	idents  map[string]string // name -> bearer token
}

func newLeakFixture(t *testing.T) *leakFixture {
	t.Helper()
	e := dtest.New(t, dtest.Options{Hub: true})
	e.Seed()
	c := ctxT(t)
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
	f := &leakFixture{e: e, idents: map[string]string{}}
	pa := e.Admin.Project("alpha")
	j := sdk.NewJail("zalphajail", webSpecIn("alpha"))
	j.Metadata.Labels = map[string]string{"owner": "zalphaowner"}
	op, err := pa.Jails().Create(c, j)
	if err != nil {
		t.Fatal(err)
	}
	f.opAlpha = op.ID()
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	sn, err := pa.Jails().Snapshots("zalphajail").Create(c, "zalphasnap", "zalpha comment")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sn.Wait(c); err != nil {
		t.Fatal(err)
	}
	if _, err := pa.Firewall().Policies().Create(c, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "zalphapol"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pa.Firewall().AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "zalphaset"}, Spec: api.AddressSetSpec{Addresses: api.Entries("10.0.0.0/8")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pa.Profiles().Create(c, api.Profile{Metadata: api.ObjectMeta{Name: "zalphaprof"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.memory": "1G"}}}); err != nil {
		t.Fatal(err)
	}
	e.Files.Put("/jailops/projects/alpha/jails/zalphajail/root/var/log/messages", []byte("Oct 29 11:00:00 zalpha secret line\n"))
	pb := e.Admin.Project("beta")
	op, err = pb.Jails().Create(c, sdk.NewJail("web", webSpecIn("beta")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	e.Files.Put("/jailops/projects/beta/jails/web/root/var/log/messages", []byte("Oct 29 11:00:00 beta line\n"))
	for _, r := range []api.Permission{api.PermReadonly, api.PermOperator, api.PermAdmin, api.PermRestore, api.PermBackupAdmin} {
		f.idents["beta-"+string(r)] = e.IdentityToken(r, false, "beta")
	}
	return f
}

var leakClient = &http.Client{Timeout: 5 * time.Second}

// rawDo sends one request with a bearer token (none when empty) and returns the status and the body.
func rawDo(t *testing.T, e *dtest.Env, method, path, token, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.HTTP.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := leakClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b)
}

// expand fills the parameters of a pattern with every candidate value.
func expand(pattern string, names map[string][]string) []string {
	i := strings.Index(pattern, "{")
	if i < 0 {
		return []string{pattern}
	}
	j := strings.Index(pattern[i:], "}")
	vals := names[pattern[i+1:i+j]]
	if len(vals) == 0 {
		vals = []string{"x"}
	}
	var out []string
	for _, v := range vals {
		out = append(out, expand(pattern[:i]+v+pattern[i+j+1:], names)...)
	}
	return out
}

func trunc(s string) string {
	if len(s) > 400 {
		return s[:400] + "..."
	}
	return s
}

// leakReq is one request of a matrix.
type leakReq struct{ method, path, who, body string }

// runMatrix sends the requests one after the other (at once they would only wait for each other's locks) and calls
// check with each answer.
func runMatrix(t *testing.T, f *leakFixture, reqs []leakReq, check func(r leakReq, code int, body string)) {
	t.Helper()
	for _, r := range reqs {
		code, body := rawDo(t, f.e, r.method, r.path, f.idents[r.who], r.body, nil)
		check(r, code, body)
	}
	t.Logf("%d requests as beta identities", len(reqs))
}

// The admin of beta has every right a beta identity has; the other roles run too unless -short or -race (the
// mutation matrix runs as the admin only).
func leakIdentities(short ...string) []string {
	if testing.Short() || raceEnabled {
		return short
	}
	return []string{"beta-readonly", "beta-operator", "beta-admin", "beta-restore", "beta-backup_admin"}
}

func TestNoGETAnswerLeaksAnotherProject(t *testing.T) {
	f := newLeakFixture(t)
	e := f.e
	names := map[string][]string{
		"name":     {"zalphajail", "web", "alpha", "fb", "lan", "default", "zalphapol", "zalphaset", "zalphaprof"},
		"snapshot": {"zalphasnap"}, "id": {f.opAlpha}, "file...": {"messages"}, "path...": {"etc/passwd"},
	}
	projects := []string{"", "?project=beta", "?project=alpha", "?project=beta&project=alpha", "?project=alpha&project=beta",
		"?all_projects=true", "?project=host", "?project=Beta", "?project=beta%00"}
	keys := e.D.Server().RouteKeys()
	sort.Strings(keys)
	var reqs []leakReq
	for _, key := range keys {
		method, pattern, _ := strings.Cut(key, " ")
		if method != "GET" || strings.Contains(pattern, "/events") || strings.HasSuffix(pattern, "/output") || strings.HasSuffix(pattern, "/wait") {
			continue
		}
		for _, p := range expand(pattern, names) {
			for _, q := range projects {
				for _, w := range leakIdentities("beta-admin") {
					reqs = append(reqs, leakReq{method, p + q, w, ""})
				}
			}
		}
	}
	runMatrix(t, f, reqs, func(r leakReq, code int, body string) {
		if code/100 == 2 && strings.Contains(body, leakMarker) {
			t.Errorf("LEAK %s %s as %s: %d %s", r.method, r.path, r.who, code, trunc(body))
		}
	})
	for w, tok := range f.idents {
		for _, q := range []string{"", "?project=beta", "?timeout=0"} {
			if code, body := rawDo(t, e, "GET", "/api/v1/operations/"+f.opAlpha+"/wait"+q, tok, "", nil); code/100 == 2 {
				t.Errorf("LEAK wait %s as %s: %d %s", q, w, code, trunc(body))
			}
		}
	}
}

// A beta identity follows the event stream (with replay) while alpha changes.
func TestNoEventLeaksAnotherProject(t *testing.T) {
	f := newLeakFixture(t)
	e := f.e
	c := ctxT(t)
	var mu sync.Mutex
	got := map[string][]string{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opened, wg sync.WaitGroup
	var live atomic.Int32
	for who, tok := range f.idents {
		for _, q := range []string{"", "?project=beta"} {
			opened.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequestWithContext(ctx, "GET", e.HTTP.URL+"/api/v1/events"+q, nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("Last-Event-ID", "0") // replay everything retained
				resp, err := http.DefaultClient.Do(req)
				if err == nil && resp.StatusCode == 200 {
					live.Add(1)
				}
				opened.Done()
				if err != nil {
					return
				}
				defer resp.Body.Close()
				sc := bufio.NewScanner(resp.Body)
				sc.Buffer(make([]byte, 1<<20), 1<<20)
				for sc.Scan() {
					if line := sc.Text(); strings.HasPrefix(line, "data:") {
						mu.Lock()
						got[who+q] = append(got[who+q], line)
						mu.Unlock()
					}
				}
			}()
		}
	}
	opened.Wait()
	pa := e.Admin.Project("alpha")
	op, err := pa.Jails().Create(c, sdk.NewJail("zalphalive", webSpecIn("alpha")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = op.Wait(c)
	if op, _ = pa.Jails().Stop(c, "zalphalive"); op != nil {
		_, _ = op.Wait(c)
	}
	// a failing operation in alpha: its error message
	_, _ = pa.Jails().Create(c, sdk.NewJail("zalphalive", webSpecIn("alpha")))
	// an event of beta that every stream sees, so the streams have caught up when it arrives
	op, err = e.Admin.Project("beta").Jails().Create(c, sdk.NewJail("last", webSpecIn("beta")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = op.Wait(c)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := 0
		for _, lines := range got {
			if strings.Contains(strings.Join(lines, "\n"), "/jails/last") {
				n++
			}
		}
		mu.Unlock()
		if n == int(live.Load()) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	for who, lines := range got {
		for _, l := range lines {
			if strings.Contains(l, leakMarker) {
				t.Errorf("LEAK event to %s: %s", who, trunc(l))
				break
			}
		}
	}
}

// Mutations by beta identities that name alpha's objects never succeed.
func TestNoMutationReachesAnotherProject(t *testing.T) {
	f := newLeakFixture(t)
	e := f.e
	names := map[string][]string{
		"name":     {"zalphajail", "zalphapol", "zalphaset", "zalphaprof"},
		"snapshot": {"zalphasnap"}, "id": {f.opAlpha}, "file...": {"messages"}, "path...": {"etc/passwd"}, "volume": {"v"}, "peer": {"p"},
	}
	projects := []string{"", "?project=beta", "?project=alpha", "?project=beta&project=alpha", "?all_projects=true", "?project=host"}
	if raceEnabled {
		projects = []string{"?project=beta", "?project=alpha", "?all_projects=true"}
	}
	bodies := []string{`{}`, `{"metadata":{"name":"zalphajail","project":"alpha"}}`, `{"project":"alpha","jail":"zalphajail"}`,
		`{"source":"@alpha/zalphajail"}`, `{"backup":"x","project":"alpha"}`}
	var reqs []leakReq
	for _, key := range e.D.Server().RouteKeys() {
		method, pattern, _ := strings.Cut(key, " ")
		if method == "GET" || !strings.Contains(pattern, "{") {
			continue
		}
		for _, p := range expand(pattern, names) {
			for _, q := range projects {
				for _, b := range bodies {
					reqs = append(reqs, leakReq{method, p + q, "beta-admin", b})
				}
			}
		}
	}
	runMatrix(t, f, reqs, func(r leakReq, code int, body string) {
		if code/100 == 2 {
			t.Errorf("MUTATION %s %s %s as %s: %d %s", r.method, r.path, r.body, r.who, code, trunc(body))
		}
	})
}
