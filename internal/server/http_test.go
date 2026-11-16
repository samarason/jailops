package server_test

// HTTP-layer hardening: cache headers, login limits, streams that outlive their credential, console ownership and
// other users' sessions.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

var sysCtx = service.WithActor(context.Background(), service.Actor{Name: "test", Kind: "system", Perm: api.PermAdmin, Global: true})

// rawResp sends one request and returns the status, the headers and the body.
func rawResp(t *testing.T, e *dtest.Env, method, path, token, body string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.HTTP.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, string(b)
}

// Every API answer is uncacheable: a token secret, a generated password, a WireGuard key or a database password is in
// the body of some of them. The console's static files keep their own caching.
func TestAPIAnswersAreNotCached(t *testing.T) {
	e := dtest.New(t, dtest.Options{ForceWeb: true})
	e.Seed()
	tok := e.Token(api.PermAdmin)
	for _, r := range []struct{ method, path, body string }{
		{"POST", "/api/v1/tokens", `{"metadata":{"name":"cc1"},"spec":{"permission":"readonly","global":true}}`},
		{"GET", "/api/v1/auth/session", ""},
		{"GET", "/api/v1/users", ""},
		{"POST", "/api/v1/users", `{"metadata":{"name":"newuser"},"spec":{"permission":"readonly","global":true}}`},
		{"POST", "/api/v1/wireguard/none/peers", `{"name":"p"}`},
		{"POST", "/api/v1/jails/none/access?project=" + dtest.SeedProject, `{"source":"192.0.2.1"}`},
		{"GET", "/api/v1", ""},
		{"GET", "/api/v1/no-such-route", ""},
	} {
		code, h, _ := rawResp(t, e, r.method, r.path, tok, r.body)
		if h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" {
			t.Errorf("%s %s (%d): Cache-Control %q Pragma %q", r.method, r.path, code, h.Get("Cache-Control"), h.Get("Pragma"))
		}
	}
	code, h, _ := rawResp(t, e, "GET", "/", "", "")
	if code != 200 || h.Get("Cache-Control") == "no-store" || h.Get("Content-Security-Policy") == "" {
		t.Errorf("console page: %d Cache-Control %q CSP %q", code, h.Get("Cache-Control"), h.Get("Content-Security-Policy"))
	}
}

// Logins sent at once from one source: every attempt is counted before its password is derived, so no more than the
// threshold of the source (ten times that of one user, so that people behind one address are not locked out by a stranger)
// derive, and no more than auth.DeriveSlots derivations (64 MiB each) run at once.
func TestConcurrentLoginsAreBounded(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	h := e.D.Handler() // in process: no connections to run out of under the race detector
	const n = 64
	const perSource = 50 // ten times the threshold of one user
	var peak atomic.Uint64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak.Load() {
				peak.Store(ms.HeapInuse)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	_, before := auth.DerivationStats()
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(fmt.Sprintf(`{"username":"nobody%d","password":"x"}`, i)))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.0.2.200:1"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			mu.Lock()
			codes[rec.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(stop)
	<-sampled
	slots, after := auth.DerivationStats()
	if codes[401] > perSource || codes[401]+codes[429] != n {
		t.Errorf("%d logins at once from one source: %v (at most %d may be checked)", n, codes, perSource)
	}
	if after-before > perSource {
		t.Errorf("%d derivations for %d refused logins", after-before, n)
	}
	if slots > auth.DeriveSlots {
		t.Errorf("%d derivations ran at once (at most %d)", slots, auth.DeriveSlots)
	}
	if peak.Load()>>20 > 1024 {
		t.Errorf("peak heap %d MiB", peak.Load()>>20)
	}
}

// An unknown user, a wrong password and a disabled user cost one derivation each, so the time does not tell them
// apart; a locked-out source costs none.
func TestEveryLoginFailureDerivesOnce(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	for _, u := range []api.UserCreate{
		{Metadata: api.ObjectMeta{Name: "alice"}, Password: goodPassword, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}},
		{Metadata: api.ObjectMeta{Name: "dis"}, Password: goodPassword, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true, Disabled: true}},
	} {
		if _, err := e.Admin.Users().Create(c, u); err != nil {
			t.Fatal(err)
		}
	}
	h := e.D.Handler()
	try := func(user, pw, addr string) (int, int64) {
		_, before := auth.DerivationStats()
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+pw+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		_, after := auth.DerivationStats()
		return rec.Code, after - before
	}
	for i, c := range []struct{ user, pw string }{{"nosuchuser", "wrong-password-1"}, {"alice", "wrong-password-1"}, {"dis", goodPassword}, {"dis", "wrong-password-1"}} {
		if code, n := try(c.user, c.pw, fmt.Sprintf("192.0.2.%d:1", i+1)); code != 401 || n != 1 {
			t.Errorf("%s/%s: %d after %d derivations", c.user, c.pw, code, n)
		}
	}
	for range 5 {
		try("alice", "wrong-password-1", "192.0.2.99:1")
	}
	if code, n := try("alice", goodPassword, "192.0.2.99:1"); code != 429 || n != 0 {
		t.Errorf("locked-out source: %d after %d derivations", code, n)
	}
}

// The login lockout counts an IPv6 source by its /64: one host holds the whole prefix.
func TestLoginLockoutCoversTheIPv6Prefix(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "alice"}, Password: goodPassword,
		Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}}); err != nil {
		t.Fatal(err)
	}
	h := e.D.Handler()
	login := func(addr, pw string) int {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"alice","password":"`+pw+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	locked := 0
	for i := range 12 {
		if login(fmt.Sprintf("[2001:db8:1:2::%x]:5555", i+1), "wrong-password-guess") == 429 {
			locked++
		}
	}
	if locked < 7 {
		t.Errorf("12 guesses from 12 addresses of one /64: only %d refused", locked)
	}
	if code := login("[2001:db8:1:2::ffff]:5555", goodPassword); code != 429 {
		t.Errorf("the right password from the locked /64: %d", code)
	}
	// another /64 is another source; the account itself is not locked
	if code := login("[2001:db8:1:3::1]:5555", goodPassword); code != 200 {
		t.Errorf("the right password from another /64: %d", code)
	}
}

// A stream whose token is deleted ends: no event about what happens afterwards reaches it.
func TestEventStreamEndsWhenItsTokenIsDeleted(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	tk, err := e.D.Service().CreateToken(sysCtx, api.Token{Metadata: api.ObjectMeta{Name: "revoked"}, Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.HTTP.URL+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+tk.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	defer resp.Body.Close()
	lines := make(chan string, 100)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	if err := e.D.Service().DeleteToken(sysCtx, "revoked"); err != nil {
		t.Fatal(err)
	}
	op, err := e.Admin.Jails().Create(c, dtest.WebJail("afterrevoke"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = op.Wait(c)
	timeout := time.After(10 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				return // the stream ended
			}
			if strings.Contains(l, "afterrevoke") {
				t.Fatalf("a deleted token's stream received %s", l)
			}
		case <-timeout:
			t.Fatal("the stream of a deleted token is still open")
		}
	}
}

// A console session and an exec session end at the next keepalive tick after their token is deleted.
func TestConsoleAndExecEndWhenTheirTokenIsDeleted(t *testing.T) {
	e := dtest.New(t, dtest.Options{KeepAlive: 50 * time.Millisecond})
	e.Seed()
	startedWeb(t, e)
	c := ctxT(t)
	tk, err := e.D.Service().CreateToken(sysCtx, api.Token{Metadata: api.ObjectMeta{Name: "shell"}, Spec: api.TokenSpec{Permission: api.PermOperator, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	code, body := e.Raw("POST", "/api/v1/jails/web/console?project="+dtest.SeedProject, tk.Secret, `{"argv":["sleep"]}`)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var open struct {
		Metadata struct{ ID string } `json:"metadata"`
	}
	_ = json.Unmarshal([]byte(body), &open)
	out := openOutput(t, e.HTTP.URL, "/api/v1/jails/web/console/"+open.Metadata.ID+"/output?project="+dtest.SeedProject, tk.Secret, "")
	cl, err := sdk.Connect(c, sdk.Remote(e.HTTP.URL, sdk.WithToken(tk.Secret), sdk.WithProject(dtest.SeedProject)))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ex, err := cl.Jails().Exec(c, "web", []string{"sleep"}, sdk.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.D.Service().DeleteToken(sysCtx, "shell"); err != nil {
		t.Fatal(err)
	}
	ended := make(chan int, 1)
	go func() {
		_, stderr, code := drain(ex)
		if !strings.Contains(stderr, "revoked") {
			t.Errorf("stderr %q", stderr)
		}
		ended <- code
	}()
	select {
	case code := <-ended:
		if code != -1 {
			t.Errorf("exec of a deleted token ended with %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the exec session of a deleted token is still running")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, exit := out.next(); exit == -3 {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the console output of a deleted token is still open")
	}
}

// A console session belongs to the identity that opened it (its kind of credential and its name) and to its project:
// a user of the same name, or the same caller naming another project with a jail of the same name, gets not_found.
// The session id is in no log line and no audit entry.
func TestConsoleSessionBelongsToItsIdentityAndProject(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	net := e.MakeNetwork("beta")
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dtest.SeedProject, "beta"} {
		sp := webSpecIn(p)
		if p == "beta" {
			sp.Network = []api.NetworkAttach{{Network: net}}
		}
		op, err := e.Admin.Project(p).Jails().Create(c, sdk.NewJail("web", sp))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.Wait(c); err != nil {
			t.Fatal(err)
		}
		if op, err = e.Admin.Project(p).Jails().Start(c, "web"); err != nil {
			t.Fatal(err)
		}
		_, _ = op.Wait(c)
	}
	owner, err := e.D.Service().CreateToken(sysCtx, api.Token{Metadata: api.ObjectMeta{Name: "ops"}, Spec: api.TokenSpec{Permission: api.PermOperator, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ops"}, Password: goodPassword,
		Spec: api.UserSpec{Permission: api.PermOperator, Global: true}}); err != nil {
		t.Fatal(err)
	}
	code, body := rawDo(t, e, "POST", "/api/v1/jails/web/console?project="+dtest.SeedProject, owner.Secret, `{"argv":["cat"]}`, nil)
	if code != 200 {
		t.Fatalf("console: %d %s", code, body)
	}
	var open struct {
		Metadata struct{ ID string } `json:"metadata"`
	}
	_ = json.Unmarshal([]byte(body), &open)
	id := open.Metadata.ID
	// the same caller, the right id, another project's jail of the same name
	if code, body := rawDo(t, e, "POST", "/api/v1/jails/web/console/"+id+"/input?project=beta", owner.Secret, `{"data":"id\n"}`, nil); code != 404 {
		t.Errorf("the session answered in another project: %d %s", code, body)
	}
	// the user of the same name
	hc := jarClient(t)
	if st, _ := login(t, e, hc, "ops", goodPassword, ""); st != 200 {
		t.Fatal(st)
	}
	var csrf string
	for _, ck := range hc.Jar.Cookies(mustURL(e.HTTP.URL)) {
		if ck.Name == "jailops_csrf" {
			csrf = ck.Value
		}
	}
	req, _ := http.NewRequest("POST", e.HTTP.URL+"/api/v1/jails/web/console/"+id+"/input?project="+dtest.SeedProject, strings.NewReader(`{"data":"id\n"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", e.HTTP.URL)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("user ops drove token ops's console session: %d", resp.StatusCode)
	}
	// the owner itself
	if code, body := rawDo(t, e, "POST", "/api/v1/jails/web/console/"+id+"/input?project="+dtest.SeedProject, owner.Secret, `{"data":"id\n"}`, nil); code != 200 {
		t.Errorf("owner: %d %s", code, body)
	}
	_, audit := rawDo(t, e, "GET", "/api/v1/audit?limit=200", e.Token(api.PermAdmin), "", nil)
	if strings.Contains(audit, id) || strings.Contains(e.Log(), id) {
		t.Error("the console session id is in the audit log or the daemon log")
	}
	if !strings.Contains(audit, "/console/#") {
		t.Errorf("no console entry with the session's reference: %s", trunc(audit))
	}
}

// Only a global administrator sees and ends other users' sessions; a global reader sees its own.
func TestOnlyAGlobalAdminSeesOtherUsersSessions(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "boss"}, Password: goodPassword,
		Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}}); err != nil {
		t.Fatal(err)
	}
	hc := jarClient(t)
	if st, _ := login(t, e, hc, "boss", goodPassword, ""); st != 200 {
		t.Fatal(st)
	}
	admin := e.Token(api.PermAdmin)
	_, body := rawDo(t, e, "GET", "/api/v1/sessions", admin, "", nil)
	var env struct{ Metadata []api.Session }
	if err := json.Unmarshal([]byte(body), &env); err != nil || len(env.Metadata) != 1 {
		t.Fatalf("a global admin lists: %v %s", err, body)
	}
	id := env.Metadata[0].ID
	ro := e.IdentityToken(api.PermReadonly, true)
	if code, body := rawDo(t, e, "GET", "/api/v1/sessions", ro, "", nil); code != 200 || strings.Contains(body, id) {
		t.Errorf("a global reader lists: %d %s", code, body)
	}
	if code, _ := rawDo(t, e, "DELETE", "/api/v1/sessions/"+id, ro, "", nil); code != 404 {
		t.Errorf("a global reader ended an admin's session: %d", code)
	}
	resp, err := hc.Get(e.HTTP.URL + "/api/v1/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("the session ended: %d", resp.StatusCode)
	}
	if code, body := rawDo(t, e, "DELETE", "/api/v1/sessions/"+id, admin, "", nil); code != 200 {
		t.Errorf("a global admin: %d %s", code, body)
	}
}

// A spray over many users from one address is slowed (fifty failures lock the address, with a lockout that grows), while a
// user at the same address who has not failed keeps working until then: the numbers of the two limiters.
func TestSourceLimitStopsASprayButNotAGoodUserBelowIt(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Password: goodPassword,
		Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}}); err != nil {
		t.Fatal(err)
	}
	h := e.D.Handler()
	login := func(user, pw, addr string) int {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+pw+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	const addr = "192.0.2.77:1"
	checked, refused := 0, 0
	for i := 0; i < 80; i++ {
		switch login(fmt.Sprintf("nobody%d", i), "wrong-password-guess", addr) {
		case 401:
			checked++
		case 429:
			refused++
		}
	}
	t.Logf("a spray of 80 users from one address: %d checked, %d refused", checked, refused)
	// the fiftieth failure is answered with the lock, so 49 are answered as wrong passwords
	if checked != 49 || refused != 31 {
		t.Errorf("the source limit is 50 failures: %d checked and %d refused of 80", checked, refused)
	}
	if code := login("ann", goodPassword, addr); code != 429 {
		t.Errorf("a locked address: the right password gets %d", code)
	}
	// below the limit a user behind the same address signs in
	if code := login("ann", goodPassword, "192.0.2.78:1"); code != 200 {
		t.Errorf("another address: %d", code)
	}
	for i := 0; i < 40; i++ {
		login(fmt.Sprintf("other%d", i), "wrong-password-guess", "192.0.2.79:1")
	}
	if code := login("ann", goodPassword, "192.0.2.79:1"); code != 200 {
		t.Errorf("an address with 40 failures over other users: ann gets %d", code)
	}
}
