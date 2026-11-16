package server_test

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

const goodPassword = "Sup3r-Secret-pw!"

func TestTokens(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	tok, err := e.Admin.Tokens().Create(c, api.Token{Metadata: api.ObjectMeta{Name: "ci"}, Spec: api.TokenSpec{Permission: api.PermOperator, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Secret, "jot_") || tok.Spec.Permission != api.PermOperator {
		t.Fatalf("%+v", tok)
	}
	// The secret is shown once.
	got, err := e.Admin.Tokens().Get(c, "ci")
	if err != nil || got.Secret != "" {
		t.Fatalf("%v %+v", err, got)
	}
	for tk, err := range e.Admin.Tokens().List(c) {
		if err != nil || tk.Secret != "" {
			t.Fatalf("%v %+v", err, tk)
		}
	}
	_, err = e.Admin.Tokens().Create(c, api.Token{Metadata: api.ObjectMeta{Name: "ci"}, Spec: api.TokenSpec{Permission: api.PermOperator, Global: true}})
	wantCode(t, err, api.CodeAlreadyExists)
	_, err = e.Admin.Tokens().Create(c, api.Token{Spec: api.TokenSpec{}})
	wantCode(t, err, api.CodeInvalid)
	_, err = e.Admin.Tokens().Create(c, api.Token{Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true, ExpiresAt: time.Now().Add(-time.Hour)}})
	wantCode(t, err, api.CodeInvalid)
	_, err = e.Admin.Tokens().Create(c, api.Token{Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true, AllowFrom: []string{"not an ip"}}})
	wantCode(t, err, api.CodeInvalid)
	// An operator token works as an operator and no more.
	if code, _ := e.Raw("PUT", "/api/v1/jails/x/state?project=alpha", tok.Secret, `{"action":"start"}`); code != 404 {
		t.Fatalf("operator: %d", code)
	}
	if code, _ := e.Raw("POST", "/api/v1/networks", tok.Secret, `{}`); code != 403 {
		t.Fatalf("operator created a network: %d", code)
	}
	// An operator cannot hand out an admin token.
	opc := e.Client(api.PermOperator)
	_, err = opc.Tokens().Create(c, api.Token{Spec: api.TokenSpec{Permission: api.PermAdmin, Global: true}})
	wantCode(t, err, api.CodeForbidden)
	// A token restricted to another address is refused.
	lim, _ := e.Admin.Tokens().Create(c, api.Token{Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true, AllowFrom: []string{"192.0.2.0/24"}}})
	if code, _ := e.Raw("GET", "/api/v1/jails?project=alpha", lim.Secret, ""); code != 403 {
		t.Fatalf("allow_from: %d", code)
	}
	// Revocation takes effect at once.
	if err := e.Admin.Tokens().Delete(c, "ci"); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.Raw("GET", "/api/v1/jails?project=alpha", tok.Secret, ""); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
}

func TestCertificates(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	fp := strings.Repeat("ab", 32)
	cert, err := e.Admin.Certificates().Create(c, api.Certificate{Spec: api.CertificateSpec{Fingerprint: strings.ToUpper(fp), Permission: api.PermReadonly, Global: true, Kind: "host"}})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Spec.Fingerprint != fp || cert.Metadata.Name != "host-"+fp[:12] {
		t.Fatalf("%+v", cert)
	}
	if _, err := e.Admin.Certificates().Create(c, api.Certificate{Metadata: api.ObjectMeta{Name: "dup"}, Spec: api.CertificateSpec{Fingerprint: fp, Permission: api.PermAdmin, Global: true}}); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("%v", err)
	}
	// By name and by fingerprint.
	for _, k := range []string{cert.Metadata.Name, fp} {
		g, err := e.Admin.Certificates().Get(c, k)
		if err != nil || g.Metadata.Name != cert.Metadata.Name {
			t.Fatalf("%s: %v", k, err)
		}
	}
	cert.Spec.Permission = api.PermOperator
	up, err := e.Admin.Certificates().Update(c, cert.Metadata.Name, cert, `"1"`)
	if err != nil || up.Spec.Permission != api.PermOperator || up.Metadata.Generation != 2 {
		t.Fatalf("%v %+v", err, up)
	}
	if a, ok := e.D.Service().CertActor(fp, "x"); !ok || a.Perm != api.PermOperator {
		t.Fatalf("%+v %v", a, ok)
	}
	if err := e.Admin.Certificates().Delete(c, fp); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.D.Service().CertActor(fp, "x"); ok {
		t.Fatal("a deleted certificate is still trusted")
	}
	_, err = e.Admin.Certificates().Create(c, api.Certificate{Spec: api.CertificateSpec{Fingerprint: "zz", Permission: api.PermAdmin, Global: true}})
	wantCode(t, err, api.CodeInvalid)
}

// A global administrator replaces a user's password without knowing the old one (the recovery path); the user's
// sessions end, and nobody else may do it.
func TestSetUserPassword(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermOperator, Global: true}, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	hc := jarClient(t)
	if code, _ := login(t, e, hc, "ann", goodPassword, ""); code != 200 {
		t.Fatalf("login: %d", code)
	}
	const next = "a different long passphrase 42"
	out, err := e.Global().Users().SetPassword(c, "ann", next)
	if err != nil || out.Password != "" {
		t.Fatalf("a chosen password is not echoed: %v %+v", err, out)
	}
	if code, _ := login(t, e, nil, "ann", goodPassword, ""); code != 401 {
		t.Fatalf("the old password still works: %d", code)
	}
	if code, _ := login(t, e, nil, "ann", next, ""); code != 200 {
		t.Fatalf("the new password does not work: %d", code)
	}
	resp, err := hc.Get(e.HTTP.URL + "/api/v1/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("a session survived the password reset: %d", resp.StatusCode)
	}
	gen, err := e.Global().Users().SetPassword(c, "ann", "")
	if err != nil || gen.Password == "" || auth.CheckPasswordPolicy(gen.Password, "ann") != nil {
		t.Fatalf("generated: %v %+v", err, gen)
	}
	if code, _ := login(t, e, nil, "ann", gen.Password, ""); code != 200 {
		t.Fatalf("the generated password does not work: %d", code)
	}
	_, err = e.Global().Users().SetPassword(c, "ann", "short")
	wantCode(t, err, api.CodeInvalid)
	_, err = e.Global().Users().SetPassword(c, "ghost", next)
	wantCode(t, err, api.CodeNotFound)
	// Not for a project-scoped administrator, an operator or a caller without credentials.
	_, err = e.Scoped(api.PermAdmin, "alpha").Users().SetPassword(c, "ann", next)
	wantCode(t, err, api.CodeForbidden)
	_, err = e.Client(api.PermOperator).Users().SetPassword(c, "ann", next)
	wantCode(t, err, api.CodeForbidden)
	_, err = e.Anonymous().Users().SetPassword(c, "ann", next)
	wantCode(t, err, api.CodeUnauthorized)
}

func TestUsers(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	made, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermOperator, Global: true}})
	if err != nil || made.Password == "" || made.User.Spec.Permission != api.PermOperator {
		t.Fatalf("%v %+v", err, made)
	}
	if auth.CheckPasswordPolicy(made.Password, "ann") != nil {
		t.Fatalf("generated password breaks the policy: %q", made.Password)
	}
	own, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "bob"}, Spec: api.UserSpec{Permission: api.PermReadonly, Global: true}, Password: goodPassword})
	if err != nil || own.Password != "" {
		t.Fatalf("a chosen password is not echoed: %v %+v", err, own)
	}
	_, err = e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "weak"}, Spec: api.UserSpec{Permission: api.PermReadonly, Global: true}, Password: "short"})
	wantCode(t, err, api.CodeInvalid)
	_, err = e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermReadonly, Global: true}})
	wantCode(t, err, api.CodeAlreadyExists)
	u, etag, err := e.Admin.Users().GetETag(c, "ann")
	if err != nil {
		t.Fatal(err)
	}
	u.Spec.Disabled = true
	if _, err := e.Admin.Users().Update(c, "ann", u, etag); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Users().Update(c, "ann", u, etag); !api.IsCode(err, api.CodeConflict) {
		t.Fatalf("stale user update: %v", err)
	}
	// A disabled user cannot log in.
	code, _ := login(t, e, nil, "ann", made.Password, "")
	if code != 401 {
		t.Fatalf("disabled user logged in: %d", code)
	}
	if err := e.Admin.Users().Delete(c, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Users().Get(c, "bob"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("%v", err)
	}
}

func jarClient(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func login(t *testing.T, e *dtest.Env, hc *http.Client, user, pw, totp string) (int, map[string]any) {
	t.Helper()
	if hc == nil {
		hc = jarClient(t)
	}
	body, _ := json.Marshal(map[string]string{"username": user, "password": pw, "totp": totp})
	resp, err := hc.Post(e.HTTP.URL+"/api/v1/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env api.Response
	_ = json.NewDecoder(resp.Body).Decode(&env)
	out := map[string]any{}
	if len(env.Metadata) > 0 {
		_ = json.Unmarshal(env.Metadata, &out)
	}
	if env.Error != nil {
		out["error"] = env.Error
	}
	return resp.StatusCode, out
}

func TestSessionLoginCSRFAndLogout(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	hc := jarClient(t)
	code, out := login(t, e, hc, "ann", goodPassword, "")
	if code != 200 || out["user"] != "ann" || out["csrf"] == "" {
		t.Fatalf("%d %v", code, out)
	}
	u, _ := url.Parse(e.HTTP.URL)
	var csrf string
	var sessionCookie *http.Cookie
	for _, ck := range hc.Jar.Cookies(u) {
		switch ck.Name {
		case "jailops_csrf":
			csrf = ck.Value
		case auth.SessionCookieName:
			sessionCookie = ck
		}
	}
	if csrf == "" || csrf != out["csrf"] || sessionCookie == nil {
		t.Fatalf("cookies: %v", hc.Jar.Cookies(u))
	}
	do := func(method, path, body string, hdr map[string]string) int {
		req, _ := http.NewRequest(method, e.HTTP.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("GET", "/api/v1/projects", "", nil); code != 200 {
		t.Fatalf("session read: %d", code)
	}
	info, _ := e.Anonymous().Info(c)
	_ = info
	// Mutations need the CSRF header and a same-origin Origin.
	origin := map[string]string{"Origin": e.HTTP.URL}
	if code := do("POST", "/api/v1/networks", "{}", origin); code != 403 {
		t.Fatalf("no CSRF header: %d", code)
	}
	if code := do("POST", "/api/v1/networks", "{}", map[string]string{"X-CSRF-Token": csrf}); code != 403 {
		t.Fatalf("no Origin: %d", code)
	}
	if code := do("POST", "/api/v1/networks", "{}", map[string]string{"X-CSRF-Token": csrf, "Origin": "http://evil.example"}); code != 403 {
		t.Fatalf("foreign Origin: %d", code)
	}
	if code := do("POST", "/api/v1/networks", "{}", map[string]string{"X-CSRF-Token": "wrong", "Origin": e.HTTP.URL}); code != 403 {
		t.Fatalf("wrong CSRF token: %d", code)
	}
	if code := do("POST", "/api/v1/networks", `{"metadata":{"name":"n1"}}`, map[string]string{"X-CSRF-Token": csrf, "Origin": e.HTTP.URL}); code != 400 {
		t.Fatalf("authorised mutation reached the handler: %d", code)
	}
	if code := do("GET", "/api/v1/auth/session", "", nil); code != 200 {
		t.Fatalf("session info: %d", code)
	}
	if code := do("POST", "/api/v1/auth/logout", "", map[string]string{"X-CSRF-Token": csrf, "Origin": e.HTTP.URL}); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	// The cookie is dead server side, not merely cleared in the browser.
	raw, _ := http.NewRequest("GET", e.HTTP.URL+"/api/v1/projects", nil)
	raw.AddCookie(sessionCookie)
	resp, err := http.DefaultClient.Do(raw)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("session survived logout: %d", resp.StatusCode)
	}
	// Password change.
	hc2 := jarClient(t)
	login(t, e, hc2, "ann", goodPassword, "")
	hc = hc2
	var csrf2 string
	for _, ck := range hc.Jar.Cookies(u) {
		if ck.Name == "jailops_csrf" {
			csrf2 = ck.Value
		}
	}
	h2 := map[string]string{"X-CSRF-Token": csrf2, "Origin": e.HTTP.URL}
	if code := do("POST", "/api/v1/auth/password", `{"current":"wrong","new":"An0ther-Good-pw!"}`, h2); code != 401 {
		t.Fatalf("%d", code)
	}
	if code := do("POST", "/api/v1/auth/password", `{"current":"`+goodPassword+`","new":"An0ther-Good-pw!"}`, h2); code != 200 {
		t.Fatalf("%d", code)
	}
	if code, _ := login(t, e, nil, "ann", goodPassword, ""); code != 401 {
		t.Fatalf("old password still works: %d", code)
	}
	if code, _ := login(t, e, nil, "ann", "An0ther-Good-pw!", ""); code != 200 {
		t.Fatalf("new password: %d", code)
	}
}

func TestTOTPEnrollmentAndLogin(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	hc := jarClient(t)
	login(t, e, hc, "ann", goodPassword, "")
	u, _ := url.Parse(e.HTTP.URL)
	var csrf string
	for _, ck := range hc.Jar.Cookies(u) {
		if ck.Name == "jailops_csrf" {
			csrf = ck.Value
		}
	}
	post := func(path, body string) (int, api.Response) {
		req, _ := http.NewRequest("POST", e.HTTP.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Origin", e.HTTP.URL)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var env api.Response
		_ = json.NewDecoder(resp.Body).Decode(&env)
		return resp.StatusCode, env
	}
	if code, _ := post("/api/v1/auth/totp", ""); code != 401 {
		t.Fatalf("enrolment without the password: %d", code)
	}
	if code, _ := post("/api/v1/auth/totp", `{"password":"wrong-password-1"}`); code != 401 {
		t.Fatalf("enrolment with a wrong password: %d", code)
	}
	code, env := post("/api/v1/auth/totp", `{"password":"`+goodPassword+`"}`)
	var enr struct{ Secret, URI string }
	_ = json.Unmarshal(env.Metadata, &enr)
	if code != 200 || enr.Secret == "" || !strings.HasPrefix(enr.URI, "otpauth://") {
		t.Fatalf("%d %s", code, env.Metadata)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(enr.Secret))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post("/api/v1/auth/totp", `{"code":"000000"}`); code != 401 {
		t.Fatalf("a wrong code enabled TOTP: %d", code)
	}
	code, env = post("/api/v1/auth/totp", `{"code":"`+auth.TOTPCode(secret, time.Now(), auth.TOTPConfig{})+`"}`)
	var rec struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(env.Metadata, &rec)
	if code != 200 || len(rec.RecoveryCodes) != 10 {
		t.Fatalf("%d %s", code, env.Metadata)
	}
	// Login now asks for the second factor.
	st, out := login(t, e, nil, "ann", goodPassword, "")
	if st != 401 || out["error"].(*api.Error).Detail["totp"] != "required" {
		t.Fatalf("%d %v", st, out)
	}
	if st, _ := login(t, e, nil, "ann", goodPassword, "123456"); st != 401 {
		t.Fatalf("%d", st)
	}
	// A recovery code works once.
	if st, _ := login(t, e, nil, "ann", goodPassword, rec.RecoveryCodes[0]); st != 200 {
		t.Fatalf("recovery code: %d", st)
	}
	if st, _ := login(t, e, nil, "ann", goodPassword, rec.RecoveryCodes[0]); st != 401 {
		t.Fatalf("recovery code reused: %d", st)
	}
	// A TOTP code works, and not twice in the same step.
	code6 := auth.TOTPCode(secret, time.Now().Add(30*time.Second), auth.TOTPConfig{}) // next step: unused so far
	if st, _ := login(t, e, nil, "ann", goodPassword, code6); st != 200 {
		t.Fatalf("totp: %d", st)
	}
	if st, _ := login(t, e, nil, "ann", goodPassword, code6); st != 401 {
		t.Fatalf("totp replay: %d", st)
	}
	// New recovery codes need the password again.
	if code, _ := post("/api/v1/auth/recovery-codes", ""); code != 401 {
		t.Fatalf("recovery codes without the password: %d", code)
	}
	code, env = post("/api/v1/auth/recovery-codes", `{"password":"`+goodPassword+`"}`)
	_ = json.Unmarshal(env.Metadata, &rec)
	if code != 200 || len(rec.RecoveryCodes) != 10 {
		t.Fatalf("%d %s", code, env.Metadata)
	}
}

func TestLoginLockoutAnd429(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	var last int
	var retry string
	for i := 0; i < 8; i++ {
		body := `{"username":"ann","password":"wrong-password-` + string(rune('a'+i)) + `"}`
		resp, err := http.Post(e.HTTP.URL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		last, retry = resp.StatusCode, resp.Header.Get("Retry-After")
		if last == 429 {
			break
		}
		if last != 401 {
			t.Fatalf("attempt %d: %d", i, last)
		}
	}
	if last != 429 || retry == "" {
		t.Fatalf("no lockout: %d %q", last, retry)
	}
	// While locked, even the right password is refused: no oracle.
	if st, out := login(t, e, nil, "ann", goodPassword, ""); st != 429 {
		t.Fatalf("%d %v", st, out)
	}
	// The envelope carries the stable code.
	resp, _ := http.Post(e.HTTP.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"username":"ann","password":"x"}`))
	var env api.Response
	_ = json.NewDecoder(resp.Body).Decode(&env)
	resp.Body.Close()
	if env.Error == nil || env.Error.Code != api.CodeRateLimited {
		t.Fatalf("%+v", env)
	}
}

func TestBadTokenLockout(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	bad := "jot_" + strings.Repeat("a", 52)
	var last int
	for i := 0; i < 10; i++ {
		last, _ = e.Raw("GET", "/api/v1/jails?project=alpha", bad, "")
		if last == 429 {
			break
		}
		if last != 401 {
			t.Fatalf("%d", last)
		}
	}
	if last != 429 {
		t.Fatalf("no lockout after repeated bad tokens: %d", last)
	}
}

type urlT = url.URL

func parseURL(s string) (*url.URL, error) { return url.Parse(s) }

// enrolled returns an environment with user ann enrolled for TOTP, her secret, and a signed-in client.
func enrolled(t *testing.T) (*dtest.Env, []byte, func(method, path, body string) int) {
	t.Helper()
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	hc := jarClient(t)
	login(t, e, hc, "ann", goodPassword, "")
	u, _ := url.Parse(e.HTTP.URL)
	var csrf string
	for _, ck := range hc.Jar.Cookies(u) {
		if ck.Name == "jailops_csrf" {
			csrf = ck.Value
		}
	}
	var enrolledSecret string
	send := func(method, path, body string) int {
		req, _ := http.NewRequest(method, e.HTTP.URL+path, strings.NewReader(body))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Origin", e.HTTP.URL)
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if path == "/api/v1/auth/totp" && strings.Contains(body, "password") {
			var env api.Response
			_ = json.NewDecoder(resp.Body).Decode(&env)
			var enr struct{ Secret string }
			_ = json.Unmarshal(env.Metadata, &enr)
			enrolledSecret = enr.Secret
		}
		return resp.StatusCode
	}
	if send("POST", "/api/v1/auth/totp", `{"password":"`+goodPassword+`"}`) != 200 {
		t.Fatal("enrollment")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(enrolledSecret))
	if err != nil {
		t.Fatal(err)
	}
	if send("POST", "/api/v1/auth/totp", `{"code":"`+auth.TOTPCode(secret, time.Now(), auth.TOTPConfig{})+`"}`) != 200 {
		t.Fatal("confirm")
	}
	return e, secret, send
}

// The same code presented by many logins at once is accepted once.
func TestTOTPCodeIsSingleUseUnderConcurrency(t *testing.T) {
	e, secret, _ := enrolled(t)
	code := auth.TOTPCode(secret, time.Now().Add(30*time.Second), auth.TOTPConfig{})
	var wg sync.WaitGroup
	var okN atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st, _ := login(t, e, nil, "ann", goodPassword, code); st == 200 {
				okN.Add(1)
			}
		}()
	}
	wg.Wait()
	if okN.Load() != 1 {
		t.Fatalf("%d logins accepted the same code", okN.Load())
	}
}

// Verifying the password or a code for a signed-in user is rate-limited like a login.
func TestSecretCheckingEndpointsLockOut(t *testing.T) {
	_, _, send := enrolled(t)
	var last int
	for i := 0; i < 12; i++ {
		last = send("POST", "/api/v1/auth/password", `{"current":"wrong-`+strconv.Itoa(i)+`","new":"another-long-password-1"}`)
		if last == 429 {
			break
		}
	}
	if last != 429 {
		t.Fatalf("no lockout on password change: %d", last)
	}
}

// A body that is not declared as JSON is refused, so a cross-site form post cannot reach a handler.
func TestBodiesMustBeJSON(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	tok := e.ScopelessToken(api.PermAdmin)
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		req, _ := http.NewRequest("POST", e.HTTP.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"a","password":"b"}`))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("content type %q: %d", ct, resp.StatusCode)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	resp, err := http.Get(e.HTTP.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "base-uri 'none'") || !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("csp: %q", csp)
	}
}

// What strangers at one address did does not lock out the others: a valid token is never refused for the bad tokens
// that came from its address, and the wrong passwords of one user do not lock another user at the same address.
func TestSharedAddressDoesNotLockOutOthers(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	c := ctxT(t)
	for _, name := range []string{"ann", "bob"} {
		if _, err := e.Admin.Users().Create(c, api.UserCreate{Metadata: api.ObjectMeta{Name: name}, Password: goodPassword,
			Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}}); err != nil {
			t.Fatal(err)
		}
	}
	good := e.Token(api.PermAdmin)
	bad := "jot_" + strings.Repeat("a", 52)
	for range 12 {
		e.Raw("GET", "/api/v1/jails?project=alpha", bad, "")
	}
	if code, _ := e.Raw("GET", "/api/v1/jails?project=alpha", bad, ""); code != 429 {
		t.Fatalf("bad tokens are not limited: %d", code)
	}
	if code, body := e.Raw("GET", "/api/v1/jails?project=alpha", good, ""); code == 401 || code == 429 {
		t.Fatalf("a valid token from an address with bad tokens: %d %s", code, body)
	}
	h := e.D.Handler()
	login := func(user, pw string) int {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+pw+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.50:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for range 6 {
		login("ann", "wrong-password-guess")
	}
	if code := login("ann", goodPassword); code != 429 {
		t.Fatalf("ann after six wrong passwords: %d", code)
	}
	if code := login("bob", goodPassword); code != 200 {
		t.Fatalf("bob at the same address as ann's wrong passwords: %d", code)
	}
}
