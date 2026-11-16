package server_test

// One identity system over every transport. For every route and every (role, scope) the same identity is presented
// as an API token, as a console session (cookie, CSRF token and Origin) and as a pinned client certificate over the
// TLS listener. The decision (unauthorized, forbidden, hidden as not_found of the project, or passed) must be the
// same on the three, and must match the permission table's role and class. Root and an ordinary user on the unix
// socket are added.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

type matrixIdent struct {
	role     api.Permission
	global   bool
	projects []string
}

func (i matrixIdent) key() string {
	if i.global {
		return string(i.role) + "/global"
	}
	return string(i.role) + "/" + strings.Join(i.projects, ",")
}

type matrixCaller func(method, path, body string) (int, string)

func TestEveryTransportDecidesAlike(t *testing.T) {
	e := dtest.New(t, dtest.Options{Listen: true, Mutate: func(c *daemon.Config) { c.Limits.AuthFailureThreshold = 100000 }})
	e.Seed()
	c := ctxT(t)
	net := e.MakeNetwork("beta")
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	mustJail(t, e, "web")
	svc := e.D.Service()
	addr := e.D.HTTPSAddr()
	base := "https://" + addr

	var idents []matrixIdent
	roles := []api.Permission{api.PermReadonly, api.PermOperator, api.PermAdmin, api.PermRestore}
	if raceEnabled || testing.Short() {
		roles = []api.Permission{api.PermReadonly, api.PermAdmin} // the lowest and the highest
	}
	for _, r := range roles {
		idents = append(idents, matrixIdent{role: r, global: true}, matrixIdent{role: r, projects: []string{"alpha"}}, matrixIdent{role: r, projects: []string{"beta"}})
	}
	plainTC, err := auth.ClientConfigPinned(context.Background(), nil, addr, e.D.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	mkClient := func(tc *tls.Config) *http.Client {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		t.Cleanup(cl.CloseIdleConnections)
		return cl
	}
	plain := mkClient(plainTC)
	send := func(cl *http.Client, method, path, body string, hdr map[string]string, ck *http.Cookie) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if ck != nil {
			req.AddCookie(ck)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return resp.StatusCode, string(b)
	}
	callers := map[string]map[string]matrixCaller{} // identity -> transport -> caller
	for n, id := range idents {
		name := "m" + strconv.Itoa(n)
		ts := map[string]matrixCaller{}
		tk, err := svc.CreateToken(sysCtx, api.Token{Metadata: api.ObjectMeta{Name: "tok-" + name}, Spec: api.TokenSpec{Permission: id.role, Global: id.global, Projects: id.projects}})
		if err != nil {
			t.Fatal(err)
		}
		ts["token"] = func(method, path, body string) (int, string) {
			return send(plain, method, path, body, map[string]string{"Authorization": "Bearer " + tk.Secret}, nil)
		}
		if _, err := svc.CreateUser(sysCtx, api.UserCreate{Metadata: api.ObjectMeta{Name: "usr-" + name}, Password: goodPassword,
			Spec: api.UserSpec{Permission: id.role, Global: id.global, Projects: id.projects}}); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", base+"/api/v1/auth/login", strings.NewReader(`{"username":"usr-`+name+`","password":"`+goodPassword+`"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := plain.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("login %v %v", err, resp)
		}
		resp.Body.Close()
		var sess *http.Cookie
		csrf := ""
		for _, ck := range resp.Cookies() {
			switch ck.Name {
			case auth.SessionCookieNameSecure:
				sess = ck
			case "jailops_csrf":
				csrf = ck.Value
			}
		}
		if sess == nil || csrf == "" {
			t.Fatalf("no secure session cookie: %v", resp.Cookies())
		}
		ts["session"] = func(method, path, body string) (int, string) {
			return send(plain, method, path, body, map[string]string{"X-CSRF-Token": csrf, "Origin": base}, sess)
		}
		cert := newClientCert(t, "crt-"+name)
		leaf := cert.Leaf
		if leaf == nil {
			if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := svc.CreateCertificate(sysCtx, api.Certificate{Metadata: api.ObjectMeta{Name: "crt-" + name},
			Spec: api.CertificateSpec{Fingerprint: auth.CertFingerprint(leaf), Permission: id.role, Kind: "client", Global: id.global, Projects: id.projects}}); err != nil {
			t.Fatal(err)
		}
		ctc, err := auth.ClientConfigPinned(context.Background(), &cert, addr, e.D.Fingerprint())
		if err != nil {
			t.Fatal(err)
		}
		ccl := mkClient(ctc)
		ts["cert"] = func(method, path, body string) (int, string) { return send(ccl, method, path, body, nil, nil) }
		callers[id.key()] = ts
	}
	classify := func(code int, body string) string {
		switch {
		case code == 401:
			return "unauthorized"
		case code == 403 && errorCode(body) == "not_managed":
			return "passed"
		case code == 403:
			return "forbidden"
		case code == 404 && strings.Contains(body, "project") && strings.Contains(body, "not found"):
			return "hidden"
		}
		return "passed"
	}
	reg := auth.DefaultRegistry()
	keys := e.D.Server().RouteKeys()
	sort.Strings(keys)
	checks := 0
	for _, key := range keys {
		method, pattern, _ := strings.Cut(key, " ")
		ent, _ := reg.Lookup(method, pattern)
		// routes that would change what the next transport sees, or that stream
		if method == "DELETE" || strings.HasSuffix(pattern, "/output") || strings.Contains(pattern, "/events") || strings.HasSuffix(pattern, "/wait") ||
			strings.HasSuffix(pattern, "/exec") || pattern == "/api/v1/setup/token" || pattern == "/api/v1/host/certificate/self-signed" ||
			strings.HasPrefix(pattern, "/api/v1/auth/") {
			continue
		}
		path := concrete(pattern) + "?project=alpha"
		// a member no route knows: an authorised request is refused when its body is read, before anything changes
		body := `{"matrix_probe":true}`
		for _, id := range idents {
			got, raw := map[string]string{}, map[string]string{}
			for _, tr := range []string{"cert", "session", "token"} {
				code, b := callers[id.key()][tr](method, path, body)
				got[tr] = classify(code, b)
				if got[tr] == "hidden" && ent.Class != auth.ClassProject && ent.Class != auth.ClassVisible {
					got[tr] = "passed" // the object "x" of the fixture does not exist: the request was authorised
				}
				raw[tr] = strconv.Itoa(code) + " " + errorCode(b)
				checks++
			}
			if got["cert"] != got["token"] || got["session"] != got["token"] {
				t.Errorf("%s as %s: token %s, session %s, cert %s", key, id.key(), raw["token"], raw["session"], raw["cert"])
				continue
			}
			// the decision of the table: role first, then scope
			want := "passed"
			switch {
			case ent.Public:
			case !id.role.Satisfies(ent.Perm):
				want = "forbidden"
			case ent.Class == auth.ClassGlobal && !id.global:
				want = "forbidden"
			case ent.Class == auth.ClassGranted && method != "GET" && !id.global:
				want = "forbidden"
			case (ent.Class == auth.ClassProject || ent.Class == auth.ClassVisible) && !id.global && id.projects[0] != "alpha":
				want = "hidden"
			}
			// a route of class object answers not_found for the object, not for the project: either is right
			objectAlike := ent.Class == auth.ClassObject && (want == "hidden" || got["token"] == "hidden")
			if got["token"] != want && !objectAlike {
				t.Errorf("%s as %s: got %s (%s), the table says %s", key, id.key(), got["token"], raw["token"], want)
			}
		}
	}
	t.Logf("%d requests", checks)
	// the unix socket: root is a global admin, everyone else anonymous
	rootCode, rootBody := serveAs(e, auth.Cred{UID: 0}, "GET", "/api/v1/users", "", "")
	userCode, _ := serveAs(e, auth.Cred{UID: 1001, GID: 1001}, "GET", "/api/v1/users", "", "")
	if rootCode != 200 || userCode != 401 {
		t.Errorf("unix peers: root %d %s, user %d", rootCode, trunc(rootBody), userCode)
	}
}
