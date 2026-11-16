package fake_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// webProject seeds the project the wire tests work in: the server has no default project.
func webProject(s *fake.Server) {
	s.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "lan"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}})
	s.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.20"}}})
}

func do(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string) (*httptest.ResponseRecorder, api.Response) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var env api.Response
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	return w, env
}

// The wire contract as seen without the SDK: envelopes, status codes, ETag.
func TestWireContract(t *testing.T) {
	s := fake.New()
	defer s.Close()
	webProject(s)
	if w, env := do(t, s, "GET", "/api/v1/firewall/address-sets", "", nil); w.Code != 400 || env.Error.Code != api.CodeInvalid || !strings.Contains(env.Error.Message, "a project is required") {
		t.Fatalf("no project: %d %s", w.Code, w.Body)
	}
	w, env := do(t, s, "POST", "/api/v1/firewall/address-sets?project=web", `{"metadata":{"name":"office"},"spec":{"addresses":[{"address":"10.0.0.0/8"}]}}`, nil)
	if w.Code != 201 || env.Type != api.ResponseSync {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	w, _ = do(t, s, "GET", "/api/v1/firewall/address-sets/office?project=web", "", nil)
	if w.Header().Get("ETag") != `"1"` {
		t.Fatalf("etag %q", w.Header().Get("ETag"))
	}
	body := `{"metadata":{"name":"office"},"spec":{"addresses":[{"address":"10.1.0.0/16"}]}}`
	w, env = do(t, s, "PUT", "/api/v1/firewall/address-sets/office?project=web", body, map[string]string{"If-Match": `"7"`})
	if w.Code != 412 || env.Type != api.ResponseError || env.Error.Code != api.CodeConflict {
		t.Fatalf("stale put: %d %s", w.Code, w.Body)
	}
	w, _ = do(t, s, "PUT", "/api/v1/firewall/address-sets/office?project=web", body, map[string]string{"If-Match": `"1"`})
	if w.Code != 200 || w.Header().Get("ETag") != `"2"` {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	// An identical PUT changes nothing and keeps the generation.
	w, _ = do(t, s, "PUT", "/api/v1/firewall/address-sets/office?project=web", body, nil)
	if w.Header().Get("ETag") != `"2"` {
		t.Fatalf("no-op put bumped the generation: %s", w.Header().Get("ETag"))
	}
	w, env = do(t, s, "GET", "/api/v1/nothing", "", nil)
	if w.Code != 404 || env.Error.Code != api.CodeNotFound {
		t.Fatal(w.Body)
	}
}

func TestAsyncEnvelope(t *testing.T) {
	s := fake.New()
	defer s.Close()
	webProject(s)
	s.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "img"}})
	w, env := do(t, s, "POST", "/api/v1/jails?project=web", `{"metadata":{"name":"web"},"spec":{"image":"img","storage":"default","network":[{"network":"lan"}]}}`, nil)
	if w.Code != 202 || env.Type != api.ResponseAsync || !strings.HasPrefix(env.Operation, "/api/v1/operations/") ||
		w.Header().Get("Location") != env.Operation {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var op api.Operation
	_ = json.Unmarshal(env.Metadata, &op)
	if op.ID == "" || op.Status.Final() && op.Status != api.OpSuccess {
		t.Fatalf("%+v", op)
	}
	w, env = do(t, s, "GET", env.Operation+"/wait?timeout=5", "", nil)
	_ = json.Unmarshal(env.Metadata, &op)
	if w.Code != 200 || op.Status != api.OpSuccess {
		t.Fatalf("%d %+v", w.Code, op)
	}
}
