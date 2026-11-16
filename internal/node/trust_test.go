package node_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

// The first session of a repository that records no key domain binds it, as the first escrow does: a host with
// another key is refused before it stores anything.
func TestBeginBindsTheKeyDomain(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	if d := e.Node.Info().KeyDomain; d != "" {
		t.Fatalf("a new repository is bound to %q", d)
	}
	a, b := e.Host(t, "a"), e.Host(t, "b")
	f := nodetest.NewFixture(t, 31)
	const x, y = "0123456789abcdef", "fedcba9876543210"
	si, err := e.Node.BeginWith(ctx, a, wire.BeginRequest{Group: f.Group("a", "j"), Snapshot: snapID(e, 1), KeyDomain: x})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Node.Abort(ctx, a, si.ID)
	if got := e.Node.Info().KeyDomain; got != x {
		t.Fatalf("the session did not bind the key domain: %q", got)
	}
	if _, err := e.Node.BeginWith(ctx, b, wire.BeginRequest{Group: f.Group("b", "j"), Snapshot: snapID(e, 2), KeyDomain: y}); code(err) != api.CodeForbidden {
		t.Fatalf("a host with another key: %v", err)
	}
	// a malformed request binds nothing
	e2 := nodetest.NewEnv(t, nodetest.Options{})
	if _, err := e2.Node.BeginWith(ctx, e2.Host(t, "a"), wire.BeginRequest{Group: "nonsense", Snapshot: snapID(e2, 1), KeyDomain: x}); code(err) != api.CodeInvalid {
		t.Fatalf("%v", err)
	}
	if d := e2.Node.Info().KeyDomain; d != "" {
		t.Fatalf("a refused request bound the repository to %q", d)
	}
}

// The node cannot open an escrow blob, but it refuses what is not an age file, and an administrator can delete a
// damaged one so that a host stores a new one.
func TestEscrowIsAnAgeFileAndAnAdminCanDeleteIt(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	h := e.Host(t, "a")
	const d = "0123456789abcdef"
	for _, bad := range []string{"not age at all", "age-encryption.org/v1 blob", "age-encryption.org/v2\n-> X25519 x\n", "-----BEGIN AGE ENCRYPTED FILE-----\n"} {
		if err := e.Node.PutEscrow(ctx, h, d, strings.NewReader(bad), int64(len(bad))); code(err) != api.CodeInvalid {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if got := e.Node.Info().KeyDomain; got != "" {
		t.Fatalf("a refused blob bound the repository to %q", got)
	}
	wrong := []byte("age-encryption.org/v1\n-> X25519 to the wrong recipient\n")
	if err := e.Node.PutEscrow(ctx, h, d, bytes.NewReader(wrong), int64(len(wrong))); err != nil {
		t.Fatal(err)
	}
	good := []byte("age-encryption.org/v1\n-> X25519 to the recovery recipient\n")
	if err := e.Node.PutEscrow(ctx, h, d, bytes.NewReader(good), int64(len(good))); code(err) != api.CodeAlreadyExists {
		t.Fatalf("a host replaced an escrow blob: %v", err)
	}

	// over the admin handler: a reader may list, only an admin may delete
	srv := httptest.NewServer(withActor(e.Node.AdminHandler(), node.ScopeRead))
	defer srv.Close()
	if st := do(t, "DELETE", srv.URL+node.Base+"/admin/escrow/"+d); st != http.StatusForbidden {
		t.Fatalf("a reader deleted an escrow blob: %d", st)
	}
	if st := do(t, "GET", srv.URL+node.Base+"/admin/escrow"); st != 200 {
		t.Fatalf("list: %d", st)
	}
	adm := httptest.NewServer(withActor(e.Node.AdminHandler(), node.ScopeAdmin))
	defer adm.Close()
	if st := do(t, "DELETE", adm.URL+node.Base+"/admin/escrow/"+d); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if st := do(t, "DELETE", adm.URL+node.Base+"/admin/escrow/"+d); st != http.StatusNotFound {
		t.Fatalf("delete again: %d", st)
	}
	if st := do(t, "DELETE", adm.URL+node.Base+"/admin/escrow/..%2Fmeta"); st != http.StatusBadRequest {
		t.Fatalf("a malformed domain: %d", st)
	}
	if err := e.Node.PutEscrow(ctx, h, d, bytes.NewReader(good), int64(len(good))); err != nil {
		t.Fatalf("a new blob after the delete: %v", err)
	}
	if got, _ := e.Node.GetEscrow(ctx, d); !bytes.Equal(got, good) {
		t.Fatalf("%q", got)
	}
	if got := e.Node.Info().KeyDomain; got != d {
		t.Fatalf("the delete unbound the repository: %q", got)
	}
}

// Poisoning inside one key domain: the node checks only the unkeyed trailer and stores chunks create-only, so a
// host that uploads a self-consistent blob under another host's chunk id first makes the node answer "present" to
// the honest host. This stays possible within a key domain (hosts of one domain hold the same key and trust each
// other); the remedy is an administrator's quarantine of the chunk a host reported, after which the honest host
// uploads it again.
func TestChunkPoisoningWithinAKeyDomainAndTheRemedy(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	evil, honest := e.Host(t, "evil"), e.Host(t, "honest")
	f := nodetest.NewFixture(t, 41)
	victim := f.NewChunk(t) // what the honest host will back up
	other := f.NewChunk(t)  // a valid blob of other content

	si, err := e.Node.Begin(ctx, evil, f.Group("evil", "j"), snapID(e, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Node.PutChunk(ctx, evil, si.ID, victim.ID, bytes.NewReader(other.Blob), int64(len(other.Blob))); err != nil {
		t.Fatalf("the node refused a blob with a valid trailer under another id: %v", err)
	}
	_ = e.Node.Abort(ctx, evil, si.ID)
	if _, err := f.Keys.DecodeChunk(mustRead(t, e.Raw, chunkKey(victim.ID)), victim.ID); err == nil {
		t.Fatal("the planted blob decodes as the victim's chunk")
	}

	missing := func() []format.ID {
		t.Helper()
		si, err := e.Node.Begin(ctx, honest, f.Group("honest", "j"), snapID(e, 2), "")
		if err != nil {
			t.Fatal(err)
		}
		defer e.Node.Abort(ctx, honest, si.ID)
		m, err := e.Node.Missing(ctx, honest, si.ID, []format.ID{victim.ID})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := missing(); len(m) != 0 {
		t.Fatalf("the node reported the planted chunk missing: %v", m)
	}
	// keyless verification and the ordinary quarantine see nothing wrong
	if moved, err := e.Node.Quarantine(ctx, victim.ID); err != nil || moved {
		t.Fatalf("the keyless quarantine moved a blob with a valid trailer: %v %v", moved, err)
	}

	// the remedy: an administrator quarantines the chunk the honest host reported
	srv := httptest.NewServer(withActor(e.Node.AdminHandler(), node.ScopeRead))
	defer srv.Close()
	if st := do(t, "POST", srv.URL+node.Base+"/admin/quarantine/"+victim.ID.String()); st != http.StatusForbidden {
		t.Fatalf("a reader quarantined a chunk: %d", st)
	}
	adm := httptest.NewServer(withActor(e.Node.AdminHandler(), node.ScopeAdmin))
	defer adm.Close()
	if st := do(t, "POST", adm.URL+node.Base+"/admin/quarantine/not-an-id"); st != http.StatusBadRequest {
		t.Fatalf("a malformed id: %d", st)
	}
	if st := do(t, "POST", adm.URL+node.Base+"/admin/quarantine/"+victim.ID.String()); st != 200 {
		t.Fatalf("quarantine: %d", st)
	}
	if m := missing(); len(m) != 1 || m[0] != victim.ID {
		t.Fatalf("after the quarantine the chunk is not missing: %v", m)
	}
	b := f.NewBackup(t, f.Group("honest", "j"), snapID(e, 3), []nodetest.Chunk{victim})
	b.Upload(t, e.Node, honest, "")
	got, err := f.Keys.DecodeChunk(mustRead(t, e.Raw, chunkKey(victim.ID)), victim.ID)
	if err != nil || len(got) != victim.Size {
		t.Fatalf("the honest copy is not in the repository: %v", err)
	}
	if _, err := datastore.ReadAll(ctx, e.Raw, "quarantine/"+victim.ID.String(), 1<<30); err != nil {
		t.Fatalf("the planted blob was not kept for inspection: %v", err)
	}
}

func withActor(h http.Handler, perm api.Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(node.WithActor(r.Context(), node.Actor{Name: "root", Perm: perm})))
	})
}

func do(t *testing.T, method, url string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
