package node_test

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"jailops.net/jailops/internal/node"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/sdk/api"
)

func TestEscrowBindsTheKeyDomainOnFirstUse(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	a, b := e.Host(t, "a"), e.Host(t, "b")
	const x, y = "5e62dd65bc023787", "0123456789abcdef"
	blob := []byte("age-encryption.org/v1\n-> X25519 stanza\nblob")
	if err := e.Node.PutEscrow(ctx, a, x, bytes.NewReader(blob), int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	if got := e.Node.Info().KeyDomain; got != x {
		t.Fatalf("the repository is bound to %q", got)
	}
	// another host cannot park an escrow of another domain in this repository
	if err := e.Node.PutEscrow(ctx, b, y, bytes.NewReader(blob), int64(len(blob))); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a second domain was accepted: %v", err)
	}
	// and a session for another key is refused from now on
	f := nodetest.NewFixture(t, 21)
	if _, err := e.Node.BeginWith(ctx, b, wire.BeginRequest{Group: f.Group("b", "j"), Snapshot: nodetest.SnapshotID(e.Clock.Now(), 1), KeyDomain: y}); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a session with another key domain: %v", err)
	}
}

func TestHostsSeeOnlyTheirGroupsAndReportOnlyOnThem(t *testing.T) {
	e := nodetest.NewEnv(t, nodetest.Options{})
	owner, other := e.Host(t, "owner"), e.Host(t, "other")
	recovery := e.Host(t, "recovery", "backup-pull", "restore")
	f := nodetest.NewFixture(t, 22)
	g := f.Group("owner", "j")
	snap := nodetest.SnapshotID(e.Clock.Now(), 1)
	f.NewBackup(t, g, snap, []nodetest.Chunk{f.NewChunk(t)}).Upload(t, e.Node, owner, "")

	get := func(h node.Host, path string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", wire.Base+path, nil).WithContext(node.WithHost(ctx, h))
		e.Node.Handler().ServeHTTP(w, r)
		return w.Code
	}
	for _, p := range []string{"/groups/" + g + "/snapshots/" + snap, "/groups/" + g + "/snapshots/" + snap + "/manifest"} {
		if c := get(owner, p); c != 200 {
			t.Errorf("owner %s: %d", p, c)
		}
		if c := get(recovery, p); c != 200 {
			t.Errorf("recovery host %s: %d", p, c)
		}
		if c := get(other, p); c != 404 {
			t.Errorf("another host %s: %d", p, c)
		}
	}
	if gs, err := e.Node.GroupsOf(ctx, other); err != nil || len(gs) != 0 {
		t.Fatalf("another host lists %v %v", gs, err)
	}
	if gs, err := e.Node.GroupsOf(ctx, owner); err != nil || len(gs) != 1 {
		t.Fatalf("the owner lists %v %v", gs, err)
	}

	// restore-test reports: not for another host's group, not for a snapshot that does not exist
	rt := node.RestoreTest{Group: g, Snapshot: snap, Method: "deep", OK: false, Problems: []string{"x"}}
	if err := e.Node.RecordRestoreTest(ctx, other, rt); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("another host reported on the group: %v", err)
	}
	ghost := rt
	ghost.Snapshot = nodetest.SnapshotID(e.Clock.Now(), 9)
	if err := e.Node.RecordRestoreTest(ctx, owner, ghost); err == nil {
		t.Fatal("a report on a snapshot nobody committed was recorded")
	}
	if jobs, _ := e.DB.Jobs(ctx, "restore-test", 50); len(jobs) != 0 {
		t.Fatalf("%d jobs were written by refused reports", len(jobs))
	}
	if err := e.Node.RecordRestoreTest(ctx, recovery, rt); err != nil {
		t.Fatal(err)
	}
}
