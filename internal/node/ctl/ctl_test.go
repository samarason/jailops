package ctl_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func open(t *testing.T) *ctl.DB {
	t.Helper()
	db, err := ctl.Open(context.Background(), testdb.New(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

const (
	g1 = "00000000000000000000000000000001"
	fp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestMigrateTwiceAndRefuseNewer(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if _, err := db.Pool().Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ('9999_from_the_future.sql')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "newer release") {
		t.Fatalf("a database from a newer release must be refused, got %v", err)
	}
}

func TestOneOpenSessionPerGroup(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now() // the leases run on a clock the test moves by hand
	db.SetClock(func() time.Time { return now })
	h, err := db.EnrollHost(ctx, "h1", fp, []string{"backup-push"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ClaimGroup(ctx, g1, h.ID); err != nil {
		t.Fatal(err)
	}
	s1, err := db.OpenSession(ctx, g1, h.ID, "20260101000000-00000001", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.OpenSession(ctx, g1, h.ID, "20260101000001-00000002", "", time.Minute); !errors.Is(err, ctl.ErrConflict) {
		t.Fatalf("second open session: %v", err)
	}
	// renewing extends and counts
	r, err := db.RenewSession(ctx, s1.ID, time.Hour, 3, 300)
	if err != nil || r.ChunksPut != 3 || !r.LeaseUntil.After(s1.LeaseUntil) {
		t.Fatalf("renew: %+v %v", r, err)
	}
	// closing frees the group
	if err := db.CloseSession(ctx, s1.ID, ctl.SessionAborted); err != nil {
		t.Fatal(err)
	}
	s2, err := db.OpenSession(ctx, g1, h.ID, "20260101000001-00000002", "", time.Millisecond*50)
	if err != nil {
		t.Fatal(err)
	}
	// an expired lease is taken over, and cannot be renewed
	now = now.Add(120 * time.Millisecond)
	if _, err := db.RenewSession(ctx, s2.ID, time.Minute, 0, 0); !errors.Is(err, ctl.ErrNotFound) {
		t.Fatalf("renewing an expired lease: %v", err)
	}
	if _, err := db.OpenSession(ctx, g1, h.ID, "20260101000002-00000003", "", time.Minute); err != nil {
		t.Fatalf("takeover after expiry: %v", err)
	}
	got, _ := db.Session(ctx, s2.ID)
	if got.State != ctl.SessionExpired {
		t.Fatalf("old session is %s", got.State)
	}
}

func TestGroupOwnership(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	a, _ := db.EnrollHost(ctx, "a", fp, []string{"backup-push"}, "", "")
	b, _ := db.EnrollHost(ctx, "b", strings.Repeat("b", 64), []string{"backup-push"}, "", "")
	if err := db.ClaimGroup(ctx, g1, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.ClaimGroup(ctx, g1, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.ClaimGroup(ctx, g1, b.ID); !errors.Is(err, ctl.ErrGroupOwned) {
		t.Fatalf("another host's group: %v", err)
	}
	if _, err := db.EnrollHost(ctx, "c", fp, nil, "", ""); !errors.Is(err, ctl.ErrConflict) {
		t.Fatalf("duplicate fingerprint: %v", err)
	}
	if _, err := db.RevokeHost(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	h, _ := db.HostByFingerprint(ctx, fp)
	if h.Active() {
		t.Fatal("revoked host is active")
	}
	// a config entry never resurrects a revoked host
	_ = db.EnsureHost(ctx, "a2", fp, []string{"backup-push"}, "")
	h, _ = db.HostByFingerprint(ctx, fp)
	if h.Active() {
		t.Fatal("EnsureHost resurrected a revoked host")
	}
}

func TestSnapshotsAndJobs(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := ctl.Snapshot{GroupID: g1, SnapshotID: "20260101000000-00000001", CommittedAt: now, ChunkCount: 5, IndexBytes: 100,
		IndexDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64), Source: "client"}
	if err := db.UpsertSnapshot(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProtected(ctx, g1, s.SnapshotID, true); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVerify(ctx, g1, s.SnapshotID, "failed", now, []string{"chunk-corrupt: x"}); err != nil {
		t.Fatal(err)
	}
	got, err := db.Snapshot(ctx, g1, s.SnapshotID)
	if err != nil || !got.Protected || got.VerifyState != "failed" || len(got.VerifyProblems) != 1 || !got.CommittedAt.Equal(now) {
		t.Fatalf("%+v %v", got, err)
	}
	if err := db.SetProtected(ctx, g1, "nope", true); !errors.Is(err, ctl.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	j, err := db.StartJob(ctx, ctl.JobGC, "t", map[string]any{"dry": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartJob(ctx, ctl.JobVerify, "t", nil); !errors.Is(err, ctl.ErrConflict) {
		t.Fatalf("exclusive jobs: %v", err)
	}
	if _, err := db.StartJob(ctx, ctl.JobRestoreTest, "t", nil); err != nil {
		t.Fatalf("a restore test is not exclusive: %v", err)
	}
	if err := db.FinishJob(ctx, j.ID, ctl.JobSucceeded, map[string]int{"removed": 2}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartJob(ctx, ctl.JobVerify, "t", nil); err != nil {
		t.Fatalf("after finishing: %v", err)
	}
	last, err := db.LastJob(ctx, ctl.JobGC)
	if err != nil || !strings.Contains(string(last.Result), "removed") {
		t.Fatalf("%+v %v", last, err)
	}
	n, _ := db.AbandonJobs(ctx)
	if n != 2 {
		t.Fatalf("abandoned %d", n)
	}
	if err := db.ClearIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if l, _ := db.Snapshots(ctx, ""); len(l) != 0 {
		t.Fatal("index not cleared")
	}
}

func TestUsersTokensAudit(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	if err := db.CreateUser(ctx, "alice", "hash", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(ctx, "alice", "hash", "admin"); !errors.Is(err, ctl.ErrConflict) {
		t.Fatal(err)
	}
	if err := db.CreateUser(ctx, "Bad Name", "hash", "admin"); err == nil {
		t.Fatal("a bad name was accepted")
	}
	if _, err := db.CreateToken(ctx, "ci", []byte("h"), "readonly", nil, nil); err != nil {
		t.Fatal(err)
	}
	tk, err := db.TokenByHash(ctx, []byte("h"))
	if err != nil || tk.Role != "readonly" {
		t.Fatalf("%+v %v", tk, err)
	}
	if err := db.CreateUISession(ctx, []byte("sid"), "alice", "csrf", time.Hour); err != nil {
		t.Fatal(err)
	}
	if s, err := db.UISessionByHash(ctx, []byte("sid")); err != nil || s.User != "alice" {
		t.Fatalf("%+v %v", s, err)
	}
	if err := db.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UISessionByHash(ctx, []byte("sid")); !errors.Is(err, ctl.ErrNotFound) {
		t.Fatal("a deleted user's session survives")
	}
	_ = db.Audit(ctx, "alice", "gc.start", "", map[string]string{"x": "y"}, "unix")
	_ = db.Audit(ctx, "alice", "host.revoke", "h", nil, "")
	l, err := db.AuditLog(ctx, "gc.", 10, 0)
	if err != nil || len(l) != 1 || l[0].Actor != "alice" {
		t.Fatalf("%+v %v", l, err)
	}
	var mode string
	if err := db.Setting(ctx, "maintenance", &mode); !errors.Is(err, ctl.ErrNotFound) {
		t.Fatal(err)
	}
	_ = db.SetSetting(ctx, "maintenance", "read-only")
	_ = db.Setting(ctx, "maintenance", &mode)
	if mode != "read-only" {
		t.Fatal(mode)
	}
}
