package store

import (
	"strings"
	"testing"
	"time"
)

// The escape and cut of every audit field.
func TestAuditText(t *testing.T) {
	for in, want := range map[string]string{
		"plain /api/v1/jails/web":  "plain /api/v1/jails/web",
		"a\x1b[2Jb\r\nc":           `a\x1b[2Jb\r\nc`,
		"bidi\u202eevil\u200b":     `bidi\u202eevil\u200b`,
		"bad\xffutf8":              `bad\xffutf8`,
		strings.Repeat("x", 300):   strings.Repeat("x", 256) + "...",
		`quoted "x" stays \ as is`: `quoted "x" stays \ as is`,
	} {
		if got := AuditText(in, 256); got != want {
			t.Errorf("AuditText(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every entry is escaped and cut when it is appended; an anonymous caller's detail is cut shorter.
func TestAuditAppendBoundsItsFields(t *testing.T) {
	s, _ := newStore(t, Options{})
	long := strings.Repeat("y", 10000)
	for _, kind := range []string{"anonymous", "token"} {
		if _, err := s.Audit.Append(ctx, AuditEntry{Actor: "-", ActorKind: kind, Method: "GET", Route: "/r", Result: "denied",
			Object: "/api/v1/jails/\x1b]0;x\x07" + long, Detail: long}); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.Audit.List(ctx, AuditFilter{})
	if err != nil || len(l) != 2 {
		t.Fatal(l, err)
	}
	for _, e := range l {
		max := MaxAuditDetail
		if e.ActorKind == "anonymous" {
			max = MaxAuditDetailAnonymous
		}
		if len(e.Object) > MaxAuditObject+3 || strings.Contains(e.Object, "\x1b") || len(e.Detail) != max+3 {
			t.Errorf("%s: object %d bytes %q..., detail %d bytes", e.ActorKind, len(e.Object), e.Object[:30], len(e.Detail))
		}
	}
}

// Retention deletes what is older than the cut and what lies beyond the row limit, never one of the newest AuditKeep
// entries; the database refuses to delete those as well.
func TestAuditPruneKeepsTheNewest(t *testing.T) {
	s, clk := newStore(t, Options{})
	add := func(n int) {
		for range n {
			if _, err := s.Audit.Append(ctx, AuditEntry{Actor: "a", Method: "POST", Route: "/r", Result: "ok"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	count := func() int {
		l, err := s.Audit.List(ctx, AuditFilter{Limit: 10000})
		if err != nil {
			t.Fatal(err)
		}
		return len(l)
	}
	add(300) // old
	clk.Add(100 * 24 * time.Hour)
	add(200) // recent
	// all 500 are among the newest 1000: nothing goes, however old
	if n, err := s.Audit.Prune(ctx, clk.Now().Add(-90*24*time.Hour), 1000); err != nil || n != 0 || count() != 500 {
		t.Fatalf("pruned %d (%v), %d left", n, err, count())
	}
	add(1000)
	// 1500 entries: the 300 old ones are older than 90 days and not among the newest 1000
	if n, err := s.Audit.Prune(ctx, clk.Now().Add(-90*24*time.Hour), 1000000); err != nil || n != 300 || count() != 1200 {
		t.Fatalf("by age: pruned %d (%v), %d left", n, err, count())
	}
	// the row limit: at most 1100 entries
	if n, err := s.Audit.Prune(ctx, clk.Now().Add(-365*24*time.Hour), 1100); err != nil || n != 100 || count() != 1100 {
		t.Fatalf("by rows: pruned %d (%v), %d left", n, err, count())
	}
	// a limit below AuditKeep keeps AuditKeep
	if n, err := s.Audit.Prune(ctx, clk.Now(), 10); err != nil || n != 100 || count() != AuditKeep {
		t.Fatalf("below the floor: pruned %d (%v), %d left", n, err, count())
	}
	if _, err := s.w.Exec("DELETE FROM audit WHERE id = (SELECT MAX(id) FROM audit)"); err == nil {
		t.Fatal("the database deleted the newest entry")
	}
}
