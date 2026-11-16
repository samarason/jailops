package server_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/store"
)

// Anonymous callers cannot grow the audit log: nothing of a public route's body is recorded, a path is cut and
// escaped, and while a source is locked out its refusals are counted instead of written one by one.
func TestAnonymousRequestsCannotGrowTheAuditLog(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	big := strings.Repeat("A", 1<<20)
	for range 20 {
		rawDo(t, e, "POST", "/api/v1/auth/login", "", `{"username":"`+big+`","password":"x"}`, nil)
	}
	longPath := "/api/v1/jails/" + strings.Repeat("B", 60<<10) + "%1B]0;OWNED%07"
	for range 20 {
		rawDo(t, e, "GET", longPath, "jot_bogus", "", nil)
	}
	// read in the database: the source of these requests is locked out now, valid tokens included
	ents, err := e.D.Service().DB().Audit.List(ctxT(t), store.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range ents {
		if a.Actor != "-" {
			continue
		}
		n++
		if len(a.Object) > store.MaxAuditObject+8 || len(a.Detail) > store.MaxAuditDetailAnonymous+8 {
			t.Errorf("an anonymous entry of %d+%d bytes", len(a.Object), len(a.Detail))
		}
		if strings.Contains(a.Object, "AAAA") || strings.ContainsAny(a.Object+a.Detail, "\x1b\x07") {
			t.Errorf("entry %q / %q", a.Object, a.Detail)
		}
	}
	// five failures each before the lockout, then one entry per locked-out source
	if n == 0 || n > 12 {
		t.Errorf("%d anonymous entries for 40 refused requests", n)
	}
}
