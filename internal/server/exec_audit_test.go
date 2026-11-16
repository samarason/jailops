package server

import (
	"strings"
	"testing"
)

func TestAuditArgvCutsLongArguments(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := auditArgv([]string{"sh", "-c", long, "short"})
	if got[0] != "sh" || got[3] != "short" || !strings.HasSuffix(got[2], "...(300 bytes more)") || len(got[2]) > auditArgvMax+30 {
		t.Fatalf("%q", got)
	}
}
