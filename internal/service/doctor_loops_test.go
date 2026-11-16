package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/supervise"
	"jailops.net/jailops/sdk/api"
)

func TestDoctorWarnsOfARestartedLoop(t *testing.T) {
	supervise.Reset()
	s := &Service{}
	c := &checkSet{}
	s.doctorLoops(c)
	if got := checkStatus(c, "daemon.loops"); got != api.DoctorOK {
		t.Fatalf("no restart: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	supervise.Run(ctx, nil, "heal", func(context.Context) {
		if n++; n == 1 {
			cancel() // the loop is stopped after its panic: the counters stay
			panic("odd state")
		}
	})
	c = &checkSet{}
	s.doctorLoops(c)
	if got := checkStatus(c, "daemon.loops"); got != api.DoctorWarn {
		t.Fatalf("a restarted loop: %v", got)
	}
}

func checkStatus(c *checkSet, name string) api.DoctorStatus {
	for _, ck := range c.list {
		if ck.Name == name {
			return ck.Status
		}
	}
	return ""
}

func TestDoctorMentionsALongOperation(t *testing.T) {
	s := newSvc(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	put := func(id string, age time.Duration, st api.OperationStatus) {
		t.Helper()
		if err := s.d.DB.Operations.Put(bg, api.Operation{ID: id, Description: "Backup " + id, Status: st, CreatedAt: now.Add(-age), UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithActor(bg, Actor{Name: "root", Kind: "unix", Perm: api.PermAdmin, Global: true})
	c := &checkSet{}
	s.doctorLongOperations(ctx, c)
	if got := checkStatus(c, "operations.long"); got != api.DoctorOK {
		t.Fatalf("nothing running: %v", got)
	}
	put("young", 2*time.Minute, api.OpRunning)
	put("old-done", time.Hour, api.OpSuccess)
	c = &checkSet{}
	s.doctorLongOperations(ctx, c)
	if got := checkStatus(c, "operations.long"); got != api.DoctorOK {
		t.Fatalf("a young one and an old finished one: %v", got)
	}
	put("old", 40*time.Minute, api.OpRunning)
	c = &checkSet{}
	s.doctorLongOperations(ctx, c)
	if got := checkStatus(c, "operations.long"); got != api.DoctorWarn || !strings.Contains(c.list[0].Message, "old") {
		t.Fatalf("an operation that runs for 40 minutes: %+v", c.list)
	}
}
