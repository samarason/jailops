package service_test

import (
	"context"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// Usage is measured when asked: the space of the datasets always, racct only
// while the jail runs, and a part that cannot be read says why.
func TestJailUsage(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	j := dtest.WebJail("web")
	op, err := s.CreateJail(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create: %+v\n%s", got, e.Log())
	}
	const container = "tank/jailops/projects/alpha/jails/web"

	// Stopped, and the fake pool reports no space yet: nothing is invented.
	u, err := s.JailUsage(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if u.Jail != "web" || u.Power != api.PowerStopped || u.Accounting != nil || u.MeasuredAt.IsZero() {
		t.Fatalf("%+v", u)
	}
	if u.Disk.Error == "" || u.Disk.RootBytes != 0 {
		t.Fatalf("disk without numbers: %+v", u.Disk)
	}

	// The root counts by itself; the persistent datasets are the data.
	rows, err := e.ZFS.List(context.Background(), zfs.ListOpts{Root: container, Recursive: true, Props: []string{lifecycle.PropKind}})
	if err != nil {
		t.Fatal(err)
	}
	persistent := 0
	for _, r := range rows {
		switch {
		case r.Name == container+"/root":
			e.ZFS.SetSpace(r.Name, 123456, 2_000_000)
		case r.Props[lifecycle.PropKind] == lifecycle.KindPersistent:
			e.ZFS.SetSpace(r.Name, 1000, 1000)
			persistent++
		default:
			e.ZFS.SetSpace(r.Name, 1<<40, 1<<40) // the container and anything else: never counted
		}
	}
	if persistent == 0 {
		t.Fatalf("no persistent datasets: %+v", rows)
	}
	u, _ = s.JailUsage(ctx, "web")
	if u.Disk.Error != "" || u.Disk.RootBytes != 123456 || u.Disk.RootReferencedBytes != 2_000_000 || u.Disk.DataBytes != int64(persistent*1000) {
		t.Fatalf("disk: %+v (persistent %d)", u.Disk, persistent)
	}

	// Running: racct through rctl. An rctl that cannot run is reported, not zeroed.
	op, err = s.JailAction(ctx, "web", api.JailAction{Action: "start"})
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("start: %+v\n%s", got, e.Log())
	}
	u, _ = s.JailUsage(ctx, "web")
	if u.Power != api.PowerRunning || u.Accounting == nil || !strings.Contains(u.Accounting.Error, "rctl") {
		t.Fatalf("unscripted rctl: %+v", u.Accounting)
	}
	e.Run.On("rctl", []string{"-u", "jail:alpha_web"}, "cputime=297\nmemoryuse=407048192\nmaxproc=23\npcpu=1\n")
	u, _ = s.JailUsage(ctx, "web")
	if a := u.Accounting; a == nil || a.Error != "" || a.Processes != 23 || a.CPUSeconds != 297 || a.MemoryBytes != 407048192 {
		t.Fatalf("accounting: %+v", u.Accounting)
	}
	if u.Disk.RootBytes != 123456 {
		t.Fatalf("disk while running: %+v", u.Disk)
	}

	// racct off: the reason, and no rctl call.
	calls := len(e.Run.Calls())
	e.SetSysctl("kern.racct.enable", "0")
	u, _ = s.JailUsage(ctx, "web")
	if a := u.Accounting; a == nil || !strings.HasPrefix(a.Error, "racct is off") || a.Processes != 0 {
		t.Fatalf("racct off: %+v", u.Accounting)
	}
	if len(e.Run.Calls()) != calls {
		t.Fatal("rctl ran although racct is off")
	}

	// Scope: a jail of another project is not found; an unknown name neither.
	_, err = s.JailUsage(as(alphaOnly, "ghost"), "web")
	if err == nil {
		t.Fatal("usage read through a project the identity has no scope in")
	}
	_, err = s.JailUsage(ctx, "ghost")
	wantCode(t, err, api.CodeNotFound)
}
