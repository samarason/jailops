package daemon_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/leakcheck"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// TestSoakManyJails makes JAILOPS_SOAK_JAILS jails (default 600) on the fakes and reports what they cost: the heap per
// jail, the time of a list, a show and a start/stop of one jail among many, and the goroutines. It asserts that the
// number of goroutines does not depend on the number of jails and that one more jail costs bounded memory. Run it with
// JAILOPS_SOAK=1; it takes a while with thousands of jails.
func TestSoakManyJails(t *testing.T) {
	if os.Getenv("JAILOPS_SOAK") != "1" {
		t.Skip("set JAILOPS_SOAK=1 (and JAILOPS_SOAK_JAILS=N)")
	}
	n := 600
	if v, err := strconv.Atoi(os.Getenv("JAILOPS_SOAK_JAILS")); err == nil && v > 0 {
		n = v
	}
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	// a network with room for the jails, in a project of its own
	glob := e.Global()
	if _, err := glob.Networks().Create(ctx, api.Network{Metadata: api.ObjectMeta{Name: "big"}, Spec: api.NetworkSpec{
		IPv4: &api.IPv4Net{Subnet: "10.100.0.0/16", Gateway: "10.100.0.1", Range: "10.100.0.10-10.100.250.250"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := glob.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "soak"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "big"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	e.Admin = glob.Project("soak")
	mem := func() (heap uint64, gor int) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc, runtime.NumGoroutine()
	}
	h0, g0 := mem()
	start := time.Now()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("j%05d", i)
		op, err := e.Admin.Jails().Create(ctx, dtest.WebJailOn(name, "big"))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if _, err := op.Wait(ctx); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if i%100 == 99 || i == n-1 {
			h, g := mem()
			t.Logf("%5d jails: heap %6.1f MiB (%5.0f KiB per jail), goroutines %d, %.1f s", i+1, float64(h)/(1<<20), float64(h-h0)/1024/float64(i+1), g, time.Since(start).Seconds())
			if g > g0+20 {
				t.Errorf("goroutines grow with the number of jails: %d -> %d at %d jails", g0, g, i+1)
			}
		}
	}
	timeIt := func(what string, f func()) {
		t0 := time.Now()
		f()
		t.Logf("%-28s %v", what, time.Since(t0).Round(time.Millisecond))
	}
	timeIt(fmt.Sprintf("list of %d jails", n), func() {
		c := 0
		for _, err := range e.Admin.Jails().List(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			c++
		}
		if c != n {
			t.Fatalf("listed %d of %d", c, n)
		}
	})
	timeIt("desired state (a reconcile pass)", func() {
		for i := 0; i < 3; i++ {
			if _, err := e.D.Service().Desired(ctx); err != nil {
				t.Fatal(err)
			}
		}
	})
	timeIt("show one", func() {
		if _, err := e.Admin.Jails().Get(ctx, "j00000"); err != nil {
			t.Fatal(err)
		}
	})
	timeIt("start+stop one", func() {
		so, err := e.Admin.Jails().Start(ctx, "j00001")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := so.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		xo, err := e.Admin.Jails().Stop(ctx, "j00001")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := xo.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	})
	timeIt("doctor", func() {
		if _, err := e.Admin.Doctor(ctx); err != nil {
			t.Logf("doctor: %v", err)
		}
	})
	timeIt("events replay (last 100)", func() {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		c := 0
		for _, err := range e.Admin.Events(cctx, sdk.FromID("0")) {
			if err != nil {
				break
			}
			if c++; c >= 100 {
				break
			}
		}
	})
	// delete them all: memory returns, goroutines return
	t0 := time.Now()
	for i := 0; i < n; i++ {
		op, err := e.Admin.Jails().Delete(ctx, fmt.Sprintf("j%05d", i))
		if err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
		if _, err := op.Wait(ctx); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	h, g := mem()
	t.Logf("after deleting all %d jails: heap %.1f MiB (was %.1f MiB empty), goroutines %d (was %d), %.1f s", n, float64(h)/(1<<20), float64(h0)/(1<<20), g, g0, time.Since(t0).Seconds())
	if h > h0+uint64(n)*8<<10+16<<20 { // 8 KiB per deleted jail and 16 MiB of slack
		t.Errorf("the heap did not come back after deleting %d jails: %.1f MiB -> %.1f MiB", n, float64(h0)/(1<<20), float64(h)/(1<<20))
	}
	_ = api.PermAdmin
	_ = leakcheck.FDs
}
