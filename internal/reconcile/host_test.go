package reconcile_test

import (
	"context"
	"strings"
	"testing"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/sys/run"
)

func TestHostPassLoadsModulesBeforeSysctlsAndGivesBack(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	loaded := map[string]bool{}
	vals := map[string]string{"net.link.epair.q1": "0", "net.link.epair.q2": "1", "net.link.epair.q3": "1", "kern.elf64.fallback_brand": "-1"}
	var log []string
	f := run.NewFake()
	f.Add(run.Rule{Name: "kldstat", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		if loaded[c.Args[2]] {
			return run.Result{}, nil
		}
		return run.Result{}, &run.ExitError{Code: 1}
	}})
	f.Add(run.Rule{Name: "kldload", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		loaded[c.Args[0]] = true
		log = append(log, "kldload "+c.Args[0])
		return run.Result{}, nil
	}})
	f.Add(run.Rule{Name: "sysctl", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		k, v, _ := strings.Cut(c.Args[0], "=")
		if !loaded["if_epair"] && strings.HasPrefix(k, "net.link.epair") {
			return run.Result{}, &run.ExitError{Code: 1, Stderr: "unknown oid"}
		}
		vals[k] = v
		log = append(log, "sysctl "+c.Args[0])
		return run.Result{}, nil
	}})
	want := reconcile.HostDesired{
		Modules: []string{"if_epair", "pf", "linux64"},
		Sysctls: map[string]string{"net.link.epair.q1": "1", "net.link.epair.q2": "0", "net.link.epair.q3": "0", "kern.elf64.fallback_brand": "3"},
		Release: map[string]string{"kern.elf64.fallback_brand": "-1"},
	}
	rd := func(_ context.Context, n string) (string, error) { return vals[n], nil }
	r := reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: w.PF, Jails: w.Jails, Run: f, Sysctl: rd, Clock: w.clock})
	w.des = reconcile.Desired{Host: want}
	rep := r.Pass(bg)
	if len(rep.Failures) != 0 {
		t.Fatalf("%v", rep.Failures)
	}
	got := strings.Join(log, "; ")
	wantLog := "kldload if_epair; kldload pf; kldload linux64; sysctl kern.elf64.fallback_brand=3; sysctl net.link.epair.q1=1; sysctl net.link.epair.q2=0; sysctl net.link.epair.q3=0"
	if got != wantLog {
		t.Fatalf("%s", got)
	}
	// Converged: a second pass does nothing.
	log = nil
	r.Pass(bg)
	if len(log) != 0 {
		t.Fatalf("%v", log)
	}
	// Drift is corrected again.
	vals["net.link.epair.q2"] = "1"
	r.Pass(bg)
	if strings.Join(log, ";") != "sysctl net.link.epair.q2=0" {
		t.Fatalf("%v", log)
	}
	// The last Linux jail is gone: the brand returns to -1, the others stay.
	log = nil
	delete(want.Sysctls, "kern.elf64.fallback_brand")
	w.des = reconcile.Desired{Host: want}
	r.Pass(bg)
	if strings.Join(log, ";") != "sysctl kern.elf64.fallback_brand=-1" || vals["kern.elf64.fallback_brand"] != "-1" {
		t.Fatalf("%v %v", log, vals)
	}
	// A value the helper refuses is a failure, not a crash.
	f2 := run.NewFake()
	f2.Add(run.Rule{Name: "kldstat", Args: []string{run.RestArgs}})
	f2.Add(run.Rule{Name: "sysctl", Args: []string{run.RestArgs}, Fn: func(run.Cmd) (run.Result, error) {
		return run.Result{}, &run.ExitError{Code: 1, Stderr: "forbidden"}
	}})
	vals["net.link.epair.q2"] = "1"
	r2 := reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: w.PF, Jails: w.Jails, Run: f2, Sysctl: rd, Clock: w.clock})
	rep = r2.Pass(bg)
	if !strings.Contains(rep.Failures["host/sysctl/net.link.epair.q2"], "forbidden") {
		t.Fatalf("%v", rep.Failures)
	}
}

// AssertHost loads the modules and sets the sysctls at once (the image builder calls it before a Linux build) and
// reports what the helper refused.
func TestAssertHostLoadsAndReports(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	loaded := map[string]bool{}
	vals := map[string]string{"kern.elf64.fallback_brand": "-1"}
	var log []string
	f := run.NewFake()
	f.Add(run.Rule{Name: "kldstat", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		if loaded[c.Args[2]] {
			return run.Result{}, nil
		}
		return run.Result{}, &run.ExitError{Code: 1}
	}})
	f.Add(run.Rule{Name: "kldload", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		loaded[c.Args[0]] = true
		log = append(log, "kldload "+c.Args[0])
		return run.Result{}, nil
	}})
	f.Add(run.Rule{Name: "sysctl", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		k, v, _ := strings.Cut(c.Args[0], "=")
		vals[k] = v
		log = append(log, "sysctl "+c.Args[0])
		return run.Result{}, nil
	}})
	rd := func(_ context.Context, n string) (string, error) { return vals[n], nil }
	r := reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: w.PF, Jails: w.Jails, Run: f, Sysctl: rd, Clock: w.clock})
	want := reconcile.HostDesired{Modules: []string{"linux64", "linprocfs", "linsysfs", "fdescfs"}, Sysctls: map[string]string{"kern.elf64.fallback_brand": "3"}}
	if err := r.AssertHost(bg, want); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "; "); got != "kldload linux64; kldload linprocfs; kldload linsysfs; kldload fdescfs; sysctl kern.elf64.fallback_brand=3" {
		t.Fatal(got)
	}
	log = nil
	if err := r.AssertHost(bg, want); err != nil || len(log) != 0 {
		t.Fatalf("a second call changed things: %v %v", err, log)
	}
	// a module the helper will not load is an error that names it
	f2 := run.NewFake()
	f2.Add(run.Rule{Name: "kldstat", Args: []string{run.RestArgs}, Fn: func(run.Cmd) (run.Result, error) { return run.Result{}, &run.ExitError{Code: 1} }})
	f2.Add(run.Rule{Name: "kldload", Args: []string{run.RestArgs}, Fn: func(run.Cmd) (run.Result, error) {
		return run.Result{}, &run.ExitError{Code: 1, Stderr: "forbidden"}
	}})
	r2 := reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: w.PF, Jails: w.Jails, Run: f2, Sysctl: rd, Clock: w.clock})
	if err := r2.AssertHost(bg, want); err == nil || !strings.Contains(err.Error(), "linux64") {
		t.Fatalf("%v", err)
	}
}
