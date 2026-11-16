package imagegen

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/lifecycle/fakes"
	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/internal/lifecycle/zfsmodel"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

var bg = context.Background()

type world struct {
	t     *testing.T
	F     *fault.Injector
	Z     *zfsmodel.Model
	Files *fakes.Files
	Exec  *fakes.Exec
	M     *Manager
	J     *plan.MemJournal
	// repoVersion is what the fake package repository serves.
	repoVersion string
	specs       map[string]api.ImageSpec
	roots       map[string][]Package
	now         time.Time
}

func newWorld(t *testing.T) *world {
	f := &fault.Injector{}
	w := &world{t: t, F: f, Z: zfsmodel.New(f, "tank"), Files: fakes.NewFiles(f), Exec: &fakes.Exec{F: f},
		J: &plan.MemJournal{}, repoVersion: "15.0p1", specs: map[string]api.ImageSpec{}, roots: map[string][]Package{},
		now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for _, d := range []string{"tank/jailops", "tank/jailops/images", "tank/jailops/jails"} {
		if err := w.Z.Create(bg, d, map[string]string{"jailops:managed": "on"}); err != nil {
			t.Fatal(err)
		}
	}
	w.Exec.Handler = w.handle
	w.M = &Manager{
		Layout: Layout{Root: "tank/jailops", MountBase: "/jailops"}, Work: "/var/tmp/jo",
		ZFS: w.Z, Exec: w.Exec, Files: w.Files, Executor: &plan.Executor{Journal: w.J},
		Specs: func(_ context.Context, img string) (api.ImageSpec, error) {
			s, ok := w.specs[img]
			if !ok {
				return s, api.Errorf(api.CodeNotFound, "no image %s", img)
			}
			return s, nil
		},
		Now: func() time.Time { return w.now },
	}
	w.AddImage("fb", "stable", "latest")
	return w
}

func (w *world) AddImage(name string, aliases ...string) {
	w.specs[name] = api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE", Arch: "amd64",
		Source: api.ImageSource{Type: "pkgbase"}, Aliases: aliases}
}

func (w *world) repoPkgs() []Package {
	return []Package{{"FreeBSD-runtime", w.repoVersion}, {"FreeBSD-utilities", w.repoVersion}}
}

func (w *world) handle(argv []string) ([]byte, error) {
	if argv[0] != "pkg" {
		return nil, nil
	}
	if len(argv) > 2 && argv[1] == "config" && argv[2] == "abi" {
		return []byte("FreeBSD:15:amd64\n"), nil
	}
	root := argv[2]
	sub := argv[11]
	switch sub {
	case "install", "upgrade":
		w.roots[root] = w.repoPkgs()
		w.Files.Data[root+"/bin/sh"] = []byte("x")
		w.Files.Data[root+"/libexec/ld-elf.so.1"] = []byte("x")
	case "query":
		var b strings.Builder
		for _, p := range w.roots[root] {
			fmt.Fprintf(&b, "%s %s\n", p.Name, p.Version)
		}
		return []byte(b.String()), nil
	}
	return nil, nil
}

// snapshotState captures everything a failed operation must restore.
func (w *world) state() string {
	// files under /jailops live inside datasets in reality; the fake keeps them
	// apart, so only files outside the pool count here.
	var outside []string
	for _, p := range w.Files.Paths() {
		if !strings.HasPrefix(p, "/jailops/") {
			outside = append(outside, p)
		}
	}
	return w.Z.Dump() + "\nFILES " + strings.Join(outside, ",")
}

// sweep runs op once to count mutating steps, then once per step with that
// step failing, asserting the state is restored after each failure. setup
// builds a fresh world for each run.
func sweep(t *testing.T, setup func(t *testing.T) *world, op func(w *world) error) {
	t.Helper()
	w := setup(t)
	w.F.Reset(0)
	if err := op(w); err != nil {
		t.Fatalf("baseline run: %v", err)
	}
	n := w.F.Count()
	if n == 0 {
		t.Fatal("no mutating operations")
	}
	for k := 1; k <= n; k++ {
		w := setup(t)
		before := w.state()
		w.F.Reset(k)
		err := op(w)
		if err == nil {
			// failure landed in best-effort follow-up work; state must still be sane
			continue
		}
		if after := w.state(); after != before {
			t.Fatalf("failing op %d/%d (%s): state changed\nerr: %v\nbefore:\n%s\nafter:\n%s", k, n, w.F.Log[k-1], err, before, after)
		}
		if len(w.J.Recs) != 0 {
			t.Fatalf("op %d: journal not cleaned: %v", k, w.J.Recs)
		}
	}
}
