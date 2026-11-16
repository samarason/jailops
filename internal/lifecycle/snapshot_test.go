package lifecycle

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestSnapshotIsOneAtomicOperation(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.F.Reset(0)
	r, err := w.S.SnapshotJail(bg, "alpha_web", "before", "hello")
	if err != nil {
		t.Fatal(err)
	}
	snaps := 0
	for _, l := range w.F.Log {
		if strings.HasPrefix(l, "zfs snapshot") {
			snaps++
		}
	}
	if snaps != 1 {
		t.Fatalf("%d zfs snapshot calls, want exactly one: %v", snaps, w.F.Log)
	}
	c := "tank/jailops/projects/alpha/jails/web"
	for _, d := range []string{c, c + "/root", c + "/etc", c + "/home"} {
		if ok, _ := w.Z.Exists(bg, d+"@before"); !ok {
			t.Errorf("%s has no snapshot", d)
		}
	}
	if len(r.Datasets) != 10 {
		t.Fatal(r.Datasets)
	}
	if got := w.Z.PropOrEmpty(c+"@before", PropGen); got != "1" {
		t.Fatalf("gen on snapshot %q", got)
	}
	// written reporting covers data datasets only
	w.Z.WriteFile(c+"/home", "/home/a", "12345")
	w.Z.WriteFile(dbVol, "/db", "123")
	w.Z.WriteFile(c+"/etc", "/etc/x", "9999999")
	l, err := w.S.ListSnapshots(bg, "alpha_web")
	if err != nil || len(l) != 1 {
		t.Fatal(l, err)
	}
	if l[0].TotalWritten != 5 || l[0].Written[c+"/home"] != 5 {
		t.Fatalf("%+v", l[0])
	}
	if _, ok := l[0].Written[c+"/etc"]; ok {
		t.Fatal("system dataset counted as data")
	}
	if _, err := w.S.SnapshotJail(bg, "alpha_web", "before", ""); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatal(err)
	}
}

func TestSnapshotValidation(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	for name, code := range map[string]api.Code{"a b": api.CodeInvalid, "x@y": api.CodeInvalid, "jo-evil": api.CodeInvalid, "-x": api.CodeInvalid} {
		if _, err := w.S.SnapshotJail(bg, "alpha_web", name, ""); !api.IsCode(err, code) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if r, err := w.S.SnapshotJail(bg, "alpha_web", "", ""); err != nil || !strings.HasPrefix(r.Name, "snap-2026") {
		t.Fatal(r.Name, err)
	}
}

func TestSnapshotFailureLeavesNothing(t *testing.T) {
	setup := func(t *testing.T) *world { w := newWorld(t); w.created("web"); return w }
	sweep(t, setup, func(w *world) error { _, err := w.S.SnapshotJail(bg, "alpha_web", "s", ""); return err })
}
