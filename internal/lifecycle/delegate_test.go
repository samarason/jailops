package lifecycle

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

const dc = "tank/jailops/projects/alpha/jails/web"

func delegatedWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	j := w.jail("web")
	j.Spec.Delegate = true
	if _, err := w.S.CreateJail(bg, j, false); err != nil {
		t.Fatal(err)
	}
	return w
}

// A jail with delegation gets <container>/delegated, jailed and not mounted on the host.
func TestCreateWithDelegation(t *testing.T) {
	w := delegatedWorld(t)
	ds := dc + "/delegated"
	for p, want := range map[string]string{PropManaged: "on", PropKind: KindDelegated, PropID: "uuid-web", "jailed": "on", "mountpoint": "none", "canmount": "noauto"} {
		if got := w.Z.PropOrEmpty(ds, p); got != want {
			t.Errorf("%s %s = %q, want %q", ds, p, got, want)
		}
	}
	if w.S.Cfg.DelegatedDS("alpha_web") != ds {
		t.Errorf("DelegatedDS %q", w.S.Cfg.DelegatedDS("alpha_web"))
	}
	// a plain jail has none
	w2 := newWorld(t)
	if _, err := w2.S.CreateJail(bg, w2.jail("web"), false); err != nil {
		t.Fatal(err)
	}
	for _, n := range w2.Z.Names() {
		if strings.HasSuffix(n, "/delegated") {
			t.Errorf("a jail without delegation has %s", n)
		}
	}
}

// The delegated dataset is part of the jail's snapshots and of its data rollback, and a backup leaves it out.
func TestDelegatedDatasetIsSnapshottedAndNotBackedUp(t *testing.T) {
	w := delegatedWorld(t)
	res, err := w.S.SnapshotJail(bg, "alpha_web", "s1", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range res.Datasets {
		found = found || d == dc+"/delegated"
	}
	if !found {
		t.Errorf("the snapshot set lacks the delegated dataset: %v", res.Datasets)
	}
	if ok, _ := w.Z.Exists(bg, dc+"/delegated@s1"); !ok {
		t.Error("the delegated dataset has no snapshot s1")
	}
	st, err := w.S.observe(bg, "alpha_web")
	if err != nil {
		t.Fatal(err)
	}
	if st.Delegated != dc+"/delegated" || !strings.Contains(strings.Join(dataDatasets(st), " "), "/delegated") {
		t.Errorf("state %q data %v", st.Delegated, dataDatasets(st))
	}
	for _, d := range st.mountOrder() {
		if strings.HasSuffix(d, "/delegated") {
			t.Error("the host must never mount the delegated dataset")
		}
	}
	lay, err := w.S.Layout(bg, "alpha_web")
	if err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, d := range lay.Datasets {
		if d.Kind == KindDelegated {
			marked = d.Delegated
		}
	}
	if !marked {
		t.Errorf("the layout does not mark the delegated dataset: %+v", lay.Datasets)
	}
}

// Turning delegation on makes the dataset, turning it off clears jailed and keeps the data, and a running jail keeps it.
func TestSetDelegation(t *testing.T) {
	w := runningSetup(t)
	ds := dc + "/delegated"
	if ok, _ := w.Z.Exists(bg, ds); ok {
		t.Fatal("the jail had a delegated dataset before")
	}
	if err := w.S.SetDelegation(bg, "alpha_web", true); err != nil {
		t.Fatal(err)
	}
	if w.Z.PropOrEmpty(ds, "jailed") != "on" || w.Z.PropOrEmpty(ds, PropKind) != KindDelegated {
		t.Errorf("after turning it on: jailed %q kind %q", w.Z.PropOrEmpty(ds, "jailed"), w.Z.PropOrEmpty(ds, PropKind))
	}
	if err := w.S.SetDelegation(bg, "alpha_web", true); err != nil {
		t.Errorf("turning it on twice: %v", err)
	}
	if err := w.S.SetDelegation(bg, "alpha_web", false); !api.IsCode(err, api.CodeConflict) {
		t.Errorf("turning it off while the jail runs: %v", err)
	}
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := w.S.SetDelegation(bg, "alpha_web", false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := w.Z.Exists(bg, ds); !ok || w.Z.PropOrEmpty(ds, "jailed") != "off" {
		t.Errorf("turning it off must keep the dataset and clear jailed: exists %v jailed %q", ok, w.Z.PropOrEmpty(ds, "jailed"))
	}
	if err := w.S.SetDelegation(bg, "alpha_web", false); err != nil {
		t.Errorf("turning it off twice: %v", err)
	}
	if err := w.S.SetDelegation(bg, "alpha_ghost", true); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("an unknown jail: %v", err)
	}
}

// A copy of a jail with delegation gets its own delegated dataset, handed to it again.
func TestCopyKeepsDelegation(t *testing.T) {
	w := delegatedWorld(t)
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.S.CopyJail(bg, "alpha_web", "alpha_web2", "uuid-web2", "7", false); err != nil {
		t.Fatal(err)
	}
	ds := "tank/jailops/projects/alpha/jails/web2/delegated"
	if ok, _ := w.Z.Exists(bg, ds); !ok {
		t.Fatal("the copy has no delegated dataset")
	}
	if w.Z.PropOrEmpty(ds, "jailed") != "on" || w.Z.PropOrEmpty(ds, PropID) != "uuid-web2" {
		t.Errorf("copy: jailed %q id %q", w.Z.PropOrEmpty(ds, "jailed"), w.Z.PropOrEmpty(ds, PropID))
	}
}
