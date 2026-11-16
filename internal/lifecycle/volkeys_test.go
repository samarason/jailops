package lifecycle

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

const (
	testPass = "marker-correct-horse-staple"
	newPass  = "marker-another-long-phrase"
	volDS    = "tank/jailops/projects/alpha/volumes/vault"
)

// logJournal keeps every record it was given, to prove no passphrase reaches the journal.
type logJournal struct {
	plan.MemJournal
	log []string
}

func (l *logJournal) Put(ctx context.Context, r plan.Record) error {
	b, _ := json.Marshal(r)
	l.log = append(l.log, string(b))
	return l.MemJournal.Put(ctx, r)
}

func encWorld(t *testing.T) (*world, *logJournal) {
	w := newWorld(t)
	lj := &logJournal{}
	w.S.Executor = &plan.Executor{Journal: lj}
	w.S.Keys = w.Z
	return w, lj
}

// encVolume makes the encrypted volume vault of the project alpha.
func encVolume(t *testing.T, w *world) ([]string, error) {
	t.Helper()
	req := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "vault", UUID: "vol-vault", UID: 770, GID: 770, Mode: 0o700, Encrypted: true}
	return w.S.CreateVolume(bg, req, []byte(testPass), false)
}

// encJail makes a jail web that attaches the encrypted volume vault at /srv/vault.
func encJail(t *testing.T, w *world, name string) {
	t.Helper()
	if ok, _ := w.Z.Exists(bg, volDS); !ok {
		if _, err := encVolume(t, w); err != nil {
			t.Fatal(err)
		}
	}
	st := w.storage()
	key := "alpha_" + name
	w.attach[key] = append(w.attach[key], Attached{Dataset: volDS, Mountpoint: VolumeMP(st, "alpha", "vault"), Path: "/srv/vault", Encrypted: true})
	j := w.jail(name)
	j.Spec.Volumes = []api.VolumeAttach{{Name: "vault", Mount: "/srv/vault"}}
	if _, err := w.S.CreateJail(bg, j, false); err != nil {
		t.Fatal(err)
	}
}

func TestCreateEncryptedVolume(t *testing.T) {
	w, lj := encWorld(t)
	plan, err := encVolume(t, w)
	if err != nil {
		t.Fatal(err)
	}
	if w.Z.Passphrase(volDS) != testPass || w.Z.PropOrEmpty(volDS, PropEncrypted) != "on" {
		t.Fatalf("volume not encrypted: %q", w.Z.Passphrase(volDS))
	}
	if ks, _ := w.Z.KeyStatus(bg, volDS); ks != "available" {
		t.Fatalf("a new volume is unlocked, got %q", ks)
	}
	if got := w.Files.Owners["/jailops/projects/alpha/volumes/vault"]; got != "770:770:0700" {
		t.Fatalf("owner of the root of the volume: %q", got)
	}
	for _, s := range append(append(plan, lj.log...), w.Z.Dump()) {
		if strings.Contains(s, "marker-") {
			t.Fatalf("the passphrase leaked: %s", s)
		}
	}
}

func TestCreateEncryptedVolumeRefusals(t *testing.T) {
	w, _ := encWorld(t)
	req := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "vault", UUID: "vol-vault", Encrypted: true}
	for name, c := range map[string]struct {
		req  VolumeRequest
		pass string
		want api.Code
	}{
		"no passphrase":                  {req, "", api.CodeInvalid},
		"short passphrase":               {req, "short", api.CodeInvalid},
		"a passphrase and no encryption": {VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "vault", UUID: "u"}, testPass, api.CodeInvalid},
	} {
		if _, err := w.S.CreateVolume(bg, c.req, []byte(c.pass), false); !api.IsCode(err, c.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	w.S.Keys = nil
	if _, err := w.S.CreateVolume(bg, req, []byte(testPass), false); !api.IsCode(err, api.CodeUnsupported) {
		t.Fatalf("no key operations: %v", err)
	}
	if ok, _ := w.Z.Exists(bg, volDS); ok {
		t.Fatal("a refused creation left a dataset")
	}
}

func TestCreateEncryptedVolumeFailureSweep(t *testing.T) {
	sweep(t, func(t *testing.T) *world { w, _ := encWorld(t); return w }, func(w *world) error {
		_, err := encVolume(t, w)
		return err
	})
}

// reboot unloads every key and unmounts what was mounted, as a host start does.
func reboot(w *world) {
	for _, n := range w.Z.Names() {
		_ = w.Z.Unmount(bg, n)
	}
	w.Z.DropKeys()
	w.Jails.Up = map[string]bool{}
}

func TestLockedJailDoesNotStartUntilUnlocked(t *testing.T) {
	w, _ := encWorld(t)
	encJail(t, w, "web")
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	w.Z.WriteFile(volDS, "/data.txt", "kept")
	reboot(w)
	if l, err := w.S.Locked(bg, "alpha_web"); err != nil || len(l) != 1 || l[0] != "vault" {
		t.Fatalf("locked %v %v", l, err)
	}
	r, err := w.S.Rebuild(bg, "alpha_web")
	if err != nil || len(r.Locked) != 1 {
		t.Fatalf("rebuild %v %v", r.Locked, err)
	}
	err = w.S.StartJail(bg, "alpha_web")
	wantCode(t, err, api.CodeLocked)
	var ae *api.Error
	if !strings.Contains(err.Error(), "jailops volume unlock vault") || !asErr(err, &ae) || ae.Detail["volumes"] != "vault" {
		t.Fatalf("hint and detail: %v", err)
	}
	if w.Jails.Up["alpha_web"] {
		t.Fatal("a locked jail started")
	}
	st := w.storage()
	wantCode(t, w.S.UnlockVolume(bg, st, "alpha", "vault", []byte("marker-wrong-passphrase")), api.CodeBadPassphrase)
	if l, _ := w.S.Locked(bg, "alpha_web"); len(l) != 1 {
		t.Fatal("a wrong passphrase unlocked")
	}
	if err := w.S.UnlockVolume(bg, st, "alpha", "vault", []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if c, ok := w.Z.ReadFile(volDS, "/data.txt"); !ok || c != "kept" {
		t.Fatal("the data of the volume is gone")
	}
	// lock: the caller stops the jail, the volume is unmounted and its key unloaded
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := w.S.LockVolume(bg, st, "alpha", "vault"); err != nil {
		t.Fatal(err)
	}
	if m, _ := w.Z.Mounted(bg, volDS); m {
		t.Fatal("lock left the volume mounted")
	}
	if l, _ := w.S.Locked(bg, "alpha_web"); len(l) != 1 {
		t.Fatal("lock left the key loaded")
	}
	wantCode(t, w.S.StartJail(bg, "alpha_web"), api.CodeLocked)
}

func asErr(err error, out **api.Error) bool {
	e, ok := err.(*api.Error)
	*out = e
	return ok
}

func TestChangeVolumePassphrase(t *testing.T) {
	w, _ := encWorld(t)
	if _, err := encVolume(t, w); err != nil {
		t.Fatal(err)
	}
	st := w.storage()
	wantCode(t, w.S.ChangeVolumePassphrase(bg, st, "alpha", "vault", []byte("marker-wrong-passphrase"), []byte(newPass)), api.CodeBadPassphrase)
	if err := w.S.ChangeVolumePassphrase(bg, st, "alpha", "vault", []byte(testPass), []byte(newPass)); err != nil {
		t.Fatal(err)
	}
	if w.Z.Passphrase(volDS) != newPass {
		t.Fatal("not changed")
	}
	reboot(w)
	wantCode(t, w.S.ChangeVolumePassphrase(bg, st, "alpha", "vault", []byte(newPass), []byte(testPass)), api.CodeLocked)
	wantCode(t, w.S.UnlockVolume(bg, st, "alpha", "vault", []byte(testPass)), api.CodeBadPassphrase)
	if err := w.S.UnlockVolume(bg, st, "alpha", "vault", []byte(newPass)); err != nil {
		t.Fatal(err)
	}
}

// An upgrade ends with a start: a locked jail is refused before anything changes. The plans that roll an interrupted
// start or upgrade back are still built after a reboot.
func TestLockedJailRefusesAnUpgradeButRecovers(t *testing.T) {
	w, _ := encWorld(t)
	encJail(t, w, "web")
	reboot(w)
	before := w.state()
	_, _, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{Stamp: "9"})
	wantCode(t, err, api.CodeLocked)
	if w.state() != before {
		t.Fatal("a refused upgrade changed the pool")
	}
	if _, err := w.S.PlanStart(bg, "alpha_web"); err != nil {
		t.Fatalf("the start plan of a recovery: %v", err)
	}
	if _, _, err := w.S.PlanUpgrade(bg, "alpha_web", UpgradeRequest{Stamp: "9", Resume: &SwitchState{FromGen: 1}}); api.IsCode(err, api.CodeLocked) {
		t.Fatalf("the upgrade plan of a recovery: %v", err)
	}
}
