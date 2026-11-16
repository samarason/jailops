package server_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The passphrase of encrypted volumes goes to the helper and nowhere else: not into a reply, an operation, the audit
// log, the daemon's log, a command line, the journal or any file the daemon writes. Each request carries a unique
// marker, and everything that can be read back afterwards is searched for it.
func TestVolumePassphraseNeverLeaks(t *testing.T) {
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { off := false; c.Reconcile.Autostart = &off }})
	e.Seed()
	c := ctxT(t)
	const (
		create = "leak-marker-create-0001"
		wrong  = "leak-marker-wrong-0002"
		change = "leak-marker-change-0003"
		bad    = "leak-marker-newline\n0004"
	)
	vop, err := e.Admin.Volumes().Create(c, sdk.NewVolume("vault", api.VolumeSpec{Encrypted: true, UID: 770, GID: 770, Mode: "0700"}), create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vop.Wait(c); err != nil {
		t.Fatalf("create volume: %v\n%s", err, e.Log())
	}
	j := dtest.WebJail("vault")
	j.Spec.Volumes = []api.VolumeAttach{{Name: "vault", Mount: "/var/db/app"}}
	op, err := e.Admin.Jails().Create(c, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("create: %v\n%s", err, e.Log())
	}
	vol := "tank/jailops/projects/" + dtest.SeedProject + "/volumes/vault"
	if e.Keys.Passphrase(vol) != create {
		t.Fatal("the passphrase did not reach the helper")
	}
	var errs []string
	lock, err := e.Admin.Volumes().Lock(c, "vault")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Wait(c); err != nil {
		t.Fatal(err)
	}
	u, err := e.Admin.Volumes().Unlock(c, "vault", wrong, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Wait(c); !api.IsCode(err, api.CodeBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	} else {
		errs = append(errs, err.Error())
	}
	if _, err := e.Admin.Volumes().Unlock(c, "vault", bad, false); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a line break: %v", err)
	} else {
		errs = append(errs, err.Error())
	}
	_, err = e.Admin.Jails().Start(c, "vault")
	if !api.IsCode(err, api.CodeLocked) {
		t.Fatalf("start of a locked jail: %v", err)
	}
	errs = append(errs, err.Error())
	u, err = e.Admin.Volumes().Unlock(c, "vault", create, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Wait(c); err != nil {
		t.Fatalf("unlock --start: %v", err)
	}
	if j, err := e.Admin.Jails().Get(c, "vault"); err != nil || j.Status.Power != api.PowerRunning {
		t.Fatalf("unlock --start left the jail %v: %v", j.Status.Power, err)
	}
	pc, err := e.Admin.Volumes().ChangePassphrase(c, "vault", create, change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.Wait(c); err != nil {
		t.Fatal(err)
	}
	if e.Keys.Passphrase(vol) != change {
		t.Fatal("the new passphrase did not reach the helper")
	}
	// operator may unlock and lock, not change the passphrase
	if _, err := e.Client(api.PermOperator).Volumes().ChangePassphrase(c, "vault", change, create); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("an operator changed the passphrase: %v", err)
	}

	var all strings.Builder
	for _, p := range []string{"/api/v1/jails?project=" + dtest.SeedProject, "/api/v1/jails/vault?project=" + dtest.SeedProject, "/api/v1/volumes?project=" + dtest.SeedProject,
		"/api/v1/volumes/vault?project=" + dtest.SeedProject, "/api/v1/operations", "/api/v1/audit?limit=500", "/api/v1/doctor"} {
		code, body := e.Raw("GET", p, e.Token(api.PermAdmin), "")
		if code != 200 {
			t.Fatalf("%s: %d %s", p, code, body)
		}
		all.WriteString(body)
	}
	all.WriteString(e.Log())
	all.WriteString(strings.Join(e.Run.Argv(), "\n"))
	all.WriteString(strings.Join(e.Keys.Ops(), "\n"))
	all.WriteString(strings.Join(errs, "\n"))
	// every file the daemon wrote: its database, the journal, the state
	_ = filepath.WalkDir(e.Dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			all.Write(b)
		}
		return nil
	})
	for _, p := range e.Files.Paths() {
		b, _ := e.Files.Get(p)
		all.Write(b)
	}
	got := all.String()
	if !strings.Contains(got, "Unlock volume vault") || !strings.Contains(got, "/api/v1/volumes/{name}/unlock") {
		t.Fatal("the read-back misses the unlock: the search would prove nothing")
	}
	for _, m := range []string{create, wrong, change, "leak-marker"} {
		if strings.Contains(got, m) {
			i := strings.Index(got, m)
			t.Errorf("%q leaked: ...%s...", m, got[max(0, i-200):min(len(got), i+100)])
		}
	}
}
