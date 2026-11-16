package sdk_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The volume calls against the fake server: create with an owner, attach and detach, the rules of the fake that the
// daemon shares (a running jail, one jail for an encrypted volume), snapshots, and the key operations.
func TestVolumes(t *testing.T) {
	srv, c := newEnv(t)
	seedBasics(srv)
	ctx := ctxT(t)
	op, err := c.Volumes().Create(ctx, sdk.NewVolume("maildir", api.VolumeSpec{UID: 5000, GID: 5000, Mode: "770"}), "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := op.Wait(ctx)
	if err != nil || v.Spec.UID != 5000 || v.Spec.Mode != "0770" || v.Spec.Storage != "default" {
		t.Fatalf("%+v %v", v, err)
	}
	for _, n := range []string{"mail", "desktop"} {
		jop, err := c.Jails().Create(ctx, sdk.NewJail(n, api.JailSpec{Image: "freebsd-15@stable", Storage: "default", Network: []api.NetworkAttach{{Network: "lan"}}}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jop.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	attach := func(jail, mount string) error {
		aop, err := c.Jails().AttachVolume(ctx, jail, api.VolumeAttachRequest{Volume: "maildir", Mount: mount})
		if err != nil {
			return err
		}
		_, err = aop.Wait(ctx)
		return err
	}
	if err := attach("mail", "/var/mail/vhosts"); err != nil {
		t.Fatal(err)
	}
	if err := attach("desktop", "/home/ann/Mail"); err != nil {
		t.Fatal(err)
	}
	if v, _ = c.Volumes().Get(ctx, "maildir"); len(v.Status.AttachedTo) != 2 || len(v.Status.Warnings) != 1 || !strings.Contains(v.Status.Warnings[0], "writable in more than one jail") {
		t.Fatalf("%+v", v.Status)
	}
	if err := attach("mail", "/srv/other"); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("attached twice: %v", err)
	}
	if _, err := c.Volumes().Delete(ctx, "maildir"); !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("a volume that is attached: %v", err)
	}
	vols, err := c.Jails().Volumes(ctx, "mail")
	if err != nil || len(vols) != 1 || vols[0].Mount != "/var/mail/vhosts" {
		t.Fatalf("%+v %v", vols, err)
	}
	// a running jail neither attaches nor detaches
	sop, _ := c.Jails().Start(ctx, "mail")
	if _, err := sop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Jails().DetachVolume(ctx, "mail", "maildir"); !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("detach from a running jail: %v", err)
	}
	// snapshots
	snop, err := c.Volumes().Snapshots("maildir").Create(ctx, "s1", "first")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	n := 0
	for s, err := range c.Volumes().Snapshots("maildir").List(ctx) {
		if err != nil || s.Metadata.Name != "s1" {
			t.Fatalf("%+v %v", s, err)
		}
		n++
	}
	if n != 1 {
		t.Fatalf("%d snapshots", n)
	}
	if _, err := c.Volumes().Rollback(ctx, "maildir", api.VolumeRollback{Snapshot: "s1"}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a rollback without confirmation: %v", err)
	}
}

func TestEncryptedVolume(t *testing.T) {
	srv, c := newEnv(t)
	seedBasics(srv)
	ctx := ctxT(t)
	const pass, wrong = "marker-correct-horse-staple", "marker-wrong-passphrase"
	if _, err := c.Volumes().Create(ctx, sdk.NewVolume("vault", api.VolumeSpec{Encrypted: true}), ""); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("no passphrase: %v", err)
	}
	op, err := c.Volumes().Create(ctx, sdk.NewVolume("vault", api.VolumeSpec{Encrypted: true}), pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	jop, _ := c.Jails().Create(ctx, sdk.NewJail("v", api.JailSpec{Image: "freebsd-15@stable", Storage: "default", Network: []api.NetworkAttach{{Network: "lan"}},
		Volumes: []api.VolumeAttach{{Name: "vault", Mount: "/srv/v"}}}))
	if _, err := jop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	srv.RebootHost()
	if j, _ := c.Jails().Get(ctx, "v"); j.Status.Power != api.PowerLocked || len(j.Status.Locked) != 1 {
		t.Fatalf("%+v", j.Status)
	}
	if _, err := c.Jails().Start(ctx, "v"); !api.IsCode(err, api.CodeLocked) {
		t.Fatalf("start of a locked jail: %v", err)
	}
	uop, _ := c.Volumes().Unlock(ctx, "vault", wrong, false)
	if _, err := uop.Wait(ctx); !api.IsCode(err, api.CodeBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	uop, _ = c.Volumes().Unlock(ctx, "vault", pass, true)
	if _, err := uop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if j, _ := c.Jails().Get(ctx, "v"); j.Status.Power != api.PowerRunning {
		t.Fatalf("%+v", j.Status)
	}
	for _, r := range srv.Requests() {
		if strings.Contains(string(r.Body), "marker-") {
			t.Fatalf("the fake recorded a passphrase: %s", r.Body)
		}
	}
}

// A volume that is a directory of the host: made with a path below the allowed directory, it has a state, no
// snapshots, and a jail that attaches it does not start while the mount is lost; with on-loss stop the daemon stops
// the jails, and the watch's events say what happened.
func TestHostDirectoryVolume(t *testing.T) {
	srv, c := newEnv(t)
	seedBasics(srv)
	ctx := ctxT(t)
	if _, err := c.Volumes().Create(ctx, sdk.NewVolume("box", api.VolumeSpec{Path: "/etc/passwd"}), ""); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a path outside the allowed directory: %v", err)
	}
	if _, err := c.Volumes().Create(ctx, sdk.NewVolume("box", api.VolumeSpec{Path: "/mnt/box/backups", Size: "1G"}), ""); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a size on a host directory: %v", err)
	}
	op, err := c.Volumes().Create(ctx, sdk.NewVolume("box", api.VolumeSpec{Path: "/mnt/box/backups", Watch: true, OnLoss: api.VolumeOnLossStop}), "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := op.Wait(ctx)
	if err != nil || v.Spec.Probe != api.VolumeProbeMounted || v.Status.State != api.VolumeStateOK || v.Status.Dataset != "" || v.Status.Mountpoint != "/mnt/box/backups" {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := c.Volumes().Snapshots("box").Create(ctx, "s1", ""); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a snapshot of a host directory: %v", err)
	}
	jop, err := c.Jails().Create(ctx, sdk.NewJail("backup", api.JailSpec{Image: "freebsd-15@stable", Storage: "default", Network: []api.NetworkAttach{{Network: "lan"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Jails().AttachVolume(ctx, "backup", api.VolumeAttachRequest{Volume: "box", Mount: "/srv/backups", CopyExisting: true}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("copy-existing: %v", err)
	}
	aop, err := c.Jails().AttachVolume(ctx, "backup", api.VolumeAttachRequest{Volume: "box", Mount: "/srv/backups"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	sop, _ := c.Jails().Start(ctx, "backup")
	if _, err := sop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	srv.LoseHostDir("/mnt/box/backups")
	if v, _ = c.Volumes().Get(ctx, "box"); v.Status.State != api.VolumeStateLost || v.Status.Detail == "" {
		t.Fatalf("%+v", v.Status)
	}
	if j, _ := c.Jails().Get(ctx, "backup"); j.Status.Power == api.PowerRunning {
		t.Fatal("on-loss stop left the jail running")
	}
	if _, err := c.Jails().Start(ctx, "backup"); !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("a start without the mount: %v", err)
	}
	srv.RestoreHostDir("/mnt/box/backups")
	if v, _ = c.Volumes().Get(ctx, "box"); v.Status.State != api.VolumeStateOK {
		t.Fatalf("%+v", v.Status)
	}
	sop, err = c.Jails().Start(ctx, "backup")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}
