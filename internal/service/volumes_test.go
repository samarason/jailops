package service_test

import (
	"context"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

func newVolume(t *testing.T, s *service.Service, ctx context.Context, name string, spec api.VolumeSpec) {
	t.Helper()
	op, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: name}, Spec: spec})
	mustOp(t, s, op, err)
}

func TestVolumeCreateShowUpdateDelete(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newVolume(t, s, ctx, "maildir", api.VolumeSpec{UID: 5000, GID: 5000, Mode: "770", Size: "5G", Comment: "the mail"})
	v, err := s.GetVolume(ctx, "maildir")
	if err != nil {
		t.Fatal(err)
	}
	if v.Spec.Mode != "0770" || v.Spec.UID != 5000 || v.Spec.Storage == "" || v.Status.Dataset != "tank/jailops/projects/"+dtest.SeedProject+"/volumes/maildir" {
		t.Fatalf("%+v", v)
	}
	if e.ZFS == nil {
		t.Fatal("no zfs")
	}
	// the owner and the mode reached the helper's operation
	if got := e.Files.Owners["/jailops/projects/"+dtest.SeedProject+"/volumes/maildir"]; got != "5000:5000:0770" {
		t.Fatalf("owner %q", got)
	}
	// defaults: root, 0755
	newVolume(t, s, ctx, "plain", api.VolumeSpec{})
	if v, _ := s.GetVolume(ctx, "plain"); v.Spec.Mode != "0755" || v.Spec.UID != 0 || v.Spec.GID != 0 {
		t.Fatalf("%+v", v.Spec)
	}
	l, err := s.ListVolumes(ctx, nil)
	if err != nil || len(l) != 2 {
		t.Fatalf("%v %v", l, err)
	}
	op, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "maildir"}})
	if err == nil {
		failedWith(t, s, op, err, api.CodeAlreadyExists)
	} else {
		wantCode(t, err, api.CodeAlreadyExists)
	}
	for name, spec := range map[string]api.VolumeSpec{"mode": {Mode: "4755"}, "mode text": {Mode: "rwx"}, "uid": {UID: -1}, "size": {Size: "lots"}} {
		_, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "bad"}, Spec: spec})
		if !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// labels, comment and size change; owner, mode and storage do not
	v.Spec.Comment, v.Spec.Size = "mail of everyone", "6G"
	if _, err := s.UpdateVolume(ctx, "maildir", v, service.AnyGeneration); err != nil {
		t.Fatal(err)
	}
	for what, mut := range map[string]func(*api.Volume){"uid": func(x *api.Volume) { x.Spec.UID = 1 }, "gid": func(x *api.Volume) { x.Spec.GID = 1 },
		"mode": func(x *api.Volume) { x.Spec.Mode = "0700" }, "storage": func(x *api.Volume) { x.Spec.Storage = "elsewhere" }} {
		x, _ := s.GetVolume(ctx, "maildir")
		mut(&x)
		if _, err := s.UpdateVolume(ctx, "maildir", x, service.AnyGeneration); !api.IsCode(err, api.CodeInvalid) && !api.IsCode(err, api.CodeNotFound) && !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: %v", what, err)
		}
	}
	op, err = s.DeleteVolume(ctx, "plain", service.AnyGeneration)
	mustOp(t, s, op, err)
	if _, err := s.GetVolume(ctx, "plain"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestAttachAndDetachRules(t *testing.T) {
	_, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newVolume(t, s, ctx, "maildir", api.VolumeSpec{UID: 5000, GID: 5000, Mode: "0770"})
	for _, n := range []string{"mail", "desktop"} {
		op, err := s.CreateJail(ctx, dtest.WebJail(n))
		mustOp(t, s, op, err)
	}
	attach := func(jail, mount string, ro bool) error {
		op, err := s.AttachVolume(ctx, jail, api.VolumeAttachRequest{Volume: "maildir", Mount: mount, ReadOnly: ro})
		if err != nil {
			return err
		}
		if got := wait(t, s, op); got.Status != api.OpSuccess {
			return &api.Error{Code: got.Error.Code, Message: got.Error.Message}
		}
		return nil
	}
	if err := attach("mail", "/var/mail/vhosts", false); err != nil {
		t.Fatal(err)
	}
	// the same volume, writable in a second jail: allowed, and reported
	if err := attach("desktop", "/home/ann/Mail", false); err != nil {
		t.Fatal(err)
	}
	v, _ := s.GetVolume(ctx, "maildir")
	if len(v.Status.AttachedTo) != 2 || len(v.Status.Warnings) != 1 || !strings.Contains(v.Status.Warnings[0], "writable in more than one jail") {
		t.Fatalf("%+v", v.Status)
	}
	// attached twice to one jail, over a persistent path, a bad path, a missing volume
	if err := attach("mail", "/srv/other", false); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Errorf("twice: %v", err)
	}
	if _, err := s.AttachVolume(ctx, "mail", api.VolumeAttachRequest{Volume: "ghost", Mount: "/x"}); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("a volume that does not exist: %v", err)
	}
	newVolume(t, s, ctx, "other", api.VolumeSpec{})
	for name, mount := range map[string]string{"persistent": "/var/mail", "relative": "x", "dotdot": "/a/../etc", "root": "/", "taken": "/var/mail/vhosts"} {
		op, err := s.AttachVolume(ctx, "mail", api.VolumeAttachRequest{Volume: "other", Mount: mount})
		if err == nil {
			failedWith(t, s, op, err, api.CodeInvalid)
		} else if !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a volume that is attached is not deleted
	_, err := s.DeleteVolume(ctx, "maildir", service.AnyGeneration)
	wantCode(t, err, api.CodeBusy)
	// a running jail neither attaches nor detaches
	op, err := s.JailAction(ctx, "desktop", api.JailAction{Action: "start"})
	mustOp(t, s, op, err)
	op, err = s.DetachVolume(ctx, "desktop", "maildir")
	failedWith(t, s, op, err, api.CodeBusy)
	op, err = s.AttachVolume(ctx, "desktop", api.VolumeAttachRequest{Volume: "other", Mount: "/srv/o"})
	failedWith(t, s, op, err, api.CodeBusy)
	// editing the jail's spec is the same thing and is refused alike
	j, _ := s.GetJail(ctx, "desktop")
	j.Spec.Volumes = nil
	_, err = s.UpdateJail(ctx, "desktop", j, service.AnyGeneration)
	wantCode(t, err, api.CodeBusy)
	op, err = s.JailAction(ctx, "desktop", api.JailAction{Action: "stop"})
	mustOp(t, s, op, err)
	op, err = s.DetachVolume(ctx, "desktop", "maildir")
	mustOp(t, s, op, err)
	// deleting a jail never deletes its volume
	op, err = s.DeleteJail(ctx, "mail")
	mustOp(t, s, op, err)
	if v, err := s.GetVolume(ctx, "maildir"); err != nil || len(v.Status.AttachedTo) != 0 {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestJailCreateAttachesExistingVolumesOnly(t *testing.T) {
	_, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	j := dtest.WebJail("db")
	j.Spec.Volumes = []api.VolumeAttach{{Name: "db-data", Mount: "/srv/dbdata"}}
	_, err := s.CreateJail(ctx, j)
	wantCode(t, err, api.CodeNotFound)
	if !strings.Contains(hintOf(err), "jailops volume create db-data") {
		t.Fatalf("hint %q", hintOf(err))
	}
	newVolume(t, s, ctx, "db-data", api.VolumeSpec{UID: 770, GID: 770})
	op, err := s.CreateJail(ctx, j)
	mustOp(t, s, op, err)
}

func TestVolumeSnapshotsAndRollback(t *testing.T) {
	_, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newVolume(t, s, ctx, "data", api.VolumeSpec{})
	op, err := s.CreateVolumeSnapshot(ctx, "data", api.VolumeSnapshot{Metadata: api.ObjectMeta{Name: "s1"}, Spec: api.VolumeSnapshotSpec{Comment: "first"}})
	mustOp(t, s, op, err)
	l, err := s.ListVolumeSnapshots(ctx, "data")
	if err != nil || len(l) != 1 || l[0].Metadata.Name != "s1" || l[0].Spec.Comment != "first" {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := s.CreateVolumeSnapshot(ctx, "data", api.VolumeSnapshot{Metadata: api.ObjectMeta{Name: "jo-x"}}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("a reserved name: %v", err)
	}
	if _, err := s.RollbackVolume(ctx, "data", api.VolumeRollback{Snapshot: "s1"}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("a rollback without confirmation: %v", err)
	}
	if _, err := s.RollbackVolume(ctx, "data", api.VolumeRollback{Snapshot: "ghost", ConfirmDataLoss: true}); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("a snapshot that does not exist: %v", err)
	}
	// no running jail may have the volume attached
	jop, err := s.CreateJail(ctx, dtest.WebJail("web"))
	mustOp(t, s, jop, err)
	aop, err := s.AttachVolume(ctx, "web", api.VolumeAttachRequest{Volume: "data", Mount: "/srv/data"})
	mustOp(t, s, aop, err)
	jop, err = s.JailAction(ctx, "web", api.JailAction{Action: "start"})
	mustOp(t, s, jop, err)
	op, err = s.RollbackVolume(ctx, "data", api.VolumeRollback{Snapshot: "s1", ConfirmDataLoss: true})
	failedWith(t, s, op, err, api.CodeBusy)
	jop, err = s.JailAction(ctx, "web", api.JailAction{Action: "stop"})
	mustOp(t, s, jop, err)
	op, err = s.RollbackVolume(ctx, "data", api.VolumeRollback{Snapshot: "s1", ConfirmDataLoss: true})
	mustOp(t, s, op, err)
	op, err = s.DeleteVolumeSnapshot(ctx, "data", "s1")
	mustOp(t, s, op, err)
}
