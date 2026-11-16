package service_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// A project is deleted only when nothing of it is left: its volumes are data, and deleting the project does not
// destroy them without the operator's say (the volume's own delete asks for it).
func TestProjectDeleteRefusesWhileItHoldsVolumes(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	if _, err := s.CreateProject(as(globalAdmin, ""), api.Project{Metadata: api.ObjectMeta{Name: "beta"},
		Spec: api.ProjectSpec{Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	bctx := as(globalAdmin, "beta")
	newVolume(t, s, bctx, "maildir", api.VolumeSpec{UID: 5000, GID: 5000, Mode: "770"})
	ds := "tank/jailops/projects/beta/volumes/maildir"
	if ok, _ := e.ZFS.Exists(ctx, ds); !ok {
		t.Fatalf("the volume dataset %s was not made", ds)
	}
	err := s.DeleteProject(as(globalAdmin, ""), "beta", 1)
	wantCode(t, err, api.CodeBusy)
	if !strings.Contains(err.Error(), "1 volumes") {
		t.Fatalf("the refusal does not name the volumes: %v", err)
	}
	if ok, _ := e.ZFS.Exists(ctx, ds); !ok {
		t.Fatal("a refused project delete destroyed the volume")
	}
	// with the volume deleted the project goes, and its datasets with it
	op, err := s.DeleteVolume(bctx, "maildir", 1)
	mustOp(t, s, op, err)
	if err := s.DeleteProject(as(globalAdmin, ""), "beta", 1); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.ZFS.Exists(ctx, "tank/jailops/projects/beta"); ok {
		t.Fatal("the datasets of the deleted project are still there")
	}
}

// A dataset below the project that no object accounts for (a container parked by a replace-restore, what an
// interrupted operation left) is named and kept, never destroyed with the project.
func TestProjectDeleteRefusesWhileDatasetsAreLeft(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, "")
	if _, err := s.CreateProject(ctx, api.Project{Metadata: api.ObjectMeta{Name: "beta"},
		Spec: api.ProjectSpec{Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tank/jailops/projects/beta/jails/web.replaced-ab12cd", "tank/jailops/projects/beta/volumes/orphan"} {
		if err := e.ZFS.Create(ctx, zfs.CreateOpts{Name: name, Parents: true}); err != nil {
			t.Fatal(err)
		}
	}
	err := s.DeleteProject(ctx, "beta", 1)
	wantCode(t, err, api.CodeBusy)
	for _, want := range []string{"jails/web.replaced-ab12cd", "volumes/orphan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
	if ok, _ := e.ZFS.Exists(ctx, "tank/jailops/projects/beta/volumes/orphan"); !ok {
		t.Fatal("a refused project delete destroyed a dataset")
	}
}
