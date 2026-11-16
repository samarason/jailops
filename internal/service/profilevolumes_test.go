package service_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// What a profile gives a jail passes the checks of what the jail's own spec attaches or takes: the volumes (a host
// directory is granted by a global administrator only; an encrypted volume belongs to one jail) and the project's
// quotas. Editing the profile is another way to the same jail, not a way around them.

func profileJail(name, profile string) api.Jail {
	j := dtest.WebJail(name)
	j.Spec.Profiles = []string{profile}
	return j
}

func TestProfileEditCannotGiveAJailAHostDirectory(t *testing.T) {
	e, s := newEnv(t)
	newBoxVolume(t, e, s, api.VolumeSpec{})
	pctx := as(alphaOnly, dtest.SeedProject)
	if _, err := s.CreateProfile(pctx, api.Profile{Metadata: api.ObjectMeta{Name: "p"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.pids": "100"}}}); err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateJail(pctx, profileJail("web", "p"))
	mustOp(t, s, op, err)
	p, err := s.GetProfile(pctx, "p")
	if err != nil {
		t.Fatal(err)
	}
	p.Spec.Config = map[string]string{"limits.pids": "100", "disk.box": "/srv/backups"}
	_, err = s.UpdateProfile(pctx, "p", p, p.Metadata.Generation)
	wantCode(t, err, api.CodeForbidden)
	if !strings.Contains(err.Error(), "directory of the host") {
		t.Fatalf("%v", err)
	}
	// the same edit by a global administrator is the grant
	p, _ = s.GetProfile(pctx, "p")
	p.Spec.Config = map[string]string{"limits.pids": "100", "disk.box": "/srv/backups"}
	if _, err := s.UpdateProfile(as(globalAdmin, dtest.SeedProject), "p", p, p.Metadata.Generation); err != nil {
		t.Fatalf("a global administrator gives a host directory through a profile: %v", err)
	}
}

func TestEncryptedVolumeStaysWithOneJailThroughProfiles(t *testing.T) {
	_, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	vop, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "vault"}, Spec: api.VolumeSpec{Encrypted: true, UID: 770, GID: 770, Mode: "0700"}, Passphrase: encPass})
	mustOp(t, s, vop, err)
	if _, err := s.CreateProfile(ctx, api.Profile{Metadata: api.ObjectMeta{Name: "p"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.pids": "100"}}}); err != nil {
		t.Fatal(err)
	}
	// two jails of one profile
	for _, n := range []string{"a", "b"} {
		op, err := s.CreateJail(ctx, profileJail(n, "p"))
		mustOp(t, s, op, err)
	}
	p, _ := s.GetProfile(ctx, "p")
	p.Spec.Config = map[string]string{"limits.pids": "100", "disk.vault": "/var/db/app"}
	_, err = s.UpdateProfile(ctx, "p", p, p.Metadata.Generation)
	wantCode(t, err, api.CodeConflict)
	if !strings.Contains(err.Error(), "attached to one jail") {
		t.Fatalf("%v", err)
	}
	// a jail made with a profile that carries it takes the volume only when no other jail has it
	if _, err := s.CreateProfile(ctx, api.Profile{Metadata: api.ObjectMeta{Name: "q"}, Spec: api.ProfileSpec{Config: map[string]string{"disk.vault": "/var/db/app"}}}); err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateJail(ctx, profileJail("c", "q"))
	mustOp(t, s, op, err)
	_, err = s.CreateJail(ctx, profileJail("d", "q"))
	wantCode(t, err, api.CodeConflict)
}

func TestProfileEditCannotPassTheQuotasOfTheProject(t *testing.T) {
	_, s := newEnv(t)
	gctx := as(globalAdmin, dtest.SeedProject)
	p, err := s.GetProject(as(globalAdmin, ""), dtest.SeedProject)
	if err != nil {
		t.Fatal(err)
	}
	p.Spec.Quotas.Memory = "4G"
	if _, err := s.UpdateProject(as(globalAdmin, ""), dtest.SeedProject, p, p.Metadata.Generation); err != nil {
		t.Fatal(err)
	}
	pctx := as(alphaOnly, dtest.SeedProject)
	if _, err := s.CreateProfile(pctx, api.Profile{Metadata: api.ObjectMeta{Name: "p"}, Spec: api.ProfileSpec{Config: map[string]string{"limits.memory": "1G"}}}); err != nil {
		t.Fatal(err)
	}
	op, err := s.CreateJail(pctx, profileJail("web", "p"))
	mustOp(t, s, op, err)
	prof, _ := s.GetProfile(pctx, "p")
	prof.Spec.Config = map[string]string{"limits.memory": "100G"}
	_, err = s.UpdateProfile(pctx, "p", prof, prof.Metadata.Generation)
	wantCode(t, err, api.CodeQuotaExceeded)
	// within the quota it goes through
	prof.Spec.Config = map[string]string{"limits.memory": "2G"}
	if _, err := s.UpdateProfile(pctx, "p", prof, prof.Metadata.Generation); err != nil {
		t.Fatal(err)
	}
	// the memory a profile gives a jail counts for the project (it did not: only a jail's own limits did)
	op, err = s.CreateJail(gctx, withMemory(dtest.WebJail("db"), "3G"))
	_ = op
	wantCode(t, err, api.CodeQuotaExceeded)
}

func withMemory(j api.Jail, m string) api.Jail {
	j.Spec.Resources.Memory = m
	return j
}
