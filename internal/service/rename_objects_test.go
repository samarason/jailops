package service_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// The renames of the objects that stand on their own: a backup target, a backup policy, a certificate, a storage, a
// volume and a user.

func TestRenameBackupTargetRewritesThePolicies(t *testing.T) {
	_, s := newEnv(t)
	g := as(globalAdmin, "")
	alpha := as(globalAdmin, dtest.SeedProject)
	if _, err := s.CreateTarget(g, api.BackupTarget{Metadata: api.ObjectMeta{Name: "vault"}, Spec: api.BackupTargetSpec{Kind: "directory", Path: "/backups/vault"}}); err != nil {
		t.Fatal(err)
	}
	pol := api.BackupPolicy{Metadata: api.ObjectMeta{Name: "nightly"}, Spec: api.BackupPolicySpec{Selector: map[string]string{"all": ""},
		Targets: []string{"vault"}, Schedule: "0 3 * * *", Retention: api.RetentionPolicy{Last: 3}}}
	if _, err := s.CreateBackupPolicy(alpha, pol); err != nil {
		t.Fatal(err)
	}
	_, dry, err := s.RenameBackupTarget(g, "vault", service.RenameOptions{NewName: "safe", DryRun: true, Expect: service.AnyGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || !hasChange(*dry, api.RenameReference, "backup policy nightly") {
		t.Fatalf("dry run: %+v", dry)
	}
	_, _, err = s.RenameBackupTarget(as(alphaOnly, dtest.SeedProject), "vault", renameOpts("safe"))
	wantCode(t, err, api.CodeForbidden)
	_, _, err = s.RenameBackupTarget(g, "nowhere", renameOpts("safe"))
	wantCode(t, err, api.CodeNotFound)
	_, _, err = s.RenameBackupTarget(g, "vault", renameOpts("Safe_"))
	wantCode(t, err, api.CodeInvalid)
	res := doRename(t, s)(s.RenameBackupTarget(g, "vault", renameOpts("safe")))
	if res.From != "vault" || res.To != "safe" || len(res.Warnings) == 0 {
		t.Fatalf("%+v", res)
	}
	if _, err := s.GetTarget(g, "vault"); err == nil {
		t.Fatal("the old name is still there")
	}
	p, err := s.GetBackupPolicy(alpha, "nightly")
	if err != nil || !slices.Equal(p.Spec.Targets, []string{"safe"}) {
		t.Fatalf("%+v %v", p.Spec.Targets, err)
	}
}

func TestRenameBackupPolicy(t *testing.T) {
	_, s := newEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	if _, err := s.CreateTarget(as(globalAdmin, ""), api.BackupTarget{Metadata: api.ObjectMeta{Name: "vault"}, Spec: api.BackupTargetSpec{Kind: "directory", Path: "/backups/vault"}}); err != nil {
		t.Fatal(err)
	}
	pol := api.BackupPolicy{Metadata: api.ObjectMeta{Name: "nightly"}, Spec: api.BackupPolicySpec{Selector: map[string]string{"all": ""},
		Targets: []string{"vault"}, Schedule: "0 3 * * *", Retention: api.RetentionPolicy{Last: 3}}}
	if _, err := s.CreateBackupPolicy(alpha, pol); err != nil {
		t.Fatal(err)
	}
	pol.Metadata.Name = "weekly"
	if _, err := s.CreateBackupPolicy(alpha, pol); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.RenameBackupPolicy(alpha, "nightly", renameOpts("weekly"))
	wantCode(t, err, api.CodeAlreadyExists)
	_, _, err = s.RenameBackupPolicy(alpha, "nowhere", renameOpts("daily"))
	wantCode(t, err, api.CodeNotFound)
	doRename(t, s)(s.RenameBackupPolicy(alpha, "nightly", renameOpts("daily")))
	if _, err := s.GetBackupPolicy(alpha, "daily"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetBackupPolicy(alpha, "nightly"); err == nil {
		t.Fatal("the old name is still there")
	}
}

func TestRenameUserKeepsThePassword(t *testing.T) {
	_, s := newEnv(t)
	g := as(globalAdmin, "")
	created, err := s.CreateUser(g, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(g, api.UserCreate{Metadata: api.ObjectMeta{Name: "bob"}, Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}}); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.RenameUser(g, "ann", renameOpts("bob"))
	wantCode(t, err, api.CodeAlreadyExists)
	_, _, err = s.RenameUser(g, "nobody", renameOpts("carl"))
	wantCode(t, err, api.CodeNotFound)
	_, _, err = s.RenameUser(as(alphaOnly, dtest.SeedProject), "ann", renameOpts("carl"))
	wantCode(t, err, api.CodeForbidden)
	_, dry, err := s.RenameUser(g, "ann", service.RenameOptions{NewName: "carl", DryRun: true, Expect: service.AnyGeneration})
	if err != nil || !dry.DryRun {
		t.Fatalf("%+v %v", dry, err)
	}
	if _, err := s.GetUser(g, "carl"); err == nil {
		t.Fatal("the dry run renamed the user")
	}
	doRename(t, s)(s.RenameUser(g, "ann", renameOpts("carl")))
	u, err := s.GetUser(g, "carl")
	if err != nil || u.Spec.Permission != api.PermAdmin {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := s.GetUser(g, "ann"); err == nil {
		t.Fatal("the old name is still there")
	}
	_ = created
}

func TestRenameVolumeMovesTheDatasetAndTheAttachments(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newVolume(t, s, ctx, "maildir", api.VolumeSpec{UID: 5000, GID: 5000, Mode: "770"})
	web := dtest.WebJail("web")
	web.Spec.Volumes = []api.VolumeAttach{{Name: "maildir", Mount: "/srv/mailbox"}}
	mkJail(t, e, s, ctx, web)
	renameJailAction(t, e, s, ctx, "web", "start")

	// a jail that runs with the volume attached keeps it from being renamed
	_, _, err := s.RenameVolume(ctx, "maildir", renameOpts("mail"))
	wantCode(t, err, api.CodeBusy)
	renameJailAction(t, e, s, ctx, "web", "stop")

	_, dry, err := s.RenameVolume(ctx, "maildir", service.RenameOptions{NewName: "mail", DryRun: true, Expect: service.AnyGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || !hasChange(*dry, api.RenameDataset, "dataset ") || !hasChange(*dry, api.RenameReference, "jail web") {
		t.Fatalf("dry run: %+v", dry)
	}
	newVolume(t, s, ctx, "taken", api.VolumeSpec{})
	_, _, err = s.RenameVolume(ctx, "maildir", renameOpts("taken"))
	wantCode(t, err, api.CodeAlreadyExists)
	_, _, err = s.RenameVolume(ctx, "nowhere", renameOpts("mail"))
	wantCode(t, err, api.CodeNotFound)
	_, _, err = s.RenameVolume(ctx, "maildir", renameOpts("Mail_"))
	wantCode(t, err, api.CodeInvalid)

	doRename(t, s)(s.RenameVolume(ctx, "maildir", renameOpts("mail")))
	v, err := s.GetVolume(ctx, "mail")
	if err != nil || v.Status.Dataset != "tank/jailops/projects/"+dtest.SeedProject+"/volumes/mail" {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := s.GetVolume(ctx, "maildir"); err == nil {
		t.Fatal("the old name is still there")
	}
	j, err := s.GetJail(ctx, "web")
	if err != nil || len(j.Spec.Volumes) != 1 || j.Spec.Volumes[0].Name != "mail" {
		t.Fatalf("%+v %v", j.Spec.Volumes, err)
	}
	// the jail starts again with the volume under its new name
	renameJailAction(t, e, s, ctx, "web", "start")
}

func TestRenameStorageRewritesTheGrantsAndTheVolumes(t *testing.T) {
	e, s := newEnv(t)
	g := as(globalAdmin, "")
	ctx := as(globalAdmin, dtest.SeedProject)
	_, _, err := s.RenameStorage(g, "default", renameOpts("main"))
	wantCode(t, err, api.CodeBusy)
	_, _, err = s.RenameStorage(g, "nowhere", renameOpts("main"))
	wantCode(t, err, api.CodeNotFound)
	_, _, err = s.RenameStorage(as(alphaOnly, dtest.SeedProject), "default", renameOpts("main"))
	wantCode(t, err, api.CodeForbidden)

	if err := e.ZFS.Create(context.Background(), zfs.CreateOpts{Name: "tank/bulk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateStorage(g, api.Storage{Metadata: api.ObjectMeta{Name: "bulk"}, Spec: api.StorageSpec{Dataset: "tank/bulk"}}); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	pr, err := s.GetProject(g, dtest.SeedProject)
	if err != nil {
		t.Fatal(err)
	}
	pr.Spec.Storage = append(pr.Spec.Storage, api.ProjectStorage{Storage: "bulk"})
	if _, err := s.UpdateProject(g, dtest.SeedProject, pr, service.AnyGeneration); err != nil {
		t.Fatal(err)
	}
	newVolume(t, s, ctx, "data", api.VolumeSpec{Storage: "bulk"})

	_, dry, err := s.RenameStorage(g, "bulk", service.RenameOptions{NewName: "big", DryRun: true, Expect: service.AnyGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || !hasChange(*dry, api.RenameReference, "project "+dtest.SeedProject) || !hasChange(*dry, api.RenameReference, "volume data") {
		t.Fatalf("dry run: %+v", dry)
	}
	_, _, err = s.RenameStorage(g, "bulk", renameOpts("default"))
	wantCode(t, err, api.CodeAlreadyExists)
	doRename(t, s)(s.RenameStorage(g, "bulk", renameOpts("big")))
	if _, err := s.GetStorage(g, "big"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetStorage(g, "bulk"); err == nil {
		t.Fatal("the old name is still there")
	}
	pr, _ = s.GetProject(g, dtest.SeedProject)
	var granted []string
	for _, st := range pr.Spec.Storage {
		granted = append(granted, st.Storage)
	}
	if !slices.Contains(granted, "big") || slices.Contains(granted, "bulk") {
		t.Fatalf("grants %v", granted)
	}
	v, err := s.GetVolume(ctx, "data")
	if err != nil || v.Spec.Storage != "big" {
		t.Fatalf("%+v %v", v.Spec, err)
	}
	// the registry knows the new name: a volume can be made on it
	newVolume(t, s, ctx, "more", api.VolumeSpec{Storage: "big"})
}

// volumeState is what a volume rename touches: the object, the datasets and the jail's attachments.
func volumeState(t *testing.T, e *dtest.Env, s *service.Service) string {
	t.Helper()
	ctx := as(globalAdmin, dtest.SeedProject)
	var out []string
	if vs, err := s.ListVolumes(ctx, nil); err == nil {
		for _, v := range vs {
			out = append(out, "volume "+v.Metadata.Name+" "+v.Status.Dataset)
		}
	}
	if j, err := s.GetJail(ctx, "web"); err == nil {
		for _, v := range j.Spec.Volumes {
			out = append(out, "attach "+v.Name)
		}
	}
	for _, ds := range dsNames(e) {
		if strings.Contains(ds, "/volumes/") {
			out = append(out, "ds "+ds)
		}
	}
	slices.Sort(out)
	return strings.Join(out, "\n")
}

func TestRenameVolumeRollsBackEveryStep(t *testing.T) {
	e, s := faultEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newVolume(t, s, ctx, "maildir", api.VolumeSpec{})
	web := dtest.WebJail("web")
	web.Spec.Volumes = []api.VolumeAttach{{Name: "maildir", Mount: "/srv/mailbox"}}
	mkJail(t, e, s, ctx, web)
	before := volumeState(t, e, s)
	for k := 1; ; k++ {
		if k > 80 {
			t.Fatal("the rename never succeeded")
		}
		e.Fault.Reset(k)
		op, _, err := s.RenameVolume(ctx, "maildir", renameOpts("mail"))
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, s, op)
		e.Fault.Reset(0)
		if got.Status == api.OpSuccess {
			if k < 3 {
				t.Fatalf("only %d steps were faulted", k-1)
			}
			break
		}
		if now := volumeState(t, e, s); now != before {
			t.Fatalf("failure at mutation %d (%s) left\n%s\ninstead of\n%s", k, got.Error.Message, now, before)
		}
	}
}

func TestRenameWireGuardMovesTheKeys(t *testing.T) {
	e, s := newEnv(t)
	g := as(globalAdmin, "")
	spec := api.WireGuardSpec{Mode: api.WireGuardServer, Interface: "wg-office", Address: []string{"10.99.0.1/24"}, ListenPort: 51820, AllowedIPs: []string{"10.99.0.0/24"}}
	if _, err := s.CreateWireGuard(g, api.WireGuard{Metadata: api.ObjectMeta{Name: "office"}, Spec: spec}); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	_, _, err := s.RenameWireGuard(as(alphaOnly, dtest.SeedProject), "office", renameOpts("hq"))
	wantCode(t, err, api.CodeForbidden)
	_, _, err = s.RenameWireGuard(g, "nowhere", renameOpts("hq"))
	wantCode(t, err, api.CodeNotFound)
	_, _, err = s.RenameWireGuard(g, "office", renameOpts("Bad_Name"))
	wantCode(t, err, api.CodeInvalid)
	_, dry, err := s.RenameWireGuard(g, "office", service.RenameOptions{NewName: "hq", DryRun: true, Expect: service.AnyGeneration})
	if err != nil || !dry.DryRun {
		t.Fatalf("%+v %v", dry, err)
	}
	doRename(t, s)(s.RenameWireGuard(g, "office", renameOpts("hq")))
	if _, err := s.GetWireGuard(g, "hq"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWireGuard(g, "office"); err == nil {
		t.Fatal("the old name is still there")
	}
	if !e.WG.HasKeys("hq") || e.WG.HasKeys("office") {
		t.Fatalf("the keys did not follow the name: %v", e.WG.Calls())
	}
	var moved bool
	for _, l := range e.WG.Calls() {
		if strings.Contains(l, "rename office hq") {
			moved = true
		}
	}
	if !moved {
		t.Fatalf("the keys did not move: %v", e.WG.Calls())
	}
}
