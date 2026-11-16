package backupe2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// TestVolumesAreBackedUpOnceAndRestored runs the whole path through the daemon: a volume that two jails attach is one
// backup of its own, a run or a policy can leave volumes out, a volume backup restores as a new volume, and a jail
// restore brings back the volume that was lost.
func TestVolumesAreBackedUpOnceAndRestored(t *testing.T) {
	e, mnt, _, addr := setup(t)
	c := ctxT(t)
	bk := e.Admin.Backups()
	if _, err := bk.CreateKey(c); err != nil {
		t.Fatal(err)
	}
	if _, err := bk.Targets().Create(c, api.BackupTarget{Metadata: api.ObjectMeta{Name: "vault"}, Spec: api.BackupTargetSpec{Kind: "node", Address: addr, Fingerprint: strings.Repeat("0", 64)}}); err != nil {
		t.Fatal(err)
	}
	policy := func(name string, exclude bool) {
		t.Helper()
		if _, err := bk.Policies().Create(c, api.BackupPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: api.BackupPolicySpec{
			Selector: map[string]string{"all": ""}, Targets: []string{"vault"}, Schedule: "0 3 * * *", Retention: api.RetentionPolicy{Last: 3}, ExcludeVolumes: exclude}}); err != nil {
			t.Fatal(err)
		}
	}
	policy("nightly", false)
	policy("jails-only", true)

	vop, err := e.Admin.Volumes().Create(c, sdk.NewVolume("mail", api.VolumeSpec{UID: 5000, GID: 5000, Mode: "0770"}), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vop.Wait(c); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"web1", "web2"} {
		j := dtest.WebJail(n)
		j.Spec.Volumes = []api.VolumeAttach{{Name: "mail", Mount: "/srv/mail"}}
		jop, err := e.Admin.Jails().Create(c, j)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jop.Wait(c); err != nil {
			t.Fatal(err)
		}
	}
	dataset := func(volume string) string {
		t.Helper()
		vs, err := e.D.Service().BackupVolumes(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			if v.Name == volume {
				return v.Dataset
			}
		}
		t.Fatalf("no dataset of volume %s in %+v", volume, vs)
		return ""
	}
	if err := os.WriteFile(filepath.Join(mnt.dir(dataset("mail")), "m1"), []byte("hello mail"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(req api.BackupRunRequest) []string {
		t.Helper()
		op, err := bk.RunWith(c, req)
		if err != nil {
			t.Fatal(err)
		}
		runs, err := op.Wait(c)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, r := range runs {
			if !r.OK {
				t.Fatalf("a run failed: %+v", r)
			}
			names = append(names, r.Jail)
		}
		return names
	}
	volumeBackups := func() (ids []string) {
		t.Helper()
		for b, err := range bk.List(c) {
			if err != nil {
				t.Fatal(err)
			}
			if b.Spec.Kind == "volume" && b.Spec.Jail == "mail" {
				ids = append(ids, b.Metadata.Name)
			}
		}
		return ids
	}
	jailBackup := func(name string) string {
		t.Helper()
		for b, err := range bk.List(c) {
			if err != nil {
				t.Fatal(err)
			}
			if b.Spec.Kind != "volume" && b.Spec.Jail == name {
				return b.Metadata.Name
			}
		}
		t.Fatalf("no backup of jail %s", name)
		return ""
	}

	if got := strings.Join(run(api.BackupRunRequest{Policy: "nightly"}), ","); got != "mail,web1,web2" {
		t.Fatalf("runs = %s, want the volume once between the two jails", got)
	}
	ids := volumeBackups()
	if len(ids) != 1 {
		t.Fatalf("%d backups of a volume that two jails attach, want one", len(ids))
	}
	if got := strings.Join(run(api.BackupRunRequest{Policy: "nightly", NoVolumes: true}), ","); got != "web1,web2" {
		t.Fatalf("a run without volumes = %s", got)
	}
	if got := strings.Join(run(api.BackupRunRequest{Policy: "jails-only"}), ","); got != "web1,web2" {
		t.Fatalf("a policy that excludes volumes = %s", got)
	}
	if n := len(volumeBackups()); n != 1 {
		t.Fatalf("%d volume backups after runs that leave volumes out, want 1", n)
	}

	// a volume backup restores as a new volume, with the owner and the files; a volume is never replaced
	req := api.RestoreRequest{Backup: ids[0], As: "mail2", Project: dtest.SeedProject}
	rop, err := bk.RestoreVolume(c, req)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := rop.Wait(c)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Metadata.Name != "mail2" || v2.Spec.UID != 5000 || v2.Spec.Mode != "0770" {
		t.Fatalf("restored volume = %+v", v2)
	}
	if b, err := os.ReadFile(filepath.Join(mnt.dir(dataset("mail2")), "m1")); err != nil || string(b) != "hello mail" {
		t.Fatalf("restored file = %q, %v", b, err)
	}
	if pf, err := bk.Preflight(c, req); err != nil || pf.OK {
		t.Fatalf("restoring over an existing volume: %+v, %v", pf, err)
	}

	// a jail restore brings the lost volume back first
	bid := jailBackup("web1")
	for _, n := range []string{"web1", "web2"} {
		dop, err := e.Admin.Jails().Delete(c, n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dop.Wait(c); err != nil {
			t.Fatal(err)
		}
	}
	mailDS := dataset("mail")
	dvop, err := e.Admin.Volumes().Delete(c, "mail")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dvop.Wait(c); err != nil {
		t.Fatal(err)
	}
	emptyDir(t, mnt.dir(mailDS)) // the stand-in directory of a destroyed dataset is empty again
	jreq := api.RestoreRequest{Backup: bid, Project: dtest.SeedProject}
	pf, err := bk.Preflight(c, jreq)
	if err != nil || !pf.OK {
		t.Fatalf("preflight = %+v, %v", pf, err)
	}
	if !strings.Contains(strings.Join(pf.Changes, "|"), "restores volume mail from backup "+ids[0]) {
		t.Fatalf("the preflight does not list the volume: %v", pf.Changes)
	}
	jop, err := bk.Restore(c, jreq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jop.Wait(c); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Volumes().Get(c, "mail"); err != nil {
		t.Fatalf("the volume did not come back with the jail: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(mnt.dir(dataset("mail")), "m1")); err != nil || string(b) != "hello mail" {
		t.Fatalf("the volume's file after the jail restore = %q, %v", b, err)
	}

	// --no-volumes leaves every attachment out, also of a volume the project has
	pop, err := bk.Restore(c, api.RestoreRequest{Backup: bid, As: "web9", Project: dtest.SeedProject, NoVolumes: true})
	if err != nil {
		t.Fatal(err)
	}
	if j9, err := pop.Wait(c); err != nil || len(j9.Spec.Volumes) != 0 {
		t.Fatalf("no_volumes with the volume present: %+v, %v", j9.Spec.Volumes, err)
	}
	if got, err := e.Admin.Jails().Get(c, "web9"); err != nil || len(got.Spec.Volumes) != 0 {
		t.Fatalf("the registered jail attaches %+v, %v", got.Spec.Volumes, err)
	}
	// a normal restore keeps them
	nop2, err := bk.Restore(c, api.RestoreRequest{Backup: bid, As: "web8", Project: dtest.SeedProject})
	if err != nil {
		t.Fatal(err)
	}
	if j8, err := nop2.Wait(c); err != nil || len(j8.Spec.Volumes) != 1 {
		t.Fatalf("a normal restore: %+v, %v", j8.Spec.Volumes, err)
	}
	for _, n := range []string{"web8", "web9"} {
		dop, err := e.Admin.Jails().Delete(c, n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dop.Wait(c); err != nil {
			t.Fatal(err)
		}
	}
	// and with the volume gone, no_volumes restores the jail without the attachment
	lop, err := e.Admin.Jails().Delete(c, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lop.Wait(c); err != nil {
		t.Fatal(err)
	}
	mailDS = dataset("mail")
	dv2, err := e.Admin.Volumes().Delete(c, "mail")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dv2.Wait(c); err != nil {
		t.Fatal(err)
	}
	emptyDir(t, mnt.dir(mailDS))
	nop, err := bk.Restore(c, api.RestoreRequest{Backup: bid, Project: dtest.SeedProject, NoVolumes: true})
	if err != nil {
		t.Fatal(err)
	}
	j, err := nop.Wait(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Spec.Volumes) != 0 {
		t.Fatalf("a jail restored with no_volumes attaches %+v", j.Spec.Volumes)
	}
	if _, err := e.Admin.Volumes().Get(c, "mail"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("no_volumes made the volume: %v", err)
	}
}

// emptyDir removes what a directory holds.
func emptyDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// An encrypted volume goes the whole way: backed up while unlocked, skipped while locked, and restored as a new
// encrypted volume under a passphrase that is asked for and never kept.
func TestAnEncryptedVolumeIsBackedUpAndRestored(t *testing.T) {
	e, mnt, _, addr := setup(t)
	c := ctxT(t)
	bk := e.Admin.Backups()
	if _, err := bk.CreateKey(c); err != nil {
		t.Fatal(err)
	}
	if _, err := bk.Targets().Create(c, api.BackupTarget{Metadata: api.ObjectMeta{Name: "vault"}, Spec: api.BackupTargetSpec{Kind: "node", Address: addr, Fingerprint: strings.Repeat("0", 64)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := bk.Policies().Create(c, api.BackupPolicy{Metadata: api.ObjectMeta{Name: "all"}, Spec: api.BackupPolicySpec{
		Selector: map[string]string{"all": ""}, Targets: []string{"vault"}, Schedule: "0 3 * * *", Retention: api.RetentionPolicy{Last: 3}}}); err != nil {
		t.Fatal(err)
	}
	const pass = "correct horse battery staple"
	vop, err := e.Admin.Volumes().Create(c, sdk.NewVolume("vault", api.VolumeSpec{Encrypted: true, UID: 770, GID: 770, Mode: "0700"}), pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vop.Wait(c); err != nil {
		t.Fatal(err)
	}
	vs, err := e.D.Service().BackupVolumes(c)
	if err != nil || len(vs) != 1 {
		t.Fatalf("%+v %v", vs, err)
	}
	if err := os.WriteFile(filepath.Join(mnt.dir(vs[0].Dataset), "secret"), []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	rop, err := bk.Run(c, "all")
	if err != nil {
		t.Fatal(err)
	}
	runs, err := rop.Wait(c)
	if err != nil || len(runs) != 1 || !runs[0].OK || runs[0].Jail != "vault" {
		t.Fatalf("runs = %+v, %v", runs, err)
	}
	var id string
	for b, err := range bk.List(c) {
		if err != nil {
			t.Fatal(err)
		}
		id = b.Metadata.Name
		if b.Spec.Volume == nil || !b.Spec.Volume.Encrypted {
			t.Fatalf("the backup does not know the volume is encrypted: %+v", b.Spec)
		}
	}
	// no passphrase: refused by the preflight, and a wrong kind of one by the check
	req := api.RestoreRequest{Backup: id, As: "vault2", Project: dtest.SeedProject}
	if pf, err := bk.Preflight(c, req); err != nil || pf.OK {
		t.Fatalf("an encrypted volume without a passphrase: %+v, %v", pf, err)
	}
	if _, err := bk.RestoreVolume(c, api.RestoreRequest{Backup: id, As: "vault2", Project: dtest.SeedProject, Passphrase: "short"}); err == nil {
		t.Fatal("a short passphrase was taken")
	}
	req.Passphrase = pass
	rr, err := bk.RestoreVolume(c, req)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := rr.Wait(c)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.Spec.Encrypted || v2.Spec.UID != 770 {
		t.Fatalf("restored volume = %+v", v2.Spec)
	}
	if strings.Contains(e.Log(), pass) {
		t.Fatal("the passphrase of the restored volume is in the log")
	}
	vs, _ = e.D.Service().BackupVolumes(c)
	for _, v := range vs {
		if v.Name == "vault2" {
			if b, err := os.ReadFile(filepath.Join(mnt.dir(v.Dataset), "secret")); err != nil || string(b) != "s3cret" {
				t.Fatalf("restored file = %q, %v", b, err)
			}
			return
		}
	}
	t.Fatal("the restored volume is not listed")
}
