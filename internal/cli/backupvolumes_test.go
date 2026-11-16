package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// A volume is a backup of its own: the policy backs it up once with the jails that attach it, a run or a policy can
// leave volumes out, the list tells the kinds apart, and a volume backup restores as a new volume.
func TestBackupVolumes(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("volume", "create", "mail", "--uid", "5000", "--gid", "5000", "--mode", "0770")
	for _, n := range []string{"web1", "web2"} {
		h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: n, Project: "main", Labels: map[string]string{"env": "prod"}},
			Spec: api.JailSpec{Image: "freebsd-15@stable", Volumes: []api.VolumeAttach{{Name: "mail", Mount: "/srv/mail"}}}})
	}
	tr.ok("backup", "key", "create", "--recipient", "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	tr.ok("backup", "target", "create", "vault", "--kind", "node", "--url", "https://b.example:8443", "--fingerprint", "abcd")
	tr.ok("backup", "policy", "create", "nightly", "--selector", "env=prod", "--target", "vault", "--schedule", "0 2 * * *")

	out := tr.ok("backup", "run", "nightly")
	if strings.Count(out, "mail") != 1 || !strings.Contains(out, "web1") || !strings.Contains(out, "web2") {
		t.Fatalf("the run lists the volume once next to the two jails:\n%s", out)
	}
	if out := tr.ok("backup", "run", "nightly", "--no-volumes"); strings.Contains(out, "mail") {
		t.Fatalf("--no-volumes backed the volume up:\n%s", out)
	}
	tr.ok("backup", "policy", "create", "jails-only", "--selector", "env=prod", "--target", "vault", "--schedule", "0 2 * * *", "--no-volumes")
	if body := string(h.lastBody("POST", "/api/v1/backup-policies")); !strings.Contains(body, `"exclude_volumes":true`) {
		t.Fatalf("the policy was sent without exclude_volumes: %s", body)
	}
	if out := tr.ok("backup", "run", "jails-only"); strings.Contains(out, "mail") {
		t.Fatalf("a policy with --no-volumes backed the volume up:\n%s", out)
	}

	list := tr.ok("backup", "list", "--volume", "mail")
	if !strings.Contains(list, "KIND") || strings.Count(list, "volume") != 1 || strings.Contains(list, "web1") {
		t.Fatalf("the volume's backups:\n%s", list)
	}
	id := strings.TrimSpace(tr.ok("backup", "list", "--volume", "mail", "-o", "name"))
	if strings.Contains(id, "\n") || id == "" {
		t.Fatalf("one backup of the volume expected, got %q", id)
	}
	if jails := tr.ok("backup", "list", "--jail", "web1", "-o", "name"); strings.Contains(jails, id) {
		t.Fatalf("a volume backup is listed as a jail's: %s", jails)
	}

	// it restores as a new volume, never over an existing one
	if _, _, code := tr.do("", "backup", "restore", id, "-y"); code != 2 {
		t.Fatalf("restore over the existing volume: exit %d", code)
	}
	if out := tr.ok("backup", "restore", id, "--as", "mail2", "-y"); !strings.Contains(out, "volume/mail2 restored") {
		t.Fatalf("restore: %s", out)
	}
	if v := tr.ok("volume", "show", "mail2"); !strings.Contains(v, "uid: 5000") {
		t.Fatalf("the restored volume lost its owner:\n%s", v)
	}

	// an encrypted volume needs its passphrase
	h.srv.SeedBackup(api.Backup{Metadata: api.ObjectMeta{Name: "20260103020000-aa11bb22", Project: "main"},
		Spec: api.BackupSpec{Kind: "volume", Jail: "vault", JailUUID: "11111111-2222-4333-8444-555555555556", Target: "vault", Snapshot: "20260103020000-aa11bb22",
			Volume: &api.VolumeSpec{Storage: "default", Encrypted: true}}})
	if _, _, code := tr.do("", "backup", "restore", "20260103020000-aa11bb22", "-y"); code == 0 {
		t.Fatal("an encrypted volume was restored without a passphrase")
	}
	pass := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(pass, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := tr.ok("backup", "restore", "20260103020000-aa11bb22", "--passphrase-file", pass, "-y"); !strings.Contains(out, "volume/vault restored") {
		t.Fatalf("restore with a passphrase file: %s", out)
	}
	if body := string(h.lastBody("POST", "/api/v1/restores")); strings.Contains(body, "correct horse") && !strings.Contains(body, "passphrase") {
		t.Fatalf("unexpected body: %s", body)
	}

	// a jail restore without the volumes it attaches that the project lacks
	h.srv.SeedBackup(api.Backup{Metadata: api.ObjectMeta{Name: "20260104020000-cc33dd44", Project: "main"},
		Spec: api.BackupSpec{Jail: "web3", JailUUID: "11111111-2222-4333-8444-555555555557", Target: "vault", Snapshot: "20260104020000-cc33dd44",
			Bundle: api.RestoreBundle{Spec: api.JailSpec{Image: "freebsd-15@stable", Volumes: []api.VolumeAttach{{Name: "gone", Mount: "/srv/gone"}}}}}})
	pre := tr.ok("backup", "restore", "20260104020000-cc33dd44", "--dry-run")
	if !strings.Contains(pre, "no backup of it was found") {
		t.Fatalf("the preflight does not say the volume is missing:\n%s", pre)
	}
	if out := tr.ok("backup", "restore", "20260104020000-cc33dd44", "--as", "web4", "--no-volumes", "-y"); !strings.Contains(out, "jail/web4 restored") {
		t.Fatalf("restore --no-volumes: %s", out)
	}
	if j := tr.ok("jail", "show", "web4"); strings.Contains(j, "gone") {
		t.Fatalf("the jail attaches the volume it was restored without:\n%s", j)
	}
	if out := tr.ok("backup", "restore", "20260104020000-cc33dd44", "-y"); !strings.Contains(out, "jail/web3 restored") {
		t.Fatalf("restore: %s", out)
	}
	if j := tr.ok("jail", "show", "web3"); !strings.Contains(j, "gone") {
		t.Fatalf("the restored jail lost its attachment:\n%s", j)
	}
}

// --no-volumes leaves every attachment out, also of a volume the project has; a normal restore keeps it.
func TestBackupRestoreNoVolumesDropsEveryAttachment(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("volume", "create", "mail")
	h.srv.SeedBackup(api.Backup{Metadata: api.ObjectMeta{Name: "20260105020000-ee55ff66", Project: "main"},
		Spec: api.BackupSpec{Jail: "web5", JailUUID: "11111111-2222-4333-8444-555555555558", Target: "vault", Snapshot: "20260105020000-ee55ff66",
			Bundle: api.RestoreBundle{Spec: api.JailSpec{Image: "freebsd-15@stable", Volumes: []api.VolumeAttach{{Name: "mail", Mount: "/srv/mail"}}}}}})
	tr.ok("backup", "restore", "20260105020000-ee55ff66", "--as", "keeps", "-y")
	if j := tr.ok("jail", "show", "keeps"); !strings.Contains(j, "mail") {
		t.Fatalf("a normal restore lost the attachment:\n%s", j)
	}
	tr.ok("backup", "restore", "20260105020000-ee55ff66", "--as", "drops", "--no-volumes", "-y")
	if j := tr.ok("jail", "show", "drops"); strings.Contains(j, "mail") {
		t.Fatalf("--no-volumes left the attachment of a volume the project has:\n%s", j)
	}
}
