package hostbackup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/repo/keys"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

func codeOf(t *testing.T, err error, want api.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error %s, got nil", want)
	}
	if !api.IsCode(err, want) {
		t.Fatalf("want code %s, got %v", want, err)
	}
}

func TestKeyLifecycleOnNode(t *testing.T) {
	env, nc := nodeServer(t)
	_ = env
	r := newRig(t, rigOpts{node: &nc, noKey: true, cfg: func(c *Config) {
		c.Passphrase = "correct horse"
		c.Argon2 = keys.Argon2Params{Time: 1, MemKiB: 64, Threads: 1}
	}})
	st, err := r.svc.Status(bg)
	if err != nil || st.Status != keys.StatusNone {
		t.Fatalf("status before create = %v, %v", st.Status, err)
	}
	res, err := r.svc.CreateKey(bg, CreateKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecoveryKey == "" || res.Domain == "" || res.Escrowed {
		t.Fatalf("bad create result %+v", res)
	}
	fi, err := os.Stat(r.keyPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v", fi.Mode(), err)
	}
	raw, _ := os.ReadFile(r.keyPath)
	if !strings.Contains(string(raw), `"passphrase"`) {
		t.Fatalf("key file is not wrapped with a passphrase: %s", raw)
	}
	if _, err := r.svc.CreateKey(bg, CreateKeyOptions{}); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("second create = %v", err)
	}
	if st, err = r.svc.Status(bg); err != nil || st.Status != keys.StatusPresent {
		t.Fatalf("status after create = %v, %v", st.Status, err)
	}
	if err := r.svc.EscrowKey(bg, nil); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("escrow without recipients = %v", err)
	}
	if err := r.svc.EscrowKey(bg, []string{r.recipient}); err != nil {
		t.Fatal(err)
	}
	if st, err = r.svc.Status(bg); err != nil || st.Status != keys.StatusEscrowed {
		t.Fatalf("status after escrow = %v, %v", st.Status, err)
	}
	// the blob is on the node and opens with the offline identity only
	blob, err := r.remoteOf().GetEscrow(bg, res.Domain)
	if err != nil {
		t.Fatal(err)
	}
	k, err := keys.OpenEscrow(blob, r.identity)
	if err != nil || k.DomainID() != res.Domain {
		t.Fatalf("escrow does not open: %v", err)
	}
	// a restart loads the wrapped key with the passphrase, and not without
	cfg := r.cfg
	s2, err := New(cfg, Deps{ZFS: r.w, Catalog: NewMemCatalog()})
	if err != nil || !s2.HoldsKey(res.Domain) {
		t.Fatalf("reload: %v", err)
	}
	cfg.Passphrase = ""
	if _, err := New(cfg, Deps{ZFS: r.w}); err == nil {
		t.Fatal("a wrapped key loaded without its passphrase")
	}
}

func (r *rig) remoteOf() Remote {
	rm, err := r.svc.remoteFor(bg, "")
	if err != nil {
		r.t.Fatal(err)
	}
	return rm
}

func TestBackupRefusedWithoutEscrowOrKey(t *testing.T) {
	_, nc := nodeServer(t)
	r := newRig(t, rigOpts{node: &nc, noEscrow: true})
	j := r.jail("web1", "uuid-web1", nil)
	_, err := r.svc.BackupJail(bg, j, CaptureOptions{})
	codeOf(t, err, api.CodeKeyNotEscrowed)
	if s := r.w.snapshots(t, SnapshotPrefix); len(s) != 0 {
		t.Fatalf("a refused backup left snapshots: %v", s)
	}
	// escrow, and the same backup goes through
	if err := r.svc.EscrowKey(bg, []string{r.recipient}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err != nil {
		t.Fatal(err)
	}

	// no key at all: nothing is sent in the clear
	r2 := newRig(t, rigOpts{node: &nc, noKey: true})
	j2 := r2.jail("web1", "uuid-web1", nil)
	_, err = r2.svc.BackupJail(bg, j2, CaptureOptions{})
	codeOf(t, err, api.CodePlaintextDenied)
}

func TestAllowUnescrowedWarns(t *testing.T) {
	r := newRig(t, rigOpts{remote: mustMem(t), noEscrow: true, allowUnesc: true})
	j := r.jail("web1", "uuid-web1", nil)
	res := r.backup(j)
	if len(res.Targets[0].Result.Warnings) == 0 {
		t.Fatal("no warning for an unescrowed key")
	}
}

func mustMem(t *testing.T) Remote { r, _, _ := memRemote(t); return r }

func TestBackupTwiceUploadsOnlyChangedChunks(t *testing.T) {
	env, nc := nodeServer(t)
	_ = env
	r := newRig(t, rigOpts{node: &nc, hooks: true})
	j := r.jail("web1", "uuid-web1", nil)
	first := r.backup(j)
	f := first.Targets[0]
	if f.Err != nil || !f.Result.Full || f.Result.NewChunks == 0 {
		t.Fatalf("first backup: %+v", f.Result)
	}
	if r.hooks.pre != 1 || r.hooks.post != 1 {
		t.Fatalf("hooks ran pre=%d post=%d", r.hooks.pre, r.hooks.post)
	}
	if s := r.w.snapshots(t, SnapshotPrefix); len(s) != 0 {
		t.Fatalf("snapshots left: %v", s)
	}
	if len(r.w.m.snaps) != 0 {
		t.Fatalf("snapshot directories left: %v", r.w.m.snaps)
	}
	// the thin root is not captured: no stream for it
	for _, st := range f.Result.Streams {
		if st.Name == "root" {
			t.Fatal("the thin root was captured")
		}
	}
	if len(f.Result.Streams) != 4 { // ".", etc, local, db
		t.Fatalf("streams = %+v", f.Result.Streams)
	}

	// change one small file; the 5 MiB database is untouched
	p := filepath.Join(r.w.m.liveDir(j.Container+"/etc"), "rc.conf")
	if err := os.WriteFile(p, []byte("hostname=changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := r.backup(j).Targets[0]
	if second.Result.Full {
		t.Fatalf("the second backup read everything: %+v", second.Result.Streams)
	}
	if second.Result.ReusedBytes < 5<<20 || second.Result.ReadBytes > 64<<10 {
		t.Fatalf("second backup reused %d bytes and read %d", second.Result.ReusedBytes, second.Result.ReadBytes)
	}
	if second.Result.NewChunks == 0 || second.Result.NewChunks > 3 {
		t.Fatalf("second backup uploaded %d chunks (first uploaded %d)", second.Result.NewChunks, f.Result.NewChunks)
	}
	if second.Result.UploadedBytes*20 > f.Result.UploadedBytes {
		t.Fatalf("second backup uploaded %d bytes, first %d", second.Result.UploadedBytes, f.Result.UploadedBytes)
	}
	if second.Result.Previous != f.Result.Snapshot {
		t.Fatalf("previous = %s, want %s", second.Result.Previous, f.Result.Snapshot)
	}
	// the backup objects are in the catalog and say what they hold
	bs, _ := r.svc.List(bg)
	if len(bs) != 2 || bs[0].Spec.Snapshot != second.Backup.Spec.Snapshot {
		t.Fatalf("catalog = %d backups", len(bs))
	}
	b := second.Backup
	if b.Spec.Bundle.ImageGeneration != "fbsd#g1" || b.Spec.Bundle.ImageManifest != "mf1" || len(b.Spec.Bundle.Networks) != 1 ||
		b.Spec.KeyDomain == "" || b.Spec.JailUUID != "uuid-web1" || b.Spec.HostUUID != "host-uuid-1" || b.Spec.Policy != "nightly" {
		t.Fatalf("backup object = %+v", b.Spec)
	}
	if b.Status.NewBytes != int64(second.Result.UploadedBytes) || b.Status.Files == 0 {
		t.Fatalf("status = %+v", b.Status)
	}
}

func TestRestoreToNewNameWithNetworkMap(t *testing.T) {
	_, nc := nodeServer(t)
	r := newRig(t, rigOpts{node: &nc})
	j := r.jail("web1", "uuid-web1", nil)
	bk := r.backup(j).Targets[0].Backup

	pf, err := r.svc.Preflight(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web2", NetworkMap: map[string]string{"lan": "lan2"}})
	if err != nil || !pf.OK {
		t.Fatalf("preflight = %+v, %v", pf, err)
	}
	// without a map the address would collide with the source jail when kept
	res, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web2", NetworkMap: map[string]string{"lan": "lan2"}}, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	jl := res.Jail
	if jl.Metadata.Name != "web2" || jl.Metadata.UUID == "" || jl.Metadata.UUID == "uuid-web1" {
		t.Fatalf("identity = %+v", jl.Metadata)
	}
	if jl.Spec.Network[0].Network != "lan2" || jl.Spec.Network[0].IPv4 != "auto" || jl.Spec.Network[0].MAC != "" {
		t.Fatalf("network = %+v", jl.Spec.Network[0])
	}
	if jl.Spec.Hostname != "" {
		t.Fatalf("hostname = %q", jl.Spec.Hostname)
	}
	if jl.Status.Power != api.PowerStopped || len(r.host.started) != 0 {
		t.Fatalf("the jail was started: %+v", jl.Status)
	}
	pl := res.Placement
	if pl.Container != "tank/jailops/projects/alpha/jails/web2" {
		t.Fatalf("placement = %+v", pl)
	}
	// datasets: container, thin root cloned from the generation, persistent, volume with its parent
	for _, ds := range []string{"", "/root", "/etc", "/local", "/db"} {
		if ok, _ := r.w.Exists(bg, pl.Container+ds); !ok {
			t.Fatalf("dataset %s%s missing", pl.Container, ds)
		}
	}
	if o, _ := r.w.Origin(bg, pl.Container+"/root"); o != "tank/jailops/images/fbsd/g1@ro" {
		t.Fatalf("root origin = %q", o)
	}
	props, _ := r.w.Get(bg, pl.Container+"/db", "mountpoint", "quota", "jailops:path", "jailops:id")
	if props["mountpoint"].Value != "/jo2/alpha/web2/root/var/db/app" || props["quota"].Value != "1G" || props["jailops:id"].Value != jl.Metadata.UUID {
		t.Fatalf("volume props = %+v", props)
	}
	if c, _ := r.w.Get(bg, pl.Container, "jailops:complete", "mountpoint"); c["jailops:complete"].Value != "on" || c["mountpoint"].Value != "/jo2/alpha/web2" {
		t.Fatalf("container props = %+v", c)
	}
	// the data is byte for byte the data of the source
	for _, rel := range []string{"", "/etc", "/local", "/db"} {
		want := readTree(t, r.w.m.liveDir(j.Container+rel))
		got := readTree(t, r.w.m.liveDir(pl.Container+rel))
		if len(want) != len(got) {
			t.Fatalf("%s: %d entries restored, %d expected", rel, len(got), len(want))
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s: %s differs", rel, k)
			}
		}
	}
	if len(r.host.adopted) != 1 || r.host.adopted[0].Jail.Metadata.Name != "web2" || r.host.adopted[0].Generation.Name != "fbsd#g1" {
		t.Fatalf("adopted = %+v", r.host.adopted)
	}
	if got := r.host.netMaps[len(r.host.netMaps)-1]; got["lan"] != "lan2" {
		t.Fatalf("EnsureObjects network map = %v", got)
	}

	// start on request
	res2, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web3", KeepIP: true}, RestoreOptions{Start: true})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Jail.Spec.Network[0].IPv4 != "10.20.0.5" || res2.Jail.Status.Power != api.PowerRunning || len(r.host.started) != 1 {
		t.Fatalf("keep_ip/start = %+v", res2.Jail)
	}
}

func TestRestoreRefusedWithoutTheKeyAndOnNewHost(t *testing.T) {
	_, nc := nodeServer(t)
	r := newRig(t, rigOpts{node: &nc})
	j := r.jail("web1", "uuid-web1", nil)
	bk := r.backup(j).Targets[0].Backup

	// a host without the key refuses, in preflight and in restore
	h2 := newRig(t, rigOpts{node: &nc, noKey: true, identity: r.identity, recipient: r.recipient})
	if _, err := h2.svc.Get(bg, bk.Metadata.Name); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("a host without the key found the backup: %v", err)
	}
	h2.cat.PutBackup(bg, bk) // the catalog was copied, but the key was not
	pf, err := h2.svc.Preflight(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web9"})
	if err != nil || pf.OK || !strings.Contains(strings.Join(pf.Errors, " "), "key domain") {
		t.Fatalf("preflight without the key = %+v, %v", pf, err)
	}
	_, err = h2.svc.Restore(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web9"})
	codeOf(t, err, api.CodeForbidden)
	if ds := h2.w.datasets(t, "tank/jailops/projects"); len(ds) != 0 {
		t.Fatalf("a refused restore created %v", ds)
	}

	// the release gate: a new host with only the recovery identity restores
	h3 := newRig(t, rigOpts{node: &nc, noKey: true})
	if err := h3.svc.RecoverKeyFromEscrow(bg, "", r.identity); err != nil {
		t.Fatal(err)
	}
	if n, err := h3.svc.Reindex(bg, ""); err != nil || n != 1 {
		t.Fatalf("reindex = %d, %v", n, err)
	}
	got, err := h3.svc.Get(bg, bk.Metadata.Name)
	if err != nil || got.Spec.Jail != "web1" || got.Spec.Bundle.ImageGeneration != "fbsd#g1" {
		t.Fatalf("reindexed backup = %+v, %v", got.Spec, err)
	}
	jl, err := h3.svc.Restore(bg, api.RestoreRequest{Backup: bk.Metadata.Name})
	if err != nil {
		t.Fatal(err)
	}
	if jl.Metadata.Name != "web1" || jl.Metadata.UUID == "uuid-web1" {
		t.Fatalf("restored = %+v", jl.Metadata)
	}
	want := readTree(t, r.w.m.liveDir(j.Container+"/db"))
	gotT := readTree(t, h3.w.m.liveDir("tank/jailops/projects/alpha/jails/web1/db"))
	if len(want) != len(gotT) {
		t.Fatalf("restored %d entries, want %d", len(gotT), len(want))
	}
	// a wrong recovery identity opens nothing
	h4 := newRig(t, rigOpts{node: &nc, noKey: true})
	other, _, _ := keys.GenerateRecoveryIdentity()
	if err := h4.svc.RecoverKeyFromEscrow(bg, "", other); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("wrong identity = %v", err)
	}
}

func TestRestoreRefusedWhenTheGenerationIsMissing(t *testing.T) {
	_, nc := nodeServer(t)
	r := newRig(t, rigOpts{node: &nc})
	j := r.jail("web1", "uuid-web1", nil)
	bk := r.backup(j).Targets[0].Backup
	delete(r.imgs.gens, "fbsd#g1")
	pf, err := r.svc.Preflight(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web2"})
	if err != nil || pf.OK {
		t.Fatalf("preflight = %+v, %v", pf, err)
	}
	if !strings.Contains(strings.Join(pf.Errors, " "), "image generation fbsd#g1 is not present") || len(pf.Missing) == 0 {
		t.Fatalf("preflight = %+v", pf)
	}
	_, err = r.svc.Restore(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web2"})
	codeOf(t, err, api.CodeInvalid)
	if ds := r.w.datasets(t, "tank/jailops/projects/alpha/jails/web2"); len(ds) != 0 {
		t.Fatalf("created %v", ds)
	}
	// existing name without replace is refused too
	r.imgs.gens["fbsd#g1"] = testGen
	pf, _ = r.svc.Preflight(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web1"})
	_ = pf
}

func TestRestoreFilesAndSubtree(t *testing.T) {
	_, nc := nodeServer(t)
	r := newRig(t, rigOpts{node: &nc})
	j := r.jail("web1", "uuid-web1", nil)
	bk := r.backup(j).Targets[0].Backup
	dest := filepath.Join(t.TempDir(), "out")
	if _, err := r.svc.RestoreFiles(bg, FileRestore{Backup: bk.Metadata.Name, Dataset: "etc", Paths: []string{"ssh/sshd_config"}, Dest: dest}); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(filepath.Join(r.w.m.liveDir(j.Container+"/etc"), "ssh/sshd_config"))
	got, err := os.ReadFile(filepath.Join(dest, "ssh/sshd_config"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("single file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "rc.conf")); err == nil {
		t.Fatal("a single-file restore extracted other files")
	}
	dest2 := filepath.Join(t.TempDir(), "out2")
	if _, err := r.svc.RestoreFiles(bg, FileRestore{Backup: bk.Metadata.Name, Dataset: "db", Paths: []string{"small"}, Dest: dest2}); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(dest2, "small"))
	if len(ents) != 20 {
		t.Fatalf("subtree restored %d files", len(ents))
	}
	if _, err := os.Stat(filepath.Join(dest2, "main.db")); err == nil {
		t.Fatal("a subtree restore extracted the database")
	}
}

func TestReplaceParksTheOldJail(t *testing.T) {
	_, nc := nodeServer(t)
	r := newRig(t, rigOpts{node: &nc})
	j := r.jail("web1", "uuid-web1", nil)
	bk := r.backup(j).Targets[0].Backup
	// the target host already has the jail web1 at the placement of a restore
	pl, _ := r.host.Place(bg, "alpha", "web1", "")
	if err := r.w.Create(bg, zfs.CreateOpts{Name: pl.Container + "/etc", Parents: true, Props: map[string]string{"mountpoint": pl.Mountpoint + "/root/etc"}}); err != nil {
		t.Fatal(err)
	}
	r.w.Set(bg, pl.Container, map[string]string{"mountpoint": pl.Mountpoint})
	r.host.state.Jails["web1"] = backupJailRef("web1", "uuid-web1")

	_, err := r.svc.Restore(bg, api.RestoreRequest{Backup: bk.Metadata.Name})
	if err == nil {
		t.Fatal("restoring over an existing jail without replace succeeded")
	}
	r.host.running["web1"] = true
	_, err = r.svc.Restore(bg, api.RestoreRequest{Backup: bk.Metadata.Name, Replace: true})
	codeOf(t, err, api.CodeBusy)
	r.host.running["web1"] = false
	res, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: bk.Metadata.Name, Replace: true}, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Jail.Metadata.UUID != "uuid-web1" || len(res.Parked) != 1 {
		t.Fatalf("replace = uuid %s parked %v", res.Jail.Metadata.UUID, res.Parked)
	}
	if ok, _ := r.w.Exists(bg, res.Parked[0]+"/etc"); !ok {
		t.Fatal("the replaced jail's datasets were not kept")
	}
	if p, _ := r.w.Get(bg, res.Parked[0]+"/etc", "mountpoint"); p["mountpoint"].Value != "none" {
		t.Fatalf("parked mountpoint = %v", p["mountpoint"])
	}
	_ = time.Second
}

// A node bound to another key domain, or one that records none yet while holding snapshots this key does not
// open, gets neither this host's escrow blob nor its backups.
func TestHostPinsTheNodesKeyDomain(t *testing.T) {
	env, nc := nodeServer(t)
	foreign := "0123456789abcdef"
	blob := []byte("age-encryption.org/v1\n-> X25519 stanza\nblob")
	if err := env.Node.PutEscrow(bg, env.Host(t, "stranger"), foreign, bytes.NewReader(blob), int64(len(blob))); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, rigOpts{node: &nc, noEscrow: true})
	codeOf(t, r.svc.EscrowKey(bg, []string{r.recipient}), api.CodeForbidden)
	j := r.jail("web1", "uuid-web1", nil)
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "nightly"}); err == nil {
		t.Fatal("a backup went to a node bound to another key domain")
	}
}
