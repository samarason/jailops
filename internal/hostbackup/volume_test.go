package hostbackup

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/backup"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// volHost is a fakeHost that also restores volumes and knows which volumes the project has.
type volHost struct {
	*fakeHost
	mu        sync.Mutex
	existing  map[string]bool
	made      []string
	passes    []string
	completed []string
	w         *world
}

func (h *volHost) State(ctx context.Context, p string) (backup.HostState, error) {
	st, _ := h.fakeHost.State(ctx, p)
	st.Volumes = map[string]bool{}
	h.mu.Lock()
	defer h.mu.Unlock()
	for k := range h.existing {
		st.Volumes[k] = true
	}
	return st, nil
}

func (h *volHost) StateIn(ctx context.Context, p, s string) (backup.HostState, error) {
	return h.State(ctx, p)
}

func (h *volHost) RestoreVolume(ctx context.Context, project, name string, spec api.VolumeSpec, _ map[string]string, pass string) (string, func(context.Context) error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.existing[name] {
		return "", nil, api.Errorf(api.CodeAlreadyExists, "volume %q exists", name)
	}
	ds := "tank/jailops/projects/" + project + "/volumes/" + name
	if err := h.w.Create(ctx, zfs.CreateOpts{Name: ds, Parents: true, Props: map[string]string{"jailops:managed": "on"}}); err != nil {
		return "", nil, err
	}
	h.existing[name] = true
	h.made = append(h.made, name)
	h.passes = append(h.passes, pass)
	return ds, func(ctx context.Context) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.existing, name)
		return h.w.Destroy(ctx, ds, zfs.DestroyOpts{Recursive: true})
	}, nil
}

func (h *volHost) CompleteVolume(_ context.Context, project, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.completed = append(h.completed, project+"/"+name)
	return nil
}

type fakeVolumes struct {
	mu   sync.Mutex
	recs []JailRecord
}

func (f *fakeVolumes) Volumes(context.Context) ([]JailRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]JailRecord(nil), f.recs...), nil
}

// volumeRig is a rig whose host restores volumes and whose daemon lists them.
func volumeRig(t *testing.T) (*rig, *volHost, *fakeVolumes) {
	t.Helper()
	r := newRig(t, rigOpts{remote: mustMem(t)})
	h := &volHost{fakeHost: r.host, existing: map[string]bool{}, w: r.w}
	r.svc.deps.Host = h
	v := &fakeVolumes{}
	r.svc.deps.Volumes = v
	return r, h, v
}

// addVolume creates the dataset and the files of a volume and lists it.
func addVolume(t *testing.T, r *rig, v *fakeVolumes, h *volHost, name, uuid string, labels map[string]string, spec api.VolumeSpec) JailRecord {
	t.Helper()
	ds := "tank/jailops/projects/alpha/volumes/" + name
	mustCreate(t, r, ds, map[string]string{"jailops:managed": "on", "jailops:id": uuid})
	writeFile(t, r.w.m.liveDir(ds), "cur/msg1", "hello "+name)
	writeFile(t, r.w.m.liveDir(ds), "cur/msg2", "second "+name)
	rec := JailRecord{Name: name, UUID: uuid, Project: "alpha", Labels: labels, Container: ds, IsVolume: true, Volume: &spec,
		Datasets: []Dataset{{Name: ds, Kind: KindVolume, Mountpoint: "/jo/vol/" + name}}}
	v.mu.Lock()
	v.recs = append(v.recs, rec)
	v.mu.Unlock()
	h.existing[name] = true
	return rec
}

func volumeBackups(t *testing.T, r *rig, name string) []api.Backup {
	t.Helper()
	all, err := r.svc.List(bg)
	if err != nil {
		t.Fatal(err)
	}
	var out []api.Backup
	for _, b := range all {
		if b.Spec.Kind == "volume" && b.Spec.Jail == name {
			out = append(out, b)
		}
	}
	return out
}

// lose removes a volume from the project, dataset and files, as a lost host would.
func lose(t *testing.T, r *rig, h *volHost, name string) {
	t.Helper()
	ds := "tank/jailops/projects/alpha/volumes/" + name
	if err := r.w.Destroy(bg, ds, zfs.DestroyOpts{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	delete(h.existing, name)
}

func attach(j JailRecord, vols ...string) JailRecord {
	j.Spec.Volumes = nil
	j.VolumeIDs = nil
	for _, v := range vols {
		j.Spec.Volumes = append(j.Spec.Volumes, api.VolumeAttach{Name: v, Mount: "/var/" + v})
		if j.VolumeIDs == nil {
			j.VolumeIDs = map[string]string{}
		}
		j.VolumeIDs[v] = "uuid-" + v
	}
	return j
}

func TestAVolumeIsBackedUpOnceHoweverManyJailsAttachIt(t *testing.T) {
	r, h, vols := volumeRig(t)
	addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{UID: 1001, GID: 1001, Mode: "0750", Size: "2G"})
	for _, n := range []string{"web1", "web2"} {
		j := attach(r.jail(n, "uuid-"+n, map[string]string{"tier": "web"}), "mail")
		r.jails.mu.Lock()
		for i := range r.jails.jails {
			if r.jails.jails[i].Name == n {
				r.jails.jails[i] = j
			}
		}
		r.jails.mu.Unlock()
	}
	r.setPolicies(policy("web", map[string]string{"tier": "web"}, "0 2 * * *"))
	runs, err := r.svc.RunNow(bg, "alpha", "web")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range runs {
		if !x.OK {
			t.Fatalf("run failed: %+v", x)
		}
		names = append(names, x.Jail)
	}
	if fmt.Sprint(names) != "[mail web1 web2]" {
		t.Fatalf("runs = %v, want the volume once next to the two jails", names)
	}
	bs := volumeBackups(t, r, "mail")
	if len(bs) != 1 {
		t.Fatalf("%d backups of the volume, want exactly one", len(bs))
	}
	b := bs[0]
	if b.Spec.JailUUID != "uuid-mail" || b.Spec.Volume == nil || b.Spec.Volume.UID != 1001 || b.Spec.Volume.Mode != "0750" || b.Spec.Volume.Size != "2G" {
		t.Fatalf("volume backup = %+v", b.Spec)
	}
	// the jail backups hold no volume files
	for _, jb := range []string{"web1", "web2"} {
		all, _ := r.svc.List(bg)
		for _, x := range all {
			if x.Spec.Jail == jb && x.Spec.Kind != "" {
				t.Fatalf("a jail backup has kind %q", x.Spec.Kind)
			}
		}
	}
}

func TestExcludeVolumesLeavesThemOut(t *testing.T) {
	r, h, vols := volumeRig(t)
	addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{})
	j := attach(r.jail("web1", "uuid-web1", map[string]string{"tier": "web"}), "mail")
	r.jails.mu.Lock()
	r.jails.jails[0] = j
	r.jails.mu.Unlock()
	p := policy("web", map[string]string{"tier": "web"}, "0 2 * * *")
	r.setPolicies(p)
	runs, err := r.svc.RunNowWith(bg, "alpha", "web", RunOptions{NoVolumes: true})
	if err != nil || len(runs) != 1 || runs[0].Jail != "web1" {
		t.Fatalf("no_volumes: runs = %+v, %v", runs, err)
	}
	p.Spec.ExcludeVolumes = true
	r.setPolicies(p)
	runs, err = r.svc.RunNow(bg, "alpha", "web")
	if err != nil || len(runs) != 1 || runs[0].Jail != "web1" {
		t.Fatalf("exclude_volumes: runs = %+v, %v", runs, err)
	}
	if len(volumeBackups(t, r, "mail")) != 0 {
		t.Fatal("a volume was backed up although volumes are excluded")
	}
}

func TestAVolumeIsSelectedByItsOwnLabels(t *testing.T) {
	r, h, vols := volumeRig(t)
	addVolume(t, r, vols, h, "pbs", "uuid-pbs", map[string]string{"tier": "storage"}, api.VolumeSpec{})
	addVolume(t, r, vols, h, "scratch", "uuid-scratch", nil, api.VolumeSpec{})
	r.setPolicies(policy("store", map[string]string{"tier": "storage"}, "0 2 * * *"))
	runs, err := r.svc.RunNow(bg, "alpha", "store")
	if err != nil || len(runs) != 1 || runs[0].Jail != "pbs" || !runs[0].OK {
		t.Fatalf("runs = %+v, %v", runs, err)
	}
	r.setPolicies(policy("everything", map[string]string{"all": ""}, "0 2 * * *"))
	runs, _ = r.svc.RunNow(bg, "alpha", "everything")
	if len(runs) != 2 {
		t.Fatalf("selector all: %d runs, want both volumes", len(runs))
	}
}

func TestALockedVolumeIsNotBackedUp(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "vault", "uuid-vault", nil, api.VolumeSpec{Encrypted: true})
	rec.Datasets[0].Skip = SkipLocked
	if _, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"}); !api.IsCode(err, api.CodeLocked) {
		t.Fatalf("err = %v, want locked", err)
	}
	if retryable(api.Errorf(api.CodeLocked, "x")) {
		t.Fatal("a locked volume is retried at once; it waits for the next slot")
	}
}

func TestRestoreAVolumeBackupMakesTheVolume(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{UID: 1001, GID: 1001, Mode: "0750"})
	res, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"})
	if err != nil {
		t.Fatal(err)
	}
	id := res.Targets[0].Backup.Metadata.Name

	// the name is taken: refused, and a volume is never replaced
	pf, err := r.svc.Preflight(bg, api.RestoreRequest{Backup: id, Project: "alpha"})
	if err != nil || pf.OK {
		t.Fatalf("restore over an existing volume: %+v, %v", pf, err)
	}
	if _, err := r.svc.RestoreVolumeBackup(bg, api.RestoreRequest{Backup: id, Project: "alpha", Replace: true}); err == nil {
		t.Fatal("a volume was replaced")
	}
	// as another name
	v, err := r.svc.RestoreVolumeBackup(bg, api.RestoreRequest{Backup: id, Project: "alpha", As: "mail2"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Metadata.Name != "mail2" || v.Spec.UID != 1001 || v.Spec.Mode != "0750" {
		t.Fatalf("volume = %+v", v)
	}
	if fmt.Sprint(h.completed) != "[alpha/mail2]" {
		t.Fatalf("the restore of the volume was not ended: %v", h.completed)
	}
	want := readTree(t, r.w.m.liveDir(rec.Container))
	got := readTree(t, r.w.m.liveDir("tank/jailops/projects/alpha/volumes/mail2"))
	if len(want) != len(got) || got["cur/msg1"] != "hello mail" || got["cur/msg2"] != "second mail" {
		t.Fatalf("restored files = %v", got)
	}
	// a jail restore refuses a volume backup and says so
	if _, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: id, Project: "alpha", As: "mail3"}, RestoreOptions{}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("RestoreWith on a volume backup: %v", err)
	}
	// a failed extraction removes the volume again
	r.w.m.failMount = func(ds string) error {
		if ds == "tank/jailops/projects/alpha/volumes/mail4" {
			return fmt.Errorf("mount failed")
		}
		return nil
	}
	if _, err := r.svc.RestoreVolumeBackup(bg, api.RestoreRequest{Backup: id, Project: "alpha", As: "mail4"}); err == nil {
		t.Fatal("expected the failure")
	}
	if h.existing["mail4"] {
		t.Fatal("a failed restore left the volume behind")
	}
}

func TestRestoreAnEncryptedVolumeNeedsItsPassphrase(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "vault", "uuid-vault", nil, api.VolumeSpec{Encrypted: true})
	res, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"})
	if err != nil {
		t.Fatal(err)
	}
	id := res.Targets[0].Backup.Metadata.Name
	if pf, _ := r.svc.Preflight(bg, api.RestoreRequest{Backup: id, Project: "alpha", As: "vault2"}); pf.OK {
		t.Fatalf("an encrypted volume was restorable without a passphrase: %+v", pf)
	}
	if _, err := r.svc.RestoreVolumeBackup(bg, api.RestoreRequest{Backup: id, Project: "alpha", As: "vault2", Passphrase: "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	if len(h.passes) != 1 || h.passes[0] != "correct horse battery" {
		t.Fatalf("the host got passphrases %v", h.passes)
	}
}

func TestAJailRestoreBringsBackItsMissingVolumes(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{UID: 1001, GID: 1001})
	j := attach(r.jail("web1", "uuid-web1", nil), "mail")
	jb, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"})
	if err != nil {
		t.Fatal(err)
	}
	vb, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"})
	if err != nil {
		t.Fatal(err)
	}
	jid, vid := jb.Targets[0].Backup.Metadata.Name, vb.Targets[0].Backup.Metadata.Name

	// the volume is gone from the project (the host was lost)
	lose(t, r, h, "mail")
	pf, err := r.svc.Preflight(bg, api.RestoreRequest{Backup: jid, As: "web2", Project: "alpha"})
	if err != nil || !pf.OK {
		t.Fatalf("preflight = %+v, %v", pf, err)
	}
	for _, m := range pf.Missing {
		if strings.Contains(m, "volume") {
			t.Fatalf("a volume with a backup is reported missing: %v", pf.Missing)
		}
	}
	found := false
	for _, c := range pf.Changes {
		found = found || c == "restores volume mail from backup "+vid+" first"
	}
	if !found {
		t.Fatalf("changes = %v", pf.Changes)
	}
	res, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: jid, As: "web2", Project: "alpha"}, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(h.made) != "[mail]" || len(res.Jail.Spec.Volumes) != 1 || res.Jail.Spec.Volumes[0].Name != "mail" {
		t.Fatalf("made %v, volumes %+v", h.made, res.Jail.Spec.Volumes)
	}
	if got := readTree(t, r.w.m.liveDir("tank/jailops/projects/alpha/volumes/mail")); got["cur/msg1"] != "hello mail" {
		t.Fatalf("volume files = %v", got)
	}

	// a second jail restore finds the volume there, attaches it and does not touch it
	h.made = nil
	res3, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: jid, As: "web3", Project: "alpha"}, RestoreOptions{})
	if err != nil || len(h.made) != 0 {
		t.Fatalf("second restore: made %v, %v", h.made, err)
	}
	if len(res3.Jail.Spec.Volumes) != 1 || res3.Jail.Spec.Volumes[0].Name != "mail" {
		t.Fatalf("a normal restore lost the attachment: %+v", res3.Jail.Spec.Volumes)
	}
	// no_volumes leaves every attachment out, also those of volumes the project has
	res5, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: jid, As: "web5", Project: "alpha", NoVolumes: true}, RestoreOptions{})
	if err != nil || len(h.made) != 0 || len(res5.Jail.Spec.Volumes) != 0 {
		t.Fatalf("no_volumes with the volume present: made %v, volumes %+v, %v", h.made, res5.Jail.Spec.Volumes, err)
	}
	if len(r.host.adopted) == 0 || len(r.host.adopted[len(r.host.adopted)-1].Jail.Spec.Volumes) != 0 {
		t.Fatalf("the registered jail has attachments: %+v", r.host.adopted[len(r.host.adopted)-1].Jail.Spec.Volumes)
	}

	// no_volumes: the attachment is left out and nothing is made
	lose(t, r, h, "mail")
	h.made = nil
	res, err = r.svc.RestoreWith(bg, api.RestoreRequest{Backup: jid, As: "web4", Project: "alpha", NoVolumes: true}, RestoreOptions{})
	if err != nil || len(h.made) != 0 || len(res.Jail.Spec.Volumes) != 0 {
		t.Fatalf("no_volumes: made %v, volumes %+v, %v", h.made, res.Jail.Spec.Volumes, err)
	}
}

func TestAJailRestoreUndoesItsVolumesWhenItFails(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{})
	j := attach(r.jail("web1", "uuid-web1", nil), "mail")
	jb, _ := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"})
	if _, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"}); err != nil {
		t.Fatal(err)
	}
	lose(t, r, h, "mail")
	r.host.failAdpt = fmt.Errorf("registry down")
	if _, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: jb.Targets[0].Backup.Metadata.Name, As: "web2", Project: "alpha"}, RestoreOptions{}); err == nil {
		t.Fatal("expected the failure")
	}
	if h.existing["mail"] {
		t.Fatal("the restored volume stayed after the failed jail restore")
	}
}

func TestAnEncryptedVolumeIsNotRestoredWithTheJail(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "vault", "uuid-vault", nil, api.VolumeSpec{Encrypted: true})
	j := attach(r.jail("web1", "uuid-web1", nil), "vault")
	jb, _ := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"})
	if _, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"}); err != nil {
		t.Fatal(err)
	}
	lose(t, r, h, "vault")
	pf, _ := r.svc.Preflight(bg, api.RestoreRequest{Backup: jb.Targets[0].Backup.Metadata.Name, As: "web2", Project: "alpha"})
	if pf.OK {
		t.Fatalf("preflight passed: %+v", pf)
	}
}

func TestARestoreTestNeverTouchesTheVolumes(t *testing.T) {
	r, h, vols := volumeRig(t)
	addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{})
	j := attach(r.jail("web1", "uuid-web1", nil), "mail")
	jb, _ := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"})
	res, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: jb.Targets[0].Backup.Metadata.Name, As: "drill1", Project: "alpha", NoVolumes: true},
		RestoreOptions{NoNetwork: true, DropVolumes: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Jail.Spec.Volumes) != 0 || len(h.made) != 0 {
		t.Fatalf("a restore test attached %+v / made %v", res.Jail.Spec.Volumes, h.made)
	}
}

func TestAVolumeBackupKeepsItsKindAndSpecWhenTheCatalogIsRebuilt(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{UID: 1001, GID: 1001, Mode: "0750", Size: "2G", Encrypted: true})
	res, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"})
	if err != nil {
		t.Fatal(err)
	}
	id := res.Targets[0].Backup.Metadata.Name
	if err := r.cat.DeleteBackup(bg, id); err != nil {
		t.Fatal(err)
	}
	if n, err := r.svc.Reindex(bg, ""); err != nil || n != 1 {
		t.Fatalf("reindex = %d, %v", n, err)
	}
	b, err := r.svc.Get(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	if b.Spec.Kind != "volume" || b.Spec.Jail != "mail" || b.Spec.JailUUID != "uuid-mail" || b.Spec.Volume == nil ||
		b.Spec.Volume.UID != 1001 || b.Spec.Volume.Mode != "0750" || b.Spec.Volume.Size != "2G" || !b.Spec.Volume.Encrypted {
		t.Fatalf("rebuilt backup = %+v", b.Spec)
	}
}

// stoppedZFS reports the datasets in down as not mounted until the capture mounts them.
type stoppedZFS struct {
	*world
	mu    sync.Mutex
	down  map[string]bool
	order []string // mount and unmount calls, in order
}

func (z *stoppedZFS) Get(ctx context.Context, name string, props ...string) (map[string]zfs.Prop, error) {
	p, err := z.world.Get(ctx, name, props...)
	if err != nil {
		return p, err
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, k := range props {
		if k == "mounted" {
			v := "yes"
			if z.down[name] {
				v = "no"
			}
			p[k] = zfs.Prop{Value: v}
		}
	}
	return p, nil
}

func (z *stoppedZFS) Mount(_ context.Context, ds string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.down[ds] = false
	z.order = append(z.order, "mount "+ds)
	return nil
}

func (z *stoppedZFS) Unmount(_ context.Context, ds string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.down[ds] = true
	z.order = append(z.order, "unmount "+ds)
	return nil
}

// stopped makes every dataset of the records unmounted, as a jail that was created and never started leaves them.
func stopped(r *rig, recs ...JailRecord) *stoppedZFS {
	z := &stoppedZFS{world: r.w, down: map[string]bool{}}
	for _, rec := range recs {
		for _, d := range rec.Datasets {
			z.down[d.Name] = true
		}
	}
	r.svc.zfs = z
	r.w.m.failSnapDir = func(ds string) error {
		z.mu.Lock()
		defer z.mu.Unlock()
		if z.down[ds] {
			return fmt.Errorf("%s is not mounted: no .zfs/snapshot", ds)
		}
		return nil
	}
	return z
}

func TestAJailThatWasNeverStartedIsBackedUpWithItsDatasetsUnmounted(t *testing.T) {
	r, h, vols := volumeRig(t)
	r.svc.deps.Datasets = nil
	j := r.jail("web1", "uuid-web1", nil)
	z := stopped(r, j)
	// without a way to mount, the capture says what is wrong
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"}); !api.IsCode(err, api.CodeUnsupported) {
		t.Fatalf("err = %v, want unsupported", err)
	}
	r.svc.deps.Datasets = z
	res, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"})
	if err != nil {
		t.Fatal(err)
	}
	var mounts, unmounts []string
	for _, o := range z.order {
		if ds, ok := strings.CutPrefix(o, "mount "); ok {
			mounts = append(mounts, ds)
		} else if ds, ok := strings.CutPrefix(o, "unmount "); ok {
			unmounts = append(unmounts, ds)
		}
	}
	// the thin root is not captured, so it is not mounted; the container comes first, and everything is unmounted again
	if len(mounts) != 4 || mounts[0] != j.Container || len(unmounts) != 4 || unmounts[3] != j.Container {
		t.Fatalf("mounts %v, unmounts %v", mounts, unmounts)
	}
	for ds, down := range z.down {
		if !down {
			t.Fatalf("%s is still mounted after the backup", ds)
		}
	}
	// what was read is the data of the jail
	if b := res.Targets[0].Backup; b.Spec.Jail != "web1" || b.Status.Files == 0 {
		t.Fatalf("backup = %+v", b)
	}

	// a failure while reading unmounts what was mounted
	z.order = nil
	r.w.m.failSnapDir = func(ds string) error {
		if strings.HasSuffix(ds, "/local") {
			return fmt.Errorf("snapshot of %s is unreadable", ds)
		}
		z.mu.Lock()
		defer z.mu.Unlock()
		if z.down[ds] {
			return fmt.Errorf("%s is not mounted", ds)
		}
		return nil
	}
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"}); err == nil {
		t.Fatal("expected the failure")
	}
	for ds, down := range z.down {
		if !down {
			t.Fatalf("%s stayed mounted after the failed backup", ds)
		}
	}
	_, _ = h, vols
}

func TestAVolumeThatIsNotMountedIsBackedUp(t *testing.T) {
	r, h, vols := volumeRig(t)
	rec := addVolume(t, r, vols, h, "mail", "uuid-mail", nil, api.VolumeSpec{})
	z := stopped(r, rec)
	r.svc.deps.Datasets = z
	if _, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(z.order) != fmt.Sprintf("[mount %s unmount %s]", rec.Container, rec.Container) {
		t.Fatalf("order = %v", z.order)
	}
	// a dataset that is mounted is left as it is
	z.order = nil
	if _, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"}); err != nil || len(z.order) != 2 {
		t.Fatalf("second run: %v %v", z.order, err)
	}
	z.down[rec.Container] = false
	z.order = nil
	if _, err := r.svc.BackupJail(bg, rec, CaptureOptions{Policy: "p"}); err != nil || len(z.order) != 0 {
		t.Fatalf("a mounted volume was mounted again: %v %v", z.order, err)
	}
}

// A volume that was deleted and made again under the same name is another volume: the newer backups of the new one are
// not what an older jail's restore brings back.
func TestNewestVolumeBackupIsOfTheVolumeTheJailAttached(t *testing.T) {
	r, _, _ := volumeRig(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(name, uuid string, at time.Time) api.Backup {
		return api.Backup{Metadata: api.ObjectMeta{Name: name + uuid, Project: "alpha", CreatedAt: at},
			Spec: api.BackupSpec{Kind: "volume", Jail: name, JailUUID: uuid, KeyDomain: r.svc.currentKey().DomainID()}}
	}
	key := r.svc.currentKey()
	all := []api.Backup{mk("mail", "uuid-1", old), mk("mail", "uuid-2", old.Add(time.Hour))}
	if b, ok := newestVolumeBackup(all, "alpha", "mail", "uuid-1", key); !ok || b.Spec.JailUUID != "uuid-1" {
		t.Fatalf("%+v %v", b, ok)
	}
	if _, ok := newestVolumeBackup(all, "alpha", "mail", "", key); ok {
		t.Fatal("a bundle that does not know the volume matched a backup by its name")
	}
	if _, ok := newestVolumeBackup(all, "alpha", "mail", "uuid-3", key); ok {
		t.Fatal("a backup of another volume was taken")
	}
}
