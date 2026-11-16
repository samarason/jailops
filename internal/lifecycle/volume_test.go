package lifecycle

import (
	"errors"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestCreateVolumeLayoutOwnerAndMode(t *testing.T) {
	w := newWorld(t)
	req := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "maildir", UUID: "vol-1", Size: "5G", UID: 5000, GID: 5000, Mode: 0o770}
	plan, err := w.S.CreateVolume(bg, req, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 {
		t.Fatalf("plan %v", plan)
	}
	ds := "tank/jailops/projects/alpha/volumes/maildir"
	for k, v := range map[string]string{"mountpoint": "/jailops/projects/alpha/volumes/maildir", "canmount": "on", "devices": "off", "quota": "5G",
		PropManaged: "on", PropKind: KindVolume, PropName: "maildir", PropProject: "alpha"} {
		if got := w.Z.PropOrEmpty(ds, k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	// the parent holds nothing and mounts nowhere
	if w.Z.PropOrEmpty("tank/jailops/projects/alpha/volumes", "canmount") != "off" {
		t.Error("the volumes parent is mountable")
	}
	// owner and mode are set once, through the helper's operation, on the mountpoint
	if got := w.Files.Owners["/jailops/projects/alpha/volumes/maildir"]; got != "5000:5000:0770" {
		t.Fatalf("owner %q", got)
	}
	// a second volume reuses the parent
	req2 := req
	req2.Name, req2.UUID = "second", "vol-2"
	plan, err = w.S.CreateVolume(bg, req2, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.S.CreateVolume(bg, req, nil, false); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("a volume made twice: %v", err)
	}
}

func TestCreateVolumeRefusals(t *testing.T) {
	w := newWorld(t)
	base := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "v", UUID: "u"}
	for name, mut := range map[string]func(*VolumeRequest){
		"bad name":     func(r *VolumeRequest) { r.Name = "a/b" },
		"bad size":     func(r *VolumeRequest) { r.Size = "lots" },
		"negative uid": func(r *VolumeRequest) { r.UID = -1 },
		"setuid bit":   func(r *VolumeRequest) { r.Mode = 0o4755 },
		"sticky bit":   func(r *VolumeRequest) { r.Mode = 0o1777 },
	} {
		r := base
		mut(&r)
		if _, err := w.S.CreateVolume(bg, r, nil, false); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ok, _ := w.Z.Exists(bg, VolumeDS(w.storage(), "alpha", "v")); ok {
		t.Fatal("a refused creation left a dataset")
	}
}

func TestCreateVolumeFailureSweep(t *testing.T) {
	sweep(t, newWorld, func(w *world) error {
		_, err := w.S.CreateVolume(bg, VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "v", UUID: "u", UID: 1, GID: 1, Mode: 0o755}, nil, false)
		return err
	})
}

func TestVolumeSnapshotRollbackResizeDelete(t *testing.T) {
	w := newWorld(t)
	w.volume("db")
	st := w.storage()
	w.Z.WriteFile(dbVol, "/a", "one")
	if err := w.S.SnapshotVolume(bg, st, "alpha", "db", "s1", map[string]string{PropComment: "before"}); err != nil {
		t.Fatal(err)
	}
	if err := w.S.SnapshotVolume(bg, st, "alpha", "db", "s1", nil); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("a snapshot made twice: %v", err)
	}
	w.Z.WriteFile(dbVol, "/a", "two-two")
	info, err := w.S.VolumeInfo(bg, st, "alpha", "db")
	if err != nil || len(info.Snapshots) != 1 || info.Snapshots[0].Name != "s1" || info.Snapshots[0].Comment != "before" || info.Snapshots[0].Written != int64(len("two-two")) {
		t.Fatalf("%+v %v", info, err)
	}
	if err := w.S.RollbackVolume(bg, st, "alpha", "db", "s1"); err != nil {
		t.Fatal(err)
	}
	if v, _ := w.Z.ReadFile(dbVol, "/a"); v != "one" {
		t.Fatalf("rolled back to %q", v)
	}
	if err := w.S.ResizeVolume(bg, st, "alpha", "db", "7G"); err != nil || w.Z.PropOrEmpty(dbVol, "quota") != "7G" {
		t.Fatalf("resize: %v %q", err, w.Z.PropOrEmpty(dbVol, "quota"))
	}
	if err := w.S.DeleteVolumeSnapshot(bg, st, "alpha", "db", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := w.S.DestroyVolume(bg, st, "alpha", "db"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := w.Z.Exists(bg, dbVol); ok {
		t.Fatal("not destroyed")
	}
	// only a volume of JailOps is destroyed
	w.Z.Create(bg, "tank/jailops/projects/alpha/volumes/foreign", map[string]string{})
	if err := w.S.DestroyVolume(bg, st, "alpha", "foreign"); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a dataset that is not a volume of JailOps: %v", err)
	}
}

// A jail whose attached volume cannot be found does not start, and everything else about it still works.
func TestJailWithAMissingVolumeDoesNotStart(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	missing := errors.New("the volume db of this jail does not exist")
	w.S.Cfg.Attached = func(string) ([]Attached, error) { return nil, missing }
	if err := w.S.StartJail(bg, "alpha_web"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("start: %v", err)
	}
	if w.Jails.Up["alpha_web"] {
		t.Fatal("started without its volume")
	}
	if _, err := w.S.SnapshotJail(bg, "alpha_web", "s", ""); err != nil {
		t.Fatalf("a snapshot of the jail needs no volume: %v", err)
	}
}

func TestCheckVolumes(t *testing.T) {
	w := newWorld(t)
	ok := []api.VolumeAttach{{Name: "maildir", Mount: "/var/mail/vhosts"}, {Name: "docs", Mount: "/srv/docs", ReadOnly: true}}
	if got, err := w.S.Cfg.CheckVolumes(ok); err != nil || len(got) != 2 {
		t.Fatalf("a path below a persistent dataset is fine: %v", err)
	}
	for name, vs := range map[string][]api.VolumeAttach{
		"over a persistent dataset": {{Name: "a", Mount: "/var/mail"}},
		"twice":                     {{Name: "a", Mount: "/x"}, {Name: "a", Mount: "/y"}},
		"one path twice":            {{Name: "a", Mount: "/x"}, {Name: "b", Mount: "/x"}},
		"relative":                  {{Name: "a", Mount: "x"}},
		"dotdot":                    {{Name: "a", Mount: "/x/../etc"}},
		"root":                      {{Name: "a", Mount: "/"}},
		"bad name":                  {{Name: "a b", Mount: "/x"}},
	} {
		if _, err := w.S.Cfg.CheckVolumes(vs); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCopyIntoVolume(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.volume("fresh")
	w.Files.Dirs["/jailops/projects/alpha/jails/web/root/srv/old"] = true
	if err := w.S.CopyIntoVolume(bg, "alpha_web", "/srv/old", w.storage(), "alpha", "fresh"); err != nil {
		t.Fatal(err)
	}
	copied := false
	for _, l := range w.F.Log {
		copied = copied || strings.HasPrefix(l, "copytree /jailops/projects/alpha/jails/web/root/srv/old /jailops/projects/alpha/volumes/fresh")
	}
	if !copied {
		t.Fatal(w.F.Log)
	}
	// a running jail is refused
	w.running("live")
	wantCode(t, w.S.CopyIntoVolume(bg, "alpha_live", "/srv/old", w.storage(), "alpha", "fresh"), api.CodeBusy)
}

func TestAVolumeMadeForARestoreIsIncompleteUntilCompleted(t *testing.T) {
	w := newWorld(t)
	ds := "tank/jailops/projects/alpha/volumes/restored"
	req := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "restored", UUID: "vol-r", UID: 5000, GID: 5000, Mode: 0o770, Restoring: true}
	if _, err := w.S.CreateVolume(bg, req, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := w.Z.PropOrEmpty(ds, PropComplete); got != "off" {
		t.Fatalf("a volume made for a restore is %q, want incomplete", got)
	}
	if err := w.S.CompleteVolume(bg, w.storage(), "alpha", "restored"); err != nil {
		t.Fatal(err)
	}
	if got := w.Z.PropOrEmpty(ds, PropComplete); got != "on" {
		t.Fatalf("after CompleteVolume: %q", got)
	}
	// a volume made the usual way carries no such property
	req2 := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: "plain", UUID: "vol-p", Mode: 0o755}
	if _, err := w.S.CreateVolume(bg, req2, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := w.Z.PropOrEmpty("tank/jailops/projects/alpha/volumes/plain", PropComplete); got != "" {
		t.Fatalf("an ordinary volume has %s=%q", PropComplete, got)
	}
	if err := w.S.CompleteVolume(bg, w.storage(), "alpha", "nothing"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("completing a volume that is not there: %v", err)
	}
}

// A box that failed is unmounted by force by the system, and the nullfs mounts on it go with it: jail(8) cannot unmount
// the fstab line then and refuses to remove the jail. The stop gives each target it names a placeholder (a small tmpfs)
// that jail(8) unmounts, and tries again.
func TestStopOfAJailWhoseHostDirectoryMountsAreGone(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.Files.Sources["/mnt/box/backups"] = true
	w.attach["alpha_web"] = append(w.attach["alpha_web"], Attached{Name: "box", HostDir: true, Mountpoint: "/mnt/box/backups", Path: "/srv/box"})
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	target := "/jailops/projects/alpha/jails/web/root/srv/box"
	gone := true
	w.Jails.OnStop = func(name string) error {
		if gone {
			return errors.New("jail: " + name + ": mount.fstab: " + target + ": not a mount point")
		}
		return nil
	}
	w.Exec.Handler = func(argv []string) ([]byte, error) {
		if strings.Join(argv, " ") == "mount -t tmpfs -o size=1m tmpfs "+target {
			gone = false // the placeholder is a mount point: jail(8) can unmount it
		}
		return w.handle(argv)
	}
	if err := w.S.StopJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if w.Jails.IsUp("alpha_web") {
		t.Fatal("the jail still runs")
	}
	placed := 0
	for _, c := range w.Exec.Calls {
		if len(c) > 2 && c[0] == "mount" && c[2] == "tmpfs" {
			placed++
		}
	}
	if placed != 1 {
		t.Fatalf("%d placeholders: %v", placed, w.Exec.Calls)
	}
	last := w.Exec.Calls[len(w.Exec.Calls)-1]
	if strings.Join(last, " ") != "umount -f "+target {
		t.Fatalf("the placeholder was left mounted: %v", w.Exec.Calls)
	}
	// a stop that fails for another reason is not retried with placeholders
	w.Files.Sources["/mnt/box/backups"] = true
	if err := w.S.StartJail(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	w.Jails.OnStop = func(string) error { return errors.New("jail: web: some other failure") }
	before := len(w.Exec.Calls)
	if err := w.S.StopJail(bg, "alpha_web"); err == nil || !strings.Contains(err.Error(), "some other failure") {
		t.Fatalf("%v", err)
	}
	if len(w.Exec.Calls) != before {
		t.Fatal("a placeholder was mounted for an unrelated failure")
	}
}

// A jail that has never run gets its volumes bound into its root, so the files the host installs land in them, and
// unbound again before the start mounts them itself.
func TestBindVolumesIntoAStoppedJail(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.attachTo("alpha_web", "www", "/usr/local/www", false)
	w.attachTo("alpha_web", "data", "/var/db/web", false)
	if err := w.S.BindVolumes(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(w.Exec.Commands(), "\n")
	for _, want := range []string{
		"mount -t nullfs /jailops/projects/alpha/volumes/www /jailops/projects/alpha/jails/web/root/usr/local/www",
		"mount -t nullfs /jailops/projects/alpha/volumes/data /jailops/projects/alpha/jails/web/root/var/db/web",
	} {
		if !strings.Contains(cmds, want) {
			t.Errorf("no %q in\n%s", want, cmds)
		}
	}
	if strings.Contains(cmds, "-o ro") {
		t.Errorf("a read-write bind was read-only:\n%s", cmds)
	}
	if err := w.S.UnbindVolumes(bg, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	cmds = strings.Join(w.Exec.Commands(), "\n")
	data := strings.Index(cmds, "umount /jailops/projects/alpha/jails/web/root/var/db/web")
	www := strings.Index(cmds, "umount /jailops/projects/alpha/jails/web/root/usr/local/www")
	if data < 0 || www < 0 || data > www {
		t.Errorf("the volumes are unmounted in reverse order, the last first:\n%s", cmds)
	}
}

// A daemon that dies in the middle of a volume's creation takes the dataset away again at its next start, whatever
// step it died after, and leaves the project's other datasets alone.
func TestCreateVolumeCrashRecovery(t *testing.T) {
	req := VolumeRequest{Project: "alpha", Name: "maildir", UUID: "vol-1", Size: "5G", UID: 5000, GID: 5000, Mode: 0o770}
	w0 := newWorld(t)
	req.Storage = w0.storage()
	steps := len(w0.S.volumePlan(req, nil).Steps)
	for k := 1; k <= steps; k++ {
		w := newWorld(t)
		req.Storage = w.storage()
		crash(t, w, "create-volume/alpha_maildir", w.S.volumePlan(req, nil), k)
		if found, err := w.S.RecoverCreateVolume(bg, req); !found || err != nil {
			t.Fatalf("after %d steps: %v %v", k, found, err)
		}
		// the dataset is gone (the empty volumes parent of the project stays: it is the project's, not the volume's)
		if ok, _ := w.Z.Exists(bg, "tank/jailops/projects/alpha/volumes/maildir"); ok {
			t.Fatalf("crash after %d steps: the dataset of the volume is still there\n%s", k, w.Z.Dump())
		}
		// the name is free again
		if _, err := w.S.CreateVolume(bg, req, nil, false); err != nil {
			t.Fatalf("after the recovery: %v", err)
		}
	}
}

// A remount that cannot be made (the box is back but the mount fails) must not leave the jail on the empty directory of
// its own root: a small read-only tmpfs stands in, and the error is returned so that the watch tries again.
func TestRemountOfAHostDirectoryThatFailsLeavesAPlaceholder(t *testing.T) {
	w := newWorld(t)
	w.created("web")
	w.Files.Sources["/mnt/box/backups"] = true
	a := Attached{Name: "box", HostDir: true, Mountpoint: "/mnt/box/backups", Path: "/srv/box"}
	w.attach["alpha_web"] = append(w.attach["alpha_web"], a)
	target := "/jailops/projects/alpha/jails/web/root/srv/box"
	w.Exec.Handler = func(argv []string) ([]byte, error) {
		if len(argv) > 3 && argv[0] == "mount" && argv[2] == "nullfs" {
			return []byte("mount_nullfs: Device busy"), errors.New("exit 1")
		}
		return w.handle(argv)
	}
	err := w.S.RemountHostDir(bg, "alpha_web", a)
	if err == nil || !strings.Contains(err.Error(), "Device busy") {
		t.Fatalf("a failed mount was not reported: %v", err)
	}
	last := strings.Join(w.Exec.Calls[len(w.Exec.Calls)-1], " ")
	if last != "mount -t tmpfs -o size=1m,ro tmpfs "+target {
		t.Fatalf("no stand-in on the target: %v", w.Exec.Calls)
	}
}
