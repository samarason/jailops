package service_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

const boxDir = "/mnt/box/backups"

// mountBox makes the fake host's directory a mount, and unmountBox takes it away again: what a storage box does.
func mountBox(e *dtest.Env)   { e.Files.Sources[boxDir] = true }
func unmountBox(e *dtest.Env) { delete(e.Files.Sources, boxDir) }

func newBoxVolume(t *testing.T, e *dtest.Env, s *service.Service, spec api.VolumeSpec) {
	t.Helper()
	mountBox(e)
	spec.Path = boxDir
	newVolume(t, s, as(globalAdmin, dtest.SeedProject), "box", spec)
}

func TestHostDirVolumeIsMadeByAGlobalAdministratorForAMount(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	// a project operator is not granted the host's directories
	_, err := s.CreateVolume(as(alphaOnly, dtest.SeedProject), api.VolumeCreate{Metadata: api.ObjectMeta{Name: "box"}, Spec: api.VolumeSpec{Path: boxDir}})
	wantCode(t, err, api.CodeForbidden)
	// the directory is not on a mount: that is a mistake, not a volume
	op, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "box"}, Spec: api.VolumeSpec{Path: boxDir}})
	failedWith(t, s, op, err, api.CodeInvalid)
	newBoxVolume(t, e, s, api.VolumeSpec{Comment: "the storage box"})
	v, err := s.GetVolume(ctx, "box")
	if err != nil {
		t.Fatal(err)
	}
	if v.Spec.Path != boxDir || v.Status.State != api.VolumeStateOK || v.Status.Mountpoint != boxDir || v.Status.Dataset != "" || v.Spec.Watch {
		t.Fatalf("%+v", v)
	}
	// no dataset was made, and no owner was set
	if len(e.Files.Owners) != 0 {
		t.Fatalf("owners set for a host directory: %v", e.Files.Owners)
	}
	// what a dataset has does not apply; the watch says what it needs
	for name, spec := range map[string]api.VolumeSpec{
		"size": {Path: boxDir, Size: "1G"}, "uid": {Path: boxDir, UID: 5}, "mode": {Path: boxDir, Mode: "0700"}, "encrypted": {Path: boxDir, Encrypted: true},
		"storage": {Path: boxDir, Storage: "default"}, "relative": {Path: "mnt/box"}, "root": {Path: "/"}, "dots": {Path: "/mnt/../etc"},
		"on-loss without a watch": {Path: boxDir, OnLoss: api.VolumeOnLossStop}, "probe without a watch": {Path: boxDir, Probe: api.VolumeProbeWrite},
		"a watch of a dataset": {Watch: true}, "bad probe": {Path: boxDir, Watch: true, Probe: "ping"}, "bad on-loss": {Path: boxDir, Watch: true, OnLoss: "reboot"},
	} {
		_, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "bad"}, Spec: spec})
		if !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a passphrase is for an encrypted volume
	_, err = s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "bad"}, Spec: api.VolumeSpec{Path: boxDir}, Passphrase: "correct horse battery"})
	wantCode(t, err, api.CodeInvalid)
}

func TestHostDirVolumeHasNoSnapshotsKeysOrSize(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newBoxVolume(t, e, s, api.VolumeSpec{})
	if _, err := s.CreateVolumeSnapshot(ctx, "box", api.VolumeSnapshot{}); !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.Error(), "directory of the host") {
		t.Errorf("snapshot: %v", err)
	}
	if _, err := s.ListVolumeSnapshots(ctx, "box"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("list snapshots: %v", err)
	}
	if _, err := s.RollbackVolume(ctx, "box", api.VolumeRollback{Snapshot: "x", ConfirmDataLoss: true}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("rollback: %v", err)
	}
	// the path is fixed, a dataset volume does not become a host directory, the watch is changed by an administrator
	v, _ := s.GetVolume(ctx, "box")
	v.Spec.Path = "/mnt/other"
	_, err := s.UpdateVolume(ctx, "box", v, service.AnyGeneration)
	wantCode(t, err, api.CodeInvalid)
	v, _ = s.GetVolume(ctx, "box")
	v.Spec.Size = "1G"
	_, err = s.UpdateVolume(ctx, "box", v, service.AnyGeneration)
	wantCode(t, err, api.CodeInvalid)
	v, _ = s.GetVolume(ctx, "box")
	v.Spec.Watch, v.Spec.Probe, v.Spec.OnLoss = true, api.VolumeProbeWrite, api.VolumeOnLossStop
	if _, err := s.UpdateVolume(as(alphaOnly, dtest.SeedProject), "box", v, service.AnyGeneration); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("an operator changed the watch: %v", err)
	}
	if got, err := s.UpdateVolume(ctx, "box", v, service.AnyGeneration); err != nil || !got.Spec.Watch || got.Spec.Probe != api.VolumeProbeWrite || got.Spec.OnLoss != api.VolumeOnLossStop {
		t.Fatalf("%+v %v", got, err)
	}
	newVolume(t, s, ctx, "plain", api.VolumeSpec{})
	p, _ := s.GetVolume(ctx, "plain")
	p.Spec.Path = boxDir
	_, err = s.UpdateVolume(ctx, "plain", p, service.AnyGeneration)
	wantCode(t, err, api.CodeInvalid)
	// deleting forgets the volume and leaves the directory
	op, err := s.DeleteVolume(ctx, "box", service.AnyGeneration)
	mustOp(t, s, op, err)
	if _, err := s.GetVolume(ctx, "box"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("%v", err)
	}
	if !e.Files.Sources[boxDir] {
		t.Fatal("the directory was touched")
	}
}

func attachBox(t *testing.T, s *service.Service, ctx context.Context, jail string) error {
	t.Helper()
	op, err := s.AttachVolume(ctx, jail, api.VolumeAttachRequest{Volume: "box", Mount: "/srv/backups"})
	if err != nil {
		return err
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		return &api.Error{Code: got.Error.Code, Message: got.Error.Message}
	}
	return nil
}

func TestHostDirVolumeIsAttachedByAGlobalAdministratorAndTheJailDoesNotStartWithoutItsMount(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newBoxVolume(t, e, s, api.VolumeSpec{})
	for _, n := range []string{"backup", "other"} {
		op, err := s.CreateJail(ctx, dtest.WebJail(n))
		mustOp(t, s, op, err)
	}
	if err := attachBox(t, s, as(alphaOnly, dtest.SeedProject), "backup"); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a project operator attached a directory of the host: %v", err)
	}
	if _, err := s.AttachVolume(ctx, "backup", api.VolumeAttachRequest{Volume: "box", Mount: "/srv/backups", CopyExisting: true}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("copy-existing into a host directory: %v", err)
	}
	if err := attachBox(t, s, ctx, "backup"); err != nil {
		t.Fatal(err)
	}
	// two jails may attach it
	if err := attachBox(t, s, ctx, "other"); err != nil {
		t.Fatal(err)
	}
	v, _ := s.GetVolume(ctx, "box")
	if len(v.Status.AttachedTo) != 2 {
		t.Fatalf("%+v", v.Status)
	}
	// a volume that is attached is not deleted
	_, err := s.DeleteVolume(ctx, "box", service.AnyGeneration)
	wantCode(t, err, api.CodeBusy)
	// with the mount there, the jail starts; without it, it does not, and nothing is left running
	unmountBox(e)
	op, err := s.JailAction(ctx, "backup", api.JailAction{Action: "start"})
	failedWith(t, s, op, err, api.CodeBusy)
	if j, _ := s.GetJail(ctx, "backup"); j.Status.Power == api.PowerRunning {
		t.Fatal("a jail runs on an empty directory")
	}
	if v, _ := s.GetVolume(ctx, "box"); v.Status.State != api.VolumeStateLost || !strings.Contains(v.Status.Detail, "not on a mount") {
		t.Fatalf("%+v", v.Status)
	}
	mountBox(e)
	op, err = s.JailAction(ctx, "backup", api.JailAction{Action: "start"})
	mustOp(t, s, op, err)
}

func events(t *testing.T, s *service.Service) (func(action string) bool, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := s.Events().Subscribe(ctx, -1)
	seen := map[string]bool{}
	return func(action string) bool {
		deadline := time.After(2 * time.Second)
		for {
			if seen[action] {
				return true
			}
			select {
			case se := <-ch:
				var le api.LifecycleEvent
				if json.Unmarshal(se.Event.Metadata, &le) == nil {
					seen[le.Action] = true
				}
			case <-deadline:
				return seen[action]
			}
		}
	}, cancel
}

func TestWatchedHostDirectoryStopsItsJailsOnLossAndGivesTheMountBack(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newBoxVolume(t, e, s, api.VolumeSpec{Watch: true, OnLoss: api.VolumeOnLossStop})
	newVolume(t, s, ctx, "quiet", api.VolumeSpec{})
	op, err := s.CreateJail(ctx, dtest.WebJail("backup"))
	mustOp(t, s, op, err)
	if err := attachBox(t, s, ctx, "backup"); err != nil {
		t.Fatal(err)
	}
	op, err = s.JailAction(ctx, "backup", api.JailAction{Action: "start"})
	mustOp(t, s, op, err)
	saw, stop := events(t, s)
	defer stop()
	sys := context.Background()
	s.WatchHostDirs(sys) // the first look: the mount is there
	if j, _ := s.GetJail(ctx, "backup"); j.Status.Power != api.PowerRunning {
		t.Fatal("the jail stopped with its mount there")
	}
	unmountBox(e)
	s.WatchHostDirs(sys)
	if !saw("volume-lost") {
		t.Fatal("no volume-lost event")
	}
	if j, _ := s.GetJail(ctx, "backup"); j.Status.Power == api.PowerRunning {
		t.Fatal("on-loss stop left the jail running")
	}
	// a second round with the mount still gone does not repeat anything
	s.WatchHostDirs(sys)
	mountBox(e)
	s.WatchHostDirs(sys)
	if !saw("volume-restored") {
		t.Fatal("no volume-restored event")
	}
	// the jail stays stopped: the operator starts it
	if j, _ := s.GetJail(ctx, "backup"); j.Status.Power == api.PowerRunning {
		t.Fatal("the jail was started by the watch")
	}
	v, _ := s.GetVolume(ctx, "box")
	if v.Status.State != api.VolumeStateOK {
		t.Fatalf("%+v", v.Status)
	}
}

func TestWatchedHostDirectoryRemountsForRunningJailsThatKeepRunning(t *testing.T) {
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newBoxVolume(t, e, s, api.VolumeSpec{Watch: true}) // on-loss none
	op, err := s.CreateJail(ctx, dtest.WebJail("backup"))
	mustOp(t, s, op, err)
	if err := attachBox(t, s, ctx, "backup"); err != nil {
		t.Fatal(err)
	}
	op, err = s.JailAction(ctx, "backup", api.JailAction{Action: "start"})
	mustOp(t, s, op, err)
	saw, stop := events(t, s)
	defer stop()
	sys := context.Background()
	s.WatchHostDirs(sys)
	unmountBox(e)
	s.WatchHostDirs(sys)
	if j, _ := s.GetJail(ctx, "backup"); j.Status.Power != api.PowerRunning {
		t.Fatal("on-loss none stopped the jail")
	}
	before := len(e.Run.Calls())
	mountBox(e)
	s.WatchHostDirs(sys)
	if !saw("volume-restored") || !saw("volume-remounted") {
		t.Fatal("no events for the return of the mount")
	}
	var umounted, mounted bool
	for _, c := range e.Run.Calls()[before:] {
		args := strings.Join(c.Cmd.Args, " ")
		umounted = umounted || c.Cmd.Name == "umount" && strings.Contains(args, "/srv/backups")
		mounted = mounted || c.Cmd.Name == "mount" && strings.Contains(args, "-t nullfs "+boxDir+" ") && strings.HasSuffix(args, "/srv/backups")
	}
	if !umounted || !mounted {
		t.Fatalf("umount %v mount %v: %v", umounted, mounted, e.Run.Calls()[before:])
	}
}

func TestDoctorSaysWhenAHostDirectoryIsNotOnItsMount(t *testing.T) {
	e, s := newEnv(t)
	newBoxVolume(t, e, s, api.VolumeSpec{})
	find := func() api.DoctorCheck {
		rep := s.Doctor(as(globalAdmin, ""))
		for _, c := range rep.Checks {
			if c.Name == "volume.hostdirs" {
				return c
			}
		}
		t.Fatal("no volume.hostdirs check")
		return api.DoctorCheck{}
	}
	if c := find(); c.Status != api.DoctorOK {
		t.Fatalf("%+v", c)
	}
	unmountBox(e)
	if c := find(); c.Status != api.DoctorFail || !strings.Contains(c.Message, boxDir) {
		t.Fatalf("%+v", c)
	}
}

// A share that does not answer holds the helper request of its probe until it does: the daemon sends one, however
// many looks (the watch, a list, a show, doctor) come while it hangs, and none of them waits longer than its own limit.
func TestAHostDirectoryThatDoesNotAnswerCostsOneProbe(t *testing.T) {
	defer service.SetHostDirTimeouts(60*time.Millisecond, 60*time.Millisecond)()
	e, s := newEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	newBoxVolume(t, e, s, api.VolumeSpec{Watch: true})
	hold := make(chan struct{})
	base := e.Files.Probes()
	e.Files.ProbeHold = hold
	start := time.Now()
	for i := 0; i < 5; i++ {
		s.WatchHostDirs(context.Background())
		if l, err := s.ListVolumes(ctx, nil); err != nil || len(l) != 1 || l[0].Status.State != api.VolumeStateLost {
			t.Fatalf("list: %+v %v", l, err)
		}
		if v, err := s.GetVolume(ctx, "box"); err != nil || v.Status.State != api.VolumeStateLost || !strings.Contains(v.Status.Detail, "does not answer") {
			t.Fatalf("show: %+v %v", v.Status, err)
		}
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("fifteen looks at a dead share took %v", took)
	}
	if n := e.Files.Probes() - base; n != 1 {
		t.Fatalf("%d probes reached the helper, want 1", n)
	}
	// the share answers again: the next look is a new probe and sees it
	close(hold)
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.WatchHostDirs(context.Background())
		if v, _ := s.GetVolume(ctx, "box"); v.Status.State == api.VolumeStateOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the share is back and the volume is still lost")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
