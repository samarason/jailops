package hostbackup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/internal/repo/engine"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

var errInjected = errors.New("injected failure")

// flakyRemote fails the n-th call of an operation ("begin", "putchunk",
// "putindex", "putmanifest", "commit", "getchunk", "missing").
type flakyRemote struct {
	Remote
	mu    sync.Mutex
	op    string
	n     int
	calls map[string]int
	err   error
	// failUntil (with n == 0) fails the first failUntil calls of op.
	failUntil int
}

func (f *flakyRemote) hit(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[op]++
	if op == f.op && (f.calls[op] == f.n || (f.n == 0 && f.calls[op] <= f.failUntil)) {
		if f.err != nil {
			return f.err
		}
		return errInjected
	}
	return nil
}

func (f *flakyRemote) NewUploader(ctx context.Context, g, s, p string) (engine.Uploader, error) {
	if err := f.hit("begin"); err != nil {
		return nil, err
	}
	u, err := f.Remote.NewUploader(ctx, g, s, p)
	if err != nil {
		return nil, err
	}
	return &flakyUp{Uploader: u, f: f}, nil
}

func (f *flakyRemote) GetChunk(ctx context.Context, id format.ID) ([]byte, error) {
	if err := f.hit("getchunk"); err != nil {
		return nil, err
	}
	return f.Remote.GetChunk(ctx, id)
}

type flakyUp struct {
	engine.Uploader
	f *flakyRemote
}

func (u *flakyUp) Missing(ctx context.Context, ids []format.ID) ([]format.ID, error) {
	if err := u.f.hit("missing"); err != nil {
		return nil, err
	}
	return u.Uploader.Missing(ctx, ids)
}
func (u *flakyUp) PutChunk(ctx context.Context, id format.ID, b []byte) error {
	if err := u.f.hit("putchunk"); err != nil {
		return err
	}
	return u.Uploader.PutChunk(ctx, id, b)
}
func (u *flakyUp) PutIndex(ctx context.Context, b []byte) error {
	if err := u.f.hit("putindex"); err != nil {
		return err
	}
	return u.Uploader.PutIndex(ctx, b)
}
func (u *flakyUp) PutManifest(ctx context.Context, b []byte) error {
	if err := u.f.hit("putmanifest"); err != nil {
		return err
	}
	return u.Uploader.PutManifest(ctx, b)
}
func (u *flakyUp) Commit(ctx context.Context) (*format.Receipt, error) {
	if err := u.f.hit("commit"); err != nil {
		return nil, err
	}
	return u.Uploader.Commit(ctx)
}

// recordPoints runs fn with a recording fault function and returns the points
// the operation passed through, in order.
func recordPoints(r *rig, fn func()) []string {
	var mu sync.Mutex
	var pts []string
	r.svc.fault = func(p string) error {
		mu.Lock()
		pts = append(pts, p)
		mu.Unlock()
		return nil
	}
	fn()
	r.svc.fault = nil
	return pts
}

func (r *rig) assertNoCaptureDebris(label string) {
	r.t.Helper()
	if s := r.w.snapshots(r.t, SnapshotPrefix); len(s) != 0 {
		r.t.Fatalf("%s: ZFS snapshots left behind: %v", label, s)
	}
	if n := len(r.w.m.snaps); n != 0 {
		r.t.Fatalf("%s: %d snapshot directories left", label, n)
	}
	if bs, _ := r.cat.Backups(bg); len(bs) != 0 {
		r.t.Fatalf("%s: a failed backup was recorded", label)
	}
}

func TestCaptureFailureAtEveryStepLeavesNoSnapshot(t *testing.T) {
	mk := func() (*rig, JailRecord, *flakyRemote) {
		inner, _, _ := memRemote(t)
		fr := &flakyRemote{Remote: inner}
		r := newRig(t, rigOpts{remote: fr, hooks: true})
		return r, r.jail("web1", "uuid-web1", nil), fr
	}
	// the points of a good run
	r0, j0, _ := mk()
	pts := recordPoints(r0, func() { r0.backup(j0) })
	if len(pts) < 6 {
		t.Fatalf("only %d fault points: %v", len(pts), pts)
	}
	for _, p := range pts {
		t.Run("point "+p, func(t *testing.T) {
			r, j, _ := mk()
			r.svc.fault = func(q string) error {
				if q == p {
					return errInjected
				}
				return nil
			}
			if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err == nil {
				t.Fatal("the injected failure was swallowed")
			}
			r.assertNoCaptureDebris(p)
			if r.hooks.post != r.hooks.pre {
				t.Fatalf("pre-hook ran %d times, post-hook %d: the application stays quiesced", r.hooks.pre, r.hooks.post)
			}
			// and the next run works
			r.svc.fault = nil
			if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err != nil {
				t.Fatalf("the run after the failure: %v", err)
			}
		})
	}
	for _, c := range []struct {
		op string
		n  int
	}{{"begin", 1}, {"missing", 1}, {"putchunk", 1}, {"putchunk", 6}, {"putindex", 1}, {"putmanifest", 1}, {"commit", 1}} {
		t.Run(fmt.Sprintf("repository %s #%d", c.op, c.n), func(t *testing.T) {
			r, j, fr := mk()
			fr.op, fr.n = c.op, c.n
			_, err := r.svc.BackupJail(bg, j, CaptureOptions{})
			if err == nil {
				t.Fatal("the repository failure was swallowed")
			}
			r.assertNoCaptureDebris(c.op)
			if _, rerr := r.svc.Get(bg, "x"); rerr == nil {
				t.Fatal("unexpected backup")
			}
		})
	}
	t.Run("zfs snapshot fails", func(t *testing.T) {
		r, j, _ := mk()
		r.hooks.failPre = nil
		r.svc.zfs = failingZFS{world: r.w, failSnapshot: true}
		_, err := r.svc.BackupJail(bg, j, CaptureOptions{})
		if err == nil || r.hooks.post != r.hooks.pre {
			t.Fatalf("err = %v, hooks %d/%d", err, r.hooks.pre, r.hooks.post)
		}
		r.assertNoCaptureDebris("snapshot")
	})
	t.Run("guid fails", func(t *testing.T) {
		r, j, _ := mk()
		r.svc.zfs = failingZFS{world: r.w, failGUID: true}
		if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err == nil {
			t.Fatal("swallowed")
		}
		r.assertNoCaptureDebris("guid")
	})
	t.Run("snapshot directory unreadable", func(t *testing.T) {
		r, j, _ := mk()
		r.w.m.failSnapDir = func(ds string) error {
			if strings.HasSuffix(ds, "/local") {
				return errInjected
			}
			return nil
		}
		if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err == nil {
			t.Fatal("swallowed")
		}
		r.assertNoCaptureDebris("snapdir")
	})
	t.Run("pre hook fails", func(t *testing.T) {
		r, j, _ := mk()
		r.hooks.failPre = errInjected
		if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err == nil {
			t.Fatal("swallowed")
		}
		r.assertNoCaptureDebris("pre")
		if r.hooks.post != 0 {
			t.Fatal("the post hook ran although the pre hook failed")
		}
	})
	t.Run("post hook fails is a warning", func(t *testing.T) {
		r, j, _ := mk()
		r.hooks.failPost = errInjected
		res, err := r.svc.BackupJail(bg, j, CaptureOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if w := res.Targets[0].Run.Warnings; len(w) == 0 || !strings.Contains(w[0], "post-backup hook") {
			t.Fatalf("warnings = %v", w)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		r, j, _ := mk()
		ctx, cancel := context.WithCancel(bg)
		r.svc.fault = func(q string) error {
			if q == "capture.engine" {
				cancel()
			}
			return nil
		}
		if _, err := r.svc.BackupJail(ctx, j, CaptureOptions{}); err == nil {
			t.Fatal("a cancelled backup succeeded")
		}
		r.assertNoCaptureDebris("cancel")
	})
}

func TestBusyJailRefusesASecondJob(t *testing.T) {
	r := newRig(t, rigOpts{remote: mustMem(t)})
	j := r.jail("web1", "uuid-web1", nil)
	if !r.svc.acquire(j.UUID) {
		t.Fatal("acquire")
	}
	_, err := r.svc.BackupJail(bg, j, CaptureOptions{})
	codeOf(t, err, api.CodeBusy)
	r.svc.release(j.UUID)
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) assertNoRestoreDebris(label, container string) {
	r.t.Helper()
	if ds := r.w.datasets(r.t, container); len(ds) != 0 {
		r.t.Fatalf("%s: half-created datasets: %v", label, ds)
	}
	r.host.mu.Lock()
	defer r.host.mu.Unlock()
	objs, adopts := 0, 0
	for _, u := range r.host.undone {
		switch u {
		case "objects":
			objs++
		case "adopt":
			adopts++
		}
	}
	if objs != len(r.host.created) || adopts != len(r.host.adopted) {
		r.t.Fatalf("%s: %d objects created/%d undone, %d adopted/%d undone", label, len(r.host.created), objs, len(r.host.adopted), adopts)
	}
}

func TestRestoreFailureAtEveryStepLeavesNothing(t *testing.T) {
	remote, _, _ := memRemote(t)
	mk := func() (*rig, api.Backup, *flakyRemote) {
		fr := &flakyRemote{Remote: remote}
		r := newRig(t, rigOpts{remote: fr})
		j := r.jail("web1", "uuid-web1", nil)
		return r, r.backup(j).Targets[0].Backup, fr
	}
	req := func(b api.Backup) api.RestoreRequest {
		return api.RestoreRequest{Backup: b.Metadata.Name, As: "web2", NetworkMap: map[string]string{"lan": "lan2"}}
	}
	container := "tank/jailops/projects/alpha/jails/web2"
	r0, b0, _ := mk()
	pts := recordPoints(r0, func() {
		if _, err := r0.svc.Restore(bg, req(b0)); err != nil {
			t.Fatal(err)
		}
	})
	if len(pts) < 8 {
		t.Fatalf("only %d restore points: %v", len(pts), pts)
	}
	for _, p := range pts {
		t.Run("point "+p, func(t *testing.T) {
			r, b, _ := mk()
			r.svc.fault = func(q string) error {
				if q == p {
					return errInjected
				}
				return nil
			}
			if _, err := r.svc.Restore(bg, req(b)); err == nil {
				t.Fatal("swallowed")
			}
			r.assertNoRestoreDebris(p, container)
			r.svc.fault = nil
			if _, err := r.svc.Restore(bg, req(b)); err != nil {
				t.Fatalf("the restore after the failure: %v", err)
			}
		})
	}
	t.Run("mount fails for every dataset", func(t *testing.T) {
		for _, name := range []string{container, container + "/etc", container + "/local", container + "/db"} {
			r, b, _ := mk()
			r.w.m.failMount = func(ds string) error {
				if ds == name {
					return errInjected
				}
				return nil
			}
			if _, err := r.svc.Restore(bg, req(b)); err == nil {
				t.Fatal("swallowed")
			}
			r.assertNoRestoreDebris(name, container)
		}
	})
	t.Run("objects, adopt and start", func(t *testing.T) {
		r, b, _ := mk()
		r.host.failObj = errInjected
		if _, err := r.svc.Restore(bg, req(b)); err == nil {
			t.Fatal("swallowed")
		}
		r.assertNoRestoreDebris("objects", container)
		r.host.failObj, r.host.failAdpt = nil, errInjected
		if _, err := r.svc.Restore(bg, req(b)); err == nil {
			t.Fatal("swallowed")
		}
		r.assertNoRestoreDebris("adopt", container)
		if len(r.host.undone) == 0 {
			t.Fatal("the objects created before the failed adopt were not removed")
		}
		// a jail that restored but does not start is kept, with a note
		r.host.failAdpt, r.host.failStrt = nil, errInjected
		res, err := r.svc.RestoreWith(bg, req(b), RestoreOptions{Start: true})
		if err != nil || len(res.Notes) == 0 || res.Jail.Status.Power != api.PowerStopped {
			t.Fatalf("start failure = %+v, %v", res, err)
		}
	})
	t.Run("repository fails during extraction", func(t *testing.T) {
		for n := 1; n <= 4; n++ {
			r, b, fr := mk()
			fr.op, fr.n = "getchunk", n
			fr.calls = nil
			if _, err := r.svc.Restore(bg, req(b)); err == nil {
				t.Fatalf("chunk %d: swallowed", n)
			}
			r.assertNoRestoreDebris(fmt.Sprint("getchunk ", n), container)
		}
	})
	t.Run("generation lost its @ro snapshot", func(t *testing.T) {
		r, b, _ := mk()
		if err := r.w.Fake.Destroy(bg, testGen.Dataset+"@ro", zfs.DestroyOpts{}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.svc.Restore(bg, req(b)); err == nil {
			t.Fatal("swallowed")
		}
		r.assertNoRestoreDebris("no @ro", container)
	})
	t.Run("a failed replace puts the old jail back", func(t *testing.T) {
		for _, p := range []string{"restore.container", "restore.root", "restore.extract", "restore.adopt", "restore.complete"} {
			r, b, _ := mk()
			pl, _ := r.host.Place(bg, "alpha", "web1", "")
			mustCreate(t, r, pl.Container, map[string]string{"mountpoint": pl.Mountpoint, "jailops:managed": "on", "jailops:id": "uuid-web1"})
			mustCreate(t, r, pl.Container+"/etc", map[string]string{"mountpoint": pl.Mountpoint + "/root/etc"})
			r.host.state.Jails["web1"] = backupJailRef("web1", "uuid-web1")
			r.svc.fault = func(q string) error {
				if q == p {
					return errInjected
				}
				return nil
			}
			if _, err := r.svc.Restore(bg, api.RestoreRequest{Backup: b.Metadata.Name, Replace: true}); err == nil {
				t.Fatal("swallowed")
			}
			got, err := r.w.Get(bg, pl.Container+"/etc", "mountpoint")
			if err != nil || got["mountpoint"].Value != pl.Mountpoint+"/root/etc" {
				t.Fatalf("%s: the old jail's mountpoint = %v, %v", p, got, err)
			}
			if ds := r.w.datasets(t, pl.Container); len(ds) != 2 {
				t.Fatalf("%s: datasets of the old jail = %v", p, ds)
			}
			if s := r.w.snapshots(t, "jailops-prerestore-"); len(s) != 0 {
				t.Fatalf("%s: safety snapshots left: %v", p, s)
			}
			if ds := r.w.datasets(t, pl.Container+".replaced-"); len(ds) != 0 {
				t.Fatalf("%s: %v", p, ds)
			}
		}
	})
}
