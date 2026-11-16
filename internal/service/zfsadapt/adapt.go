// Package zfsadapt turns the full zfs.Client into the narrower interfaces the
// lifecycle and the image builder use. It is the only place where their
// semantics (local property values, short snapshot names, replicate as one
// piped send and receive) meet the command layer.
package zfsadapt

import (
	"context"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// Adapter implements lifecycle.ZFS and imagegen.ZFS over zfs.Client. Mount and
// unmount use the runner because zfs.Client has no such calls.
type Adapter struct {
	C zfs.Client
	R run.Runner
	// MountFn and UnmountFn replace the runner for mounting (jailops-priv
	// offers them as typed operations).
	MountFn, UnmountFn func(ctx context.Context, dataset string) error
}

// New returns an Adapter.
func New(c zfs.Client, r run.Runner) *Adapter { return &Adapter{C: c, R: r} }

func (a *Adapter) Exists(ctx context.Context, name string) (bool, error) {
	return a.C.Exists(ctx, name)
}

func (a *Adapter) Create(ctx context.Context, name string, props map[string]string) error {
	return a.C.Create(ctx, zfs.CreateOpts{Name: name, Props: props})
}

func (a *Adapter) Clone(ctx context.Context, snapshot, target string, props map[string]string) error {
	return a.C.Clone(ctx, snapshot, target, props, false)
}

func (a *Adapter) Snapshot(ctx context.Context, props map[string]string, snapshots ...string) error {
	return a.C.Snapshot(ctx, zfs.SnapshotOpts{Names: snapshots, Props: props})
}

func (a *Adapter) Destroy(ctx context.Context, name string) error {
	return retryBusy(ctx, func() error { return a.C.Destroy(ctx, name, zfs.DestroyOpts{}) })
}

func (a *Adapter) DestroyRecursive(ctx context.Context, dataset string) error {
	return retryBusy(ctx, func() error { return a.C.Destroy(ctx, dataset, zfs.DestroyOpts{Recursive: true}) })
}

// retryBusy runs fn and, while it fails because a dataset is busy, runs it again for a few seconds. A jail that was
// just stopped can still be tearing down its processes when its datasets are unmounted or destroyed (seen on two
// hosts: the delete that followed a stop failed once and worked a minute later).
func retryBusy(ctx context.Context, fn func() error) error {
	var err error
	for i := 0; i < unmountTries; i++ {
		if err = fn(); err == nil || !isBusy(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(unmountWait):
		}
	}
	return err
}

func (a *Adapter) Rename(ctx context.Context, from, to string) error {
	return a.C.Rename(ctx, from, to, zfs.RenameOpts{})
}

func (a *Adapter) Rollback(ctx context.Context, snapshot string, destroyLater bool) error {
	return a.C.Rollback(ctx, snapshot, zfs.RollbackOpts{DestroyNewer: destroyLater})
}

// Get returns the value set locally ("" when inherited, default or unset).
func (a *Adapter) Get(ctx context.Context, name, prop string) (string, error) {
	m, err := a.C.Get(ctx, name, prop)
	if err != nil {
		return "", err
	}
	p, ok := m[prop]
	if !ok || (p.Source != "local" && p.Source != "received") {
		return "", nil
	}
	return p.Value, nil
}

func (a *Adapter) Set(ctx context.Context, name string, props map[string]string) error {
	return a.C.Set(ctx, name, props)
}

func (a *Adapter) Inherit(ctx context.Context, name, prop string) error {
	return a.C.Inherit(ctx, name, prop)
}

// Descendants lists every dataset below dataset, parents first.
func (a *Adapter) Descendants(ctx context.Context, dataset string) ([]string, error) {
	l, err := a.C.List(ctx, zfs.ListOpts{Root: dataset, Recursive: true})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range l {
		if d.Name != dataset {
			out = append(out, d.Name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Snapshots lists the short names of a dataset's snapshots, oldest first.
func (a *Adapter) Snapshots(ctx context.Context, dataset string) ([]string, error) {
	l, err := a.C.List(ctx, zfs.ListOpts{Root: dataset, Types: []string{"snapshot"}, Depth: 1, Props: []string{"creation"}})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range l {
		if ds, sn := zfs.SplitSnapshot(d.Name); ds == dataset && sn != "" {
			out = append(out, sn)
		}
	}
	return out, nil
}

// SnapshotTimes gives the creation time of each snapshot of a dataset, by short name.
func (a *Adapter) SnapshotTimes(ctx context.Context, dataset string) (map[string]time.Time, error) {
	l, err := a.C.List(ctx, zfs.ListOpts{Root: dataset, Types: []string{"snapshot"}, Depth: 1, Props: []string{"creation"}})
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for _, d := range l {
		ds, sn := zfs.SplitSnapshot(d.Name)
		if ds != dataset || sn == "" {
			continue
		}
		if sec, err := strconv.ParseInt(d.Props["creation"], 10, 64); err == nil && sec > 0 {
			out[sn] = time.Unix(sec, 0).UTC()
		}
	}
	return out, nil
}

// Written is the bytes written to the snapshot's dataset since the snapshot.
func (a *Adapter) Written(ctx context.Context, snapshot string) (int64, error) {
	ds, _ := zfs.SplitSnapshot(snapshot)
	n, err := a.C.Written(ctx, ds, snapshot)
	return int64(n), err
}

func (a *Adapter) Clones(ctx context.Context, snapshot string) ([]string, error) {
	return a.C.Clones(ctx, snapshot)
}

func (a *Adapter) zfsCmd(ctx context.Context, args ...string) error {
	if a.R == nil {
		return api.Errorf(api.CodeUnsupported, "no command runner configured")
	}
	_, err := a.R.Run(ctx, run.Cmd{Name: "zfs", Args: args, Timeout: 60 * time.Second})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			msg := strings.TrimSpace(ee.Stderr)
			if strings.Contains(msg, "already mounted") || strings.Contains(msg, "not currently mounted") {
				return nil
			}
			return api.Errorf(api.CodeInternal, "zfs %s: %s", args[0], msg)
		}
		return api.Errorf(api.CodeInternal, "zfs %s: %v", args[0], err)
	}
	return nil
}

func (a *Adapter) Mount(ctx context.Context, dataset string) error {
	if a.MountFn != nil {
		return a.MountFn(ctx, dataset)
	}
	if err := zfs.ValidatePool(strings.SplitN(dataset, "/", 2)[0]); err != nil {
		return err
	}
	return a.zfsCmd(ctx, "mount", dataset)
}

func (a *Adapter) Unmount(ctx context.Context, dataset string) error {
	// A jail that was just removed may still be tearing down its processes: a busy dataset is tried again for a
	// few seconds before it is called busy.
	return retryBusy(ctx, func() error { return a.unmountOnce(ctx, dataset) })
}

var (
	// a jail that was just stopped is torn down by the kernel (its processes, its vnet, its mounts), which on a slow
	// or busy host takes longer than a few seconds: a dataset still busy after a minute has a holder
	unmountTries = 120
	unmountWait  = 500 * time.Millisecond
)

func isBusy(err error) bool { return api.IsCode(err, api.CodeBusy) || zfs.IsBusy(err) }

func (a *Adapter) unmountOnce(ctx context.Context, dataset string) error {
	if a.UnmountFn != nil {
		return a.UnmountFn(ctx, dataset)
	}
	if err := zfs.ValidatePool(strings.SplitN(dataset, "/", 2)[0]); err != nil {
		return err
	}
	return a.zfsCmd(ctx, "unmount", dataset)
}

// Replicate is `zfs send -p snapshot | zfs receive dst`.
func (a *Adapter) Replicate(ctx context.Context, snapshot, dst string, props map[string]string) error {
	// A client that can copy on its own side (the helper) does, so the stream does not travel through this process.
	if r, ok := a.C.(interface {
		Replicate(context.Context, string, string, map[string]string) error
	}); ok {
		return r.Replicate(ctx, snapshot, dst, props)
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sendErr := make(chan error, 1)
	go func() {
		err := a.C.Send(ctx, zfs.SendOpts{Snapshot: snapshot, Replicate: false}, pw)
		pw.CloseWithError(err)
		sendErr <- err
	}()
	rerr := a.C.Receive(ctx, zfs.ReceiveOpts{Target: dst, Props: props}, pr)
	pr.CloseWithError(rerr)
	cancel()
	serr := <-sendErr
	if rerr != nil {
		return rerr
	}
	return serr
}

func (a *Adapter) Hold(ctx context.Context, snapshot, tag string) error {
	return a.C.Hold(ctx, tag, snapshot)
}

func (a *Adapter) Release(ctx context.Context, snapshot, tag string) error {
	return a.C.Release(ctx, tag, snapshot)
}

func (a *Adapter) Holds(ctx context.Context, snapshot string) ([]string, error) {
	h, err := a.C.Holds(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, x := range h {
		out = append(out, x.Tag)
	}
	return out, nil
}
