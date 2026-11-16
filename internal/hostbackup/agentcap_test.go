package hostbackup

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"jailops.net/jailops/internal/repo/catalog"
	"jailops.net/jailops/sdk/api"
)

// capAgents is a helper with a cap on live file agents, as the real one has: past it a start answers busy. It counts
// the agents alive at once and writes closes into the log of the mounts, to check the order of the cleanup.
type capAgents struct {
	pipeAgents
	cap      int
	live     atomic.Int32
	max      atomic.Int32
	failOpen atomic.Int32 // the n-th open fails with a plain error (0 = never)
	opens    atomic.Int32
	busyFor  atomic.Int32 // the next n opens answer busy
	z        *stoppedZFS
}

func (c *capAgents) ReadSnapshot(ctx context.Context, dir string) (catalog.ScanFS, func(), error) {
	n := c.opens.Add(1)
	if c.busyFor.Load() > 0 {
		c.busyFor.Add(-1)
		return nil, nil, api.Errorf(api.CodeBusy, "too many file agents are running (%d)", c.cap)
	}
	if k := c.failOpen.Load(); k != 0 && n == k {
		return nil, nil, fmt.Errorf("the helper refused the agent")
	}
	if int(c.live.Add(1)) > c.cap {
		c.live.Add(-1)
		return nil, nil, api.Errorf(api.CodeBusy, "too many file agents are running (%d)", c.cap)
	}
	for m := c.max.Load(); c.live.Load() > m && !c.max.CompareAndSwap(m, c.live.Load()); m = c.max.Load() {
	}
	fsys, closeFS, err := c.pipeAgents.ReadSnapshot(ctx, dir)
	if err != nil {
		c.live.Add(-1)
		return nil, nil, err
	}
	var once sync.Once
	return fsys, func() {
		once.Do(func() {
			closeFS()
			c.live.Add(-1)
			if c.z != nil {
				c.z.mu.Lock()
				c.z.order = append(c.z.order, "agent closed")
				c.z.mu.Unlock()
			}
		})
	}, nil
}

// bigJail is a thin jail with ten captured datasets, like one that has never been started.
func bigJail(t *testing.T, r *rig, name string) JailRecord {
	t.Helper()
	j := r.jail(name, "uuid-"+name, nil)
	for i := 0; i < 6; i++ {
		ds := fmt.Sprintf("%s/p%d", j.Container, i)
		mustCreate(t, r, ds, map[string]string{"jailops:managed": "on", "jailops:id": j.UUID})
		writeFile(t, r.w.m.liveDir(ds), "f", "data "+ds)
		j.Datasets = append(j.Datasets, Dataset{Name: ds, Kind: KindPersistent, Mountpoint: j.Datasets[0].Mountpoint + "/root/p" + fmt.Sprint(i)})
	}
	return j
}

func TestFileAgentsDoNotAccumulateOverAWholeBackup(t *testing.T) {
	ag := &capAgents{cap: 4}
	r := newRig(t, rigOpts{remote: mustMem(t), agents: ag})
	var jails []JailRecord
	for _, n := range []string{"web1", "web2", "web3"} {
		jails = append(jails, bigJail(t, r, n))
	}
	if got := len(capturableOrFail(t, jails[0])); got != 10 {
		t.Fatalf("a jail of %d captured datasets, the test wants ten", got)
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(jails))
	for _, j := range jails {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ag.opens.Load() < 30 {
		t.Fatalf("%d agents were started for 30 datasets", ag.opens.Load())
	}
	if m := ag.max.Load(); m > 3 {
		t.Fatalf("%d agents were alive at once for three jails: they pile up over the backup", m)
	}
	if ag.live.Load() != 0 {
		t.Fatalf("%d agents are still alive after the backups", ag.live.Load())
	}
}

func capturableOrFail(t *testing.T, j JailRecord) []Dataset {
	t.Helper()
	sets, err := capturable(j)
	if err != nil {
		t.Fatal(err)
	}
	return sets
}

func TestCleanupStopsTheAgentsThenUnmountsInReverseOrder(t *testing.T) {
	ag := &capAgents{cap: 16}
	r := newRig(t, rigOpts{remote: mustMem(t), agents: ag})
	j := bigJail(t, r, "web1")
	z := stopped(r, j)
	ag.z = z
	r.svc.deps.Datasets = z
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"}); err != nil {
		t.Fatal(err)
	}
	lastClose, firstUnmount := -1, -1
	var mounts, unmounts []string
	for i, o := range z.order {
		switch {
		case o == "agent closed":
			lastClose = i
		case strings.HasPrefix(o, "mount "):
			mounts = append(mounts, strings.TrimPrefix(o, "mount "))
		case strings.HasPrefix(o, "unmount "):
			if firstUnmount < 0 {
				firstUnmount = i
			}
			unmounts = append(unmounts, strings.TrimPrefix(o, "unmount "))
		}
	}
	if lastClose < 0 || firstUnmount < 0 || lastClose > firstUnmount {
		t.Fatalf("an agent was still open when the first unmount came: %v", z.order)
	}
	if len(mounts) != 10 || len(unmounts) != 10 {
		t.Fatalf("mounts %d, unmounts %d", len(mounts), len(unmounts))
	}
	for i := range mounts {
		if mounts[i] != unmounts[len(unmounts)-1-i] {
			t.Fatalf("unmounts are not the reverse of the mounts:\n%v\n%v", mounts, unmounts)
		}
	}
}

func TestAFailedReadStillReleasesTheAgentsAndTheMounts(t *testing.T) {
	ag := &capAgents{cap: 16}
	r := newRig(t, rigOpts{remote: mustMem(t), agents: ag})
	j := bigJail(t, r, "web1")
	z := stopped(r, j)
	ag.z = z
	r.svc.deps.Datasets = z
	ag.failOpen.Store(5)
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"}); err == nil {
		t.Fatal("expected the failure")
	}
	if ag.live.Load() != 0 {
		t.Fatalf("%d agents alive after the failure", ag.live.Load())
	}
	for ds, down := range z.down {
		if !down {
			t.Fatalf("%s stayed mounted after the failure", ds)
		}
	}
}

func TestABusyHelperAndABusyDatasetAreWaitedFor(t *testing.T) {
	ag := &capAgents{cap: 16}
	r := newRig(t, rigOpts{remote: mustMem(t), agents: ag})
	j := bigJail(t, r, "web1")
	z := stopped(r, j)
	ag.z = z
	bz := &busyUnmounts{stoppedZFS: z, busy: 3}
	r.svc.deps.Datasets = bz
	ag.busyFor.Store(2)
	if _, err := r.svc.BackupJail(bg, j, CaptureOptions{Policy: "p"}); err != nil {
		t.Fatal(err)
	}
	if bz.refused != 3 {
		t.Fatalf("%d busy unmounts, want 3", bz.refused)
	}
	for ds, down := range z.down {
		if !down {
			t.Fatalf("%s stayed mounted", ds)
		}
	}
}

// busyUnmounts refuses the first unmounts as busy, as a dataset an agent has only just let go of does.
type busyUnmounts struct {
	*stoppedZFS
	busy    int
	refused int
}

func (b *busyUnmounts) Unmount(ctx context.Context, ds string) error {
	if b.refused < b.busy {
		b.refused++
		return api.Errorf(api.CodeBusy, "cannot unmount %q: pool or dataset is busy", ds)
	}
	return b.stoppedZFS.Unmount(ctx, ds)
}
