package hostbackup

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"jailops.net/jailops/internal/fsagent"
	"jailops.net/jailops/internal/repo/catalog"
	"jailops.net/jailops/sdk/api"
)

// pipeAgents serves the agents in this process, over an in-memory connection, in the directory itself (no
// chroot: the tests do not run as root). The production agents are a separate process in a chroot.
type pipeAgents struct{ reads, writes atomic.Int32 }

func (p *pipeAgents) start(mode fsagent.Mode, dir string) *fsagent.Client {
	a, b := net.Pipe()
	go func() { _ = fsagent.Serve(a, fsagent.Config{Mode: mode, Root: dir}); a.Close() }()
	return fsagent.NewClient(b)
}

func (p *pipeAgents) ReadSnapshot(_ context.Context, dir string) (catalog.ScanFS, func(), error) {
	p.reads.Add(1)
	c := p.start(fsagent.ModeRead, dir)
	return c, func() { c.Close() }, nil
}

func (p *pipeAgents) WriteTree(_ context.Context, dir string) (catalog.Sink, func(), error) {
	p.writes.Add(1)
	c := p.start(fsagent.ModeWrite, dir)
	return c, func() { c.Close() }, nil
}

func TestCaptureAndRestoreThroughFileAgents(t *testing.T) {
	_, nc := nodeServer(t)
	ag := &pipeAgents{}
	r := newRig(t, rigOpts{node: &nc, agents: ag})
	j := r.jail("web1", "uuid-web1", nil)
	bk := r.backup(j).Targets[0].Backup
	if ag.reads.Load() == 0 {
		t.Fatal("the capture did not go through a read agent")
	}
	res, err := r.svc.RestoreWith(bg, api.RestoreRequest{Backup: bk.Metadata.Name, As: "web2"}, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ag.writes.Load() == 0 {
		t.Fatal("the restore did not go through a write agent")
	}
	for _, rel := range []string{"", "/etc", "/local", "/db"} {
		want := readTree(t, r.w.m.liveDir(j.Container+rel))
		got := readTree(t, r.w.m.liveDir(res.Placement.Container+rel))
		if len(want) == 0 || len(want) != len(got) {
			t.Fatalf("%s: %d entries restored, %d expected", rel, len(got), len(want))
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s: %s differs", rel, k)
			}
		}
	}
	// the second backup reads through the agent too and uploads nothing new
	second := r.backup(j).Targets[0]
	if second.Result == nil || second.Result.UploadedBytes != 0 {
		t.Fatalf("an unchanged tree uploaded %+v", second.Result)
	}
}
