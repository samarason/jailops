package reconcile_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// dnRunner answers `dnctl pipe list` with the pipes it has and records every other dnctl call, applying it.
type dnRunner struct {
	have  map[int]bool
	calls []string
	fail  bool
	log   *orderLog
}

func (d *dnRunner) Run(_ context.Context, c run.Cmd) (run.Result, error) {
	if c.Name != "dnctl" {
		return run.Result{}, nil
	}
	if d.fail {
		return run.Result{}, errors.New("dnctl: Protocol not available")
	}
	a := strings.Join(c.Args, " ")
	if a == "pipe list" {
		var b strings.Builder
		for n := range d.have {
			b.WriteString("0" + strconv.Itoa(n) + ":  10.000 Mbit/s    0 ms burst 0\n")
			b.WriteString("q1" + strconv.Itoa(n) + "  50 sl. 0 flows (1 buckets) sched 1 weight 0 lmax 0 pri 0 droptail\n")
		}
		return run.Result{Stdout: []byte(b.String())}, nil
	}
	d.calls = append(d.calls, a)
	if d.log != nil {
		d.log.lines = append(d.log.lines, "dnctl "+a)
	}
	switch {
	case strings.HasPrefix(a, "pipe delete "):
		delete(d.have, atoi(strings.TrimPrefix(a, "pipe delete ")))
	case strings.HasPrefix(a, "pipe "):
		d.have[atoi(strings.Fields(a)[1])] = true
	}
	return run.Result{}, nil
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

type pipeSource struct{ des reconcile.Desired }

func (p *pipeSource) Desired(context.Context) (reconcile.Desired, error) { return p.des, nil }

// The pipes of the bandwidth limits are configured, left alone while they are right, changed when a limit changes,
// and deleted when nobody wants them; a pipe outside JailOps's range is never touched.
func TestPipePass(t *testing.T) {
	dn := &dnRunner{have: map[int]bool{40010: true, 100: true}}
	src := &pipeSource{des: reconcile.Desired{Pipes: []reconcile.PipeDesired{{Number: 40000, Rate: 10000000}, {Number: 40001, Rate: 0}}}}
	r := reconcile.New(reconcile.Config{}, reconcile.Env{Source: src, Net: ifconfig.NewFake(ifconfig.Options{}), PF: pfctl.NewFake(),
		Jails: jailos.NewFake(), Run: dn, Clock: &fakeClock{}})
	t.Cleanup(r.Close)
	rep := r.Pass(bg)
	want := []string{"pipe 40000 config bw 10000000bit/s", "pipe 40001 config bw 0", "pipe delete 40010"}
	if !slices.Equal(dn.calls, want) {
		t.Fatalf("calls %q, want %q (failures %v)", dn.calls, want, rep.Failures)
	}
	if !dn.have[100] {
		t.Fatal("a pipe outside the range was deleted")
	}
	// nothing changed: nothing is done
	dn.calls = nil
	r.Pass(bg)
	if len(dn.calls) != 0 {
		t.Fatalf("a pass without a change ran %q", dn.calls)
	}
	// a limit changes: that pipe is set again, in place
	src.des.Pipes[0].Rate = 20000000
	r.Pass(bg)
	if !slices.Equal(dn.calls, []string{"pipe 40000 config bw 20000000bit/s"}) {
		t.Fatalf("calls %q", dn.calls)
	}
	// a pipe that vanished (the host rebooted) is made again
	dn.calls = nil
	delete(dn.have, 40001)
	r.Pass(bg)
	if !slices.Equal(dn.calls, []string{"pipe 40001 config bw 0"}) {
		t.Fatalf("calls %q", dn.calls)
	}
	// nobody wants the pipes any more: they go away
	dn.calls = nil
	src.des.Pipes = nil
	r.Pass(bg)
	if !slices.Equal(dn.calls, []string{"pipe delete 40000", "pipe delete 40001"}) && !slices.Equal(dn.calls, []string{"pipe delete 40001", "pipe delete 40000"}) {
		t.Fatalf("calls %q", dn.calls)
	}
}

// Without dummynet the pipes cannot be read: that is a failure only when a jail wants a limit.
func TestPipePassWithoutDummynet(t *testing.T) {
	dn := &dnRunner{have: map[int]bool{}, fail: true}
	src := &pipeSource{}
	r := reconcile.New(reconcile.Config{}, reconcile.Env{Source: src, Net: ifconfig.NewFake(ifconfig.Options{}), PF: pfctl.NewFake(),
		Jails: jailos.NewFake(), Run: dn, Clock: &fakeClock{}})
	t.Cleanup(r.Close)
	if rep := r.Pass(bg); rep.Failures["dummynet"] != "" {
		t.Fatalf("a failure without any limit: %v", rep.Failures)
	}
	src.des.Pipes = []reconcile.PipeDesired{{Number: 40000, Rate: 1000000}}
	if rep := r.Pass(bg); !strings.Contains(rep.Failures["dummynet"], "not enforced") {
		t.Fatalf("no failure for a limit: %v", rep.Failures)
	}
}

// A pipe that no jail wants goes away only after the anchors are loaded: an anchor that still names a pipe that is gone
// drops the traffic it sends into it.
func TestPipeIsDeletedAfterTheAnchorsAreLoaded(t *testing.T) {
	log := &orderLog{}
	dn := &dnRunner{have: map[int]bool{40010: true}, log: log}
	pf := &loggingPF{Fake: pfctl.NewFake(), log: log}
	w := &world{t: t, Net: ifconfig.NewFake(ifconfig.Options{}), PF: pf.Fake, Jails: jailos.NewFake(),
		locks: map[string]bool{}, fail: map[string]error{}, netSt: map[string]api.NetworkStatus{},
		jailSt: map[string][]api.Condition{}, drift: map[string][]string{},
		clock: &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
	w.R = reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: pf, Jails: w.Jails, Run: dn, Sysctl: sysctl, Clock: w.clock})
	t.Cleanup(w.R.Close)
	j := jailDesired("web_nginx")
	j.Project = "web"
	j.AnchorName = render.JailAnchor("web_nginx")
	j.ParentAnchors = map[string]string{render.ProjectAnchor("web"): render.ProjectAnchorRules()}
	w.des = reconcile.Desired{Networks: []reconcile.NetworkDesired{lan()}, Jails: []reconcile.JailDesired{j},
		Pipes: []reconcile.PipeDesired{{Number: 40011, Rate: 1000000}}}
	w.R.Pass(bg)
	_ = w.Jails.Create(bg, "/etc/jailops/jails/web_nginx/jail.conf", "web_nginx")
	h := j.Epairs[0]
	_, _, _ = w.Net.EpairCreate(bg, h[:len(h)-1])
	_ = w.Net.SetDescription(bg, h, "jailops:"+jailID)
	log.lines = nil
	dn.have = map[int]bool{40010: true} // the pipes as they were before the first pass: a stale one, and none of the wanted
	w.R.Pass(bg)
	want := []string{"dnctl pipe 40011 config bw 1000000bit/s", "pf load jailops/web/nginx", "dnctl pipe delete 40010"}
	var seen []string
	for _, l := range log.lines {
		if slices.Contains(want, l) {
			seen = append(seen, l)
		}
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("order %q, want %q (all: %q)", seen, want, log.lines)
	}
}

type orderLog struct{ lines []string }

type loggingPF struct {
	*pfctl.Fake
	log *orderLog
}

func (p *loggingPF) Load(ctx context.Context, anchor, ruleset string) error {
	p.log.lines = append(p.log.lines, "pf load "+anchor)
	return p.Fake.Load(ctx, anchor, ruleset)
}

// A pipe that a loaded anchor still names is not deleted, though no jail wants it (a reload that failed keeps the old
// anchor, which sends its traffic into that pipe); one no anchor names is.
func TestPipeCleanupKeepsAPipeALoadedAnchorNames(t *testing.T) {
	dn := &dnRunner{have: map[int]bool{40020: true, 40021: true, 40030: true}}
	pf := pfctl.NewFake()
	_ = pf.Load(bg, "jailops/alpha/web", "match in on jo0a all dnpipe(40020, 40021)\npass in quick on jo0a all\n")
	jd := jailDesired("web")
	jd.AnchorName = "jailops/alpha/web"
	src := &pipeSource{des: reconcile.Desired{Jails: []reconcile.JailDesired{jd}}}
	r := reconcile.New(reconcile.Config{}, reconcile.Env{Source: src, Net: ifconfig.NewFake(ifconfig.Options{}), PF: pf,
		Jails: jailos.NewFake(), Run: dn, Clock: &fakeClock{}})
	t.Cleanup(r.Close)
	r.Pass(bg)
	if !dn.have[40020] || !dn.have[40021] {
		t.Fatalf("a pipe a loaded anchor names was deleted: %v", dn.have)
	}
	if dn.have[40030] {
		t.Fatalf("a pipe nobody names was kept: %v", dn.have)
	}
}
