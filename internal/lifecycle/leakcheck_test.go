package lifecycle

// Leak check of the lifecycle plans against the host's runtime resources.
//
// The pool is swept already by the tests of each operation: a failure at any step restores the datasets exactly. What
// a jail leaves on the host while it runs is another matter: the epair, the pf anchor, the rctl rules, the devfs that
// jail(8) mounts, the rendered configuration. They are made by the helper's hooks and by jail(8), not by the plans, and
// the plans take nothing of them away themselves: the hook of the daemon's lifecycle has "nothing to do" after a stop
// (internal/service/renderjail.go), because the helper's poststop hook runs as jail(8) removes the jail. runtimeHost
// stands in for jail(8) and the hooks, with the order and the failure behaviour measured on FreeBSD 15.1
// (temp/audit-leaks.md), over the shared fault injector, so that every call of a plan can be failed and the host looked
// at afterwards.
//
// What the helper's hooks do with a failing step is swept in internal/priv/leakinject_test.go.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/lifecycle/fault"
)

// runtimeHost is jail(8) and the hooks of one host, with the resources they make.
type runtimeHost struct {
	f  *fault.Injector
	mu sync.Mutex
	// res is what is on the host, by "<kind> <jail>": conf (the rendered jail.conf), epair, anchor, rctl, devfs.
	res map[string]bool
	up  map[string]bool
}

func newRuntimeHost(f *fault.Injector) *runtimeHost {
	return &runtimeHost{f: f, res: map[string]bool{}, up: map[string]bool{}}
}

func (r *runtimeHost) set(kind, jail string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if on {
		r.res[kind+" "+jail] = true
	} else {
		delete(r.res, kind+" "+jail)
	}
}

// PreStart renders the configuration: the files the hooks read. The daemon makes nothing else before jail -c.
func (r *runtimeHost) PreStart(_ context.Context, jail string) error {
	if err := r.f.Hit("render conf " + jail); err != nil {
		return err
	}
	r.set("conf", jail, true)
	return nil
}

// PostStop of the daemon's lifecycle is the helper's jail.heal: for a jail that does not run it takes the devfs and the
// other mounts below the root off and removes what the poststop hook removes (rctl rules, the pf anchor, the links),
// whatever a failed start, a failed stop or a death of jail(8) left. The helper refuses a jail that runs. The model runs
// on a host that works: the helper's own failures are swept in internal/priv/leakinject_test.go.
func (r *runtimeHost) PostStop(_ context.Context, jail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.up[jail] {
		return nil
	}
	for _, kind := range []string{"rctl", "anchor", "epair", "devfs"} {
		delete(r.res, kind+" "+jail)
	}
	return nil
}

// Remove takes the rendered configuration of a jail that is deleted: after the point of no return, outside the plan.
func (r *runtimeHost) Remove(_ context.Context, jail string) error {
	if err := r.f.Hit("remove conf " + jail); err != nil {
		return err
	}
	r.set("conf", jail, false)
	return nil
}

// Start is jail -c: the devfs, exec.prestart (the epair, the anchor), the jail, exec.poststart (the rctl rules).
// Measured: a failure after the jail exists removes the jail and unmounts the devfs, and does not run exec.poststop; a
// failure of exec.prestart leaves nothing of jail(8) behind.
func (r *runtimeHost) Start(_ context.Context, name string) error {
	// measured on FreeBSD 15.1: the devfs is mounted before exec.prestart runs; a command that fails makes jail(8)
	// unmount it again, a death of jail(8) does not
	if err := r.f.Hit("jail(8) mount devfs " + name); err != nil {
		return err
	}
	r.set("devfs", name, true)
	for _, step := range []struct{ op, kind string }{{"hook prestart epair", "epair"}, {"hook prestart anchor", "anchor"}} {
		if err := r.f.Hit(step.op + " " + name); err != nil {
			r.set("devfs", name, false)
			return err
		}
		r.set(step.kind, name, true)
	}
	if err := r.f.Hit("jail -c " + name); err != nil {
		r.set("devfs", name, false)
		return err
	}
	r.mu.Lock()
	r.up[name] = true
	r.mu.Unlock()
	if err := r.f.Hit("hook poststart rctl " + name); err != nil {
		r.mu.Lock()
		delete(r.up, name)
		r.mu.Unlock()
		r.set("devfs", name, false)
		return err
	}
	r.set("rctl", name, true)
	return nil
}

// Stop is jail -r: it succeeds when the jail is not running; exec.poststop runs after the removal and never fails the
// stop (every step of the hook runs, a step that fails warns); jail(8) unmounts its devfs last.
func (r *runtimeHost) Stop(_ context.Context, name string) error {
	r.mu.Lock()
	up := r.up[name]
	r.mu.Unlock()
	if !up {
		return nil
	}
	if err := r.f.Hit("jail -r " + name); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.up, name)
	r.mu.Unlock()
	for _, kind := range []string{"rctl", "anchor", "epair"} {
		if err := r.f.Hit("hook poststop " + kind + " " + name); err == nil {
			r.set(kind, name, false)
		}
	}
	if err := r.f.Hit("jail(8) unmount devfs " + name); err != nil {
		return err
	}
	r.set("devfs", name, false)
	return nil
}

func (r *runtimeHost) Running(_ context.Context, name string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.up[name], nil
}
func (r *runtimeHost) Exec(context.Context, string, []string) ([]byte, error) { return nil, nil }
func (r *runtimeHost) HostRelease(context.Context) (string, error)            { return "15.0-RELEASE", nil }

// reconcile is the reconciler's pass about a jail that does not run: it removes the epairs no running jail owns.
func (r *runtimeHost) reconcile(jail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up[jail] {
		delete(r.res, "epair "+jail)
	}
}

// left lists the runtime resources of a jail that does not run (the rendered configuration of a jail that exists is
// not one) or, with conf, of a jail that is deleted.
func (r *runtimeHost) left(jail string, conf bool) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for k := range r.res {
		kind, j, _ := strings.Cut(k, " ")
		if j != jail || (kind == "conf" && !conf) {
			continue
		}
		out = append(out, k)
	}
	if r.up[jail] {
		out = append(out, "jail "+jail)
	}
	sort.Strings(out)
	return out
}

// newLeakWorld is the world of the plan tests with the runtime host in place of the hooks and the jail runtime.
func newLeakWorld(t *testing.T) (*world, *runtimeHost) {
	t.Helper()
	w := newWorld(t)
	rt := newRuntimeHost(w.F)
	w.S.Hooks = rt
	w.S.Jails = rt
	w.S.Cfg.ReadyTimeout = time.Second
	return w, rt
}

type leakFinding struct {
	op, where string
	step      int
	left      []string
	note      string
}

func (f leakFinding) String() string {
	return fmt.Sprintf("%s: failing call %d (%s) %s %v", f.op, f.step, f.where, f.note, f.left)
}

const web = "alpha_web"

// leakOp is an operation of a jail, set up in a world, with what the host must look like after it when it works.
type leakOp struct {
	name  string
	setup func(t *testing.T) (*world, *runtimeHost)
	run   func(w *world) error
	// okLeft is what is left on the host after the operation worked (and the jail was stopped again when it started
	// it): nothing, or for a delete nothing at all.
	okLeft func(w *world, rt *runtimeHost) []string
}

func leakOps() []leakOp {
	created := func(t *testing.T) (*world, *runtimeHost) {
		w, rt := newLeakWorld(t)
		w.created("web")
		return w, rt
	}
	running := func(t *testing.T) (*world, *runtimeHost) {
		w, rt := newLeakWorld(t)
		w.running("web")
		return w, rt
	}
	return []leakOp{
		{"start", created, func(w *world) error { return w.S.StartJail(bg, web) },
			func(w *world, rt *runtimeHost) []string {
				w.F.Reset(0)
				_ = w.S.StopJail(bg, web)
				return rt.left(web, false)
			}},
		{"stop", running, func(w *world) error { return w.S.StopJail(bg, web) },
			func(w *world, rt *runtimeHost) []string { return rt.left(web, false) }},
		{"delete", running, func(w *world) error {
			r, err := w.S.DestroyJail(bg, web, true, false)
			if err == nil && len(r.Warnings) > 0 {
				return nil // after the point of no return a failure is a warning
			}
			return err
		}, func(w *world, rt *runtimeHost) []string { return rt.left(web, true) }},
	}
}

// sweepOp fails each mutating call of op in turn. After a failure it records what is left on the host before anything
// runs again (after the reconciler's pass), then repeats the operation and records whether it fails and what it leaves.
// A jail that still exists after a failed delete, or runs after a failed stop, has its resources: that is not a leak.
func sweepOp(t *testing.T, o leakOp) (n int, leftAfterFailure, cannotRepeat, leftAfterRepeat []leakFinding) {
	t.Helper()
	w, rt := o.setup(t)
	w.F.Reset(0)
	if err := o.run(w); err != nil {
		t.Fatalf("%s: baseline failed: %v", o.name, err)
	}
	n = w.F.Count()
	if left := o.okLeft(w, rt); len(left) != 0 {
		t.Fatalf("%s: the baseline leaves %v", o.name, left)
	}
	conf := o.name == "delete"
	for k := 1; k <= n; k++ {
		w, rt := o.setup(t)
		w.F.Reset(k)
		err := o.run(w)
		where := w.F.Log[k-1]
		w.F.Reset(0)
		rt.reconcile(web)
		up, _ := rt.Running(bg, web)
		gone := !up && (o.name != "delete" || err == nil) // a delete that failed has not deleted the jail
		if gone {
			if left := rt.left(web, conf); len(left) != 0 {
				leftAfterFailure = append(leftAfterFailure, leakFinding{op: o.name, step: k, where: where, left: left, note: fmt.Sprintf("left on the host after the operation (failed: %v):", err != nil)})
			}
		}
		if err == nil && o.name == "start" {
			continue
		}
		if err == nil && o.name == "delete" {
			continue // there is nothing to repeat
		}
		if err2 := o.run(w); err2 != nil {
			cannotRepeat = append(cannotRepeat, leakFinding{op: o.name, step: k, where: where, note: "does not work when repeated: " + err2.Error()})
			continue
		}
		rt.reconcile(web)
		if left := o.okLeft(w, rt); len(left) != 0 {
			leftAfterRepeat = append(leftAfterRepeat, leakFinding{op: o.name, step: k, where: where, left: left, note: "left on the host after the repetition:"})
		}
	}
	return n, leftAfterFailure, cannotRepeat, leftAfterRepeat
}

// The sweeps run in CI: every call is an in-memory fake and nothing sleeps. What must hold today is that an operation
// works when it is repeated after any failure of it (the jail is not wedged); what a failure leaves on the host until
// the jail starts again (or for ever, for a jail that is deleted) is named, and TestLeakCheckLeftovers
// (JAILOPS_LEAKCHECK=1, leakcheck_known_test.go) requires it to be gone.
func TestLeakCheckRepeatedOperations(t *testing.T) {
	for _, o := range leakOps() {
		n, left, cannot, afterRepeat := sweepOp(t, o)
		t.Logf("%s: %d mutating calls swept by an error: %d leave something on the host, %d leave it after a repetition, %d cannot be repeated", o.name, n, len(left), len(afterRepeat), len(cannot))
		for _, f := range cannot {
			t.Errorf("%s", f)
		}
		for _, f := range append(left, afterRepeat...) {
			t.Logf("LEFT UNTIL THE NEXT START %s", f)
		}
	}
}

// A daemon that dies in the middle of a start leaves a journal record; service.recoverRun rolls the start back from it
// (internal/service/recover.go). A stop is run again by the recovery.
func TestLeakCheckKilledPlans(t *testing.T) {
	w0, _ := newLeakWorld(t)
	w0.created("web")
	p0, err := w0.S.PlanStart(bg, web)
	if err != nil {
		t.Fatal(err)
	}
	for k := 1; k <= len(p0.Steps); k++ {
		w, rt := newLeakWorld(t)
		w.created("web")
		p, _ := w.S.PlanStart(bg, web)
		crash(t, w, "start/"+web, p, k)
		rp, _ := w.S.PlanStart(bg, web)
		if found, err := w.S.RecoverRun(bg, "start", web, rp); !found || err != nil {
			t.Fatalf("start killed in step %d (%s): %v %v", k, p.Steps[k-1].Name, found, err)
		}
		w.F.Reset(0)
		rt.reconcile(web)
		if err := w.S.StartJail(bg, web); err != nil {
			t.Errorf("start killed in step %d (%s): the start does not work afterwards: %v", k, p.Steps[k-1].Name, err)
		}
		if err := w.S.StopJail(bg, web); err != nil {
			t.Errorf("start killed in step %d (%s): the stop after it fails: %v", k, p.Steps[k-1].Name, err)
		}
		if left := rt.left(web, false); len(left) != 0 {
			t.Errorf("start killed in step %d (%s): left after the next start and stop: %v", k, p.Steps[k-1].Name, left)
		}
	}
}
