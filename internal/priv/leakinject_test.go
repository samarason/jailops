package priv

// Host-resource leak injection.
//
// A jail leaves things on the host while it runs: a devfs mounted on its /dev by jail(8), an epair with routes and
// addresses, a pf anchor, rctl rules. Each of them is made by one step of a start and must be taken away by a later
// step of a stop. If a step of the start or of the stop fails, or the process that runs it is killed, the later steps
// may never run, and what was made stays on the host: a stale devfs under root/dev kept every later stop of a jail
// waiting for a minute.
//
// leakWorld emulates what jail(8), the kernel and the daemon do around the hooks of the helper, over the helper's own
// fakes, and fails (an error) or kills (a panic that ends the hook process) the n-th mutating call of a start or of a
// stop, for every n. After each injected failure it runs the recovery the product has (a stop: jail -r and the
// poststop hook, which the daemon runs again at the next stop or start) and requires that nothing of the jail is left
// on the host, and that the next start and stop work (idempotence).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// leakKilled is the panic that stands for the death of a process: nothing after it runs.
type leakKilled struct{ op string }

// leakInj counts the mutating calls of the host and fails or kills the at-th.
type leakInj struct {
	mu    sync.Mutex
	mode  string // "" (count only), "error" or "kill"
	at    int
	n     int
	log   []string
	fired string
	// paused: calls are neither counted nor failed (the recovery of the daemon runs on a host that works)
	paused bool
}

func (i *leakInj) reset(mode string, at int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mode, i.at, i.n, i.log, i.fired = mode, at, 0, nil, ""
}

// pause stops counting and injecting until resume.
func (i *leakInj) pause() {
	i.mu.Lock()
	i.paused = true
	i.mu.Unlock()
}

func (i *leakInj) resume() {
	i.mu.Lock()
	i.paused = false
	i.mu.Unlock()
}

// off stops injecting (the recovery runs on a host that works) without forgetting what was counted.
func (i *leakInj) off() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mode = ""
}

func (i *leakInj) hit(op string) error {
	i.mu.Lock()
	if i.paused {
		i.mu.Unlock()
		return nil
	}
	i.n++
	i.log = append(i.log, op)
	fire := i.mode != "" && i.n == i.at
	mode := i.mode
	if fire {
		i.fired = op
	}
	i.mu.Unlock()
	if !fire {
		return nil
	}
	if mode == "kill" {
		panic(leakKilled{op})
	}
	return fmt.Errorf("%s: injected failure", op)
}

func (i *leakInj) count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.n
}

func (i *leakInj) opLog() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]string(nil), i.log...)
}

// leakNet fails the calls of ifconfig.Client that change the host.
type leakNet struct {
	ifconfig.Client
	inj *leakInj
}

// Show and ShowInJail are what the helper's ownership check reads through (ifconfig.Reader): the fake has them.
func (n leakNet) Show(ctx context.Context, name string) (ifconfig.Iface, error) {
	return n.Client.(ifconfig.Reader).Show(ctx, name)
}
func (n leakNet) ShowInJail(ctx context.Context, jail, name string) (ifconfig.Iface, error) {
	return n.Client.(ifconfig.Reader).ShowInJail(ctx, jail, name)
}

func (n leakNet) EpairCreate(ctx context.Context, name string) (string, string, error) {
	if err := n.inj.hit("epair create " + name); err != nil {
		return "", "", err
	}
	return n.Client.EpairCreate(ctx, name)
}
func (n leakNet) EpairDestroy(ctx context.Context, iface string) error {
	if err := n.inj.hit("epair destroy " + iface); err != nil {
		return err
	}
	return n.Client.EpairDestroy(ctx, iface)
}
func (n leakNet) MoveToJail(ctx context.Context, iface, jail string) error {
	if err := n.inj.hit("move " + iface + " into " + jail); err != nil {
		return err
	}
	return n.Client.MoveToJail(ctx, iface, jail)
}
func (n leakNet) MoveFromJail(ctx context.Context, iface, jail string) error {
	if err := n.inj.hit("move " + iface + " out of " + jail); err != nil {
		return err
	}
	return n.Client.MoveFromJail(ctx, iface, jail)
}
func (n leakNet) SetLink(ctx context.Context, iface string, up bool) error {
	if err := n.inj.hit(fmt.Sprintf("link %s up=%v", iface, up)); err != nil {
		return err
	}
	return n.Client.SetLink(ctx, iface, up)
}
func (n leakNet) SetDescription(ctx context.Context, iface, desc string) error {
	if err := n.inj.hit("description " + iface); err != nil {
		return err
	}
	return n.Client.SetDescription(ctx, iface, desc)
}
func (n leakNet) AddrAdd(ctx context.Context, iface string, p netip.Prefix) error {
	if err := n.inj.hit("addr add " + iface + " " + p.String()); err != nil {
		return err
	}
	return n.Client.AddrAdd(ctx, iface, p)
}
func (n leakNet) AddrRemove(ctx context.Context, iface string, p netip.Prefix) error {
	if err := n.inj.hit("addr remove " + iface + " " + p.String()); err != nil {
		return err
	}
	return n.Client.AddrRemove(ctx, iface, p)
}
func (n leakNet) RouteAdd(ctx context.Context, r ifconfig.Route) error {
	if err := n.inj.hit(fmt.Sprintf("route add %v", r)); err != nil {
		return err
	}
	return n.Client.RouteAdd(ctx, r)
}
func (n leakNet) RouteDelete(ctx context.Context, r ifconfig.Route) error {
	if err := n.inj.hit(fmt.Sprintf("route delete %v", r)); err != nil {
		return err
	}
	return n.Client.RouteDelete(ctx, r)
}

// leakPF fails the calls of pfctl.Client that change pf.
type leakPF struct {
	pfctl.Client
	inj *leakInj
}

func (p leakPF) Load(ctx context.Context, anchor, rs string) error {
	if err := p.inj.hit("pf load " + anchor); err != nil {
		return err
	}
	return p.Client.Load(ctx, anchor, rs)
}
func (p leakPF) Flush(ctx context.Context, anchor string) error {
	if err := p.inj.hit("pf flush " + anchor); err != nil {
		return err
	}
	return p.Client.Flush(ctx, anchor)
}
func (p leakPF) KillLabel(ctx context.Context, label string) error {
	if err := p.inj.hit("pf kill " + label); err != nil {
		return err
	}
	return p.Client.KillLabel(ctx, label)
}
func (p leakPF) TableAdd(ctx context.Context, anchor, table string, addrs ...string) error {
	if err := p.inj.hit("pf table add " + anchor + " " + table); err != nil {
		return err
	}
	return p.Client.TableAdd(ctx, anchor, table, addrs...)
}
func (p leakPF) TableDelete(ctx context.Context, anchor, table string, addrs ...string) error {
	if err := p.inj.hit("pf table delete " + anchor + " " + table); err != nil {
		return err
	}
	return p.Client.TableDelete(ctx, anchor, table, addrs...)
}

// leakRunner is the host's command line: a mount table and rctl rules that remember, and the rest of the commands
// answered by the hook test fakes. A command that changes the host is counted, and can fail.
type leakRunner struct {
	inner run.Runner
	inj   *leakInj
	w     *leakWorld
}

func (r *leakRunner) fail(c run.Cmd) (run.Result, error) {
	return run.Result{ExitCode: 1, Stderr: []byte("injected failure")}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1, Stderr: "injected failure"}
}

func (r *leakRunner) Run(ctx context.Context, c run.Cmd) (run.Result, error) {
	switch c.Name {
	case "mount":
		if len(c.Args) == 1 && c.Args[0] == "-p" {
			return run.Result{Stdout: []byte(r.w.mountTable())}, nil
		}
		if r.inj.hit("mount "+strings.Join(c.Args, " ")) != nil {
			return r.fail(c)
		}
		return run.Result{}, nil
	case "umount":
		mp := c.Args[len(c.Args)-1]
		if r.inj.hit("umount "+mp) != nil {
			return r.fail(c)
		}
		if !r.w.unmountOne(mp) {
			return run.Result{ExitCode: 1, Stderr: []byte("not a mount point")}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1, Stderr: "umount: " + mp + ": not a mount point"}
		}
		return run.Result{}, nil
	case "rctl":
		if r.inj.hit("rctl "+strings.Join(c.Args, " ")) != nil {
			return r.fail(c)
		}
		r.w.rctlApply(c.Args)
		return run.Result{}, nil
	case "ifconfig", "/sbin/ifconfig", "route", "/sbin/route":
		if r.inj.hit(c.Name+" "+strings.Join(c.Args, " ")) != nil {
			return r.fail(c)
		}
	case "devfs", "/sbin/devfs":
		if len(c.Args) > 3 && (c.Args[3] == "add" || c.Args[3] == "delset") {
			if r.inj.hit("devfs "+strings.Join(c.Args, " ")) != nil {
				return r.fail(c)
			}
		}
	}
	return r.inner.Run(ctx, c)
}

// leakWorld is one jail on one host, with the pieces jail(8) and the kernel own emulated around the hook code.
type leakWorld struct {
	t     *testing.T
	h     *hookEnv
	l     *Local
	inj   *leakInj
	jn    JailName
	root  string
	mu    sync.Mutex
	mnts  []string          // "device mountpoint type": the mount table, a stacked mount appears twice
	rctl  map[string]string // rule -> "", the rctl rules in the kernel
	up    bool              // the jail exists in the kernel
	steps bool              // jail(8) runs poststop for a start that failed after the jail was made (see failedStartRunsPostStop)
}

// failedStartRunsPostStop is what jail(8) does when a command after the creation of the jail fails: it removes the
// jail again; whether exec.poststop runs then is not settled here, so a world is built for both answers.
func newLeakWorld(t *testing.T, failedStartRunsPostStop bool) *leakWorld {
	t.Helper()
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12", "tun")
	inj := &leakInj{}
	w := &leakWorld{t: t, h: h, inj: inj, rctl: map[string]string{}, steps: failedStartRunsPostStop}
	jn, err := ParseJailName("alpha_web")
	if err != nil {
		t.Fatal(err)
	}
	w.jn = jn
	w.root = filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	// a jail with limits, so that its rctl rules exist
	mp := filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web")
	spec := api.JailSpec{Image: "freebsd-15-0@stable", OS: api.OSFreeBSD, Resources: api.Resources{Memory: "256M", PIDs: 100},
		Network: []api.NetworkAttach{{Network: "lan", IPv4: "10.20.0.12", IPv6: "fd00:20::12"}},
		Devfs:   []api.DevfsDevice{{Name: "tun", Device: "tun"}}}
	rec, _ := json.Marshal(map[string]any{"version": 1, "metadata": api.ObjectMeta{Name: "web", Project: "alpha", UUID: hookUUID}, "spec": spec})
	if err := os.WriteFile(filepath.Join(mp, "spec.json"), rec, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &leakRunner{inner: h.runner, inj: inj, w: w}
	l, err := NewLocal(h.cfg, Deps{ZFS: h.zfs, Jails: h.jails, PF: leakPF{h.pf, inj}, Net: leakNet{h.net, inj}, Runner: runner,
		Jexec: h.jexec, NDP: newFakeNDP(h.base)}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	w.l = l
	return w
}

func (w *leakWorld) mountTable() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, m := range w.mnts {
		out = append(out, m+" rw 0 0")
	}
	return strings.Join(out, "\n") + "\n"
}

// unmountOne takes one layer off a mount point, the way umount(8) does.
func (w *leakWorld) unmountOne(mp string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.mnts) - 1; i >= 0; i-- {
		if f := strings.Fields(w.mnts[i]); f[1] == mp {
			w.mnts = append(w.mnts[:i], w.mnts[i+1:]...)
			return true
		}
	}
	return false
}

func (w *leakWorld) rctlApply(args []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case len(args) == 2 && args[0] == "-a":
		w.rctl[args[1]] = ""
	case len(args) == 2 && args[0] == "-r":
		for r := range w.rctl {
			if strings.HasPrefix(r, args[1]+":") || r == args[1] {
				delete(w.rctl, r)
			}
		}
	}
}

// hook runs one hook of the helper as jail(8) runs it: a process that can die. A death is a non-zero exit.
func (w *leakWorld) hook(phase string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if k, ok := r.(leakKilled); ok {
				// the runner kills the process group of jail(8): the hook and jail(8) die together
				err = j8Died{"hook " + phase + " at " + k.op}
				return
			}
			panic(r)
		}
	}()
	return w.l.RunHook(context.Background(), phase, w.jn.Internal())
}

// j8Died is the error of a step of jail(8) that died: jail(8) cleans up after a step that failed, not after a death.
type j8Died struct{ op string }

func (e j8Died) Error() string { return "jail(8) killed at " + e.op }

// cleanup is what jail(8) does when one of its own steps fails: it removes the jail again and unmounts its devfs. The
// helper's hooks are not run again (measured on FreeBSD 15.1, see temp/audit-leaks.md).
func (w *leakWorld) jail8Cleanup() {
	ctx := context.Background()
	if w.up {
		_ = w.h.jails.Remove(ctx, "/etc/jails/"+w.jn.Internal()+".conf", w.jn.Internal())
		w.up = false
		for _, i := range w.vnetIfaces() {
			_ = w.h.net.MoveFromJail(ctx, i, w.jn.Internal())
		}
	}
	w.unmountOne(w.root + "/dev")
}

// j8 is a step of jail(8) itself or of the kernel: counted, and it can be killed (the process of jail(8) dies).
func (w *leakWorld) j8(op string, do func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if k, ok := r.(leakKilled); ok {
				err = j8Died{k.op}
				return
			}
			panic(r)
		}
	}()
	if err := w.inj.hit("jail(8) " + op); err != nil {
		return err
	}
	do()
	return nil
}

func (w *leakWorld) devfsMount() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mnts = append(w.mnts, "devfs "+w.root+"/dev devfs")
}

// devfsCount is how many devfs are mounted on the /dev of the jail: a running jail has exactly one.
func (w *leakWorld) devfsCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, m := range w.mnts {
		if f := strings.Fields(m); f[1] == w.root+"/dev" && f[2] == "devfs" {
			n++
		}
	}
	return n
}

// jailEnd is the name of the end of the epair that jail(8) moves into the vnet (vnet.interface).
func (w *leakWorld) jailEnd() string { return w.h.jail }

// heal is the recovery of the daemon for a jail that does not run: the helper's jail.heal (the mounts below the root, and
// what the poststop hook removes). The daemon runs it as the heal step before jail -c, as the teardown step of a stop and
// of a delete, when it starts and in its loop; the helper refuses a jail that runs.
func (w *leakWorld) heal() {
	w.inj.pause()
	defer w.inj.resume()
	if w.up {
		return
	}
	_, _ = w.l.HealJail(context.Background(), w.jn.Internal())
}

// start is `jail -c`: exec.prestart, the jail and its devfs, the vnet interface, exec.poststart. A failure after the
// jail was made removes it again.
func (w *leakWorld) start() error {
	w.heal() // the heal step of the start plan runs before jail -c
	failed := func(err error) error {
		var died j8Died
		if !errors.As(err, &died) {
			w.jail8Cleanup() // a command failed: jail(8) removes the jail and unmounts the devfs
		}
		return err // a death cleans nothing
	}
	// measured on FreeBSD 15.1: jail(8) mounts the devfs first, then runs exec.prestart, then makes the jail, then
	// runs exec.poststart; a failure after the jail exists does NOT run exec.poststop
	if err := w.j8("mount devfs", w.devfsMount); err != nil {
		return failed(err)
	}
	if err := w.hook(PhasePreStart); err != nil {
		return failed(err)
	}
	if err := w.j8("create the jail", func() {
		_ = w.h.jails.Create(context.Background(), "/etc/jails/"+w.jn.Internal()+".conf", w.jn.Internal())
		w.up = true
	}); err != nil {
		return failed(err)
	}
	if err := w.j8("move the jail end into the vnet", func() {
		_ = w.h.net.MoveToJail(context.Background(), w.jailEnd(), w.jn.Internal())
	}); err != nil {
		return failed(err)
	}
	if err := w.hook(PhasePostStart); err != nil {
		return failed(err)
	}
	return nil
}

// remove is `jail -r`: exec.prestop, the removal of the jail, exec.poststop, and then the unmounts of the mounts jail(8)
// made. Measured on FreeBSD 15.1: a failing exec.poststop does not stop the unmounts; a death of jail(8) (the helper
// kills it when its deadline passes) after the removal does, and leaves the devfs mounted.
func (w *leakWorld) remove(runPostStop bool) (err error) {
	if !w.up {
		return errors.New("jail not found")
	}
	if err := w.j8("remove the jail", func() {
		_ = w.h.jails.Remove(context.Background(), "/etc/jails/"+w.jn.Internal()+".conf", w.jn.Internal())
		w.up = false
		// the kernel gives the interfaces of the vnet back to the host
		for _, i := range w.vnetIfaces() {
			_ = w.h.net.MoveFromJail(context.Background(), i, w.jn.Internal())
		}
	}); err != nil {
		return err
	}
	var hookErr error
	if runPostStop {
		hookErr = w.hook(PhasePostStop)
		var died j8Died
		if errors.As(hookErr, &died) {
			return hookErr // jail(8) died with its hook: the unmounts never ran
		}
	}
	if err := w.j8("unmount devfs", func() { w.unmountOne(w.root + "/dev") }); err != nil {
		return err
	}
	return hookErr
}

func (w *leakWorld) vnetIfaces() []string {
	var out []string
	if i, err := w.h.net.ShowInJail(context.Background(), w.jn.Internal(), w.jailEnd()); err == nil && i.Name != "" {
		out = append(out, i.Name)
	}
	return out
}

// reconcile is what the daemon does about a jail that does not run without starting it again: the reconciler removes
// the epairs that no running jail owns (reconcile.orphanPass). Nothing of the daemon runs the poststop hook of the
// helper: it only runs as jail(8) removes a jail (internal/service/renderjail.go: the hook of the daemon's lifecycle
// has "nothing to do").
func (w *leakWorld) reconcile() {
	w.inj.off()
	if w.up {
		return
	}
	w.heal() // the daemon's heal of a jail that does not run (daemon start, its loop, the teardown step of a stop)
	for _, i := range w.leaks() {
		if name, ok := strings.CutPrefix(i, "interface "); ok {
			_ = w.h.net.EpairDestroy(context.Background(), name)
		}
	}
}

// leaks lists what of the jail is on the host.
func (w *leakWorld) leaks() []string {
	ctx := context.Background()
	var out []string
	if list, err := w.h.net.List(ctx); err == nil {
		for _, i := range list {
			if i.Name == w.h.host || i.Name == w.h.jail {
				out = append(out, "interface "+i.Name)
			}
		}
	}
	if rules, err := w.h.pf.Read(ctx, JailAnchor(w.jn)); err == nil && strings.TrimSpace(rules) != "" {
		out = append(out, "pf anchor "+JailAnchor(w.jn))
	}
	w.mu.Lock()
	for _, m := range w.mnts {
		if f := strings.Fields(m); strings.HasPrefix(f[1], w.root+"/") {
			out = append(out, "mount "+f[2]+" "+f[1])
		}
	}
	for r := range w.rctl {
		out = append(out, "rctl "+r)
	}
	w.mu.Unlock()
	if w.up {
		out = append(out, "jail "+w.jn.Internal())
	}
	sort.Strings(out)
	return out
}

// leakCase is one injected failure and what it left.
type leakCase struct {
	scenario string // what ran: "start" or "stop"
	mode     string // "error" or "kill"
	step     int
	op       string // the call that failed
	left     []string
	retry    string // what went wrong when the operation was repeated, "" when it worked
}

func (c leakCase) String() string {
	return fmt.Sprintf("%s %s at step %d (%s): left %v retry %q", c.scenario, c.mode, c.step, c.op, c.left, c.retry)
}

// sweepLeaks injects every failure in every start and every stop and returns the cases that left something behind
// or whose repetition failed.
func sweepLeaks(t *testing.T, failedStartRunsPostStop bool) (cases []leakCase, steps map[string]int) {
	t.Helper()
	steps = map[string]int{}
	// the hooks tell the operator about warnings on stderr: not here
	if devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		saved := os.Stderr
		os.Stderr = devnull
		defer func() { os.Stderr = saved; devnull.Close() }()
	}
	// count the mutating calls of a start and of a stop
	w := newLeakWorld(t, failedStartRunsPostStop)
	w.inj.reset("", 0)
	if err := w.start(); err != nil {
		t.Fatalf("baseline start: %v", err)
	}
	nStart := w.inj.count()
	if l := w.leaks(); len(l) == 0 {
		t.Fatal("a running jail has no host resources: the model is empty")
	}
	if err := w.remove(true); err != nil {
		t.Fatalf("baseline stop: %v", err)
	}
	nTotal := w.inj.count()
	if l := w.leaks(); len(l) != 0 {
		t.Fatalf("baseline stop left %v", l)
	}
	steps["start"], steps["stop"] = nStart, nTotal-nStart

	run := func(scenario, mode string, step int, prep func(w *leakWorld), op func(w *leakWorld) error) {
		w := newLeakWorld(t, failedStartRunsPostStop)
		w.inj.reset("", 0)
		prep(w)
		w.inj.reset(mode, step)
		_ = op(w)
		fired := w.inj.fired
		if fired == "" {
			return // the failure point was past the end of this operation
		}
		c := leakCase{scenario: scenario, mode: mode, step: step, op: fired}
		if w.up {
			return // the jail runs on with what it made: the daemon sees a running jail, and the stop is its way out
		}
		if len(w.leaks()) != 0 {
			steps["leaves something before the recovery"]++
		}
		// the daemon runs the stop again
		w.reconcile()
		c.left = w.leaks()
		// and the next start and stop work (also on a host that was not recovered: a second world)
		w2 := newLeakWorld(t, failedStartRunsPostStop)
		w2.inj.reset("", 0)
		prep(w2)
		w2.inj.reset(mode, step)
		_ = op(w2)
		w2.inj.off()
		if err := w2.start(); err != nil && !w2.up {
			c.retry = "start after the failure without a stop: " + err.Error()
		} else if err := w2.remove(true); err != nil {
			c.retry = "stop after that start: " + err.Error()
		} else if l := w2.leaks(); len(l) != 0 {
			c.retry = fmt.Sprintf("left after the repeated start and stop: %v", l)
		}
		if len(c.left) != 0 {
			steps["left after the reconciler"]++
		}
		if c.retry != "" {
			steps["broken retry"]++
		}
		if len(c.left) != 0 || c.retry != "" {
			cases = append(cases, c)
		}
	}
	for _, mode := range []string{"error", "kill"} {
		for k := 1; k <= nStart; k++ {
			run("start", mode, k, func(*leakWorld) {}, func(w *leakWorld) error { return w.start() })
		}
		for k := 1; k <= nTotal-nStart; k++ {
			run("stop", mode, k, func(w *leakWorld) {
				if err := w.start(); err != nil {
					t.Fatalf("start before the stop: %v", err)
				}
			}, func(w *leakWorld) error { return w.remove(true) })
		}
	}
	return cases, steps
}

// leftKinds names the kinds of resource in a list of leftovers.
func leftKinds(left []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range left {
		k, _, _ := strings.Cut(l, " ")
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// The sweeps run in CI: nothing sleeps, every call is an in-memory fake. What must hold today is the repetition: after
// any failure or death of the start or of the stop, the next start works and the stop after it leaves nothing (the
// prestart hook takes away what an earlier run left). What a failure leaves until that next start is named, and
// TestLeakInjectionLeftovers (JAILOPS_LEAKCHECK=1) fails for it until it is fixed.
func TestLeakInjectionHostResources(t *testing.T) {
	cases, steps := sweepLeaks(t, false)
	t.Logf("%d mutating calls in a start, %d in a stop, each failed by an error and by a death: %d injected failures leave something on the host before anything runs again, %d leave something after the reconciler's pass, %d break the next start or stop",
		steps["start"], steps["stop"], steps["leaves something before the recovery"], steps["left after the reconciler"], steps["broken retry"])
	if steps["leaves something before the recovery"] == 0 {
		t.Fatal("no injected failure leaves anything behind: the model cannot see a leak")
	}
	for _, c := range cases {
		if c.retry != "" {
			t.Errorf("%s", c)
		}
	}
	for _, c := range cases {
		if len(c.left) != 0 {
			t.Logf("LEFT UNTIL THE NEXT START %s", c)
		}
	}
}

// jail(8) mounts the devfs of a jail before it runs exec.prestart (measured on FreeBSD 15.1): a prestart hook that takes
// every mount below the root off takes that one too, and the jail runs with an empty /dev. A started jail has exactly
// one devfs on its /dev, also after a start that was killed and left one (a second one is stacked by jail(8), the
// stale one must go and the fresh one must stay).
func TestAStartedJailKeepsExactlyOneDevfs(t *testing.T) {
	w := newLeakWorld(t, false)
	w.inj.reset("", 0)
	if err := w.start(); err != nil {
		t.Fatal(err)
	}
	if n := w.devfsCount(); n != 1 {
		t.Errorf("a started jail has %d devfs mounts on its /dev, want exactly one", n)
	}
	if err := w.remove(true); err != nil {
		t.Fatal(err)
	}

	// a start killed in exec.prestart (the devfs is mounted, nothing unmounts it), then the next start
	w = newLeakWorld(t, false)
	w.inj.reset("kill", 3) // the first mutating calls of a start are the prestart hook's
	_ = w.start()
	if w.devfsCount() != 1 {
		t.Fatalf("setup: the killed start left %d devfs mounts, want one stale one", w.devfsCount())
	}
	w.inj.off()
	if err := w.start(); err != nil {
		t.Fatal(err)
	}
	if n := w.devfsCount(); n != 1 {
		t.Errorf("a start after a start that died has %d devfs mounts on its /dev, want exactly one (the stale one goes, the fresh one stays)", n)
	}
}
