package daemon_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// scriptedJails answers the commands the update pipeline runs inside a jail.
type scriptedJails struct {
	mu       sync.Mutex
	cmds     []string
	pkgs     string // output of pkg upgrade -n
	failUp   bool   // pkg upgrade -y fails
	failHC   bool   // the health check fails
	upgraded bool
	env      *dtest.Env // the host-side pkg -j commands of FreeBSD jails run on its command fake
}

func (s *scriptedJails) fn(name string, o jailos.ExecOpts) (run.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := strings.Join(o.Argv, " ")
	s.cmds = append(s.cmds, name+": "+line)
	switch {
	case line == "pkg upgrade -n":
		if s.upgraded {
			return run.Result{Stdout: []byte("Your packages are up to date.\n")}, nil
		}
		return run.Result{Stdout: []byte(s.pkgs)}, nil
	case line == "pkg upgrade -y":
		if s.failUp {
			return run.Result{Stderr: []byte("pkg: repository unreachable")}, errors.New("exit status 1")
		}
		s.upgraded = true
	case line == "/bin/true" && s.failHC:
		return run.Result{Stderr: []byte("not healthy")}, errors.New("exit status 1")
	}
	return run.Result{}, nil
}

func (s *scriptedJails) ran(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	// A FreeBSD jail has no pkg of its own: the host runs `pkg -j JAIL upgrade -y`, written here as `pkg upgrade -y`.
	if s.env != nil {
		for _, c := range s.env.Run.Calls() {
			// an image build passes -o options (REPOS_DIR, PKG_CACHEDIR...): it is not a jail's pkg
			if c.Cmd.Name == "pkg" && len(c.Cmd.Args) > 2 && c.Cmd.Args[0] == "-j" && c.Cmd.Args[2] != "-o" &&
				strings.Contains("pkg "+strings.Join(c.Cmd.Args[2:], " "), sub) {
				return true
			}
		}
	}
	return false
}

const pkgDryRun = `Updating FreeBSD repository catalogue...
Checking for upgrades (2 candidates): 100%
Processing candidates (2 candidates): 100%
The following 2 package(s) will be affected (of 0 checked):

Installed packages to be UPGRADED:
	curl: 8.5.0 -> 8.6.0
	nginx: 1.24.0_1,3 -> 1.26.0,3

Number of packages to be upgraded: 2
`

func runningWeb(t *testing.T, e *dtest.Env) {
	t.Helper()
	ctx := context.Background()
	op, err := e.Admin.Jails().Create(ctx, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	so, err := e.Admin.Jails().Start(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := so.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPackageUpdatePipeline(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	sj := &scriptedJails{pkgs: pkgDryRun, env: e}
	e.SetPkgUpgrades(pkgDryRun)
	e.Jails.SetExecFn(sj.fn)
	runningWeb(t, e)
	ctx := context.Background()

	// Check lists, changes nothing and is remembered.
	cop, err := e.Admin.Updates().Check(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	reps, err := cop.Wait(ctx)
	if err != nil || len(reps) != 1 || !reps[0].Available || len(reps[0].Packages) != 2 || reps[0].Packages[0].Name != "curl" || reps[0].Packages[0].To != "8.6.0" {
		t.Fatalf("%+v %v", reps, err)
	}
	if sj.ran("pkg upgrade -y") {
		t.Fatal("a check upgraded packages")
	}
	if l, err := e.Admin.Updates().List(ctx); err != nil || len(l) != 1 || l[0].Jail != "web" {
		t.Fatalf("%+v %v", l, err)
	}

	// Apply: snapshot, upgrade, health check, history.
	aop, err := e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, Packages: true})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := aop.Wait(ctx)
	if err != nil || len(recs) != 1 || recs[0].Result != api.UpdateOK || recs[0].Kind != api.UpdateKindPackages || recs[0].Snapshot == "" || len(recs[0].Packages) != 2 {
		t.Fatalf("%+v %v", recs, err)
	}
	if !strings.Contains(recs[0].Note, "restart the jail") {
		t.Fatalf("reboot manual must say so: %q", recs[0].Note)
	}
	// The snapshot exists on the jail.
	found := false
	for s, err := range e.Admin.Jails().Snapshots("web").List(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		found = found || strings.HasPrefix(s.Metadata.Name, "update-")
	}
	if !found {
		t.Fatal("no pre-update snapshot")
	}
	h, err := e.Admin.Jails().UpdateHistory(ctx, "web")
	if err != nil || len(h) != 1 || h[0].ID != recs[0].ID {
		t.Fatalf("%+v %v", h, err)
	}
	// Nothing left: a second apply records nothing to do.
	aop, _ = e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, Packages: true})
	recs, _ = aop.Wait(ctx)
	if len(recs) != 1 || recs[0].Note != "nothing to update" {
		t.Fatalf("%+v", recs)
	}

	// A failing health check is a failed update with the way back, and no
	// data rollback on its own.
	sj.mu.Lock()
	sj.upgraded, sj.failHC = false, true
	sj.mu.Unlock()
	e.SetPkgUpgrades(pkgDryRun)
	var events []string
	evctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := e.Events(evctx, e.Admin)
	aop, _ = e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, Packages: true})
	recs, err = aop.Wait(ctx)
	if err != nil || len(recs) != 1 || recs[0].Result != api.UpdateFailed || !strings.Contains(recs[0].Error, "health check") || !strings.Contains(recs[0].Note, "--all --snapshot ") {
		t.Fatalf("%+v %v", recs, err)
	}
	assertRealCommand(t, recs[0].Note)
	deadline := time.After(3 * time.Second)
loop:
	for {
		select {
		case ev := <-ch:
			events = append(events, string(ev.Type))
			if strings.Contains(string(ev.Metadata), "update.failed") {
				break loop
			}
		case <-deadline:
			t.Fatalf("no update.failed event, saw %v", events)
		}
	}
	// A failing upgrade command fails the update too.
	sj.mu.Lock()
	sj.upgraded, sj.failHC = false, false
	sj.mu.Unlock()
	e.SetPkgUpgrades(pkgDryRun)
	e.SetPkgUpgradeErr(errors.New("exit status 1"))
	aop, _ = e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, Packages: true})
	recs, _ = aop.Wait(ctx)
	if len(recs) != 1 || recs[0].Result != api.UpdateFailed || !strings.Contains(recs[0].Error, "repository unreachable") {
		t.Fatalf("%+v", recs)
	}
	if h, _ := e.Admin.Jails().UpdateHistory(ctx, "web"); len(h) != 4 || h[0].Result != api.UpdateFailed {
		t.Fatalf("%d records, newest first: %+v", len(h), h)
	}
	// Other projects' jails are not found.
	if _, err := e.Admin.Project("nope").Jails().UpdateHistory(ctx, "web"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
	if _, err := e.Admin.Updates().Check(ctx, "ghost"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
}

func TestOSUpdateRootSwapAndAutomaticRollback(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	e.Jails.SetExecFn((&scriptedJails{}).fn)
	runningWeb(t, e)
	ctx := context.Background()
	// Build a newer generation of the image.
	bop, err := e.Admin.Images().Build(ctx, "fb", api.ImageBuild{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bop.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	cop, _ := e.Admin.Updates().Check(ctx, "web")
	reps, err := cop.Wait(ctx)
	if err != nil || len(reps) != 1 || reps[0].OS == nil || !strings.HasSuffix(reps[0].OS.To, "#g2") {
		t.Fatalf("%+v %v", reps, err)
	}
	aop, _ := e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, OS: true})
	recs, err := aop.Wait(ctx)
	if err != nil || len(recs) != 1 || recs[0].Kind != api.UpdateKindOS || recs[0].Result != api.UpdateOK {
		t.Fatalf("%+v %v", recs, err)
	}
	j, _ := e.Admin.Jails().Get(ctx, "web")
	if !strings.HasSuffix(j.Status.Generation, "g2") {
		t.Fatalf("%+v", j.Status)
	}
	// A third generation whose health check fails: the root is swapped back by the plan.
	bop, _ = e.Admin.Images().Build(ctx, "fb", api.ImageBuild{})
	_, _ = bop.Wait(ctx)
	e.Jails.SetExecFn((&scriptedJails{failHC: true}).fn)
	aop, _ = e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, OS: true})
	recs, err = aop.Wait(ctx)
	if err != nil || len(recs) != 1 || recs[0].Result != api.UpdateRolledBack || !recs[0].RootRolledBack || !strings.Contains(recs[0].Note, "application data was not touched") {
		t.Fatalf("%+v %v", recs, err)
	}
	j, _ = e.Admin.Jails().Get(ctx, "web")
	if !strings.HasSuffix(j.Status.Generation, "g2") {
		t.Fatalf("the failed update left the jail on %s", j.Status.Generation)
	}
}

func TestScheduledUpdatesAreOffByDefaultAndFollowTheMode(t *testing.T) {
	var now = struct {
		sync.Mutex
		t time.Time
	}{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { now.Lock(); defer now.Unlock(); return now.t }
	e := dtest.New(t, dtest.Options{Now: clock, Mutate: func(c *daemon.Config) { c.Updates.Tick = daemon.Duration(20 * time.Millisecond) }})
	e.Seed()
	sj := &scriptedJails{pkgs: pkgDryRun, env: e}
	e.SetPkgUpgrades(pkgDryRun)
	e.Jails.SetExecFn(sj.fn)
	runningWeb(t, e)
	ctx := context.Background()
	advance := func(d time.Duration) { now.Lock(); now.t = now.t.Add(d); now.Unlock() }

	// A jail with the default policy (manual) is never touched, however long we wait.
	advance(48 * time.Hour)
	time.Sleep(150 * time.Millisecond)
	if sj.ran("pkg update") {
		t.Fatal("a manual jail was checked")
	}
	// notify: checks and reports, applies nothing.
	op, err := e.Admin.Jails().Config(ctx, "web", map[string]string{"updates.mode": "notify", "updates.schedule": "0 3 * * *", "updates.packages": "true"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := op.Wait(ctx); err != nil || len(res.RestartRequired) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	advance(30 * time.Hour)
	waitFor(t, func() bool { l, _ := e.Admin.Updates().List(ctx); return len(l) == 1 && l[0].Available })
	if sj.ran("pkg upgrade -y") {
		t.Fatal("notify applied updates")
	}
	// managed: applies on the schedule.
	// the check the clock just triggered may still hold the jail ("busy"): ask again until the change is accepted
	var cerr error
	for i := 0; i < 500; i++ {
		if op, cerr = e.Admin.Jails().Config(ctx, "web", map[string]string{"updates.mode": "managed"}, nil, false); cerr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cerr != nil {
		t.Fatalf("switching to managed: %v", cerr)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	advance(30 * time.Hour)
	waitFor(t, func() bool { return sj.ran("pkg upgrade -y") })
	waitFor(t, func() bool {
		h, _ := e.Admin.Jails().UpdateHistory(ctx, "web")
		return len(h) > 0 && h[0].Scheduled && h[0].Result == api.UpdateOK
	})
	// Bad policies are refused.
	if _, err := e.Admin.Jails().Config(ctx, "web", map[string]string{"updates.mode": "managed", "updates.schedule": "never"}, nil, false); err == nil {
		op, _ := e.Admin.Jails().Config(ctx, "web", map[string]string{"updates.schedule": "never"}, nil, false)
		if op != nil {
			if _, err := op.Wait(ctx); err == nil {
				t.Fatal("a bad cron expression was accepted")
			}
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestProvisioningRunsOnceAndAgainOnRequest(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	sj := &scriptedJails{env: e}
	e.Jails.SetExecFn(sj.fn)
	ctx := context.Background()
	// The project's files directory holds the template.
	dir := filepath.Join(e.Cfg.StateDir, "project-files", "alpha", "templates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte("worker_processes 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Dir, "secret.txt"), []byte("host secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.Dir, "secret.txt"), filepath.Join(e.Cfg.StateDir, "project-files", "alpha", "leak")); err != nil {
		t.Fatal(err)
	}
	j := dtest.WebJail("web")
	j.Spec.Provision = &api.Provision{Packages: []string{"bash", "nginx"},
		Files:    []api.ProvisionFile{{Source: "templates/nginx.conf", Destination: "/usr/local/etc/nginx/nginx.conf", Owner: "root", Group: "wheel", Mode: "0644"}},
		Services: api.ProvisionSvc{Enable: []string{"nginx"}, Start: []string{"nginx"}}, Commands: [][]string{{"/usr/bin/touch", "/var/db/done"}}}
	j.Spec.Shell = "/usr/local/bin/bash"
	op, err := e.Admin.Jails().Create(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := e.Admin.Jails().Get(ctx, "web")
	if !got.Status.ProvisionedAt.IsZero() || got.Spec.Shell != "/usr/local/bin/bash" {
		t.Fatalf("%+v", got)
	}
	// The first start provisions.
	so, _ := e.Admin.Jails().Start(ctx, "web")
	if _, err := so.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg install -y bash nginx", "chown root:wheel /usr/local/etc/nginx/nginx.conf", "chmod 0644 /usr/local/etc/nginx/nginx.conf",
		"sysrc nginx_enable=YES", "jailops-start nginx", "/usr/bin/touch /var/db/done"}
	for _, w := range want {
		if !sj.ran(w) {
			t.Errorf("provisioning did not run %q: %v", w, sj.cmds)
		}
	}
	ord := func(s string) int {
		for i, c := range sj.cmds {
			if strings.Contains(c, s) {
				return i
			}
		}
		return -1
	}
	if !(ord("pkg install") < ord("chown") && ord("chown") < ord("sysrc") && ord("sysrc") < ord("jailops-start nginx") && ord("jailops-start nginx") < ord("/usr/bin/touch")) {
		t.Errorf("steps out of order: %v", sj.cmds)
	}
	if data, ok := e.Files.Data["/jailops/projects/alpha/jails/web/root/usr/local/etc/nginx/nginx.conf"]; !ok || string(data) != "worker_processes 1;\n" {
		t.Errorf("the template was not copied: %v", e.Files.Paths())
	}
	got, _ = e.Admin.Jails().Get(ctx, "web")
	if got.Status.ProvisionedAt.IsZero() {
		t.Fatal("provisioning was not marked complete")
	}
	// Once: a plain request is refused, again runs it.
	if _, err := e.Admin.Jails().Provision(ctx, "web", false); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("%v", err)
	}
	n := len(sj.cmds)
	pop, err := e.Admin.Jails().Provision(ctx, "web", true)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := pop.Wait(ctx); err != nil || len(res.Steps) != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(sj.cmds) <= n {
		t.Fatal("--again ran nothing")
	}
	// A symlink out of the project's files is refused.
	j2 := dtest.WebJail("web2")
	j2.Spec.Network = []api.NetworkAttach{{Network: "lan", IPv4: "auto"}}
	j2.Spec.Provision = &api.Provision{Files: []api.ProvisionFile{{Source: "leak", Destination: "/etc/leak"}}}
	op, _ = e.Admin.Jails().Create(ctx, j2)
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	so, _ = e.Admin.Jails().Start(ctx, "web2")
	if _, err := so.Wait(ctx); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a symlink out of the files directory: %v", err)
	}
	if _, ok := e.Files.Data["/jailops/projects/alpha/jails/web2/root/etc/leak"]; ok {
		t.Fatal("the host file was copied into the jail")
	}
	// A declaration that can inject is refused at creation.
	j3 := dtest.WebJail("web3")
	j3.Spec.Provision = &api.Provision{Files: []api.ProvisionFile{{Source: "/etc/passwd", Destination: "/etc/x"}}}
	if _, err := e.Admin.Jails().Create(ctx, j3); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("%v", err)
	}
}

// assertRealCommand checks that the command quoted in backticks in note is
// one the CLI accepts: the command exists and knows every flag given.
func assertRealCommand(t *testing.T, note string) {
	t.Helper()
	_, rest, ok := strings.Cut(note, "`")
	line, _, ok2 := strings.Cut(rest, "`")
	f := strings.Fields(line)
	if !ok || !ok2 || len(f) < 2 || f[0] != "jailops" {
		t.Fatalf("no jailops command in %q", note)
	}
	root := cli.NewRootCommand(&cli.Env{})
	cmd, args, err := root.Find(f[1:])
	if err == nil && cmd == root {
		err = errors.New("no such command")
	}
	if err == nil {
		err = cmd.ParseFlags(args)
	}
	if err == nil {
		err = cmd.ValidateArgs(cmd.Flags().Args())
	}
	if err != nil {
		t.Fatalf("%q is not a command the CLI accepts: %v", line, err)
	}
}

// While the host runs pkg against the root of a FreeBSD jail, no exec, shell or console session may enter the jail
// (the tree belongs to the tenant, pkg runs as root on the host); another jail is not affected and the jail is open
// again afterwards.
func TestPackageUpdateHoldsTheJailAgainstSessions(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	sj := &scriptedJails{pkgs: pkgDryRun, env: e}
	e.SetPkgUpgrades(pkgDryRun)
	ctx := context.Background()
	var during error
	e.Jails.SetExecFn(func(jail string, o jailos.ExecOpts) (run.Result, error) {
		// the library cache is refreshed right after the upgrade, while the update still holds the jail
		if o.Argv[0] == "/sbin/ldconfig" && during == nil {
			_, during = e.Admin.Jails().Exec(ctx, "web", []string{"echo", "x"}, sdk.ExecOptions{})
		}
		return sj.fn(jail, o)
	})
	runningWeb(t, e)
	aop, err := e.Admin.Updates().Apply(ctx, api.UpdateApplyRequest{Jails: []string{"web"}, Packages: true})
	if err != nil {
		t.Fatal(err)
	}
	if recs, err := aop.Wait(ctx); err != nil || len(recs) != 1 || recs[0].Result != api.UpdateOK {
		t.Fatalf("%+v %v", recs, err)
	}
	var ae *api.Error
	if !errors.As(during, &ae) || ae.Code != api.CodeBusy || !strings.Contains(ae.Message, "packages are being installed or updated") {
		t.Fatalf("exec during the update: %v", during)
	}
	if _, err := e.Admin.Jails().Exec(ctx, "web", []string{"echo", "y"}, sdk.ExecOptions{}); err != nil {
		t.Fatalf("exec after the update: %v", err)
	}
}
