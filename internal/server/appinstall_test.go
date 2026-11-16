package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// appWeb is a definition that exercises every step of an installation.
const appWeb = `version: 1
name: web
title: Web
summary: A web application.
category: web
image: {os: freebsd, release_min: "15.1"}
packages:
  - {name: web-server, version: "2.4"}
  - {name: web-tool, repo: jailops}
services:
  - name: web
    rc: {web_flags: "--listen 8080 \"quoted\""}
  - {name: web-worker, start: false}
ports:
  - {name: http, port: 8080, expose: true, description: The site.}
  - {name: admin, port: 9090}
data:
  - {path: /var/db/web, description: The content.}
  - {path: /usr/local/www/web}
config:
  - {path: /usr/local/etc/web.conf, restart: web}
logs:
  - {name: server, path: /var/log/web.log}
setup:
  - [/usr/sbin/chown, "www:www", /var/db/web]
  - [/usr/local/bin/web-init, --once]
sysvipc: true
health:
  http: {port: 8080, path: /ready, status: 204}
  wait_seconds: 2
resources: {memory: 512M, disk: 4G, cpu: "1.5"}
notes: |
  Put the site under /usr/local/www/web.
`

const appExecCheck = `version: 1
name: tool
title: Tool
summary: A tool checked by a command.
category: tools
image: {os: freebsd, release_min: "15.1"}
packages:
  - {name: tool}
health:
  exec: [/usr/local/bin/tool, --ping]
  wait_seconds: 2
`

// appEnv is a daemon with a catalog directory and an image of release 15.1
// (the seeded "fb" is 15.0, which the definitions refuse).
func appEnv(t *testing.T, defs map[string]string) (*dtest.Env, context.Context) {
	t.Helper()
	return appEnvWith(t, defs, dtest.Options{})
}

func appEnvWith(t *testing.T, defs map[string]string, o dtest.Options) (*dtest.Env, context.Context) {
	t.Helper()
	dir := t.TempDir()
	for name, def := range defs {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(def), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	o.Mutate = func(c *daemon.Config) { c.Apps.CatalogDir = dir }
	e := dtest.New(t, o)
	e.Seed()
	c := ctxT(t)
	if _, err := e.Admin.Images().Create(c, api.Image{Metadata: api.ObjectMeta{Name: "fb151"}, Spec: api.ImageSpec{
		OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}}); err != nil {
		t.Fatal(err)
	}
	op, err := e.Admin.Images().Build(c, "fb151", api.ImageBuild{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	return e, c
}

// httpAnswer is a dial function whose connections answer every request with
// one status, so the http health check runs against the daemon's own client.
func httpAnswer(status int, want *[]string) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, address string) (net.Conn, error) {
		if want != nil {
			*want = append(*want, network+" "+address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			if want != nil {
				*want = append(*want, req.Method+" "+req.URL.Path)
			}
			fmt.Fprintf(server, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
		}()
		return client, nil
	}
}

func execArgvs(e *dtest.Env, jail string) []string {
	var out []string
	for _, c := range e.Jails.Calls() {
		if c.Op == "exec" && c.Name == jail {
			out = append(out, strings.Join(c.Argv, " "))
		}
	}
	return out
}

// The whole flow: a thin jail with the data paths as volumes and the labels,
// started, the packages installed from the host, rc.conf written, the setup
// commands and the services run in the jail, the health check, the snapshot,
// and a result that says how to reach the app.
func TestAppInstall(t *testing.T) {
	e, c := appEnv(t, map[string]string{"web": appWeb})
	var seen []string
	e.SetDial(httpAnswer(204, &seen))
	evctx, cancel := context.WithCancel(c)
	defer cancel()
	events := e.Events(evctx, e.Admin)
	oper := e.Scoped(api.PermOperator, dtest.SeedProject)
	op, err := oper.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if info := op.Info(); info.Project != dtest.SeedProject || info.Resources["jails"][0] != "/api/v1/jails/web" || !strings.Contains(info.Description, "web") {
		t.Fatalf("%+v", info)
	}
	res, err := op.Wait(c)
	if err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	j := res.Jail
	if res.App != "web" || !strings.HasPrefix(res.Hash, "sha256:") || res.Version != "15.0p1" || res.Snapshot != "app-installed" || res.DryRun {
		t.Fatalf("%+v", res)
	}
	if j.Metadata.Name != "web" || j.Status.Power != api.PowerRunning || j.Spec.Image != "fb151@stable" || j.Spec.Layout != api.LayoutThin || j.Spec.Hostname != "web" {
		t.Fatalf("%+v %+v", j.Spec, j.Status)
	}
	if l := j.Metadata.Labels; l[api.LabelApp] != "web" || l[api.LabelAppHash] != res.Hash || l[api.LabelAppVersion] != "15.0p1" {
		t.Fatalf("labels %v", l)
	}
	if r := j.Spec.Resources; r.Memory != "512M" || r.Disk != "4294967296" || r.CPU != 2 {
		t.Fatalf("limits %+v", r)
	}
	if len(j.Spec.Volumes) != 2 || j.Spec.Volumes[0].Name != "web-var-db-web" || j.Spec.Volumes[0].Mount != "/var/db/web" || j.Spec.Volumes[1].Name != "web-usr-local-www-web" {
		t.Fatalf("volumes %+v", j.Spec.Volumes)
	}
	// the data are volumes of the project, made before the jail; the jail's own snapshot does not hold them
	for _, ds := range []string{"tank/jailops/projects/alpha/volumes/web-var-db-web", "tank/jailops/projects/alpha/volumes/web-usr-local-www-web", "tank/jailops/projects/alpha/jails/web@app-installed"} {
		if ok, _ := e.ZFS.Exists(c, ds); !ok {
			t.Errorf("%s does not exist", ds)
		}
	}
	if !slices.Equal(res.Addresses, []string{"10.20.0.10"}) || len(res.Ports) != 2 || res.Ports[0].Endpoint != "10.20.0.10:8080" || !res.Ports[0].Expose || res.Ports[1].Endpoint != "10.20.0.10:9090" || res.Ports[1].Expose {
		t.Fatalf("%+v %+v", res.Addresses, res.Ports)
	}
	if len(res.Data) != 2 || len(res.Config) != 1 || len(res.Logs) != 1 || !strings.Contains(res.Notes, "/usr/local/www/web") {
		t.Fatalf("%+v", res)
	}
	wantSteps := []string{"create-volume-web-var-db-web", "create-volume-web-usr-local-www-web", "create-jail", "mount-jail", "bind-volumes", "install-packages-ports", "install-packages-jailops", "seed-jailops-repo", "install-bash", "record-version", "unbind-volumes", "start-jail", "set-up-shell", "refresh-library-cache", "write-rc-conf", "setup-1", "setup-2", "start-service-web", "health-check", "close-firewall", "snapshot", "enable-autostart"}
	var steps []string
	for _, s := range res.Steps {
		_, rest, _ := strings.Cut(s, " ")
		name, _, _ := strings.Cut(rest, ":")
		steps = append(steps, name)
	}
	if !slices.Equal(steps, wantSteps) {
		t.Fatalf("steps %v", res.Steps)
	}
	// The packages went in from the host with pkg -r while the jail had never run, the FreeBSD ones and the jailops
	// ones apart, and bash with them.
	root := "/jailops/projects/alpha/jails/web/root"
	// bash, the jail's shell, came in after the app's packages (docs/shell.md)
	if !slices.Equal(e.Installed, []string{root + " web-server", root + " web-tool", root + " bash"}) {
		t.Fatalf("installed %v", e.Installed)
	}
	// The fake pkg accepts any argv with -r: the calls must be exactly what the argv builders make, the
	// vectors internal/priv checks against the helper's allow-list.
	var pkgCalls []string
	for _, call := range e.Run.Calls() {
		if a := strings.Join(call.Cmd.Args, " "); call.Cmd.Name == "pkg" && (strings.Contains(a, root) || strings.Contains(a, "-j alpha_web")) {
			pkgCalls = append(pkgCalls, strings.Join(append([]string{call.Cmd.Name}, call.Cmd.Args...), " "))
		}
	}
	const cache = "/jailops/cache/pkg" // the download cache the host shares between installs
	want := []string{strings.Join(apps.PkgInstallCachedArgv(root, "ports", cache, []string{"web-server"}), " "),
		strings.Join(apps.PkgInstallCachedArgv(root, apps.JailopsRepo, cache, []string{"web-tool"}), " "),
		strings.Join(apps.PkgInstallCachedArgv(root, "ports", cache, []string{api.BashPackage}), " "),
		strings.Join(apps.PkgVersionArgv(root, "web-server"), " ")}
	if !slices.Equal(pkgCalls, want) || want[0] != "pkg -r "+root+" -o PKG_CACHEDIR="+cache+" install -y web-server" {
		t.Fatalf("pkg calls %q, want %q", pkgCalls, want)
	}
	// The jail's bash prompt, sourced by both start-up files of bash.
	if !strings.Contains(e.File(root+api.PromptFile), `PS1='\[\e[38;5;39m\]\u@\h\[\e[0m\]${_jailops_where:+ \[\e[38;5;245m\][${_jailops_where}]\[\e[0m\]}:\w\$ '`) || !strings.Contains(e.File(root+api.BashrcPath), api.PromptFile) || !strings.Contains(e.File(root+api.ProfilePath), api.PromptFile) {
		t.Fatalf("prompt files: %v", e.Files.Paths())
	}
	// A volume is mounted on the host at its own place (zfs mount -a at boot, devices off) and reaches the jail
	// through the nullfs line of its fstab.
	for _, v := range []string{"web-var-db-web", "web-usr-local-www-web"} {
		p, err := e.ZFS.Get(c, "tank/jailops/projects/alpha/volumes/"+v, "canmount", "devices", "mountpoint")
		if err != nil || p["canmount"].Value != "on" || p["devices"].Value != "off" || p["mountpoint"].Value != "/jailops/projects/alpha/volumes/"+v {
			t.Fatalf("%s: %v %+v", v, err, p)
		}
	}
	fstab := e.File("/etc/jailops/jails/alpha_web/fstab")
	if !strings.Contains(fstab, "/jailops/projects/alpha/volumes/web-var-db-web "+root+"/var/db/web nullfs rw 0 0\n") ||
		!strings.Contains(fstab, "/jailops/projects/alpha/volumes/web-usr-local-www-web "+root+"/usr/local/www/web nullfs rw 0 0\n") {
		t.Fatalf("fstab:\n%s", fstab)
	}
	// rc.conf holds <name>_enable and the knobs, escaped; rc.conf.local of the network is untouched.
	rc := e.File(root + "/etc/rc.conf")
	if !strings.Contains(rc, "web_enable=\"YES\"\n") || !strings.Contains(rc, "web_flags=\"--listen 8080 \\\"quoted\\\"\"\n") || !strings.Contains(rc, "web_worker_enable=\"YES\"\n") {
		t.Fatalf("rc.conf: %q", rc)
	}
	if !strings.Contains(e.File(root+"/etc/rc.conf.local"), "10.20.0.10") {
		t.Fatal("rc.conf.local was not rendered")
	}
	// The library cache was refreshed, then the setup commands and the services with start: true ran in the jail, in order, as argv.
	// A service starts through the fixed wrapper, the name as its last argument (internal/priv checks the same vector).
	start, _ := apps.ServiceStartArgv("web")
	if got := execArgvs(e, "alpha_web"); !slices.Equal(got, []string{"/sbin/ldconfig -m /usr/local/lib", "/usr/sbin/chown www:www /var/db/web", "/usr/local/bin/web-init --once", strings.Join(start, " ")}) {
		t.Fatalf("exec %q", got)
	}
	if start[0] != "/bin/sh" || start[1] != "-c" || start[2] != apps.ServiceStartScript || start[4] != "web" {
		t.Fatalf("start %q", start)
	}
	// The definition asked for System V IPC: the jail has it, in namespaces of its own; the output of the jail's
	// rc goes to its console log.
	conf := e.File("/etc/jailops/jails/alpha_web/jail.conf")
	if !j.Spec.SysVIPC || !strings.Contains(conf, "\tsysvshm = new;\n") || !strings.Contains(conf, "\tsysvsem = new;\n") || !strings.Contains(conf, "\tsysvmsg = new;\n") ||
		!strings.Contains(conf, "\texec.consolelog = \"/var/log/jailops/jail_${name}_console.log\";\n") {
		t.Fatalf("sysvipc %v, jail.conf:\n%s", j.Spec.SysVIPC, conf)
	}
	// The http check went to the jail's first address from the host.
	if !slices.Equal(seen, []string{"tcp 10.20.0.10:8080", "GET /ready"}) {
		t.Fatalf("health %q", seen)
	}
	// The jail is listed as an installed app, and the snapshot is a snapshot of the jail.
	inst, err := oper.Apps().Installed(c)
	if err != nil || len(inst) != 1 || inst[0].Metadata.Name != "web" {
		t.Fatalf("%v %+v", err, inst)
	}
	if sn, err := e.Admin.Jails().Snapshots("web").Get(c, "app-installed"); err != nil || !strings.Contains(sn.Spec.Comment, "web") {
		t.Fatalf("%v %+v", err, sn)
	}
	seenEv := map[string]bool{}
	for !seenEv["jail-created"] || !seenEv["jail-started"] || !seenEv["app.installed"] {
		select {
		case ev := <-events:
			var l api.LifecycleEvent
			if ev.Type == api.EventLifecycle && json.Unmarshal(ev.Metadata, &l) == nil {
				seenEv[l.Action] = true
			}
		case <-c.Done():
			t.Fatalf("events not seen: %v", seenEv)
		}
	}
	// The record survives a rebuild of the registry from the datasets.
	if err := e.D.Service().RefreshJails(c); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.Admin.Jails().Get(c, "web"); again.Metadata.Labels[api.LabelAppVersion] != "15.0p1" || len(again.Spec.Volumes) != 2 {
		t.Fatalf("%+v", again)
	}
	// Installing again under the same name is refused before anything happens; another name works.
	_, err = oper.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	wantCode(t, err, api.CodeAlreadyExists)
	op, err = oper.Apps().Install(c, "web", api.AppInstall{Jail: "web2", Image: "fb151@stable", Network: "lan", Storage: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if r2, err := op.Wait(c); err != nil || r2.Jail.Metadata.Name != "web2" || r2.Addresses[0] != "10.20.0.11" {
		t.Fatalf("%v %+v\n%s", err, r2, e.Log())
	}
}

// A dry run returns the steps and creates nothing; the exec health check runs
// in the jail and the defaults of the request (jail name, network, storage)
// are filled in.
func TestAppInstallDryRunAndDefaults(t *testing.T) {
	e, c := appEnv(t, map[string]string{"tool": appExecCheck})
	datasets := func() []string {
		l, err := e.ZFS.List(c, zfs.ListOpts{Root: "tank", Recursive: true})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range l {
			out = append(out, d.Name)
		}
		return out
	}
	// without the project's jails dataset, which a real installation makes when it is missing and a dry run must not
	if err := e.ZFS.Destroy(c, "tank/jailops/projects/alpha/jails", zfs.DestroyOpts{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	before := datasets()
	op, err := e.Admin.Apps().Install(c, "tool", api.AppInstall{Image: "fb151@stable", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := op.Wait(c)
	if err != nil || !res.DryRun || len(res.Steps) != 12 || res.Snapshot != "" || res.Jail.Metadata.Name != "" {
		t.Fatalf("%v %+v", err, res)
	}
	if !strings.Contains(res.Steps[0], "fb151@stable") || !strings.Contains(res.Steps[6], "install -y bash") || !strings.Contains(res.Steps[8], "/usr/local/bin/tool --ping") {
		t.Fatalf("%v", res.Steps)
	}
	if _, err := e.Admin.Jails().Get(c, "tool"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("a dry run created the jail: %v", err)
	}
	if after := datasets(); !slices.Equal(before, after) {
		t.Fatalf("a dry run created datasets: %v, before %v", after, before)
	}
	// The exec check fails until the tool answers; wait_seconds bounds the attempts.
	calls := 0
	e.Jails.SetExecFn(func(_ string, o jailos.ExecOpts) (run.Result, error) {
		if o.Argv[0] == "/usr/local/bin/tool" {
			calls++
			if calls < 2 {
				return run.Result{ExitCode: 1, Stderr: []byte("not yet\n")}, errors.New("exit 1")
			}
		}
		return run.Result{}, nil
	})
	op, err = e.Admin.Apps().Install(c, "tool", api.AppInstall{Image: "fb151@stable"})
	if err != nil {
		t.Fatal(err)
	}
	res, err = op.Wait(c)
	if err != nil || res.Jail.Metadata.Name != "tool" || res.Jail.Spec.Network[0].Network != "lan" || res.Jail.Spec.Storage != "default" || calls != 2 {
		t.Fatalf("%v %+v %d\n%s", err, res, calls, e.Log())
	}
	if len(res.Jail.Spec.Volumes) != 0 || res.Jail.Spec.Resources != (api.Resources{}) {
		t.Fatalf("%+v", res.Jail.Spec)
	}
}

// Without an image the installation takes the FreeBSD image of the highest release the host runs, by its bare
// name, the first by name on a tie; an image of a newer release than the host's is passed over.
func TestAppInstallDefaultImage(t *testing.T) {
	e, c := appEnv(t, map[string]string{"tool": appExecCheck})
	from := func(want string) {
		t.Helper()
		op, err := e.Admin.Apps().Install(c, "tool", api.AppInstall{DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		res, err := op.Wait(c)
		if err != nil || !res.DryRun || !strings.Contains(res.Steps[0], "from "+want+" ") && !strings.HasSuffix(res.Steps[0], "from "+want) {
			t.Fatalf("want from %s: %v %+v", want, err, res)
		}
	}
	from("fb") // fb and fb151 are both 15.1-RELEASE
	if _, err := e.Admin.Images().Create(c, api.Image{Metadata: api.ObjectMeta{Name: "fa"}, Spec: api.ImageSpec{
		OS: api.OSFreeBSD, Release: "15.2-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}}); err != nil {
		t.Fatal(err)
	}
	from("fb") // the host runs 15.1
}

// What is refused before the operation starts.
func TestAppInstallRefusals(t *testing.T) {
	e, c := appEnv(t, map[string]string{"web": appWeb, "newer": strings.ReplaceAll(strings.Replace(appWeb, "name: web\n", "name: newer\n", 1), `release_min: "15.1"`, `release_min: "15.2"`), "broken": "version: 1\nname: broken\n"})
	req := api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"}
	_, err := e.Admin.Apps().Install(c, "nothing", req)
	wantCode(t, err, api.CodeNotFound)
	_, err = e.Admin.Apps().Install(c, "broken", req)
	wantCode(t, err, api.CodeInvalid)
	_, err = e.Admin.Apps().Install(c, "../web", req)
	wantCode(t, err, api.CodeNotFound)
	// the seeded image is 15.1, the definition wants 15.2
	_, err = e.Admin.Apps().Install(c, "newer", api.AppInstall{Image: "fb@stable", Network: "lan", Storage: "default"})
	wantCode(t, err, api.CodeInvalid)
	if !strings.Contains(err.Error(), "15.1-RELEASE") || !strings.Contains(err.Error(), "15.2") {
		t.Fatalf("%v", err)
	}
	bad := req
	bad.Jail = "Bad Name"
	_, err = e.Admin.Apps().Install(c, "web", bad)
	wantCode(t, err, api.CodeInvalid)
	bad = req
	bad.Project = "beta"
	_, err = e.Admin.Apps().Install(c, "web", bad)
	wantCode(t, err, api.CodeInvalid)
	bad = req
	bad.Network = "other"
	_, err = e.Admin.Apps().Install(c, "web", bad)
	wantCode(t, err, api.CodeForbidden)
	bad = req
	bad.Storage = "other"
	_, err = e.Admin.Apps().Install(c, "web", bad)
	wantCode(t, err, api.CodeForbidden)
	mustJail(t, e, "web")
	_, err = e.Admin.Apps().Install(c, "web", req)
	wantCode(t, err, api.CodeAlreadyExists)
	// roles: readonly cannot, operator may, a project the identity has no scope in is not found
	_, err = e.Scoped(api.PermReadonly, dtest.SeedProject).Apps().Install(c, "web", req)
	wantCode(t, err, api.CodeForbidden)
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/broken"); ok {
		t.Fatal("something was created")
	}
}

// A failure before the first start (the jail cannot be started) deletes the
// jail; a failure after it (the packages, the health check) leaves the jail
// stopped with its labels, says so, and emits app.install.failed.
func TestAppInstallFailures(t *testing.T) {
	e, c := appEnv(t, map[string]string{"web": appWeb})
	req := api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"}
	evctx, cancel := context.WithCancel(c)
	defer cancel()
	events := e.Events(evctx, e.Admin)
	failed := func() {
		t.Helper()
		for {
			select {
			case ev := <-events:
				var l api.LifecycleEvent
				if ev.Type == api.EventLifecycle && json.Unmarshal(ev.Metadata, &l) == nil && l.Action == "app.install.failed" && l.Source == "/api/v1/jails/web" {
					return
				}
			case <-c.Done():
				t.Fatal("no app.install.failed event")
			}
		}
	}
	// 1. the jail does not start: the packages are in, so the jail is kept, stopped, to look at
	e.Jails.FailCreate = errors.New("jail: cannot start")
	op, err := e.Admin.Apps().Install(c, "web", req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = op.Wait(c)
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Detail["step"] != "start-jail" || ae.Detail["jail_kept"] != "true" || !strings.Contains(ae.Hint, "left stopped") {
		t.Fatalf("%v", err)
	}
	failed()
	if j, err := e.Admin.Jails().Get(c, "web"); err != nil || j.Status.Power != api.PowerStopped {
		t.Fatalf("the jail was not kept stopped: %v", err)
	}
	e.Jails.FailCreate = nil
	deleteWithVolumes(t, e, c, "web")
	// deleting the jail takes its datasets with it
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/web"); ok {
		t.Fatal("datasets were left behind")
	}
	// 2. the packages do not install: the jail is kept, stopped, with the labels of the app
	e.SetPkgInstallErr(errors.New("pkg: no package web-server"))
	op, err = e.Admin.Apps().Install(c, "web", req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = op.Wait(c)
	if !errors.As(err, &ae) || ae.Detail["step"] != "install-packages-ports" || ae.Detail["jail_kept"] != "true" || !strings.Contains(ae.Hint, "left stopped") || !strings.Contains(ae.Message, "no package web-server") {
		t.Fatalf("%v", err)
	}
	failed()
	j, err := e.Admin.Jails().Get(c, "web")
	if err != nil || j.Status.Power != api.PowerStopped || j.Metadata.Labels[api.LabelApp] != "web" || j.Metadata.Labels[api.LabelAppVersion] != "" {
		t.Fatalf("%v %+v", err, j)
	}
	if _, ok, _ := e.Jails.Get(c, "alpha_web"); ok {
		t.Fatal("the jail still runs")
	}
	if inst, _ := e.Admin.Apps().Installed(c); len(inst) != 1 {
		t.Fatalf("%+v", inst)
	}
	// the operator looks, then deletes it and tries again
	e.SetPkgInstallErr(nil)
	deleteWithVolumes(t, e, c, "web")
	// 3. the health check never passes: the services ran, the jail is kept stopped, no snapshot was taken
	e.SetDial(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") })
	op, err = e.Admin.Apps().Install(c, "web", req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = op.Wait(c)
	if !errors.As(err, &ae) || ae.Detail["step"] != "health-check" || ae.Detail["jail_kept"] != "true" || !strings.Contains(ae.Message, "connection refused") || !strings.Contains(ae.Message, "2s") {
		t.Fatalf("%v", err)
	}
	failed()
	j, _ = e.Admin.Jails().Get(c, "web")
	if j.Status.Power != api.PowerStopped || j.Metadata.Labels[api.LabelAppVersion] != "15.0p1" {
		t.Fatalf("%+v", j)
	}
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/web@app-installed"); ok {
		t.Fatal("a snapshot of a failed installation was taken")
	}
	if !slices.ContainsFunc(execArgvs(e, "alpha_web"), func(a string) bool { return strings.HasSuffix(a, " jailops-start web") }) {
		t.Fatal("the service was not started")
	}
	// a wrong status is a failure too
	deleteWithVolumes(t, e, c, "web")
	e.SetDial(httpAnswer(500, nil))
	op, _ = e.Admin.Apps().Install(c, "web", req)
	_, err = op.Wait(c)
	if !errors.As(err, &ae) || ae.Detail["step"] != "health-check" || !strings.Contains(ae.Message, "answered 500, not 204") {
		t.Fatalf("%v", err)
	}
	// 4. the service does not start: the error names the service command, not the wrapper's script, with what
	// the rc script printed
	deleteWithVolumes(t, e, c, "web")
	e.Jails.SetExecFn(func(_ string, o jailos.ExecOpts) (run.Result, error) {
		if o.Argv[0] == "/bin/sh" && o.Argv[len(o.Argv)-1] == "web" {
			return run.Result{ExitCode: 1, Stdout: []byte("web does not start: Permission denied\n")}, errors.New("exit 1")
		}
		return run.Result{}, nil
	})
	op, _ = e.Admin.Apps().Install(c, "web", req)
	_, err = op.Wait(c)
	if !errors.As(err, &ae) || ae.Detail["step"] != "start-service-web" || ae.Detail["jail_kept"] != "true" ||
		!strings.Contains(ae.Message, "/usr/sbin/service web start") || !strings.Contains(ae.Message, "Permission denied") || strings.Contains(ae.Message, "mktemp") {
		t.Fatalf("%v", err)
	}
}

// A daemon restart during an installation: the jail of a run that never
// started is deleted, a started one is stopped and kept.
func TestAppInstallRecovery(t *testing.T) {
	e, c := appEnv(t, map[string]string{"tool": appExecCheck})
	op, err := e.Admin.Apps().Install(c, "tool", api.AppInstall{Image: "fb151@stable"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	if _, ok, _ := e.Jails.Get(c, "alpha_tool"); !ok {
		t.Fatal("the jail does not run")
	}
	journal := filepath.Join(e.Cfg.DataDir, "journal")
	leave := func(begun int) {
		t.Helper()
		rec := plan.Record{ID: "app-install/alpha_tool", Plan: "install-app tool alpha_tool", Steps: []string{"create-jail", "start-jail", "install-packages-ports", "record-version", "health-check", "snapshot"}, Begun: begun, Done: begun - 1, State: plan.StateRunning}
		b, _ := json.Marshal(rec)
		if err := os.WriteFile(filepath.Join(journal, "app-install~alpha_tool.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.Stop()
	leave(5)
	e2 := dtest.New(t, dtest.Options{Reuse: e, Mutate: func(c *daemon.Config) { c.Apps.CatalogDir = e.Cfg.Apps.CatalogDir }})
	e2.Admin = e2.Admin.Project(dtest.SeedProject)
	j, err := e2.Admin.Jails().Get(c, "tool")
	if err != nil || j.Status.Power != api.PowerStopped || j.Metadata.Labels[api.LabelApp] != "tool" {
		t.Fatalf("%v %+v\n%s", err, j, e2.Log())
	}
	if j.Spec.Boot.Autostart {
		t.Fatal("a jail kept for inspection starts with the host")
	}
	if _, ok, _ := e2.Jails.Get(c, "alpha_tool"); ok {
		t.Fatal("the jail still runs")
	}
	rec := e2.D.Service().Recovered()
	if len(rec) != 1 || rec[0].Run != "app-install/alpha_tool" || rec[0].Action != "completed" {
		t.Fatalf("%+v", rec)
	}
	if _, err := os.Stat(filepath.Join(journal, "app-install~alpha_tool.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the journal record was kept")
	}
	e2.Stop()
	leave(1)
	e3 := dtest.New(t, dtest.Options{Reuse: e, Mutate: func(c *daemon.Config) { c.Apps.CatalogDir = e.Cfg.Apps.CatalogDir }})
	e3.Admin = e3.Admin.Project(dtest.SeedProject)
	if _, err := e3.Admin.Jails().Get(c, "tool"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("the never-started jail was kept: %v\n%s", err, e3.Log())
	}
	if ok, _ := e3.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/tool"); ok {
		t.Fatal("datasets were left behind")
	}
	if rec := e3.D.Service().Recovered(); len(rec) != 1 || rec[0].Action != "rolled-back" {
		t.Fatalf("%+v", rec)
	}
	// A crash during the start of the jail: the start's own run is rolled back
	// first, then the jail, which never completed a start, is deleted.
	op, err = e3.Admin.Apps().Install(c, "tool", api.AppInstall{Image: "fb151@stable"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e3.Log())
	}
	e3.Stop()
	leave(2)
	start := plan.Record{ID: "start/alpha_tool", Plan: "start-jail alpha_tool", Steps: []string{"mount", "heal-mounts", "render", "jail-start", "ready"}, Begun: 4, Done: 3, State: plan.StateRunning}
	b, _ := json.Marshal(start)
	if err := os.WriteFile(filepath.Join(journal, "start~alpha_tool.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	e4 := dtest.New(t, dtest.Options{Reuse: e, Mutate: func(c *daemon.Config) { c.Apps.CatalogDir = e.Cfg.Apps.CatalogDir }})
	e4.Admin = e4.Admin.Project(dtest.SeedProject)
	if _, err := e4.Admin.Jails().Get(c, "tool"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("the jail whose start never completed was kept: %v\n%s", err, e4.Log())
	}
	if ok, _ := e4.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/tool"); ok {
		t.Fatal("datasets were left behind")
	}
	if _, ok, _ := e4.Jails.Get(c, "alpha_tool"); ok {
		t.Fatal("the jail still runs")
	}
	rec = e4.D.Service().Recovered()
	if len(rec) != 2 || rec[0].Run != "start/alpha_tool" || rec[0].Action != "rolled-back" || rec[1].Run != "app-install/alpha_tool" || rec[1].Action != "rolled-back" {
		t.Fatalf("%+v", rec)
	}
}

// No exec session enters a jail while it is being installed: pkg works on its
// root from the host. The same jail is reachable afterwards, and another jail
// is reachable during the installation.
func TestAppInstallRefusesExec(t *testing.T) {
	e, c := appEnv(t, map[string]string{"tool": appExecCheck})
	op, err := e.Admin.Apps().Install(c, "tool", api.AppInstall{Jail: "other", Image: "fb151@stable"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	var during, other error
	var otherOut string
	e.Jails.SetExecFn(func(jail string, o jailos.ExecOpts) (run.Result, error) {
		// the library cache is refreshed right after the packages went in, while the installation holds the jail
		if jail == "alpha_tool" && o.Argv[0] == "/sbin/ldconfig" {
			_, during = e.Admin.Jails().Exec(c, "tool", []string{"echo", "x"}, sdk.ExecOptions{})
			var s *sdk.ExecSession
			if s, other = e.Admin.Jails().Exec(c, "other", []string{"echo", "y"}, sdk.ExecOptions{}); other == nil {
				otherOut, _, _ = drain(s)
			}
		}
		return run.Result{}, nil
	})
	op, err = e.Admin.Apps().Install(c, "tool", api.AppInstall{Image: "fb151@stable"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	var ae *api.Error
	if !errors.As(during, &ae) || ae.Code != api.CodeBusy || !strings.Contains(ae.Message, "packages are being installed or updated") || ae.Hint == "" {
		t.Fatalf("exec during the installation: %v", during)
	}
	if other != nil || otherOut != "y\n" {
		t.Fatalf("exec into another jail: %v %q", other, otherOut)
	}
	s, err := e.Admin.Jails().Exec(c, "tool", []string{"echo", "z"}, sdk.ExecOptions{})
	if err != nil {
		t.Fatalf("exec after the installation: %v", err)
	}
	if out, _, code := drain(s); out != "z\n" || code != 0 {
		t.Fatalf("%q %d", out, code)
	}
}

// failReads makes the jail records unreadable while armed: the create step
// fails after the jail was made, when the registry reads it back.
type failReads struct {
	service.FS
	armed *atomic.Bool
}

func (f failReads) ReadFile(ctx context.Context, p string) ([]byte, error) {
	if f.armed.Load() && (strings.HasSuffix(p, "/spec.json") || strings.HasSuffix(p, "/spec.json.previous") || strings.HasSuffix(p, "/bundle.json")) {
		return nil, errors.New("injected: cannot read " + p)
	}
	return f.FS.ReadFile(ctx, p)
}

// A failure of the create step after the jail was made deletes the jail
// again: the step undoes itself when it fails.
func TestAppInstallCreateFailsAfterCreation(t *testing.T) {
	var armed atomic.Bool
	e, c := appEnvWith(t, map[string]string{"web": appWeb}, dtest.Options{Clients: func(cl *daemon.Clients) {
		cl.Files = failReads{FS: cl.Files, armed: &armed}
	}})
	armed.Store(true)
	op, err := e.Admin.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = op.Wait(c)
	armed.Store(false)
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Detail["step"] != "create-jail" || ae.Detail["jail_kept"] != "" || !strings.Contains(ae.Message, "injected") {
		t.Fatalf("%v", err)
	}
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/web"); ok {
		t.Fatalf("the jail was left behind\n%s", e.Log())
	}
	if _, err := e.Admin.Jails().Get(c, "web"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("%v", err)
	}
	// nothing is in the way of the next attempt
	e.SetDial(httpAnswer(204, nil))
	op, _ = e.Admin.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
}

// A definition whose data path is a persistent dataset of every jail is
// refused before the operation starts, with the validator's message; so is
// one that names a path this host keeps persistent.
func TestAppInstallRefusesPersistentPaths(t *testing.T) {
	bad := strings.Replace(appWeb, "{path: /usr/local/www/web}", "{path: /var/log}", 1)
	e, c := appEnv(t, map[string]string{"web": bad})
	_, err := e.Admin.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	wantCode(t, err, api.CodeInvalid)
	if !strings.Contains(err.Error(), "data[1].path: /var/log is a persistent dataset of every jail") {
		t.Fatalf("%v", err)
	}
	for o, err := range e.Admin.Operations().List(c) {
		if err != nil || strings.Contains(o.Description, "Install app") {
			t.Fatalf("an operation was started: %v %+v", err, o)
		}
	}
}

// An installed app starts when the host boots: the installation is the declaration that it should run.
func TestAppInstallAutostarts(t *testing.T) {
	e, c := appEnv(t, map[string]string{"web": appWeb})
	e.SetDial(httpAnswer(204, nil))
	op, err := e.Admin.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	j, err := e.Admin.Jails().Get(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if !j.Spec.Boot.Autostart {
		t.Fatalf("an installed app does not start at boot: %+v", j.Spec.Boot)
	}
}

// The doctor warns about volume datasets that are not canmount=noauto, and
// gives the command that fixes each.
func TestDoctorVolumeCanmount(t *testing.T) {
	e, c := appEnv(t, map[string]string{"web": appWeb})
	e.SetDial(httpAnswer(204, nil))
	op, err := e.Admin.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	check := func() api.DoctorCheck {
		t.Helper()
		rep, err := e.Admin.Doctor(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range rep.Checks {
			if ch.Name == "jail.volumes" {
				return ch
			}
		}
		t.Fatalf("no jail.volumes check: %+v", rep.Checks)
		return api.DoctorCheck{}
	}
	if ch := check(); ch.Status != api.DoctorOK {
		t.Fatalf("%+v", ch)
	}
	// a volume whose dataset is gone, and a jail that attaches a volume that does not exist
	ds := "tank/jailops/projects/alpha/volumes/web-var-db-web"
	if err := e.ZFS.Destroy(c, ds, zfs.DestroyOpts{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if ch := check(); ch.Status != api.DoctorFail || !strings.Contains(ch.Message, "has no dataset "+ds) {
		t.Fatalf("%+v", ch)
	}
}

// The reference catalog plans the steps its definitions describe:
// isms from the jailops repository and not started (so nothing to check),
// nsd and mail with their setup, services and health check. isms installs
// through the fakes without starting anything.
func TestAppInstallReferenceCatalog(t *testing.T) {
	src := filepath.Join("..", "apps", "testdata", "catalog")
	defs := map[string]string{}
	for _, n := range []string{"isms", "nsd", "mail"} {
		b, err := os.ReadFile(filepath.Join(src, n+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		// the icon file is not copied here; internal/apps reads the reference ones
		defs[n] = strings.Replace(string(b), "icon: "+n+".svg\n", "", 1)
	}
	e, c := appEnv(t, defs)
	names := func(steps []string) []string {
		var out []string
		for _, s := range steps {
			_, rest, _ := strings.Cut(s, " ")
			name, _, _ := strings.Cut(rest, ":")
			out = append(out, name)
		}
		return out
	}
	setup := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("setup-%d", i+1))
		}
		return out
	}
	for _, c2 := range []struct {
		app      string
		services []string
		health   bool
	}{
		{"isms", nil, false},
		{"nsd", []string{"start-service-nsd"}, true},
		{"mail", []string{"start-service-postfix", "start-service-dovecot"}, true},
	} {
		def, err := apps.Parse(c2.app, []byte(defs[c2.app]))
		if err != nil {
			t.Fatal(err)
		}
		op, err := e.Admin.Apps().Install(c, c2.app, api.AppInstall{Image: "fb151@stable", DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		res, err := op.Wait(c)
		if err != nil {
			t.Fatalf("%s: %v", c2.app, err)
		}
		repos := []string{"install-packages-ports"}
		if c2.app == "isms" { // openssh-portable from the FreeBSD packages, then isms from the JailOps repository
			repos = append(repos, "install-packages-jailops", "seed-jailops-repo")
		}
		var want []string
		for range def.Data {
			want = append(want, "create-volume")
		}
		want = append(want, "create-jail", "mount-jail")
		if len(def.Data) > 0 {
			want = append(want, "bind-volumes")
		}
		want = append(want, repos...)
		want = append(want, "install-bash", "record-version")
		if len(def.Data) > 0 {
			want = append(want, "unbind-volumes")
		}
		want = append(want, "start-jail", "set-up-shell", "refresh-library-cache", "write-rc-conf")
		want = append(want, setup(len(def.Setup))...)
		want = append(want, c2.services...)
		if c2.health {
			want = append(want, "health-check")
		}
		want = append(want, "close-firewall", "snapshot", "enable-autostart")
		got := names(res.Steps)
		for i, g := range got {
			if strings.HasPrefix(g, "create-volume-") {
				got[i] = "create-volume"
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: steps %v, want %v", c2.app, res.Steps, want)
		}
	}

	op, err := e.Admin.Apps().Install(c, "isms", api.AppInstall{Image: "fb151@stable"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := op.Wait(c)
	if err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	root := "/jailops/projects/alpha/jails/isms/root"
	if !slices.Contains(e.Installed, root+" isms") {
		t.Fatalf("installed %v", e.Installed)
	}
	var pkgCalls []string
	for _, call := range e.Run.Calls() {
		if call.Cmd.Name == "pkg" && slices.Contains(call.Cmd.Args, "install") {
			pkgCalls = append(pkgCalls, strings.Join(call.Cmd.Args, " "))
		}
	}
	if !slices.Contains(pkgCalls, "-r "+root+" -o PKG_CACHEDIR=/jailops/cache/pkg install -y -r jailops isms") {
		t.Fatalf("pkg calls %q", pkgCalls)
	}
	// enabled in rc.conf, never started: the setup ran, no service start
	if rc := e.File(root + "/etc/rc.conf"); !strings.Contains(rc, "isms_enable=\"YES\"\n") {
		t.Fatalf("rc.conf %q", rc)
	}
	for _, argv := range execArgvs(e, "alpha_isms") {
		if strings.HasPrefix(argv, "/bin/sh -c") {
			t.Errorf("a service was started: %q", argv)
		}
	}
	if res.Snapshot != "app-installed" || len(res.Ports) != 1 || res.Ports[0].Port != 8080 {
		t.Fatalf("%+v", res)
	}
}

// deleteWithVolumes deletes a jail and every volume of the project: an app's data are volumes, and they outlive the
// jail.
func deleteWithVolumes(t *testing.T, e *dtest.Env, c context.Context, jail string) {
	t.Helper()
	dop, err := e.Admin.Jails().Delete(c, jail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dop.Wait(c); err != nil {
		t.Fatal(err)
	}
	for v, err := range e.Admin.Volumes().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		op, err := e.Admin.Volumes().Delete(c, v.Metadata.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.Wait(c); err != nil {
			t.Fatal(err)
		}
	}
}
