package server_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// A definition drafted from a jail that an installation made: the packages
// it installed, the services and knobs of its rc.conf, what listens, its
// volumes, files and owners; read with the exact commands of internal/apps,
// for an operator only, audited, and refused for a stopped jail.
func TestAppDraft(t *testing.T) {
	e, c := appEnv(t, map[string]string{"web": appWeb})
	e.SetDial(httpAnswer(204, nil))
	inst, err := e.Admin.Apps().Install(c, "web", api.AppInstall{Image: "fb151@stable", Network: "lan", Storage: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	var inJail [][]string
	e.Jails.SetExecFn(func(jail string, o jailos.ExecOpts) (run.Result, error) {
		inJail = append(inJail, o.Argv)
		switch {
		case slices.Equal(o.Argv, apps.SockstatArgv()):
			return run.Result{Stdout: []byte("www web 900 6 tcp4 *:8080 *:*\nwww web 900 7 tcp4 127.0.0.1:9090 *:*\nroot sshd 7 3 tcp4 *:22 *:*\n")}, nil
		case slices.Equal(o.Argv, apps.FindNewerArgv("/usr/local/etc")):
			return run.Result{Stdout: []byte("/usr/local/etc/web.conf\n/usr/local/etc/web.conf.sample\n")}, nil
		case slices.Equal(o.Argv, apps.FindNewerArgv("/var/log")):
			return run.Result{Stdout: []byte("/var/log/web.log\n/var/log/messages\n")}, nil
		case o.Argv[0] == "/usr/bin/stat":
			return run.Result{Stdout: []byte("www:www /var/db/web\nwww:www /var/run/web-worker\n"), Stderr: []byte("stat: /var/run/web: No such file or directory\n"), ExitCode: 1}, nil
		}
		return run.Result{}, nil
	})
	// the package's rc.d scripts, as the fake's pkg does not write them
	e.Files.Put("/jailops/projects/alpha/jails/web/root/usr/local/etc/rc.d/web-worker", []byte("#!/bin/sh\n"))
	e.Run.Reset()
	oper := e.Scoped(api.PermOperator, dtest.SeedProject)
	d, err := oper.Jails().AppDraft(c, "web")
	if err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	a := d.Definition
	if err := apps.Validate(&a); err != nil {
		t.Fatal(err)
	}
	if d.Jail != "web" || a.Name != "web" || !a.SysVIPC || a.Homepage != "https://example.com/web-server" {
		t.Errorf("%+v", d)
	}
	var pkgs, svcs, ports, data, cfgs, logs []string
	for _, p := range a.Packages {
		pkgs = append(pkgs, p.Name+"@"+p.Repo)
	}
	for _, s := range a.Services {
		svcs = append(svcs, s.Name)
	}
	for _, p := range a.Ports {
		ports = append(ports, p.Name+" "+p.Proto+" "+p.Description)
	}
	for _, p := range a.Data {
		data = append(data, p.Path)
	}
	for _, p := range a.Config {
		cfgs = append(cfgs, p.Path+" "+p.Restart)
	}
	for _, p := range a.Logs {
		logs = append(logs, p.Name+" "+p.Path)
	}
	// the definition installed web-tool from the jailops repository; the fake's pkg reports the repository as FreeBSD
	for got, want := range map[string]string{
		strings.Join(pkgs, ","):  "web-server@ports,web-tool@ports",
		strings.Join(svcs, ","):  "web,web-worker",
		strings.Join(ports, ","): "web tcp Listened on by web.,web-9090 tcp Listened on by web on localhost only.",
		strings.Join(data, ","):  "/var/db/web,/usr/local/www/web",
		strings.Join(cfgs, ","):  "/usr/local/etc/web.conf web",
		strings.Join(logs, ","):  "web /var/log/web.log",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if a.Services[0].RC["web_flags"] != `--listen 8080 "quoted"` || a.Health == nil || a.Health.TCP != 8080 {
		t.Errorf("%+v %+v", a.Services, a.Health)
	}
	if len(a.Setup) != 2 || !slices.Equal(a.Setup[0], []string{"/bin/mkdir", "-p", "/var/run/web-worker"}) ||
		!slices.Equal(a.Setup[1], []string{"/usr/sbin/chown", "www:www", "/var/db/web", "/var/run/web-worker"}) {
		t.Errorf("setup %q", a.Setup)
	}
	if d.Todo["health"] == "" || !strings.Contains(strings.Join(d.Findings, "\n"), "22/tcp of sshd") {
		t.Errorf("%+v", d)
	}
	// the host command is the one the helper allows; the in-jail ones are the builders'
	if !slices.Contains(e.Run.Argv(), strings.Join(apps.PkgLeavesArgv("alpha_web"), " ")) {
		t.Errorf("host commands %q", e.Run.Argv())
	}
	want := [][]string{apps.SockstatArgv(), apps.FindNewerArgv("/usr/local/etc"), apps.FindNewerArgv("/var/log"),
		apps.StatOwnerArgv([]string{"/var/db/web", "/usr/local/www/web", "/var/run/web", "/var/run/web-worker"})}
	if len(inJail) != len(want) {
		t.Fatalf("in the jail %q", inJail)
	}
	for i := range want {
		if !slices.Equal(inJail[i], want[i]) {
			t.Errorf("in the jail %q, want %q", inJail[i], want[i])
		}
	}
	// audited, with the counts only
	entries, _ := e.Admin.Audit(c, 500)
	found := false
	for _, en := range entries {
		if strings.Contains(en.Action, "/app-draft") {
			found = strings.Contains(en.Detail, "2 package(s), 2 service(s), 2 port(s)")
		}
	}
	if !found {
		t.Errorf("no audit entry: %+v", entries)
	}

	// a reader may not run commands in the jail; a stopped jail has nothing listening
	_, err = e.Scoped(api.PermReadonly, dtest.SeedProject).Jails().AppDraft(c, "web")
	wantCode(t, err, api.CodeForbidden)
	_, err = oper.Jails().AppDraft(c, "nothing")
	wantCode(t, err, api.CodeNotFound)
	op, err := e.Admin.Jails().Stop(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	_, err = oper.Jails().AppDraft(c, "web")
	wantCode(t, err, api.CodeBusy)
}

// The host's own directory is read with the packaged catalog: a local
// definition is listed with its source, hides a packaged one of the same
// name, is the one served and installed, and an invalid one points at
// apps.local_dir.
func TestAppsLocalDir(t *testing.T) {
	cat, loc := t.TempDir(), t.TempDir()
	write := func(dir, name, def string) {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(def), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(cat, "demo", appDemo)
	write(loc, "demo", strings.Replace(appDemo, "title: Demo", "title: Our demo", 1))
	write(loc, "mine", strings.ReplaceAll(strings.ReplaceAll(appDemo, "name: demo", "name: mine"), `release_min: "15.1"`, `release_min: "15.2"`))
	write(loc, "broken", "version: 1\nname: broken\n")
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { c.Apps.CatalogDir, c.Apps.LocalDir = cat, loc }})
	e.Seed()
	c := ctxT(t)
	list, err := e.Admin.Apps().List(c)
	if err != nil || len(list) != 3 {
		t.Fatalf("%v %+v", err, list)
	}
	for _, s := range list {
		ok := s.Source == api.AppSourceLocal
		switch s.Name {
		case "demo":
			ok = ok && s.Overrides == api.AppSourceCatalog && s.Title == "Our demo"
		case "broken":
			ok = ok && !s.Valid && s.Overrides == ""
		case "mine":
			ok = ok && s.Valid && s.Overrides == ""
		}
		if !ok {
			t.Errorf("%+v", s)
		}
	}
	// doctor says the directory is read and one definition there is invalid
	rep, err := e.Admin.Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(rep.Checks, func(ch api.DoctorCheck) bool { return ch.Name == "apps.local_dir" }); i < 0 ||
		rep.Checks[i].Status != api.DoctorWarn || !strings.Contains(rep.Checks[i].Message, "1 of 3 definition(s)") {
		t.Errorf("%+v", rep.Checks)
	}
	det, err := e.Admin.Apps().Get(c, "demo")
	if err != nil || det.Source != api.AppSourceLocal || det.Overrides != api.AppSourceCatalog || det.Definition.Title != "Our demo" {
		t.Fatalf("%v %+v", err, det)
	}
	_, err = e.Admin.Apps().Get(c, "broken")
	wantCode(t, err, api.CodeInvalid)
	var ae *api.Error
	if !errors.As(err, &ae) || !strings.Contains(ae.Hint, loc) || !strings.Contains(ae.Hint, "apps.local_dir") {
		t.Errorf("%v", err)
	}
	op, err := e.Admin.Apps().Install(c, "mine", api.AppInstall{DryRun: true, Image: "fb@stable", Network: "lan", Storage: "default"})
	if err == nil {
		_, err = op.Wait(c)
	}
	// the seeded image is 15.1, which this definition (15.2 or later) refuses: the refusal shows the local definition was the one read
	if err == nil || !strings.Contains(err.Error(), "mine") {
		t.Fatalf("%v", err)
	}
	// the packaged one comes back when the local file goes
	if err := os.Remove(filepath.Join(loc, "demo.yaml")); err != nil {
		t.Fatal(err)
	}
	if det, err := e.Admin.Apps().Get(c, "demo"); err != nil || det.Source != api.AppSourceCatalog || det.Overrides != "" || det.Definition.Title != "Demo" {
		t.Fatalf("%v %+v", err, det)
	}
}
