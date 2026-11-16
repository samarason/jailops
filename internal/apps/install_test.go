package apps

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

func TestInstallCommands(t *testing.T) {
	root := "/jailops/projects/demo/jails/nginx/root"
	if got := PkgInstallArgv(root, "ports", []string{"nginx", "curl"}); !slices.Equal(got, []string{"pkg", "-r", root, "install", "-y", "nginx", "curl"}) {
		t.Errorf("%q", got)
	}
	if got := PkgInstallArgv(root, "jailops", []string{"jailops-tool"}); !slices.Equal(got, []string{"pkg", "-r", root, "install", "-y", "-r", "jailops", "jailops-tool"}) {
		t.Errorf("%q", got)
	}
	if got := PkgVersionArgv(root, "nginx"); !slices.Equal(got, []string{"pkg", "-r", root, "query", "%v", "nginx"}) {
		t.Errorf("%q", got)
	}
	if got := ServiceArgv("nginx", "start"); !slices.Equal(got, []string{"/usr/sbin/service", "nginx", "start"}) {
		t.Errorf("%q", got)
	}
	if RcConfPath(root) != root+"/etc/rc.conf" {
		t.Error(RcConfPath(root))
	}
	ports, jo := PackageGroups([]api.AppPackage{{Name: "a", Repo: "ports"}, {Name: "b", Repo: "jailops"}, {Name: "c", Repo: "ports"}})
	if !slices.Equal(ports, []string{"a", "c"}) || !slices.Equal(jo, []string{"b"}) {
		t.Errorf("%v %v", ports, jo)
	}
	vars := RcVars([]api.AppService{{Name: "php-fpm"}, {Name: "postgresql", RC: map[string]string{"postgresql_initdb_flags": "--encoding=utf-8", "postgresql_data": "/var/db/postgres/data18"}}})
	want := []RcVar{{Name: "php_fpm_enable", Value: "YES"}, {Name: "postgresql_enable", Value: "YES"}, {Name: "postgresql_data", Value: "/var/db/postgres/data18"}, {Name: "postgresql_initdb_flags", Value: "--encoding=utf-8"}}
	if !slices.Equal(vars, want) {
		t.Errorf("%v", vars)
	}
}

func TestVolumesAndLimits(t *testing.T) {
	for in, want := range map[string]string{
		"/var/db/postgres": "var-db-postgres", "/usr/local/www": "usr-local-www", "/home/Forge.Data+x": "home-forge-data-x",
		"/var/db/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v": "var-db-a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q",
		"///": "data",
	} {
		if got := VolumeName(in); got != want || len(got) > 40 {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	vols := Volumes("db", []api.AppPath{{Path: "/var/db/x"}, {Path: "/var/db.x"}, {Path: "/var/db-x"}})
	if len(vols) != 3 || vols[0].Name != "db-var-db-x" || vols[1].Name != "db-var-db-x-2" || vols[2].Name != "db-var-db-x-3" || vols[2].Mount != "/var/db-x" {
		t.Errorf("%+v", vols)
	}
	// every name is a valid volume name, whatever the jail and the path are called
	for _, jail := range []string{"db", "a-jail-with-quite-a-long-name", "a-jail-with-the-longest-name-ok"} {
		for _, v := range Volumes(jail, []api.AppPath{{Path: "/var/db/postgres"}, {Path: "/var/db.postgres"}, {Path: "/usr/local/www/data/uploads"}}) {
			if len(v.Name) > MaxVolumeName || strings.HasSuffix(v.Name, "-") || !strings.HasPrefix(v.Name, jail[:min(len(jail), MaxVolumeName-3)]) {
				t.Errorf("%s: volume name %q", jail, v.Name)
			}
		}
	}
	if l := Limits(api.AppResources{Memory: "1G", Disk: "10G", CPU: "1.5"}); l.CPU != 2 || l.Memory != "1G" || l.Disk != "10G" || l.PIDs != 0 {
		t.Errorf("%+v", l)
	}
	if l := Limits(api.AppResources{}); l != (api.Resources{}) {
		t.Errorf("%+v", l)
	}
}

func TestReleaseAtLeast(t *testing.T) {
	for _, c := range []struct {
		rel, min string
		ok, err  bool
	}{
		{"15.1-RELEASE", "15.1", true, false}, {"15.1-RELEASE-p3", "15.1", true, false}, {"15.2-RELEASE", "15.1", true, false},
		{"16.0-RELEASE", "15.1", true, false}, {"15.0-RELEASE", "15.1", false, false}, {"14.3-RELEASE", "15.1", false, false},
		{"15.1", "15.1", true, false}, {"15-RELEASE", "15.1", false, true}, {"", "15.1", false, true}, {"15.1-RELEASE", "x", false, true},
	} {
		ok, err := ReleaseAtLeast(c.rel, c.min)
		if ok != c.ok || (err != nil) != c.err {
			t.Errorf("%s >= %s: %v %v", c.rel, c.min, ok, err)
		}
	}
}

func TestServiceStartArgv(t *testing.T) {
	got, err := ServiceStartArgv("nginx")
	if err != nil || !slices.Equal(got, []string{"/bin/sh", "-c", ServiceStartScript, "jailops-start", "nginx"}) {
		t.Fatalf("%q %v", got, err)
	}
	for _, n := range []string{"php-fpm", "postgresql", "valkey", "forgejo", "a.b_c", "X11"} {
		if a, err := ServiceStartArgv(n); err != nil || a[4] != n || a[2] != ServiceStartScript {
			t.Errorf("%s: %q %v", n, a, err)
		}
	}
	for _, n := range []string{"", "-f", "a b", "a;id", "$(id)", "`id`", "a\nb", "../x", "a/b", "\"x\"", strings.Repeat("a", 65)} {
		if a, err := ServiceStartArgv(n); err == nil {
			t.Errorf("%q accepted: %q", n, a)
		}
	}
}

// The wrapper's script, run by a real sh with the in-jail programs replaced:
// a daemon the rc script leaves behind does not hold the caller's output, a
// failure prints what the script said and keeps its status, and the name is
// an argument, never shell text.
func TestServiceStartScript(t *testing.T) {
	dir := t.TempDir()
	svc := filepath.Join(dir, "service")
	// the stand-in for service(8): records its arguments, starts a "daemon" that keeps its descriptors, fails for "bad"
	if err := os.WriteFile(svc, []byte("#!/bin/sh\nprintf '%s|' \"$@\" > \"$REC\"\nsleep 5 &\necho \"starting $1\"\n[ \"$1\" != bad ] || { echo \"cannot start $1\" >&2; exit 3; }\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("/usr/sbin/service", svc, "/usr/bin/mktemp -t jailops", "mktemp").Replace(ServiceStartScript)
	if script == ServiceStartScript {
		t.Fatal("nothing replaced")
	}
	run := func(name string) (string, int, time.Duration) {
		t.Helper()
		rec := filepath.Join(dir, "rec")
		cmd := exec.Command("/bin/sh", "-c", script, ServiceStartName, name)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "REC=" + rec, "TMPDIR=" + dir}
		start := time.Now()
		out, err := cmd.CombinedOutput() // waits for the end of the output, as the in-jail exec does
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(rec); string(b) != name+"|start|" {
			t.Errorf("service got %q", b)
		}
		return string(out), code, time.Since(start)
	}
	out, code, took := run("nginx")
	if out != "" || code != 0 || took >= 4*time.Second {
		t.Errorf("success: %q %d after %s", out, code, took)
	}
	out, code, took = run("bad")
	if !strings.Contains(out, "starting bad") || !strings.Contains(out, "cannot start bad") || code != 3 || took >= 4*time.Second {
		t.Errorf("failure: %q %d after %s", out, code, took)
	}
	hostile := "x; touch " + filepath.Join(dir, "pwned") + " $(touch " + filepath.Join(dir, "pwned2") + ")"
	if _, code, _ = run(hostile); code != 0 {
		t.Errorf("hostile name: %d", code)
	}
	for _, f := range []string{"pwned", "pwned2"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("the name was run as shell text (%s)", f)
		}
	}
	// the temporary files are gone
	if left, _ := filepath.Glob(filepath.Join(dir, "tmp.*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestPkgInstallCachedArgv(t *testing.T) {
	got := strings.Join(PkgInstallCachedArgv("/r", "ports", "/c/pkg", []string{"bash"}), " ")
	if got != "pkg -r /r -o PKG_CACHEDIR=/c/pkg install -y bash" {
		t.Errorf("%q", got)
	}
	got = strings.Join(PkgInstallCachedArgv("/r", JailopsRepo, "/c/pkg", []string{"x", "y"}), " ")
	if got != "pkg -r /r -o PKG_CACHEDIR=/c/pkg install -y -r jailops x y" {
		t.Errorf("%q", got)
	}
	if got := strings.Join(PkgInstallArgv("/r", "ports", []string{"bash"}), " "); got != "pkg -r /r install -y bash" {
		t.Errorf("no cache: %q", got)
	}
}
