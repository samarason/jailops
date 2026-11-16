package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// app new writes a starter definition and its icon offline; validate lists
// its TODO lines until they are replaced; nothing is overwritten by surprise.
func TestAppNew(t *testing.T) {
	h := newHarness(t)
	h.env["JAILOPS_CONFIG"] = filepath.Join(h.dir, "none.yaml") // no server: any request would fail
	dir := filepath.Join(h.dir, "apps")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := h.transcript()
	tr.ok("app", "new", "memcached", "--package", "memcached", "--service", "memcached", "--port", "11211/tcp", "--category", "database", "--dir", dir)
	tr.do("", "app", "validate", filepath.Join(dir, "memcached.yaml"))
	tr.do("", "app", "new", "memcached", "--dir", dir)
	icon := writeFile(t, dir, "memcached.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>", 0o644) // the author's own icon
	tr.ok("app", "new", "memcached", "--package", "memcached,libevent", "--port", "11211", "--port", "11211/udp", "--dir", dir, "--overwrite")
	if b, _ := os.ReadFile(icon); !strings.HasPrefix(string(b), "<svg xmlns=\"http://www.w3.org/2000/svg\"/>") {
		t.Errorf("the icon was overwritten: %s", b)
	}
	tr.ok("app", "new", "tool", "--dir", dir, "-o", "json")
	tr.ok("app", "new", "quiet", "--dir", dir, "-q")
	tr.do("", "app", "new", "Bad_Name", "--dir", dir)
	tr.do("", "app", "new", "x", "--port", "http", "--dir", dir)
	tr.do("", "app", "new", "x", "--category", "games", "--dir", dir)
	tr.do("", "app", "new", "x", "--dir", filepath.Join(h.dir, "missing"))
	tr.do("", "app", "new", "x", "--dir", dir, "-o", "csv")
	tr.do("", "app", "new")
	tr.golden("app_new")

	data, err := os.ReadFile(filepath.Join(dir, "tool.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "app_new_file", string(data))

	// the default directory is the working directory
	t.Chdir(dir)
	if out, errs, code := h.run("", "app", "new", "here"); code != 0 || !strings.Contains(out, "Wrote here.yaml") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "here.svg")); err != nil {
		t.Fatal(err)
	}
	// once every marked line is filled in, the file validates
	filled := strings.NewReplacer("TODO:TODO", "nobody:nobody", "license: TODO", "license: BSD-3-Clause", "name: TODO", "name: memcached").Replace(string(data))
	var keep []string
	for _, l := range strings.Split(filled, "\n") {
		if strings.Contains(l, "# TODO") {
			continue
		}
		keep = append(keep, strings.ReplaceAll(l, "TODO: ", ""))
	}
	writeFile(t, dir, "tool.yaml", strings.Join(keep, "\n"), 0o644)
	if out, errs, code := h.run("", "app", "validate", filepath.Join(dir, "tool.yaml")); code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
}

// app export drafts a definition from a running jail through the server and
// writes it as a commented file; validate lists what is left to fill in.
func TestAppExport(t *testing.T) {
	h := newHarness(t)
	h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "cache", Project: "main"},
		Spec:   api.JailSpec{Image: "freebsd-15@stable", Volumes: []api.VolumeAttach{{Name: "var-db-memcached", Mount: "/var/db/memcached"}}},
		Status: api.JailStatus{Power: api.PowerRunning, Generation: "g1"}})
	h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "plain", Project: "main"},
		Spec:   api.JailSpec{Image: "freebsd-15@stable", Volumes: []api.VolumeAttach{{Name: "srv", Mount: "/var/db/plain"}}},
		Status: api.JailStatus{Power: api.PowerRunning, Generation: "g1"}})
	h.srv.SeedJail(api.Jail{Metadata: api.ObjectMeta{Name: "off", Project: "main"}, Spec: api.JailSpec{Image: "freebsd-15@stable"}})
	// what the daemon would answer for a jail that runs memcached (internal/apps builds it from the jail's answers)
	h.srv.SeedAppDraft("main", "cache", apps.BuildDraft(apps.DraftFacts{
		Jail:     "cache",
		Packages: []byte("memcached 1.6.39 FreeBSD https://memcached.org/\n"),
		RcConf:   []byte("memcached_enable=\"YES\"\nmemcached_flags=\"-l 0.0.0.0 -m 64\"\n"),
		Sockets:  []byte("nobody memcached 801 26 tcp4 *:11211 *:*\nroot sshd 7 3 tcp4 *:22 *:*\n"),
		Volumes:  []string{"/var/db/memcached"},
		Owners:   []byte("nobody:nobody /var/db/memcached\nnobody:nobody /var/run/memcached\n"),
	}))
	out := filepath.Join(h.dir, "cache.yaml")
	tr := h.transcript()
	tr.ok("app", "export", "cache")
	tr.ok("app", "export", "cache", "--file", out)
	tr.do("", "app", "validate", out)
	tr.do("", "app", "export", "cache", "--file", out)
	tr.ok("app", "export", "cache", "--file", filepath.Join(h.dir, "other.yaml"))
	tr.ok("app", "export", "cache", "-o", "json")
	tr.do("", "app", "export", "cache", "-o", "csv")
	tr.ok("app", "export", "plain")
	tr.do("", "app", "export", "off")
	tr.do("", "app", "export", "missing")
	tr.do("", "app", "export")
	tr.golden("app_export")

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Parse("cache", data); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	// -o is the output format, as everywhere: -o json prints the draft as data and writes no file named json
	t.Chdir(h.dir)
	out2, errs, code := h.run("", "app", "export", "cache", "-o", "json")
	if code != 0 || !strings.Contains(out2, `"definition"`) {
		t.Fatalf("%d %q %s", code, out2, errs)
	}
	if _, err := os.Stat("json"); err == nil {
		t.Error("-o json wrote a file")
	}
}

// A server without the extension answers unsupported before anything is sent.
func TestAppExportNeedsTheExtension(t *testing.T) {
	h := newHarness(t, fake.WithExtensions("operations", "etag", "events", "jails"))
	_, errs, code := h.run("", "app", "export", "cache")
	if code != 6 || !strings.Contains(errs, "app_draft") {
		t.Fatalf("%d %s", code, errs)
	}
}

// Definitions of the host's local directory are listed with their source,
// can be filtered on it, and say so in app info.
func TestAppsLocal(t *testing.T) {
	h := newHarness(t)
	tr := true
	h.srv.SeedLocalApp(api.App{Version: 1, Name: "memcached", Title: "memcached", Summary: "Distributed in-memory object cache.",
		Category: api.AppDatabase, Image: api.AppImage{OS: "freebsd", ReleaseMin: "15.1"},
		Packages: []api.AppPackage{{Name: "memcached", Repo: "ports", Version: "1.6.39"}}, Services: []api.AppService{{Name: "memcached", Start: &tr}},
		Ports:  []api.AppPort{{Name: "memcached", Port: 11211, Proto: "tcp"}},
		Health: &api.AppHealth{TCP: 11211, WaitSeconds: 30}})
	h.srv.SeedLocalApp(api.App{Version: 1, Name: "valkey", Title: "Valkey (ours)", Summary: "Our own Valkey.", Category: api.AppDatabase,
		Image: api.AppImage{OS: "freebsd", ReleaseMin: "15.1"}, Packages: []api.AppPackage{{Name: "valkey", Repo: "ports"}}})
	t2 := h.transcript()
	t2.ok("app", "list", "--source", "local")
	t2.ok("app", "list", "--source", "catalog", "--category", "database")
	t2.do("", "app", "list", "--source", "elsewhere")
	t2.ok("app", "info", "valkey")
	t2.ok("app", "list", "-o", "wide")
	h.tty = true
	h.env["NO_COLOR"] = "1"
	t2.ok("app", "list", "--source", "local")
	h.tty = false
	t2.golden("apps_local")

	out, _, code := h.run("", "app", "list", "-o", "json")
	var l []api.AppSummary
	if code != 0 || json.Unmarshal([]byte(out), &l) != nil {
		t.Fatal(out)
	}
	for _, s := range l {
		want := api.AppSourceCatalog
		if s.Name == "memcached" || s.Name == "valkey" {
			want = api.AppSourceLocal
		}
		if s.Source != want || (s.Name == "valkey") != (s.Overrides == api.AppSourceCatalog) {
			t.Errorf("%+v", s)
		}
	}
	if out, _, code := h.run("", "__complete", "app", "list", "--source", ""); code != 0 || !strings.Contains(out, "local") {
		t.Errorf("%d %s", code, out)
	}
}
