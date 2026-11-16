package imagegen

import (
	"errors"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/sdk/api"
)

func TestBuildFirstAndNext(t *testing.T) {
	w := newWorld(t)
	r1, err := w.M.Build(bg, "fb", api.ImageBuild{})
	if err != nil {
		t.Fatal(err)
	}
	g := r1.Generation
	if g.Number != 1 || g.Name != "fb#g1" || g.Dataset != "tank/jailops/images/fb/g1" || g.Packages != 2 || g.Parent != 0 || !strings.HasPrefix(g.Manifest, "sha256:") {
		t.Fatalf("%+v", g)
	}
	if g.CreatedAt != w.now {
		t.Fatal(g.CreatedAt)
	}
	if r1.Status.Aliases["latest"] != 1 || r1.Status.Aliases["stable"] != 1 {
		t.Fatal(r1.Status.Aliases)
	}
	if h, _ := w.Z.Holds(bg, g.Dataset+"@ro"); len(h) != 1 {
		t.Fatal("no hold on @ro")
	}
	for _, p := range []string{"jailops:managed", "jailops:gen", "jailops:manifest", "jailops:osrelease"} {
		if v, _ := w.Z.Get(bg, g.Dataset, p); v == "" {
			t.Fatalf("property %s missing", p)
		}
	}
	if len(w.Files.Paths()) != 3 { // the files staged in the root (the rc.conf too); work dir cleaned
		t.Fatal(w.Files.Paths())
	}
	w.repoVersion = "15.0p2"
	r2, err := w.M.Build(bg, "fb", api.ImageBuild{FromGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	g2 := r2.Generation
	if g2.Number != 2 || g2.Parent != 1 || g2.Manifest == g.Manifest {
		t.Fatalf("%+v", g2)
	}
	if g.FreeBSDVersion != "15.0-RELEASE-p1" || g2.FreeBSDVersion != "15.0-RELEASE-p2" {
		t.Fatalf("the FreeBSD versions of the generations: %q, %q", g.FreeBSDVersion, g2.FreeBSDVersion)
	}
	if o, _ := w.Z.Origin(bg, g2.Dataset); o != g.Dataset+"@ro" {
		t.Fatal(o)
	}
	if r2.Status.Aliases["latest"] != 2 || r2.Status.Aliases["stable"] != 1 {
		t.Fatalf("aliases %v: latest moves, stable stays", r2.Status.Aliases)
	}
	if err := w.M.SetAlias(bg, "fb", "stable", 2); err != nil {
		t.Fatal(err)
	}
	got, err := w.M.Resolve(bg, "fb@stable")
	if err != nil || got.Number != 2 {
		t.Fatal(got, err)
	}
	if got, err = w.M.Resolve(bg, "fb#g1"); err != nil || got.Number != 1 {
		t.Fatal(got, err)
	}
	if _, err = w.M.Resolve(bg, "fb#g9"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
	if _, err = w.M.Resolve(bg, "fb@nope"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
}

func TestBuildDryRunTouchesNothing(t *testing.T) {
	w := newWorld(t)
	before := w.state()
	w.F.Reset(0)
	r, err := w.M.Build(bg, "fb", api.ImageBuild{DryRun: true})
	if err != nil || !r.DryRun || w.F.Count() != 0 || w.state() != before {
		t.Fatal(err, w.F.Count())
	}
	joined := strings.Join(r.Plan, "\n")
	for _, want := range []string{"zfs create tank/jailops/images/fb/staging-g1", "pkg -r /jailops/images/fb/staging-g1", "zfs snapshot tank/jailops/images/fb/staging-g1@ro", "zfs rename"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan lacks %q:\n%s", want, joined)
		}
	}
}

func TestUpgradeKeepsNothingWhenThePackageSetDidNotChange(t *testing.T) {
	w := newWorld(t)
	if _, err := w.M.Build(bg, "fb", api.ImageBuild{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.M.Upgrade(bg, "fb", api.ImageBuild{}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("an upgrade without a parent: %v", err)
	}
	before := w.state()
	// The repository serves the same versions: pkg upgrade exits cleanly and changes nothing.
	r, err := w.M.Upgrade(bg, "fb", api.ImageBuild{FromGeneration: 1})
	if err != nil || !r.Unchanged || r.Generation.Number != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if after := w.state(); after != before {
		t.Fatalf("an unchanged upgrade left something behind\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if len(w.J.Recs) != 0 {
		t.Fatalf("journal not cleaned: %v", w.J.Recs)
	}
	if o, _ := w.M.Observe(bg, "fb"); len(o.Status.Generations) != 1 || o.MaxNumber != 1 || o.Status.Aliases["latest"] != 1 {
		t.Fatalf("%+v", o)
	}
	// A newer package set is kept as the next generation.
	w.repoVersion = "15.0p2"
	r, err = w.M.Upgrade(bg, "fb", api.ImageBuild{FromGeneration: 1})
	if err != nil || r.Unchanged || r.Generation.Number != 2 || r.Generation.Parent != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// Build keeps an identical generation: only Upgrade refuses one.
	if r, err := w.M.Build(bg, "fb", api.ImageBuild{FromGeneration: 2}); err != nil || r.Generation.Number != 3 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestBuildFailureSweepFirst(t *testing.T) {
	sweep(t, newWorld, func(w *world) error {
		_, err := w.M.Build(bg, "fb", api.ImageBuild{})
		return err
	})
}

func TestBuildFailureSweepFromParent(t *testing.T) {
	setup := func(t *testing.T) *world {
		w := newWorld(t)
		if _, err := w.M.Build(bg, "fb", api.ImageBuild{}); err != nil {
			t.Fatal(err)
		}
		w.repoVersion = "15.0p2"
		return w
	}
	sweep(t, setup, func(w *world) error {
		_, err := w.M.Build(bg, "fb", api.ImageBuild{FromGeneration: 1})
		return err
	})
}

func TestBuildErrors(t *testing.T) {
	tests := []struct {
		name string
		mut  func(w *world)
		req  api.ImageBuild
		code api.Code
	}{
		{"unknown parent", func(w *world) {}, api.ImageBuild{FromGeneration: 4}, api.CodeNotFound},
		{"unknown source", func(w *world) {
			s := w.specs["fb"]
			s.Source.Type = "zip"
			w.specs["fb"] = s
		}, api.ImageBuild{}, api.CodeUnsupported},
		{"wrong os", func(w *world) {
			s := w.specs["fb"]
			s.OS = api.OSLinux
			w.specs["fb"] = s
		}, api.ImageBuild{}, api.CodeInvalid},
		{"bad release", func(w *world) {
			s := w.specs["fb"]
			s.Release = "stable"
			w.specs["fb"] = s
		}, api.ImageBuild{}, api.CodeInvalid},
		{"quote in repo", func(w *world) {
			s := w.specs["fb"]
			s.Source.Repo = "x\"y"
			w.specs["fb"] = s
		}, api.ImageBuild{}, api.CodeInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.mut(w)
			before := w.state()
			if _, err := w.M.Build(bg, "fb", tc.req); !api.IsCode(err, tc.code) {
				t.Fatal(err)
			}
			if w.state() != before {
				t.Fatal("state changed")
			}
		})
	}
}

func TestBuildValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		hook func(w *world)
	}{
		{"empty package set", func(w *world) {
			w.repoVersion = ""
			w.Exec.Handler = func(a []string) ([]byte, error) { return nil, nil }
		}},
		{"missing /bin/sh", func(w *world) {
			orig := w.handle
			w.Exec.Handler = func(a []string) ([]byte, error) {
				out, err := orig(a)
				delete(w.Files.Data, a[2]+"/bin/sh")
				return out, err
			}
		}},
		{"pkg check fails", func(w *world) {
			orig := w.handle
			w.Exec.Handler = func(a []string) ([]byte, error) {
				if len(a) > 11 && a[11] == "check" {
					return []byte("missing dependency"), errors.New("exit 1")
				}
				return orig(a)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			before := w.state()
			tc.hook(w)
			if _, err := w.M.Build(bg, "fb", api.ImageBuild{}); err == nil {
				t.Fatal("build accepted")
			}
			if w.state() != before {
				t.Fatalf("leaked state:\n%s", w.state())
			}
		})
	}
}

func TestStagingLeftoverBlocksBuild(t *testing.T) {
	w := newWorld(t)
	w.Z.Create(bg, "tank/jailops/images/fb", map[string]string{"jailops:managed": "on"})
	w.Z.Create(bg, "tank/jailops/images/fb/staging-g1", nil)
	if _, err := w.M.Build(bg, "fb", api.ImageBuild{}); !api.IsCode(err, api.CodeBusy) {
		t.Fatal(err)
	}
}

func TestEnsureBuildsFirstGeneration(t *testing.T) {
	w := newWorld(t)
	g, err := w.M.Ensure(bg, "fb@stable")
	if err != nil || g.Number != 1 {
		t.Fatal(g, err)
	}
	if _, err := w.M.Ensure(bg, "fb#g7"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
}

func TestBuildSourcesAlpineDebian(t *testing.T) {
	w := newWorld(t)
	w.specs["alp"] = api.ImageSpec{OS: api.OSLinux, Release: "3.22", Arch: "amd64",
		Source: api.ImageSource{Type: "minirootfs", Repo: "https://example.invalid/alpine.tar.gz"}}
	if _, err := w.M.Build(bg, "alp", api.ImageBuild{}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("unpinned source accepted: %v", err)
	}
	// pin the digest of a known payload
	w.Files.Data["/var/tmp/jo/alp-g1/rootfs.tar.gz"] = []byte("tarball")
	pin, _ := w.Files.SHA256(bg, "/var/tmp/jo/alp-g1/rootfs.tar.gz")
	s := w.specs["alp"]
	s.Source.Keys = "sha256:" + pin
	w.specs["alp"] = s
	w.Files.Data["/etc/resolv.conf"] = []byte("nameserver 192.0.2.53\n")
	w.Exec.Handler = func(a []string) ([]byte, error) {
		if a[0] == "tar" {
			root := a[2]
			w.Files.Data[root+"/bin/busybox"] = []byte("x")
			w.Files.Data[root+"/lib/apk/db/installed"] = []byte("P:busybox\nV:1.37\n\nP:musl\nV:1.2\n\n")
		}
		return nil, nil
	}
	r, err := w.M.Build(bg, "alp", api.ImageBuild{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Generation.Packages != 2 {
		t.Fatal(r.Generation)
	}
	// wrong digest is refused and leaves nothing
	w2 := newWorld(t)
	w2.Files.Data["/etc/resolv.conf"] = []byte("nameserver 192.0.2.53\n")
	w2.specs["alp"] = s
	w2.Files.Data["/var/tmp/jo/alp-g1/rootfs.tar.gz"] = []byte("tampered")
	w2.Exec.Handler = w.Exec.Handler
	before := w2.Z.Dump()
	if _, err := w2.M.Build(bg, "alp", api.ImageBuild{}); err == nil || !strings.Contains(err.Error(), "does not match") || w2.Z.Dump() != before {
		// the digest check runs on the payload the fake fetch left in place
		t.Fatalf("tampered tarball: err=%v", err)
	}

	w.specs["deb"] = api.ImageSpec{OS: api.OSLinux, Release: "bookworm", Arch: "amd64", Source: api.ImageSource{Type: "debootstrap", Repo: "https://deb.invalid/debian", Keys: "/usr/local/share/keyrings/debian-archive-keyring.gpg"}}
	d, err := w.M.Build(bg, "deb", api.ImageBuild{DryRun: true})
	if err != nil || !strings.Contains(strings.Join(d.Plan, "\n"), "debootstrap --arch=amd64 --variant=minbase --keyring=/usr/local/share/keyrings/debian-archive-keyring.gpg bookworm /jailops/images/deb/staging-g1 https://deb.invalid/debian") {
		t.Fatal(err, d.Plan)
	}
	// without a keyring the release signature could not be checked: refused
	w.specs["deb-nokey"] = api.ImageSpec{OS: api.OSLinux, Release: "bookworm", Arch: "amd64", Source: api.ImageSource{Type: "debootstrap"}}
	if _, err := w.M.Build(bg, "deb-nokey", api.ImageBuild{DryRun: true}); err == nil {
		t.Fatal("a debootstrap image without a keyring was accepted")
	}
	// upgrade of a debootstrap generation is unsupported
	w.Z.Create(bg, "tank/jailops/images/deb", nil)
	w.Z.Create(bg, "tank/jailops/images/deb/g1", map[string]string{"jailops:managed": "on"})
	w.Z.Snapshot(bg, nil, "tank/jailops/images/deb/g1@ro")
	if _, err := w.M.Build(bg, "deb", api.ImageBuild{FromGeneration: 1}); !api.IsCode(err, api.CodeUnsupported) {
		t.Fatal(err)
	}
}

var _ = fault.ErrInjected
var _ = time.Now
