package imagegen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// alpineWorld serves a tarball, its digest and an index like the mirror does.
func alpineWorld(t *testing.T, spec api.ImageSpec) (*world, *[]string) {
	w := newWorld(t)
	w.specs["alp"] = spec
	w.Files.Data["/etc/resolv.conf"] = []byte("nameserver 192.0.2.53\n")
	tarball := []byte("tarball")
	var cmds []string
	w.Exec.Handler = func(a []string) ([]byte, error) {
		cmds = append(cmds, strings.Join(a, " "))
		switch a[0] {
		case "fetch":
			dst, url := a[2], a[3]
			switch {
			case strings.HasSuffix(url, ".sha256"):
				w.Files.Data[dst] = []byte(sum(tarball) + "  alpine-minirootfs-3.22.1-aarch64.tar.gz\n")
			case strings.HasSuffix(url, "latest-releases.yaml"):
				w.Files.Data[dst] = []byte("-\n  title: Mini root filesystem\n  file: alpine-minirootfs-3.22.1-aarch64.tar.gz\n  sha256: " + sum(tarball) + "\n-\n  file: alpine-standard-3.22.1-aarch64.iso\n  sha256: " + strings.Repeat("0", 64) + "\n")
			default:
				w.Files.Data[dst] = tarball
			}
		case "tar":
			root := a[2]
			w.Files.Data[root+"/bin/busybox"] = []byte("x")
			w.Files.Data[root+"/lib/apk/db/installed"] = []byte("P:busybox\nV:1.37\n\nP:musl\nV:1.2\n\n")
		}
		return nil, nil
	}
	return w, &cmds
}

func TestAlpineBuildsFromTheMirrorAndRunsApkInAJail(t *testing.T) {
	w, cmds := alpineWorld(t, api.ImageSpec{OS: api.OSLinux, Release: "3.22.1", Arch: "arm64",
		Source: api.ImageSource{Type: "minirootfs", Sets: []string{"openssh", "nginx"}}})
	r, err := w.M.Build(bg, "alp", api.ImageBuild{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Generation.Packages != 2 {
		t.Fatal(r.Generation)
	}
	all := strings.Join(*cmds, "\n")
	root := "/jailops/images/alp/staging-g1"
	for _, want := range []string{
		"fetch -o /var/tmp/jo/alp-g1/rootfs.tar.gz.sha256 https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.1-aarch64.tar.gz.sha256",
		"fetch -o /var/tmp/jo/alp-g1/rootfs.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.1-aarch64.tar.gz",
		"tar -C " + root + " -xpzf /var/tmp/jo/alp-g1/rootfs.tar.gz",
		"sysctl kern.elf64.fallback_brand=3",
		"mount -t nullfs " + root + " " + root + "/compat/linux",
		"mount -t tmpfs -o size=268435456,mode=1777 tmpfs " + root + "/compat/linux/dev/shm",
		"jexec jobuild-alp-g1 /sbin/apk --no-interactive update",
		"jexec jobuild-alp-g1 /sbin/apk --no-interactive add openssh nginx",
		"jexec jobuild-alp-g1 /sbin/apk --no-interactive verify",
		"jail -r jobuild-alp-g1",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	// Mounts go up in the verified order and come down in reverse.
	order := func(s string) int { return strings.Index(all, s) }
	if !(order("-t devfs") < order("-t fdescfs") && order("-t fdescfs") < order("-t nullfs") && order("-t nullfs") < order("-t tmpfs") &&
		order("-t tmpfs") < order("-t linprocfs") && order("-t linprocfs") < order("-t linsysfs") && order("-t linsysfs") < order("jail -c")) {
		t.Errorf("mount order:\n%s", all)
	}
	var um []string
	for _, c := range *cmds {
		if strings.HasPrefix(c, "umount ") {
			um = append(um, strings.TrimPrefix(c, "umount "+root))
		}
	}
	if strings.Join(um, " ") != "/sys /proc /compat/linux/dev/shm /compat/linux /dev/fd /dev" {
		t.Errorf("umount order: %v", um)
	}
	if got := string(w.Files.Data[root+"/etc/apk/repositories"]); got != "https://dl-cdn.alpinelinux.org/alpine/v3.22/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community\n" {
		t.Errorf("repositories %q", got)
	}
	if string(w.Files.Data[root+"/etc/resolv.conf"]) != "# written by JailOps\nnameserver 192.0.2.53\n" {
		t.Errorf("resolv.conf %q", w.Files.Data[root+"/etc/resolv.conf"])
	}
}

func TestAlpineBranchResolvesTheNewestRelease(t *testing.T) {
	w, cmds := alpineWorld(t, api.ImageSpec{OS: api.OSLinux, Release: "3.22", Arch: "arm64", Source: api.ImageSource{Type: "minirootfs"}})
	if _, err := w.M.Build(bg, "alp", api.ImageBuild{}); err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(*cmds, "\n"); !strings.Contains(all, "fetch -o /var/tmp/jo/alp-g1/latest-releases.yaml https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/latest-releases.yaml") ||
		!strings.Contains(all, "/releases/aarch64/alpine-minirootfs-3.22.1-aarch64.tar.gz") {
		t.Fatal(all)
	}
}

func TestAlpineRefusesATamperedDownloadAndCleansUp(t *testing.T) {
	w, cmds := alpineWorld(t, api.ImageSpec{OS: api.OSLinux, Release: "3.22.1", Arch: "amd64", Source: api.ImageSource{Type: "minirootfs"}})
	inner := w.Exec.Handler
	w.Exec.Handler = func(a []string) ([]byte, error) {
		out, err := inner(a)
		if a[0] == "fetch" && !strings.HasSuffix(a[3], ".sha256") {
			w.Files.Data[a[2]] = []byte("tampered")
		}
		return out, err
	}
	before := w.Z.Dump()
	if _, err := w.M.Build(bg, "alp", api.ImageBuild{}); err == nil || !strings.Contains(err.Error(), "does not match") || w.Z.Dump() != before {
		t.Fatalf("%v", err)
	}
	if all := strings.Join(*cmds, "\n"); strings.Contains(all, "-xpzf") || strings.Contains(all, "jail -c") || !strings.Contains(all, "x86_64") {
		t.Fatalf("a tampered tarball was used:\n%s", all)
	}
}

func TestAlpineFailureInTheJailTearsEverythingDown(t *testing.T) {
	w, cmds := alpineWorld(t, api.ImageSpec{OS: api.OSLinux, Release: "3.22.1", Arch: "arm64", Source: api.ImageSource{Type: "minirootfs"}})
	inner := w.Exec.Handler
	w.Exec.Handler = func(a []string) ([]byte, error) {
		if a[0] == "jexec" {
			*cmds = append(*cmds, strings.Join(a, " "))
			return []byte("ERROR: unable to select packages"), errors.New("exit status 1")
		}
		return inner(a)
	}
	if _, err := w.M.Build(bg, "alp", api.ImageBuild{}); err == nil {
		t.Fatal("a failing apk was accepted")
	}
	all := strings.Join(*cmds, "\n")
	for _, want := range []string{"jail -r jobuild-alp-g1", "umount /jailops/images/alp/staging-g1/sys", "umount /jailops/images/alp/staging-g1/dev", "devfs rule -s"} {
		if !strings.Contains(all, want) {
			t.Errorf("no cleanup %q:\n%s", want, all)
		}
	}
}

func TestAlpineSpecChecks(t *testing.T) {
	m := Minirootfs{}
	good := api.ImageSpec{OS: api.OSLinux, Release: "3.22.1", Arch: "amd64", Source: api.ImageSource{Type: "minirootfs"}}
	if err := m.CheckSpec(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*api.ImageSpec){
		"freebsd": func(s *api.ImageSpec) { s.OS = api.OSFreeBSD },
		"arch":    func(s *api.ImageSpec) { s.Arch = "riscv64" },
		"release": func(s *api.ImageSpec) { s.Release = "edge" },
		"http": func(s *api.ImageSpec) {
			s.Source.Repo = "http://x/y.tar.gz"
			s.Source.Keys = "sha256:" + strings.Repeat("a", 64)
		},
		"unpinned":  func(s *api.ImageSpec) { s.Source.Repo = "https://x/y.tar.gz" },
		"badpin":    func(s *api.ImageSpec) { s.Source.Keys = "sha256:xyz" },
		"badpkg":    func(s *api.ImageSpec) { s.Source.Sets = []string{"-o"} },
		"pkgsslash": func(s *api.ImageSpec) { s.Source.Sets = []string{"a/b"} },
	} {
		s := good
		mut(&s)
		if err := m.CheckSpec(s); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPkgBaseCopiesKeysAndUsesTheVerifiedConf(t *testing.T) {
	w := newWorld(t)
	root := "/jailops/images/fb/staging-g1"
	var cmds []string
	seededBeforePkg, sawPkg := false, false
	w.Exec.Handler = func(a []string) ([]byte, error) {
		cmds = append(cmds, strings.Join(a, " "))
		if len(a) > 1 && a[0] == "pkg" && a[1] == "-r" && !sawPkg {
			sawPkg = true
			seededBeforePkg = w.Files.Dirs[root+"/usr/share/keys"]
		}
		return w.handle(a)
	}
	if _, err := w.M.Build(bg, "fb", api.ImageBuild{}); err != nil {
		t.Fatal(err)
	}
	if !sawPkg || !seededBeforePkg {
		t.Fatalf("the host keys must be seeded into the root before the first pkg -r (pkg seen %v, seeded %v):\n%s", sawPkg, seededBeforePkg, strings.Join(cmds, "\n"))
	}
	if cmds[0] != "pkg config abi" {
		t.Errorf("the ABI comes from the host first: %s", cmds[0])
	}
	first := -1
	for i, c := range cmds {
		if strings.HasPrefix(c, "pkg -r ") {
			first = i
			break
		}
	}
	if first < 0 {
		t.Fatalf("no pkg -r command ran:\n%s", strings.Join(cmds, "\n"))
	}
	if !strings.Contains(cmds[first], "-o ABI=FreeBSD:15:amd64 -o REPOS_DIR=/var/tmp/jo/fb-g1/repos -o IGNORE_OSVERSION=yes") {
		t.Errorf("%s", cmds[first])
	}
	conf := string(w.Files.Data["/var/tmp/jo/fb-g1/repos/jailops.conf"])
	if conf != "" { // removed with the work directory after the build
		t.Logf("%s", conf)
	}
}

func TestPkgBaseRepoConfText(t *testing.T) {
	w := newWorld(t)
	const relKeys, latestKeys = "/usr/share/keys/pkgbase-${VERSION_MAJOR}", "/usr/share/keys/pkg"
	for _, c := range []struct{ rel, url, keys string }{
		{"15.0-RELEASE", "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_0", relKeys},
		{"15.0-RELEASE-p1", "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_0", relKeys},
		{"15.1-RELEASE", "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_1", relKeys},
		{"15.1-RELEASE-p6", "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_1", relKeys},
		// base_latest is signed with the key of the ports repositories (verified on 15.2-PRERELEASE)
		{"15.0-STABLE", "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest", latestKeys},
		{"15.2-PRERELEASE", "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest", latestKeys},
		{"16.0-CURRENT", "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest", latestKeys},
	} {
		b := &Build{M: w.M, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: c.rel, Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}, Work: "/w"}
		st := PkgBase{}.repoConf(b)
		if err := st.Do(bg); err != nil {
			t.Fatal(err)
		}
		got := string(w.Files.Data["/w/repos/jailops.conf"])
		for _, want := range []string{`url: "` + c.url + `"`, `mirror_type: "srv"`, `fingerprints: "` + c.keys + `"`} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: no %q in\n%s", c.rel, want, got)
			}
		}
	}
}
