package priv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"jailops.net/jailops/internal/sys/run"
)

const sealGood = "jailops: {\n  url: \"https://pkg.freebsd.org/${ABI}/latest\",\n  signature_type: \"fingerprints\",\n  fingerprints: \"/usr/share/keys/pkg\",\n  enabled: yes\n}\n"

func sealEnv(t *testing.T) (e *env, root, repos string) {
	e = newEnv(t)
	root = filepath.Join(e.cfg.MountBase, "images", "x", "g1", "root")
	repos = filepath.Join(e.cfg.StateDir, "repos")
	for _, d := range []string{root, repos} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.runner.On("/usr/sbin/pkg", []string{run.RestArgs}, "ok\n")
	return
}

func runPkgWith(e *env, root, repos string) error {
	ctx := WithAdmin(context.Background(), "a")
	_, err := e.local.Runner().Run(ctx, run.Cmd{Name: "pkg", Args: []string{"-r", root, "-o", "REPOS_DIR=" + repos, "-o", "ASSUME_ALWAYS_YES=yes", "install", "-y", "x"}})
	return err
}

// The repository check has to describe what pkg reads: the whole directory, whole files, one value per key.
func TestSealReposRefusesWhatTheCheckCouldNotSee(t *testing.T) {
	evil := "repo: {\n  url: \"http://evil.example/x\",\n  signature_type: \"none\",\n  enabled: yes\n}\n"
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"an evil file among more than the entries that are looked at": {map[string]string{"evil.conf": evil}, "evil.example"},
		"an evil block behind more than 8 KiB of comments":            {map[string]string{"r.conf": sealGood + "# " + strings.Repeat("x", 9000) + "\n" + "repo: {\n  url: \"http://evil.example/x\",\n  signature_type: \"none\"\n}\n"}, "not one JailOps writes"},
		"a key twice, the evil one first":                             {map[string]string{"r.conf": "jailops: {\n  url: \"http://evil.example/x\",\n  url: \"https://pkg.freebsd.org/x\",\n  signature_type: \"fingerprints\",\n  fingerprints: \"/usr/share/keys/pkg\"\n}\n"}, "twice"},
		"a key hidden on a line that ends in a brace":                 {map[string]string{"r.conf": "jailops: {\n  enabled: yes } evil: {\n  url: \"https://pkg.freebsd.org/x\",\n  signature_type: \"fingerprints\",\n  fingerprints: \"/usr/share/keys/pkg\"\n}\n"}, "not one JailOps writes"},
		"two blocks": {map[string]string{"r.conf": sealGood + sealGood}, "not one JailOps writes"},
	} {
		e, root, repos := sealEnv(t)
		for n, b := range tc.files {
			if err := os.WriteFile(filepath.Join(repos, n), []byte(b), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if name == "an evil file among more than the entries that are looked at" {
			for i := 0; i < 200; i++ {
				os.WriteFile(filepath.Join(repos, fmt.Sprintf("pad%03d.txt", i)), nil, 0o644)
			}
			tc.want = "more than"
		}
		err := runPkgWith(e, root, repos)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal with %q", name, err, tc.want)
		}
	}
}

// pkg gets a copy of the bytes that were checked, in a directory of the helper's that is gone afterwards: a change
// the daemon makes after the check does not reach pkg.
func TestSealReposGivesPkgACopyOfWhatWasChecked(t *testing.T) {
	e, root, repos := sealEnv(t)
	orig := filepath.Join(repos, "r.conf")
	if err := os.WriteFile(orig, []byte(sealGood), 0o644); err != nil {
		t.Fatal(err)
	}
	argv := []string{"pkg", "-r", root, "-o", "REPOS_DIR=" + repos, "install", "-y", "x"}
	sealed, cleanup, err := e.local.sealRepos(context.Background(), argv)
	if err != nil {
		t.Fatal(err)
	}
	dir := reposDirOf(sealed[1:])
	if dir == "" || dir == repos || !strings.HasPrefix(dir, e.cfg.StateDir+"/") {
		t.Fatalf("REPOS_DIR %q is not a directory of the helper's own", dir)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the sealed directory: %v %v", fi, err)
	}
	// the daemon rewrites its file after the check
	if err := os.WriteFile(orig, []byte(strings.ReplaceAll(sealGood, "pkg.freebsd.org", "evil.example")), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "r.conf"))
	if err != nil || string(b) != sealGood {
		t.Fatalf("the sealed copy changed with the original: %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "r.conf")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode of the sealed file: %v", fi)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the sealed directory is still there: %v", err)
	}
}

// What pkg is run with is the sealed directory, and a configuration that is not a plain file is refused.
func TestSealReposRunsPkgOnTheSealedDirectory(t *testing.T) {
	e, root, repos := sealEnv(t)
	if err := os.WriteFile(filepath.Join(repos, "r.conf"), []byte(sealGood), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPkgWith(e, root, repos); err != nil {
		t.Fatal(err)
	}
	var ran string
	for _, c := range e.runner.Calls() {
		if strings.Contains(strings.Join(c.Cmd.Args, " "), "REPOS_DIR=") {
			ran = strings.Join(c.Cmd.Args, " ")
		}
	}
	if ran == "" || strings.Contains(ran, "REPOS_DIR="+repos) {
		t.Fatalf("pkg ran on %q", ran)
	}
	// a link in place of the configuration
	os.Remove(filepath.Join(repos, "r.conf"))
	if err := os.Symlink("/etc/passwd", filepath.Join(repos, "r.conf")); err != nil {
		t.Fatal(err)
	}
	if err := runPkgWith(e, root, repos); err == nil {
		t.Fatal("a link as the repository configuration was accepted")
	}
}

// jail(8) follows a symbolic link in path, so the root of a jail is the one place <mount>/projects/<project>/
// jails/<name>/root, reached without a link.
func TestJailPathIsTheJailsOwnRootWithoutLinks(t *testing.T) {
	e := newEnv(t)
	own := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := func(path string) string {
		return strings.Replace(e.goodConf(), own, path, 1)
	}
	ctx := WithAdmin(context.Background(), "a")
	if err := e.cfg.checkJailConf(ctx, "alpha_web", conf(own)); err != nil {
		t.Fatalf("the jail's own root: %v", err)
	}
	link := filepath.Join(own, "x")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a link to / below the root":  link,
		"another project's root":      filepath.Join(e.cfg.MountBase, "projects", "beta", "jails", "web", "root"),
		"another jail's root":         filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "db", "root"),
		"a volume":                    filepath.Join(e.cfg.MountBase, "projects", "alpha", "volumes", "web"),
		"an image generation":         filepath.Join(e.cfg.MountBase, "images", "x", "g1", "root"),
		"the root's parent":           filepath.Dir(own),
		"a path that only looks like": own + "/../root",
	} {
		if err := e.cfg.checkJailConf(ctx, "alpha_web", conf(path)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the jail's root is replaced by a link after the file was written: the check at the start refuses it
	os.Remove(link)
	if err := os.RemoveAll(own); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", own); err != nil {
		t.Fatal(err)
	}
	if err := e.cfg.checkJailConf(ctx, "alpha_web", conf(own)); err == nil {
		t.Error("a jail root that became a link to / was accepted")
	}
}

// A mount below the mount point of a volume is refused (a link in the volume would carry it elsewhere); the layouts
// the helper lays out itself still nest.
func TestFstabNothingIsMountedBelowAVolume(t *testing.T) {
	e := newEnv(t)
	root := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	v1 := filepath.Join(e.cfg.MountBase, "projects", "alpha", "volumes", "shared")
	v2 := filepath.Join(e.cfg.MountBase, "projects", "alpha", "volumes", "other")
	for _, d := range []string{v1, v2, filepath.Join(root, "srv", "y"), filepath.Join(root, "dev", "fd")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithAdmin(context.Background(), "a")
	nested := v1 + " " + root + "/srv nullfs rw 0 0\n" + v2 + " " + root + "/srv/y nullfs rw 0 0\n"
	if err := e.cfg.checkFstab(ctx, nested, nested); err == nil || !strings.Contains(err.Error(), "nothing is mounted below a volume") {
		t.Errorf("a volume below a volume: %v", err)
	}
	twice := v1 + " " + root + "/srv nullfs rw 0 0\n" + v2 + " " + root + "/srv nullfs rw 0 0\n"
	if err := e.cfg.checkFstab(ctx, twice, twice); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("two volumes on one mount point: %v", err)
	}
	siblings := v1 + " " + root + "/srv nullfs rw 0 0\n" + v2 + " " + root + "/srv2 nullfs rw 0 0\ndevfs " + root + "/dev devfs rw 0 0\nfdescfs " + root + "/dev/fd fdescfs rw 0 0\n"
	if err := e.cfg.checkFstab(ctx, siblings, siblings); err != nil {
		t.Errorf("siblings and devfs with fdescfs: %v", err)
	}
}

// A fifo that a jail planted where the helper reads is refused at once: it neither blocks the read nor holds the slot.
func TestReadFileRefusesAFifoWithoutBlocking(t *testing.T) {
	e := newEnv(t)
	root := filepath.Join(e.cfg.MountBase, "projects", "p", "jails", "j", "root")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc", "rc.conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.local.ReadFile(context.Background(), filepath.Join(root, "etc", "rc.conf"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a fifo was read")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFile blocks on a fifo")
	}
}

// A mount that does not answer costs one probe slot, not the helper's budget of requests: the request that looks at it
// returns after a deadline, the same path is not looked at twice at once, and only a few probes can be stuck.
func TestProbeOfAHungMountDoesNotHoldTheRequestBudget(t *testing.T) {
	e := newEnv(t)
	l := e.local
	l.probeWait = 30 * time.Millisecond
	release := make(chan struct{})
	l.probeFn = func(ctx context.Context, q SourceProbeReq) (SourceProbe, error) {
		<-release
		return SourceProbe{Mounted: true}, nil
	}
	ctx := context.Background()
	start := time.Now()
	p, err := l.ProbeSource(ctx, SourceProbeReq{Path: "/mnt/box0/x"})
	if err != nil || p.Mounted || !strings.Contains(p.Detail, "does not answer") || time.Since(start) > 2*time.Second {
		t.Fatalf("a hung probe: %+v %v after %v", p, err, time.Since(start))
	}
	// the same path again: answered at once, no second goroutine
	if p, err := l.ProbeSource(ctx, SourceProbeReq{Path: "/mnt/box0/x"}); err != nil || !strings.Contains(p.Detail, "earlier look") {
		t.Fatalf("the same path twice: %+v %v", p, err)
	}
	for i := 1; i < probeSlots; i++ {
		if _, err := l.ProbeSource(ctx, SourceProbeReq{Path: fmt.Sprintf("/mnt/box%d/x", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.ProbeSource(ctx, SourceProbeReq{Path: "/mnt/other/x"}); err == nil || !strings.Contains(err.Error(), "probes of host directories") {
		t.Fatalf("a fifth stuck mount: %v", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.probeMu.Lock()
		n := len(l.probing)
		l.probeMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the probes never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A mount that landed elsewhere than at its path (the path crossed a link that a jail put there) is found by comparing
// the host's mounts before and after.
func TestAMountThatLandedElsewhereIsFound(t *testing.T) {
	before := parseMountPoints("tank/a /a zfs rw 0 0\nvol /jail/srv nullfs rw 0 0\n")
	ok := parseMountPoints("tank/a /a zfs rw 0 0\nvol /jail/srv nullfs rw 0 0\nvol2 /jail/y nullfs rw 0 0\n")
	if got := landedElsewhere(before, ok, "/jail/y"); len(got) != 0 {
		t.Errorf("a mount at its path: %v", got)
	}
	bad := parseMountPoints("tank/a /a zfs rw 0 0\nvol /jail/srv nullfs rw 0 0\nvol2 /usr/local/etc/rc.d nullfs rw 0 0\n")
	if got := landedElsewhere(before, bad, "/jail/y"); len(got) != 1 || got[0] != "/usr/local/etc/rc.d" {
		t.Errorf("a mount that went through a link: %v", got)
	}
}
