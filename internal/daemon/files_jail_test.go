package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// The daemon reads and writes files inside jails through privFiles: pg_hba.conf of app access (read, then written
// as root with Parents) and /etc/rc.conf of an app draft, at the paths the service builds from the lifecycle
// layout. Root in jail A replacing a directory of its tree with a relative symlink into jail B of another project
// must not turn either into a read or a write of B's files.
func TestJailFilesStayInTheJail(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mountBase := filepath.Join(dir, "jailops")
	cfg := priv.Config{StorageRoots: []string{"tank/jailops"}, StorageFile: filepath.Join(dir, "priv.d", "storage.conf"),
		MountBase: mountBase, ConfDir: filepath.Join(dir, "etc", "jails"), StateDir: filepath.Join(dir, "jailops", "state"),
		HelperPath: "/usr/local/libexec/jailops-priv"}
	for _, d := range []string{cfg.MountBase, cfg.ConfDir, cfg.StateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	z := zfs.NewFake("tank")
	if err := z.Create(context.Background(), zfs.CreateOpts{Name: "tank/jailops", Props: map[string]string{"jailops:managed": "on", "mountpoint": mountBase}}); err != nil {
		t.Fatal(err)
	}
	l, err := priv.NewLocal(cfg, priv.Deps{ZFS: z}, priv.WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	lc := lifecycle.Config{Root: "tank/jailops", MountBase: mountBase}
	a, b := lc.RootMP("alpha_web"), lc.RootMP("beta_db")
	const hba = "/var/db/postgres/data18/pg_hba.conf"
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(b+hba, "B hba\n")
	write(b+"/etc/rc.conf", "B rc\n")
	link := func(at, target string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(filepath.Dir(at), target)
		if err := os.Symlink(rel, at); err != nil {
			t.Fatal(err)
		}
	}
	link(a+filepath.Dir(hba), b+filepath.Dir(hba))
	link(a+"/etc", b+"/etc")
	f := privFiles{h: l}
	ctx := context.Background()
	if got, err := f.ReadFile(ctx, a+hba); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("readHBA's read: %q %v", got, err)
	}
	if err := f.WriteAtomic(ctx, a+hba, []byte("host all all 0.0.0.0/0 trust\n")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("writeHBA's write: %v", err)
	}
	if got, err := f.ReadFile(ctx, apps.RcConfPath(a)); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("the draft's rc.conf read: %q %v", got, err)
	}
	if c, _ := os.ReadFile(b + hba); string(c) != "B hba\n" {
		t.Errorf("jail B's pg_hba.conf changed: %q", c)
	}
	// the resolv.conf a network's dns change rewrites in a running jail: through A's redirected /etc, and as a symlink
	// of B's own pointing at A's tree, neither write reaches the other jail
	write(b+"/etc/resolv.conf", "B resolv\n")
	if err := f.WriteAtomic(ctx, a+"/etc/resolv.conf", []byte("nameserver 192.0.2.66\n")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("resolv.conf through a symlinked /etc: %v", err)
	}
	if c, _ := os.ReadFile(b + "/etc/resolv.conf"); string(c) != "B resolv\n" {
		t.Errorf("jail B's resolv.conf changed: %q", c)
	}
	write(a+".resolv", "A resolv\n")
	if err := os.Remove(b + "/etc/resolv.conf"); err != nil {
		t.Fatal(err)
	}
	link(b+"/etc/resolv.conf", a+".resolv")
	if err := f.WriteAtomic(ctx, b+"/etc/resolv.conf", []byte("nameserver 192.0.2.66\n")); err == nil {
		t.Error("a resolv.conf that is a symlink was replaced")
	}
	if c, _ := os.ReadFile(a + ".resolv"); string(c) != "A resolv\n" {
		t.Errorf("the symlink's target changed: %q", c)
	}
	// the same paths work in a jail that did not redirect them
	write(b+"/etc/rc.conf", "B rc\n")
	if got, err := f.ReadFile(ctx, apps.RcConfPath(b)); err != nil || string(got) != "B rc\n" {
		t.Errorf("plain rc.conf: %q %v", got, err)
	}
	if err := f.WriteAtomic(ctx, b+hba, []byte("ok\n")); err != nil {
		t.Errorf("plain pg_hba.conf: %v", err)
	}
}
