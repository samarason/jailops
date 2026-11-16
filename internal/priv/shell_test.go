package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// The shell setup of a jail (docs/shell.md) needs nothing new of the helper: pkg -r ROOT install -y bash is the
// app installer's command, and the prompt files are ordinary files below the jail root. A jail root that
// points one of them outside, with a symbolic link, gets nothing written there.
func TestShellSetupThroughTheHelper(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	if err := os.MkdirAll(filepath.Join(root, "usr", "local", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	argv := apps.PkgInstallArgv(root, "ports", []string{api.BashPackage})
	if _, out, err := e.cfg.CheckCommandCtx(ctx, argv); err != nil || out[0] != "/usr/sbin/pkg" {
		t.Fatalf("%q: %q %v", argv, out, err)
	}
	body, err := render.PromptFile(api.DefaultPS1(api.DefaultPromptColor))
	if err != nil {
		t.Fatal(err)
	}
	hook, err := render.PromptHookSet("", true)
	if err != nil {
		t.Fatal(err)
	}
	for p, data := range map[string]string{api.PromptFile: body, api.ProfilePath: hook, api.BashrcPath: hook} {
		if err := e.local.WriteFile(ctx, WriteFileReq{Path: root + p, Data: []byte(data), Mode: 0o644, Parents: true}); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		if b, err := os.ReadFile(root + p); err != nil || string(b) != data {
			t.Fatalf("%s on disk: %q %v", p, b, err)
		}
		if fi, _ := os.Stat(root + p); fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s: mode %v", p, fi.Mode())
		}
	}
	// a hostile jail made its bash.bashrc a link to a host file: refused, the host file untouched
	host := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(host, []byte("host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(root + api.BashrcPath)
	if err := os.Symlink(host, root+api.BashrcPath); err != nil {
		t.Fatal(err)
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: root + api.BashrcPath, Data: []byte(hook), Mode: 0o644}); err == nil {
		t.Fatal("wrote through a symbolic link")
	}
	if b, _ := os.ReadFile(host); string(b) != "host\n" {
		t.Fatalf("the host file changed: %q", b)
	}
	// and a link of profile.d out of the root
	os.RemoveAll(filepath.Join(root, "usr", "local", "etc", "profile.d"))
	if err := os.Symlink(filepath.Dir(host), filepath.Join(root, "usr", "local", "etc", "profile.d")); err != nil {
		t.Fatal(err)
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: root + api.PromptFile, Data: []byte(body), Mode: 0o644, Parents: true}); err == nil {
		t.Fatal("wrote through a linked directory")
	}
	if ents, _ := os.ReadDir(filepath.Dir(host)); len(ents) != 1 || !strings.HasSuffix(ents[0].Name(), "host-file") {
		t.Fatalf("something was written next to the host file: %v", ents)
	}
}
