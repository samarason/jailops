package service_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/service"
)

// The configuration of the JailOps repository, with its key, is copied into a jail's root as it is on the host; a key
// elsewhere than below the host's pkg directory is refused, and a host without the configuration copies nothing.
func TestSeedJailopsRepo(t *testing.T) {
	e, s := tickingEnv(t)
	dir := t.TempDir()
	ctx := t.Context()
	root := "/jailops/projects/alpha/jails/web/root"

	if err := service.SeedJailopsRepo(s, ctx, dir, root); err != nil {
		t.Fatalf("no configuration on the host: %v", err)
	}
	if got := e.File(root + dir + "/repos/jailops.conf"); got != "" {
		t.Fatalf("copied %q from nothing", got)
	}

	if err := os.MkdirAll(filepath.Join(dir, "repos"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "jailops: {\n  url: \"https://pkg.example.test/${ABI}/latest\",\n  signature_type: \"pubkey\",\n  pubkey: \"" + dir + "/jailops.pub\",\n  enabled: yes\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "repos", "jailops.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jailops.pub"), []byte("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.SeedJailopsRepo(s, ctx, dir, root); err != nil {
		t.Fatal(err)
	}
	if got := e.File(root + dir + "/repos/jailops.conf"); got != conf {
		t.Errorf("conf %q", got)
	}
	if got := e.File(root + dir + "/jailops.pub"); !strings.Contains(got, "BEGIN PUBLIC KEY") {
		t.Errorf("key %q", got)
	}

	elsewhere := strings.Replace(conf, dir+"/jailops.pub", "/etc/passwd", 1)
	if err := os.WriteFile(filepath.Join(dir, "repos", "jailops.conf"), []byte(elsewhere), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.SeedJailopsRepo(s, ctx, dir, root); err == nil || !strings.Contains(err.Error(), "not below") {
		t.Errorf("a key outside the pkg directory: %v", err)
	}
}
