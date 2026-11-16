package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfiguredCertificateIsNeverGenerated(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "x.crt"), filepath.Join(dir, "x.key")
	now := time.Now()

	// Configured but missing: an error, nothing written.
	if _, err := loadOrCreateCert(crt, key, true, "h", nil, now); err == nil || !strings.Contains(err.Error(), "do not exist") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(crt); err == nil {
		t.Fatal("a certificate was generated at a configured path")
	}

	// Not configured: generated once, then loaded as it is.
	c1, err := loadOrCreateCert(crt, key, false, "h", []string{"h.example.test", "192.0.2.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := loadOrCreateCert(crt, key, false, "h", nil, now)
	if err != nil || fingerprintOf(c1) != fingerprintOf(c2) {
		t.Fatalf("regenerated: %v", err)
	}

	// Half a pair is refused and the survivor is untouched.
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(crt)
	for _, explicit := range []bool{false, true} {
		if _, err := loadOrCreateCert(crt, key, explicit, "h", nil, now); err == nil || !strings.Contains(err.Error(), "must both exist") {
			t.Fatalf("explicit=%v: %v", explicit, err)
		}
	}
	if after, _ := os.ReadFile(crt); string(before) != string(after) {
		t.Fatal("the certificate was overwritten")
	}

	// A pair that exists but is not a certificate is an error, never replaced.
	if err := os.WriteFile(key, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateCert(crt, key, false, "h", nil, now); err == nil {
		t.Fatal("garbage accepted")
	}
}

// The generated key is a new file of mode 0600 renamed into place: a dangling symlink at its name is replaced, and
// its target is never created.
func TestGeneratedKeyIsWrittenAtomically(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "tls", "server.crt"), filepath.Join(dir, "tls", "server.key")
	if err := os.MkdirAll(filepath.Dir(key), 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere.key")
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateCert(crt, key, false, "h", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("the key was written through the symlink")
	}
	fi, err := os.Lstat(key)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
}
