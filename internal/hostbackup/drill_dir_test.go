package hostbackup

import (
	"os"
	"path/filepath"
	"testing"
)

// The directory a drill restores decrypted files into is this user's and nobody else's.
func TestEnsurePrivateDir(t *testing.T) {
	base := t.TempDir()
	mine := filepath.Join(base, "mine")
	if err := ensurePrivateDir(mine); err != nil {
		t.Fatalf("a directory that is not there is made: %v", err)
	}
	if err := ensurePrivateDir(mine); err != nil {
		t.Fatalf("the one made is accepted again: %v", err)
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(open); err == nil {
		t.Error("a directory others can enter was accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(mine, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(link); err == nil {
		t.Error("a symlink was accepted")
	}
}
