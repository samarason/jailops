package priv

import (
	"context"
	"path/filepath"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// What the helper verifies and then runs lives below its own directories: nobody but root may own anything there.
func TestOwnDirectoriesAreRootOwned(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if e.cfg.WorkDir == "" {
		t.Skip("no work directory")
	}
	p := filepath.Join(e.cfg.WorkDir, "dl", "x.tar")
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: 0o644, Parents: true, UID: 1001, GID: 1001}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a file below the work directory owned by another user: %v", err)
	}
	if err := e.local.WriteFile(ctx, WriteFileReq{Path: p, Data: []byte("x"), Mode: 0o644, Parents: true}); err != nil {
		t.Errorf("a file of root: %v", err)
	}
	if err := e.local.MkdirAll(ctx, MkdirReq{Path: filepath.Join(e.cfg.WorkDir, "d"), Mode: 0o755, UID: 0, GID: 1001}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a directory below the work directory with another group: %v", err)
	}
}
