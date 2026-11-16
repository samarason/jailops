package priv

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"jailops.net/jailops/sdk/api"
)

// HostKeysDir is the host directory pkg(8) finds its trusted keys in. It is
// fixed: the caller names only the image root that receives a copy.
const HostKeysDir = "/usr/share/keys"

// SeedKeys copies the host's /usr/share/keys into <root>/usr/share/keys, so
// the first pkg call inside a fresh image root can verify repository
// signatures. root must be a directory below a registered storage root (not a
// storage root itself). It is idempotent: when the destination already exists
// nothing is copied. Built on fs.copy_tree (no symlink is followed, modes,
// owners and times are kept); the source is the fixed host directory.
// UNVERIFIED on FreeBSD.
func (l *Local) SeedKeys(ctx context.Context, root string) (CopyResult, error) {
	var res CopyResult
	if !platformHasStat {
		return res, api.Errorf(api.CodeUnsupported, "fs.seed_keys is not supported on this platform")
	}
	rd, err := l.cfg.resolveMount(root)
	if err != nil {
		return res, err
	}
	root = filepath.Join(rd.root, rd.rel)
	if err := l.cfg.checkRulePath(pathJailTree, root); err != nil {
		return res, err
	}
	if fi, err := os.Lstat(root); err != nil || !fi.IsDir() {
		return res, api.Errorf(api.CodeNotFound, "image root %s is not a directory", root)
	}
	dst := filepath.Join(root, "usr", "share", "keys")
	// the destination is opened inside the image tree: a symlinked usr or share cannot lead out of it
	rk, err := l.cfg.resolveMount(dst)
	if err != nil {
		return res, err
	}
	top, err := rk.openRoot()
	if err != nil {
		return res, mapFSErr(err)
	}
	defer top.Close()
	if _, err := top.Lstat(rk.rel); err == nil {
		return res, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, mapFSErr(err)
	}
	if err := l.MkdirAll(ctx, MkdirReq{Path: dst, Mode: 0o755}); err != nil {
		return res, err
	}
	src := l.d.KeysDir
	if src == "" {
		src = HostKeysDir
	}
	sr, err := os.OpenRoot(src)
	if err != nil {
		return res, api.Errorf(api.CodeNotFound, "host keys directory %s: %v", src, err)
	}
	defer sr.Close()
	dr, err := top.OpenRoot(rk.rel)
	if err != nil {
		return res, mapFSErr(err)
	}
	defer dr.Close()
	res, err = l.runCopy(ctx, sr, dr, CopyOpts{}.filled())
	if err != nil {
		_ = top.RemoveAll(rk.rel)
	}
	return res, err
}
