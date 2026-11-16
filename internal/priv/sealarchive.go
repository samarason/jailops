package priv

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// sealArchive copies the archive an extraction is asked for into a directory of the helper's own (root's, mode 0700) and
// returns the copy. The helper lists the members of an archive before it extracts it, and the archive lies where the
// daemon can write: a file that is looked at and then read again can have changed in between. What is listed and what is
// extracted is the copy.
func (l *Local) sealArchive(path string) (string, func(), error) {
	none := func() {}
	r, err := l.cfg.resolveRead(path)
	if err != nil {
		return "", none, err
	}
	root, err := r.openRoot()
	if err != nil {
		return "", none, mapFSErr(err)
	}
	defer root.Close()
	src, err := root.OpenFile(r.rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", none, mapFSErr(err)
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return "", none, invalid("tar: %q is not a regular file", path)
	}
	dir, err := os.MkdirTemp(l.cfg.StateDir, ".tar-")
	if err != nil {
		return "", none, fmt.Errorf("sealing the archive: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst, err := os.OpenFile(filepath.Join(dir, "archive.tar.gz"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return "", none, fmt.Errorf("sealing the archive: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		cleanup()
		return "", none, mapFSErr(err)
	}
	if err := dst.Close(); err != nil {
		cleanup()
		return "", none, err
	}
	return filepath.Join(dir, "archive.tar.gz"), cleanup, nil
}
