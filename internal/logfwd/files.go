package logfwd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openNoFollow opens path for reading by walking from / one component at a time with O_NOFOLLOW: a symlink at any
// component is refused, so nobody who can change a directory on the way can point the read somewhere else between
// a check and the open. dir opens a directory, else a file (never blocking on a fifo).
func openNoFollow(path string, dir bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%s is not a clean absolute path", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: "/", Err: err}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for i, p := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 || dir {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, err := unix.Openat(fd, p, flags, 0)
		unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) || errors.Is(err, unix.ENOTDIR) {
				return nil, fmt.Errorf("%s: a component of the path is a symlink or not a directory", path)
			}
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		fd = next
	}
	if !dir {
		if err := unix.SetNonblock(fd, false); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// statOf is the mode and owner of an open file, from the descriptor.
func statOf(f *os.File) (fs.FileMode, uint32, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	return fi.Mode(), st.Uid, nil
}

// CheckSecretsDir checks the directory that API sinks name their files in: reached without a symlink, a directory
// owned by root, writable by nobody else and closed to others (0750 root:jailops, or 0700 when the daemon runs as
// root).
func CheckSecretsDir(dir string) error {
	f, err := openNoFollow(dir, true)
	if err != nil {
		return err
	}
	defer f.Close()
	mode, uid, err := statOf(f)
	if err != nil {
		return err
	}
	switch {
	case !mode.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case uid != 0:
		return fmt.Errorf("%s is not owned by root", dir)
	case mode.Perm()&0o027 != 0:
		return fmt.Errorf("%s has mode %04o: use 0750 with the group of the daemon", dir, mode.Perm())
	}
	return nil
}

// inSecretsDir reports whether p names a plain file directly in dir.
func inSecretsDir(dir, p string) bool {
	if dir == "" || filepath.Dir(p) != dir {
		return false
	}
	b := filepath.Base(p)
	return b != "." && b != ".." && len(b) <= 255
}
