package priv

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Jail logs. The daemon serves GET /api/v1/jails/<n>/logs from the files
// below /var/log of a jail root through two read-only operations:
// fs.list_logs lists that directory and its direct subdirectories, and
// fs.tail_file reads a window from the end of one file. Both take a path of
// the class pathJailLog only: <storage mount>/projects/<project>/jails/<jail>/root/var/log
// and at most two plain name segments below it. Nothing else is readable this
// way (the storage root, the rest of a jail root, other roots, host files),
// no symlink is followed below the jail root, and only regular files are
// listed and read. UNVERIFIED: on a FreeBSD host with mounted jail roots.

// MaxTailBytes is the most fs.tail_file reads in one call.
const MaxTailBytes = 1 << 20

// MaxLogFiles bounds the entries of one listing, and the entries read from
// one directory (one more, to tell that there are more).
const MaxLogFiles = 4096

// MaxLogDirs bounds the subdirectories of var/log that are listed.
const MaxLogDirs = 64

// ListLogsRes is the reply of fs.list_logs. Truncated is set when a limit
// (MaxLogFiles, MaxLogDirs) left entries out.
type ListLogsRes struct {
	Files     []api.JailLogFile `json:"files"`
	Truncated bool              `json:"truncated,omitempty"`
}

// TailFileReq reads the end of a log file: the bytes from max(offset, size-max) to the end.
type TailFileReq struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	// Max bounds the bytes read (default and at most MaxTailBytes).
	Max int64 `json:"max,omitempty"`
}

// TailFileRes is the reply of fs.tail_file.
type TailFileRes struct {
	Data []byte `json:"data"`
	// Start is the offset Data begins at; Size the size of the file when it was read.
	Start int64 `json:"start"`
	Size  int64 `json:"size"`
}

type listLogsArgs struct {
	Dir string `json:"dir"`
}

var logSegRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$`)

// logRef is a validated path of the class pathJailLog: the storage mount
// that holds it, the jail root relative to the mount and the name below
// var/log ("" for the directory itself).
type logRef struct {
	mount string
	jail  string // projects/<project>/jails/<jail>/root
	name  string
}

// logRef checks p lexically: a clean absolute path below an active storage
// root, laid out as the log directory of a jail. The segments below var/log
// are plain names (no leading dot, no "..") and at most two deep.
func (c Config) logRef(p string) (logRef, error) {
	if !cleanAbs(p) || len(p) > maxPath {
		return logRef{}, forbidden("path %q is not a clean absolute path", p)
	}
	mount := ""
	for _, m := range c.reg.mounts() {
		if within(m, p) && p != m {
			mount = m
			break
		}
	}
	if mount == "" {
		return logRef{}, c.notBelowMount(p)
	}
	segs := strings.Split(strings.TrimPrefix(p, strings.TrimSuffix(mount, "/")+"/"), "/")
	if len(segs) < 7 || segs[0] != "projects" || segs[2] != "jails" || segs[4] != "root" || segs[5] != "var" || segs[6] != "log" {
		return logRef{}, forbidden("path %q is not the log directory of a jail (%s/projects/<project>/jails/<jail>/root/var/log)", p, mount)
	}
	if validate.Name("project", segs[1]) != nil || validate.Name("name", segs[3]) != nil {
		return logRef{}, forbidden("path %q does not name a jail", p)
	}
	rest := segs[7:]
	if len(rest) > 2 {
		return logRef{}, forbidden("path %q: at most one directory below var/log", p)
	}
	for _, s := range rest {
		if !logSegRE.MatchString(s) {
			return logRef{}, forbidden("path %q: %q is not a plain log file name", p, s)
		}
	}
	return logRef{mount: mount, jail: path.Join(segs[:5]...), name: path.Join(rest...)}, nil
}

// missing marks a not_found error with what is missing: "root" when the jail
// root is absent or empty (its dataset is not mounted), "file" otherwise.
func missing(what, format string, a ...any) error {
	return api.Errorf(api.CodeNotFound, format, a...).WithDetail("missing", what)
}

// openLogDir opens the log directory of ref as a root that nothing below it
// can escape: the jail root is opened inside the storage mount, every
// component of the jail root and of var/log must be a plain directory (not
// a symlink), and the log directory is a root of its own. A jail root that
// is missing or empty is reported as such (not mounted). A missing var/log
// is a not_found of the "file" kind.
func (ref logRef) openLogDir() (*os.Root, error) {
	sr, err := os.OpenRoot(ref.mount)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer sr.Close()
	for i, segs := 1, strings.Split(ref.jail, "/"); i <= len(segs); i++ {
		d := path.Join(segs[:i]...)
		st, err := sr.Lstat(d)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, missing("root", "jail root %s/%s is missing", ref.mount, ref.jail)
			}
			return nil, mapFSErr(err)
		}
		if !st.IsDir() {
			return nil, forbidden("%s/%s is not a directory", ref.mount, d)
		}
	}
	jr, err := openBelow(sr, ref.jail)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer jr.Close()
	top, err := jr.Open(".")
	if err != nil {
		return nil, mapFSErr(err)
	}
	names, err := top.Readdirnames(1)
	top.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, mapFSErr(err)
	}
	if len(names) == 0 {
		return nil, missing("root", "jail root %s/%s is empty", ref.mount, ref.jail)
	}
	for _, d := range []string{"var", "var/log"} {
		st, err := jr.Lstat(d)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, missing("file", "jail root %s/%s has no %s", ref.mount, ref.jail, d)
			}
			return nil, mapFSErr(err)
		}
		if !st.IsDir() {
			return nil, forbidden("%s/%s/%s is not a plain directory", ref.mount, ref.jail, d)
		}
	}
	// opened segment by segment and compared with what was checked: a var or var/log swapped for a symlink after
	// the check (to .. or to /etc of the jail) is refused
	lr, err := openBelow(jr, "var/log")
	if err != nil {
		return nil, mapFSErr(err)
	}
	return lr, nil
}

// ListLogs implements Host: the regular files of a jail's log directory
// (dir is <jail root>/var/log) and of its direct subdirectories, sorted by
// name. Symlinks, devices and deeper directories are left out. At most
// MaxLogFiles+1 entries are read from a directory and MaxLogDirs
// subdirectories listed; truncated says that a limit was hit.
func (l *Local) ListLogs(ctx context.Context, dir string) ([]api.JailLogFile, bool, error) {
	ref, err := l.cfg.logRef(dir)
	if err != nil {
		return nil, false, err
	}
	if ref.name != "" {
		return nil, false, invalid("%q is not the log directory of a jail", dir)
	}
	lr, err := ref.openLogDir()
	if err != nil {
		var ae *api.Error
		if errors.As(err, &ae) && ae.Code == api.CodeNotFound && ae.Detail["missing"] == "file" {
			return []api.JailLogFile{}, false, nil // a mounted root without var/log has no logs
		}
		return nil, false, err
	}
	defer lr.Close()
	out := []api.JailLogFile{}
	truncated := false
	add := func(prefix string, es []fs.DirEntry) {
		if len(es) > MaxLogFiles {
			truncated = true
		}
		for _, e := range es {
			if !e.Type().IsRegular() || !logSegRE.MatchString(e.Name()) {
				continue
			}
			if len(out) >= MaxLogFiles {
				truncated = true
				return
			}
			st, err := e.Info()
			if err != nil {
				continue
			}
			kind, compressed := api.LogFileKind(e.Name())
			out = append(out, api.JailLogFile{Name: path.Join(prefix, e.Name()), Size: st.Size(), ModifiedAt: st.ModTime().UTC(), Kind: kind, Compressed: compressed})
		}
	}
	entries, err := readDir(lr, ".")
	if err != nil {
		return nil, false, mapFSErr(err)
	}
	add("", entries)
	dirs := 0
	for _, e := range entries {
		// only a plain directory, never a symlink to one
		if e.Type()&fs.ModeDir == 0 || !logSegRE.MatchString(e.Name()) {
			continue
		}
		if dirs++; dirs > MaxLogDirs {
			truncated = true
			break
		}
		sub, err := readDir(lr, e.Name())
		if err != nil {
			continue
		}
		add(e.Name(), sub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, truncated, nil
}

// readDir reads at most MaxLogFiles+1 entries of a directory, in directory
// order: a jail cannot make the helper hold a directory of any size.
func readDir(r *os.Root, name string) ([]fs.DirEntry, error) {
	// O_DIRECTORY: a name the jail swapped for a FIFO after the check fails instead of blocking the helper
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	es, err := f.ReadDir(MaxLogFiles + 1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return es, err
}

// TailFile implements Host: the bytes of a log file from max(offset,
// size-limit) to its end, with that start and the size. A file shorter than
// offset is read from its beginning (it was rotated). Only a regular file
// reached without a symlink is read; limit is at most MaxTailBytes.
func (l *Local) TailFile(ctx context.Context, p string, offset, limit int64) ([]byte, int64, int64, error) {
	ref, err := l.cfg.logRef(p)
	if err != nil {
		return nil, 0, 0, err
	}
	if ref.name == "" {
		return nil, 0, 0, invalid("%q is a directory", p)
	}
	if limit == 0 {
		limit = MaxTailBytes
	}
	if limit < 0 || limit > MaxTailBytes {
		return nil, 0, 0, invalid("a read is at most %d bytes", MaxTailBytes)
	}
	if offset < 0 {
		return nil, 0, 0, invalid("offset must not be negative")
	}
	lr, err := ref.openLogDir()
	if err != nil {
		return nil, 0, 0, err
	}
	defer lr.Close()
	if d := path.Dir(ref.name); d != "." {
		st, err := lr.Lstat(d)
		if err != nil {
			return nil, 0, 0, logFSErr(err)
		}
		if !st.IsDir() {
			return nil, 0, 0, forbidden("%s is not a plain directory", d)
		}
	}
	st, err := lr.Lstat(ref.name)
	if err != nil {
		return nil, 0, 0, logFSErr(err)
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, 0, 0, forbidden("%s is a symlink", ref.name)
	}
	if !st.Mode().IsRegular() {
		return nil, 0, 0, invalid("%s is not a regular file", ref.name)
	}
	// O_NONBLOCK: a file the jail swapped for a FIFO after the check must not block the helper (it is refused below)
	f, err := lr.OpenFile(ref.name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, 0, logFSErr(err)
	}
	defer f.Close()
	if st, err = f.Stat(); err != nil {
		return nil, 0, 0, mapFSErr(err)
	}
	if !st.Mode().IsRegular() {
		return nil, 0, 0, invalid("%s is not a regular file", ref.name)
	}
	size := st.Size()
	if offset > size {
		offset = 0
	}
	start := max(offset, size-limit)
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, 0, mapFSErr(err)
	}
	// the file may have been truncated meanwhile: report what was read
	return buf[:n], start, start + int64(n), nil
}

// logFSErr is mapFSErr with a missing file marked as such.
func logFSErr(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return missing("file", "%v", err)
	}
	return mapFSErr(err)
}
