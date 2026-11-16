package priv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"jailops.net/jailops/sdk/api"
)

// ReadFileReq reads a file under an allow-listed root.
type ReadFileReq struct {
	Path string `json:"path"`
}

// WriteFileReq writes a file under an allow-listed root.
type WriteFileReq struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	// Mode is the permission bits. setuid, setgid, sticky and world-write
	// bits are refused.
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	// Parents creates missing parent directories (mode 0755, root).
	Parents bool `json:"parents,omitempty"`
}

// MkdirReq creates a directory (and parents) under an allow-listed root.
type MkdirReq struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}

// VolumeOwnerReq sets the owner and the mode of the root directory of a volume.
type VolumeOwnerReq struct {
	// Path is the mountpoint of the volume: <storage mount>/projects/<project>/volumes/<name>.
	Path string `json:"path"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	// Mode is the permission bits; setuid, setgid, sticky and world-write bits are refused for files, and here the
	// sticky bit and the id bits are refused as well.
	Mode uint32 `json:"mode"`
}

// SourceProbeReq asks about a host directory that a volume of the host's own directories would give to jails.
type SourceProbeReq struct {
	// Path is the directory: below a directory of admin-host-mount in priv.conf, and not that directory itself.
	Path string `json:"path"`
	// Write also creates and removes a file in the directory.
	Write bool `json:"write,omitempty"`
}

// SourceProbe is the answer. A directory that is missing, is not on a mount or takes no file is a state of the
// directory, not an error: the detail says which. An error is a path the helper will not look at.
type SourceProbe struct {
	// Mounted says that a mount point lies on the way from the allowed directory down to Path, so that the directory
	// is the mount's and not an empty directory of the host left behind when the mount went away.
	Mounted  bool   `json:"mounted"`
	Writable bool   `json:"writable,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// RemoveReq removes one file or one empty directory.
type RemoveReq struct {
	Path string `json:"path"`
}

const maxPath = 4096

// resolved is a path split into the allow-listed root that holds it and the
// slash-free relative name inside that root. For a path inside a tree a jail
// controls (see jailTreeDepth), root is that tree and base the storage mount above it.
type resolved struct {
	root string // real path of the root (symlinks evaluated at startup)
	rel  string // clean, relative, no ".."; "." is the root itself
	base string // the storage mount root lies in, when root is a jail tree
}

var reImageGen = regexp.MustCompile(`^(staging-)?g[0-9]+$`)

// jailTreeDepth returns how many segments of rel (relative to a storage mount) name a tree whose content a jail or an
// image build controls: a jail root and its update siblings (projects/<p>/jails/<j>/root, root.new, root.old,
// root.stale), a volume of a project (projects/<p>/volumes/<v>) and an image generation (images/<i>/g<N>,
// staging-g<N>). 0 for anything else. Root in a jail can make symlinks in its own tree; opened at the storage mount, a
// relative one would lead the helper into another jail of the same mount.
func jailTreeDepth(rel string) int {
	s := strings.Split(rel, "/")
	switch {
	case len(s) >= 5 && s[0] == "projects" && s[2] == "jails" && slices.Contains([]string{"root", "root.new", "root.old", "root.stale"}, s[4]):
		return 5
	case len(s) >= 4 && s[0] == "projects" && s[2] == "volumes":
		return 4
	case len(s) >= 3 && s[0] == "images" && reImageGen.MatchString(s[2]):
		return 3
	}
	return 0
}

// mountRel splits p into the storage mount that holds it and the rest (root "" when none does).
func (c Config) mountRel(p string) resolved {
	for _, m := range c.reg.mounts() {
		if within(m, p) {
			rel, _ := filepath.Rel(m, p)
			return resolved{root: m, rel: rel}
		}
	}
	return resolved{}
}

// inJailTree narrows a path strictly below a jail tree of a storage mount to that tree, so that os.Root confines
// every symlink to it. The tree itself (rel equal to it) stays relative to the mount.
func (c Config) inJailTree(r resolved) resolved {
	if r.base != "" || r.root == "" || !c.isMountRoot(r.root) {
		return r
	}
	n := jailTreeDepth(r.rel)
	s := strings.Split(r.rel, "/")
	if n == 0 || len(s) <= n {
		return r
	}
	tree := strings.Join(s[:n], "/")
	return resolved{root: filepath.Join(r.root, tree), rel: strings.Join(s[n:], "/"), base: r.root}
}

func (c Config) resolve(path string) (resolved, error) {
	if path == "" || len(path) > maxPath || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) {
		return resolved{}, invalid("invalid path %q", path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return resolved{}, forbidden("path %q contains ..", path)
		}
	}
	p := filepath.Clean(path)
	for _, r := range c.roots() {
		if within(r, p) {
			if err := c.checkOwnRoot(r); err != nil {
				return resolved{}, err
			}
			rel, _ := filepath.Rel(r, p)
			return c.inJailTree(resolved{root: r, rel: rel}), nil
		}
	}
	return resolved{}, forbidden("path %q is outside the allowed roots", path)
}

// openRoot opens the root directory without following a symlink at its last
// component beyond what the operator configured: the root itself may be a
// symlink the operator set up, everything below it may not escape. A jail
// tree is opened from its storage mount one plain directory at a time.
func (r resolved) openRoot() (*os.Root, error) {
	if r.base == "" {
		return os.OpenRoot(r.root)
	}
	m, err := os.OpenRoot(r.base)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	rel, err := filepath.Rel(r.base, r.root)
	if err != nil {
		return nil, err
	}
	return openBelow(m, rel)
}

// openBelowHook runs between the check of a segment and its open (tests swap the segment there).
var openBelowHook func(seg string)

// openBelow opens the directory rel below r as a root of its own, one segment at a time, following no symlink:
// each segment must be a plain directory, and once opened it must still be the directory that was checked (device
// and inode), so a segment swapped for a symlink between the check and the open is refused as well.
func openBelow(r *os.Root, rel string) (*os.Root, error) {
	cur := r
	done := func(next *os.Root) {
		if cur != r {
			cur.Close()
		}
		cur = next
	}
	for _, seg := range strings.Split(rel, "/") {
		st, err := cur.Lstat(seg)
		if err != nil {
			done(nil)
			return nil, err
		}
		if !st.IsDir() {
			done(nil)
			return nil, forbidden("%s is not a plain directory", rel)
		}
		if openBelowHook != nil {
			openBelowHook(seg)
		}
		next, err := cur.OpenRoot(seg)
		if err != nil {
			done(nil)
			return nil, err
		}
		got, err := next.Stat(".")
		if err != nil || !os.SameFile(st, got) {
			next.Close()
			done(nil)
			if err != nil {
				return nil, err
			}
			return nil, forbidden("%s changed while it was opened", rel)
		}
		done(next)
	}
	return cur, nil
}

func mapFSErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return api.Errorf(api.CodeNotFound, "%v", err)
	case errors.Is(err, fs.ErrExist):
		return api.Errorf(api.CodeAlreadyExists, "%v", err)
	case errors.Is(err, fs.ErrPermission):
		return api.Errorf(api.CodeForbidden, "%v", err)
	}
	// os.Root reports an escaping path with a plain error.
	if strings.Contains(err.Error(), "escapes from parent") || strings.Contains(err.Error(), "path escapes") {
		return forbidden("path escapes the allowed root")
	}
	return api.Errorf(api.CodeInternal, "%v", err)
}

func checkMode(mode uint32) error {
	if mode&^0o777 != 0 {
		return forbidden("mode %#o has special bits", mode)
	}
	if mode&0o002 != 0 {
		return forbidden("mode %#o is world-writable", mode)
	}
	return nil
}

func checkOwner(uid, gid uint32) error {
	if uid >= 0xfffffffe || gid >= 0xfffffffe {
		return invalid("invalid owner %d:%d", uid, gid)
	}
	return nil
}

// checkRootOwned refuses an owner other than root for what is made below the helper's own directories (the work
// directory and the jail.conf directory): the helper verifies a downloaded archive or package there and then runs it, and
// a file that the daemon's user owns could be replaced between the two.
func (c Config) checkRootOwned(r resolved, uid, gid uint32) error {
	if (uid != 0 || gid != 0) && r.base == "" && (r.root == c.WorkDir || r.root == c.ConfDir) {
		return forbidden("files below %s belong to root: owner %d:%d is refused", r.root, uid, gid)
	}
	return nil
}

// ReadFile reads a file below an allow-listed root, never following a
// symlink out of it, and never more than Limits.MaxFileBytes.
func (l *Local) ReadFile(ctx context.Context, path string) ([]byte, error) {
	r, err := l.cfg.resolveRead(path)
	if err != nil {
		return nil, err
	}
	if r.rel == "." {
		return nil, invalid("%q is a root", path)
	}
	root, err := r.openRoot()
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer root.Close()
	// O_NONBLOCK: opening a fifo that a jail planted in its tree would otherwise wait for a writer for ever, with the
	// request's slot. The file is looked at before anything is read from it, and only a regular file is read.
	f, err := root.OpenFile(r.rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, mapFSErr(err)
	}
	if !st.Mode().IsRegular() {
		return nil, invalid("%q is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(l.cfg.Limits.MaxFileBytes)+1))
	if err != nil {
		return nil, mapFSErr(err)
	}
	if len(b) > l.cfg.Limits.MaxFileBytes {
		return nil, invalid("file larger than %d bytes", l.cfg.Limits.MaxFileBytes)
	}
	return b, nil
}

// WriteFile writes a file atomically (temp file, fsync, rename) below an
// allow-listed root. Files in ConfDir are content-checked.
func (l *Local) WriteFile(ctx context.Context, q WriteFileReq) error {
	if err := l.checkFrozen(q.Path); err != nil {
		return err
	}
	r, err := l.cfg.resolve(q.Path)
	if err != nil {
		return err
	}
	if r.rel == "." {
		return invalid("%q is a root", q.Path)
	}
	if len(q.Data) > l.cfg.Limits.MaxFileBytes {
		return invalid("file larger than %d bytes", l.cfg.Limits.MaxFileBytes)
	}
	if err := checkMode(q.Mode); err != nil {
		return err
	}
	if err := checkOwner(q.UID, q.GID); err != nil {
		return err
	}
	if err := l.cfg.checkRootOwned(r, q.UID, q.GID); err != nil {
		return err
	}
	if err := l.checkConfContent(ctx, r, q.Path, q.Data); err != nil {
		return err
	}
	root, err := r.openRoot()
	if err != nil {
		return mapFSErr(err)
	}
	defer root.Close()
	dir, base := filepath.Split(r.rel)
	dir = filepath.Clean(dir)
	if q.Parents && dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return mapFSErr(err)
		}
	}
	// Refuse to replace anything that is not a regular file.
	if st, err := root.Lstat(r.rel); err == nil && !st.Mode().IsRegular() {
		return forbidden("%q exists and is not a regular file", q.Path)
	}
	tmp := filepath.Join(dir, tmpName(base))
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(q.Mode))
	if err != nil {
		return mapFSErr(err)
	}
	cleanup := func() { _ = root.Remove(tmp) }
	if _, err := f.Write(q.Data); err != nil {
		f.Close()
		cleanup()
		return mapFSErr(err)
	}
	if err := f.Chmod(os.FileMode(q.Mode)); err != nil {
		f.Close()
		cleanup()
		return mapFSErr(err)
	}
	if err := f.Chown(int(q.UID), int(q.GID)); err != nil && !l.noChown {
		f.Close()
		cleanup()
		return mapFSErr(err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return mapFSErr(err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return mapFSErr(err)
	}
	if err := root.Rename(tmp, r.rel); err != nil {
		cleanup()
		return mapFSErr(err)
	}
	if d, err := root.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// MkdirAll creates a directory below an allow-listed root.
func (l *Local) MkdirAll(ctx context.Context, q MkdirReq) error {
	if err := l.checkFrozen(q.Path); err != nil {
		return err
	}
	r, err := l.cfg.resolve(q.Path)
	if err != nil {
		return err
	}
	if err := checkMode(q.Mode); err != nil {
		return err
	}
	if err := checkOwner(q.UID, q.GID); err != nil {
		return err
	}
	if err := l.cfg.checkRootOwned(r, q.UID, q.GID); err != nil {
		return err
	}
	root, err := r.openRoot()
	if err != nil {
		return mapFSErr(err)
	}
	defer root.Close()
	if r.rel == "." {
		return nil
	}
	// A directory that already exists keeps its mode and owner: re-chowning one the daemon could have
	// swapped or pre-created would hand it to whoever the request names.
	if fi, err := root.Lstat(r.rel); err == nil {
		if !fi.IsDir() {
			return invalid("%q exists and is not a directory", q.Path)
		}
		return nil
	}
	if err := root.MkdirAll(r.rel, os.FileMode(q.Mode)); err != nil {
		return mapFSErr(err)
	}
	if err := root.Chmod(r.rel, os.FileMode(q.Mode)); err != nil {
		return mapFSErr(err)
	}
	if err := root.Chown(r.rel, int(q.UID), int(q.GID)); err != nil && !l.noChown {
		return mapFSErr(err)
	}
	return nil
}

// SetVolumeOwner sets the owner and the mode of the root of a volume, once: the volume's root must be a plain
// directory with nothing in it. The path names exactly a volume of a storage mount; it is opened from the mount one
// plain directory at a time, so nothing in a jail's reach can lead the change elsewhere.
func (l *Local) SetVolumeOwner(ctx context.Context, q VolumeOwnerReq) error {
	if err := l.checkFrozen(q.Path); err != nil {
		return err
	}
	r, err := l.cfg.resolve(q.Path)
	if err != nil {
		return err
	}
	s := strings.Split(r.rel, "/")
	if r.root == "" || r.base != "" || !l.cfg.isMountRoot(r.root) || len(s) != 4 || jailTreeDepth(r.rel) != 4 {
		return forbidden("%q is not the root of a volume", q.Path)
	}
	if q.Mode&^0o777 != 0 {
		return invalid("mode %04o of a volume is at most 0777", q.Mode)
	}
	if err := checkOwner(q.UID, q.GID); err != nil {
		return err
	}
	tree := resolved{root: filepath.Join(r.root, r.rel), base: r.root, rel: "."}
	root, err := tree.openRoot()
	if err != nil {
		return mapFSErr(err)
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return mapFSErr(err)
	}
	names, err := d.Readdirnames(1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return mapFSErr(err)
	}
	if len(names) > 0 {
		return forbidden("the volume is not empty: its owner is set when it is made")
	}
	if err := root.Chmod(".", os.FileMode(q.Mode)); err != nil {
		return mapFSErr(err)
	}
	if err := root.Chown(".", int(q.UID), int(q.GID)); err != nil && !l.noChown {
		return mapFSErr(err)
	}
	return nil
}

// Remove removes a file or an empty directory below an allow-listed root.
// Roots themselves are never removed. A missing path is not an error.
func (l *Local) Remove(ctx context.Context, path string) error {
	if err := l.checkFrozen(path); err != nil {
		return err
	}
	r, err := l.cfg.resolve(path)
	if err != nil {
		return err
	}
	if r.rel == "." {
		return forbidden("%q is a root", path)
	}
	root, err := r.openRoot()
	if err != nil {
		return mapFSErr(err)
	}
	defer root.Close()
	if err := root.Remove(r.rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return mapFSErr(err)
	}
	return nil
}

// recursiveRemovable reports whether a whole tree may be removed at path: the scratch trees the daemon makes
// below its work directory (image builds), and the stage and merge directories of a jail's container.
func (c Config) recursiveRemovable(path string) bool {
	p := filepath.Clean(path)
	if c.WorkDir != "" && within(c.WorkDir, p) && p != c.WorkDir {
		return true
	}
	base := filepath.Base(p)
	return c.inMounts(p) && (strings.HasPrefix(base, ".seed-") || strings.HasPrefix(base, ".merge-"))
}

// RemoveAll removes path and everything below it where recursiveRemovable allows that; anywhere else it is
// Remove (one file or one empty directory).
func (l *Local) RemoveAll(ctx context.Context, path string) error {
	if err := l.checkFrozen(path); err != nil {
		return err
	}
	if !l.cfg.recursiveRemovable(path) {
		return l.Remove(ctx, path)
	}
	r, err := l.cfg.resolve(path)
	if err != nil {
		return err
	}
	if r.rel == "." {
		return forbidden("%q is a root", path)
	}
	root, err := r.openRoot()
	if err != nil {
		return mapFSErr(err)
	}
	defer root.Close()
	if err := root.RemoveAll(r.rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return mapFSErr(err)
	}
	return nil
}

// confFileFor returns the path of the jail.conf of a jail inside ConfDir if it
// exists as a regular file (found without following symlinks).
func (l *Local) confFileFor(name string) (string, bool) {
	root, err := os.OpenRoot(l.cfg.ConfDir)
	if err != nil {
		return "", false
	}
	defer root.Close()
	for _, rel := range []string{name + ".conf", filepath.Join(name, "jail.conf")} {
		if st, err := root.Lstat(rel); err == nil && st.Mode().IsRegular() {
			return filepath.Join(l.cfg.ConfDir, rel), true
		}
	}
	return "", false
}

// ReadOnlyFiles are host files fs.read_file may read besides the allowed
// roots: the configuration an image build copies or checks, and /etc/rc.conf, which doctor's persistence check reads
// for `gateway_enable` and `ipv6_gateway_enable` (without it the check could never see them and always warned, even
// on a host where they were set: found live on the amd64 host, October 2026).
var ReadOnlyFiles = []string{"/etc/sysctl.conf", "/etc/resolv.conf", "/etc/rc.conf"}

// resolveRead is resolve for reading: the allowed roots, the fixed files of
// ReadOnlyFiles and the configured image mirrors.
func (c Config) resolveRead(path string) (resolved, error) {
	r, err := c.resolve(path)
	if err == nil || !api.IsCode(err, api.CodeForbidden) {
		return r, err
	}
	p := filepath.Clean(path)
	if slices.Contains(ReadOnlyFiles, p) {
		return resolved{root: filepath.Dir(p), rel: filepath.Base(p)}, nil
	}
	for _, m := range c.ImageMirrors {
		if within(m, p) {
			rel, _ := filepath.Rel(m, p)
			return resolved{root: m, rel: rel}, nil
		}
	}
	return resolved{}, err
}

// checkOwnRoot refuses to work in one of the helper's own directories (the jail.conf directory and the daemon's
// work directory) unless it is a real directory of root that nobody else can write. The daemon may create or replace
// what it owns, so a directory it can write could be turned into a symlink to / between a check and its use, and
// everything below it would then be done to the host as root.
func (c Config) checkOwnRoot(r string) error {
	if c.noOwnerCheck || (r != c.ConfDir && r != c.WorkDir) {
		return nil
	}
	fi, err := os.Lstat(r)
	if err != nil {
		return nil // a missing directory is an ordinary error of the operation
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return forbidden("%s is not a plain directory", r)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return forbidden("%s must belong to root and not be writable by anybody else", r)
	}
	return nil
}

// tmpName is the name of the temporary file of a write: unique for every operation, so two writes of one path do not
// disturb each other and a file or directory that a tenant made under a predictable name cannot stop the write.
func tmpName(base string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // the system has no randomness: nothing safe can be done
	}
	return "." + base + "." + hex.EncodeToString(b[:]) + ".jotmp"
}

// hostDirRoot returns the admin-host-mount directory a path lies below. The path is clean and absolute and has no
// "..", and it is not the directory itself: the mount point has to lie below it, for a directory that is a mount point
// itself is an empty directory of the host once the mount is gone.
func (c Config) hostDirRoot(path string) (root, rel string, err error) {
	if path == "" || len(path) > maxPath || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", invalid("invalid path %q", path)
	}
	for _, r := range c.Admin.HostMountRoots {
		if !within(r, path) {
			continue
		}
		if path == r {
			return "", "", api.Errorf(api.CodeForbidden, "%q is the allowed directory itself: its mount point has to lie below it", path).
				WithHint("list the directory above the mount in admin-host-mount of priv.conf")
		}
		rel, _ = filepath.Rel(r, path)
		return r, rel, nil
	}
	return "", "", api.Errorf(api.CodeForbidden, "%q is not below a directory of admin-host-mount in priv.conf", path).
		WithHint("the host operator lists the directories jails may be given with admin-host-mount")
}

// sourceDev is the device of a directory of a probe, by its path (tests give some directory a device of its own, for
// a test cannot mount anything).
var sourceDev = func(_ string, fi fs.FileInfo) (uint64, bool) { return devOf(fi) }

// devOf is the device of a file.
func devOf(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true //nolint:unconvert // the width of Dev differs by system
}

// ProbeSource looks at a host directory: it is opened from the allowed directory one plain directory at a time, so a
// symbolic link anywhere below it is refused; a change of the device on the way is a mount point; with Write a probe
// file is made in the directory and removed again.
func (l *Local) ProbeSource(ctx context.Context, q SourceProbeReq) (SourceProbe, error) {
	// A mount that hangs (a network share whose server is gone) blocks a call on it for as long as the kernel likes,
	// and nothing can interrupt that. The probe runs in its own goroutine that the request abandons after a deadline;
	// a path that has a probe in flight is not probed again, and at most probeSlots probes are in flight, so a stuck
	// mount costs one slot and never the helper's whole budget of requests.
	l.probeMu.Lock()
	if l.probing[q.Path] {
		l.probeMu.Unlock()
		return SourceProbe{Detail: "the mount does not answer: an earlier look at it has not returned"}, nil
	}
	if len(l.probing) >= probeSlots {
		l.probeMu.Unlock()
		return SourceProbe{}, forbiddenBusy("%d probes of host directories are waiting on mounts that do not answer", probeSlots)
	}
	if l.probing == nil {
		l.probing = map[string]bool{}
	}
	l.probing[q.Path] = true
	l.probeMu.Unlock()
	type result struct {
		p   SourceProbe
		err error
	}
	done := make(chan result, 1)
	bg := context.WithoutCancel(ctx)
	go func() {
		fn := l.probeFn
		if fn == nil {
			fn = l.probeSource
		}
		p, err := fn(bg, q)
		// the path is free again before the request hears of the answer: the next look must not meet its own last one
		l.probeMu.Lock()
		delete(l.probing, q.Path)
		l.probeMu.Unlock()
		done <- result{p, err}
	}()
	select {
	case r := <-done:
		return r.p, r.err
	case <-ctx.Done():
		return SourceProbe{}, ctx.Err()
	case <-time.After(l.probeDeadline()):
		return SourceProbe{Detail: "the mount does not answer: a call on it has not returned within " + l.probeDeadline().String()}, nil
	}
}

const probeSlots = 4

func (l *Local) probeDeadline() time.Duration {
	if l.probeWait > 0 {
		return l.probeWait
	}
	return 10 * time.Second
}

func (l *Local) probeSource(ctx context.Context, q SourceProbeReq) (SourceProbe, error) {
	rootPath, rel, err := l.cfg.hostDirRoot(q.Path)
	if err != nil {
		return SourceProbe{}, err
	}
	top, err := os.OpenRoot(rootPath)
	if err != nil {
		return SourceProbe{Detail: "the allowed directory " + rootPath + " cannot be opened: " + err.Error()}, nil
	}
	defer top.Close()
	fi, err := top.Stat(".")
	if err != nil {
		return SourceProbe{}, mapFSErr(err)
	}
	prev, okDev := sourceDev(rootPath, fi)
	if !okDev {
		return SourceProbe{}, api.Errorf(api.CodeUnsupported, "the device of a directory is not known on this system")
	}
	cur, mounted, at := top, false, rootPath
	closeCur := func() {
		if cur != top {
			cur.Close()
		}
	}
	for _, seg := range strings.Split(rel, "/") {
		st, err := cur.Lstat(seg)
		if err != nil {
			closeCur()
			if errors.Is(err, fs.ErrNotExist) {
				return SourceProbe{Detail: "the directory does not exist"}, nil
			}
			return SourceProbe{}, mapFSErr(err)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			closeCur()
			return SourceProbe{}, forbidden("%q resolves through a symbolic link: a directory given to jails may not contain links", q.Path)
		}
		if !st.IsDir() {
			closeCur()
			return SourceProbe{}, forbidden("%q is not a directory", q.Path)
		}
		next, err := cur.OpenRoot(seg)
		if err != nil {
			closeCur()
			return SourceProbe{}, mapFSErr(err)
		}
		got, err := next.Stat(".")
		if err != nil || !os.SameFile(st, got) {
			next.Close()
			closeCur()
			return SourceProbe{}, forbidden("%q changed while it was opened", q.Path)
		}
		closeCur()
		cur, at = next, filepath.Join(at, seg)
		if d, ok := sourceDev(at, st); ok {
			if d != prev {
				mounted = true
			}
			prev = d
		}
	}
	defer closeCur()
	if !mounted {
		return SourceProbe{Detail: "the directory is not on a mount"}, nil
	}
	out := SourceProbe{Mounted: true}
	if !q.Write {
		return out, nil
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return SourceProbe{}, api.Errorf(api.CodeInternal, "%v", err)
	}
	name := ".jailops-probe-" + hex.EncodeToString(b[:])
	f, err := cur.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		out.Detail = "no file can be created in the directory: " + strings.TrimPrefix(err.Error(), "openat "+name+": ")
		return out, nil
	}
	// the data goes to the device before the answer: a mount whose device failed takes the write into its cache
	// and only the sync says that it cannot be kept
	_, werr := f.Write([]byte("jailops\n"))
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	rerr := cur.Remove(name)
	if err := errors.Join(werr, cerr, rerr); err != nil {
		out.Detail = "a file made in the directory could not be written or removed: " + err.Error()
		return out, nil
	}
	out.Writable = true
	return out, nil
}
