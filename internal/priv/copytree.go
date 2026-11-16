package priv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"jailops.net/jailops/sdk/api"
)

// CopyOpts tunes fs.copy_tree. Zero values are the safe defaults.
type CopyOpts struct {
	// CrossFilesystem lets the copy descend into a directory on another
	// filesystem than the source directory. Without it such a directory is an
	// error: a mount point inside an image tree is never copied silently.
	CrossFilesystem bool `json:"cross_filesystem,omitempty"`
	// MaxEntries bounds the number of files, directories and links copied
	// (default 5 000 000).
	MaxEntries int64 `json:"max_entries,omitempty"`
	// MaxDepth bounds the directory depth (default 128, at most 512).
	MaxDepth int `json:"max_depth,omitempty"`
	// MaxHardLinks bounds the number of distinct multiply-linked files kept
	// in memory to recreate hard links (default 100 000).
	MaxHardLinks int `json:"max_hard_links,omitempty"`
	// Progress, when set, is called at most a few times per second and once
	// at the end. Over the socket it travels as JSON lines on the stream.
	Progress func(CopyProgress) `json:"-"`
}

// CopyProgress is one progress report.
type CopyProgress struct {
	Entries int64  `json:"entries"`
	Bytes   int64  `json:"bytes"`
	Current string `json:"current,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

// CopyResult counts what was copied.
type CopyResult struct {
	Files     int64 `json:"files"`
	Dirs      int64 `json:"dirs"`
	Symlinks  int64 `json:"symlinks"`
	HardLinks int64 `json:"hard_links"`
	Bytes     int64 `json:"bytes"`
	// Skipped counts special files (devices, fifos, sockets), which are not
	// copied.
	Skipped int64 `json:"skipped"`
	// MetaSkipped counts extended attributes and file flags the platform or
	// the filesystem refused to preserve.
	MetaSkipped int64 `json:"meta_skipped"`
}

const (
	defMaxEntries   = 5_000_000
	defMaxDepth     = 128
	maxMaxDepth     = 512
	defMaxHardLinks = 100_000
	copyChunk       = 128 << 10
	copyTmpPrefix   = ".jocopy."
	seekData        = 3 // SEEK_DATA on FreeBSD and Linux
	seekHole        = 4 // SEEK_HOLE
)

// fileID identifies an inode.
type fileID struct{ dev, ino uint64 }

// resolveMount resolves p to the active storage root mountpoint that holds it
// and the relative path below it. Neither the mountpoint itself nor a path
// outside every root is accepted.
func (c Config) resolveMount(p string) (resolved, error) {
	if p == "" || len(p) > maxPath || strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return resolved{}, invalid("invalid path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return resolved{}, forbidden("path %q contains ..", p)
		}
	}
	p = filepath.Clean(p)
	best := ""
	for _, m := range c.reg.mounts() {
		if within(m, p) && len(m) > len(best) {
			best = m
		}
	}
	if best == "" {
		return resolved{}, forbidden("path %q is outside every registered storage root", p)
	}
	rel, _ := filepath.Rel(best, p)
	if rel == "." {
		return resolved{}, forbidden("%q is a storage root", p)
	}
	return c.inJailTree(resolved{root: best, rel: rel}), nil
}

func (o CopyOpts) filled() CopyOpts {
	if o.MaxEntries <= 0 || o.MaxEntries > defMaxEntries*4 {
		o.MaxEntries = defMaxEntries
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = defMaxDepth
	}
	o.MaxDepth = min(o.MaxDepth, maxMaxDepth)
	if o.MaxHardLinks <= 0 || o.MaxHardLinks > 4*defMaxHardLinks {
		o.MaxHardLinks = defMaxHardLinks
	}
	return o
}

// CopyTree copies the directory tree src into the existing directory dst.
// Both must lie inside registered storage roots. Nothing is followed through
// a symlink: a symlink is copied as a symlink, and a path that would leave
// its root through one is refused (os.Root). Mode, owner, times, hard links,
// extended attributes and (FreeBSD) file flags are preserved; sparse files
// stay sparse. Every top-level entry of src is first built under a temporary
// name inside dst and renamed into place when complete, so a failure or a
// cancellation leaves no partial entry behind; an existing entry of dst with
// the same name is an error. Memory is bounded by the options.
//
// UNVERIFIED on FreeBSD: extended attributes (extattr), file flags, and
// SEEK_DATA/SEEK_HOLE on ZFS.
func (l *Local) CopyTree(ctx context.Context, src, dst string, o CopyOpts) (CopyResult, error) {
	if err := l.checkFrozen(dst); err != nil {
		return CopyResult{}, err
	}
	var res CopyResult
	if !platformHasStat {
		return res, api.Errorf(api.CodeUnsupported, "fs.copy_tree is not supported on this platform")
	}
	rs, err := l.cfg.resolveMount(src)
	if err != nil {
		return res, err
	}
	rd, err := l.cfg.resolveMount(dst)
	if err != nil {
		return res, err
	}
	src, dst = filepath.Join(rs.root, rs.rel), filepath.Join(rd.root, rd.rel)
	if within(src, dst) || within(dst, src) {
		return res, invalid("source and destination overlap")
	}
	o = o.filled()
	srcTop, err := rs.openRoot()
	if err != nil {
		return res, mapFSErr(err)
	}
	defer srcTop.Close()
	dstTop, err := rd.openRoot()
	if err != nil {
		return res, mapFSErr(err)
	}
	defer dstTop.Close()
	sr, err := srcTop.OpenRoot(rs.rel)
	if err != nil {
		return res, mapFSErr(err)
	}
	defer sr.Close()
	dr, err := dstTop.OpenRoot(rd.rel)
	if err != nil {
		return res, mapFSErr(err)
	}
	defer dr.Close()
	return l.runCopy(ctx, sr, dr, o)
}

// runCopy copies the directory src into the directory dst, both already
// opened as roots.
func (l *Local) runCopy(ctx context.Context, sr, dr *os.Root, o CopyOpts) (CopyResult, error) {
	var res CopyResult
	sfi, err := sr.Lstat(".")
	if err != nil {
		return res, mapFSErr(err)
	}
	dfi, err := dr.Lstat(".")
	if err != nil {
		return res, mapFSErr(err)
	}
	sst, _ := statOf(sfi)
	dst0, _ := statOf(dfi)
	if sst.id() == dst0.id() {
		return res, invalid("source and destination are the same directory")
	}
	c := &copier{
		ctx: ctx, src: sr, dst: dr, o: o, srcDev: sst.Dev, dstID: dst0.id(),
		links: map[fileID]string{}, buf: make([]byte, copyChunk), noChown: l.noChown,
	}
	err = c.run(sfi)
	c.progress("", true)
	res = c.res
	return res, err
}

type copier struct {
	ctx     context.Context
	src     *os.Root // the source directory
	dst     *os.Root // the destination directory
	o       CopyOpts
	srcDev  uint64
	dstID   fileID
	links   map[fileID]string // inode -> path of its first copy in dst
	unit    []fileID          // links recorded by the current top-level unit
	buf     []byte
	noChown bool
	entries int64
	res     CopyResult
	last    time.Time
}

func (c *copier) progress(cur string, done bool) {
	if c.o.Progress == nil {
		return
	}
	if !done && time.Since(c.last) < 250*time.Millisecond {
		return
	}
	c.last = time.Now()
	c.o.Progress(CopyProgress{Entries: c.entries, Bytes: c.res.Bytes, Current: cur, Done: done})
}

func (c *copier) run(srcInfo os.FileInfo) error {
	if err := c.removeStale(); err != nil {
		return err
	}
	d, err := c.src.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer d.Close()
	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		ents, err := d.ReadDir(256)
		for _, e := range ents {
			if err := c.topLevel(e.Name()); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return mapFSErr(err)
		}
	}
	// The destination directory takes the source directory's metadata last.
	df, err := c.dst.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer df.Close()
	sf, err := c.src.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer sf.Close()
	return c.applyMeta(sf, df, srcInfo, ".")
}

// removeStale removes temporary entries a crashed copy left in dst.
func (c *copier) removeStale() error {
	d, err := c.dst.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer d.Close()
	var stale []string
	for {
		ents, err := d.ReadDir(256)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), copyTmpPrefix) {
				stale = append(stale, e.Name())
			}
		}
		if err != nil {
			break
		}
	}
	for _, n := range stale {
		if err := c.dst.RemoveAll(n); err != nil {
			return mapFSErr(err)
		}
	}
	return nil
}

// topLevel copies one entry of the source directory atomically.
func (c *copier) topLevel(name string) error {
	if strings.HasPrefix(name, copyTmpPrefix) {
		return invalid("source entry %q uses the reserved prefix %s", name, copyTmpPrefix)
	}
	if _, err := c.dst.Lstat(name); err == nil {
		return api.Errorf(api.CodeAlreadyExists, "%s already exists in the destination", name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return mapFSErr(err)
	}
	var tmp string
	for i := 0; ; i++ {
		tmp = fmt.Sprintf("%s%08x", copyTmpPrefix, rand.Uint32())
		if _, err := c.dst.Lstat(tmp); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if i > 8 {
			return api.Errorf(api.CodeInternal, "cannot find a free temporary name")
		}
	}
	c.unit = c.unit[:0]
	if err := c.node(name, tmp, 1); err != nil {
		c.forceRemove(tmp)
		for _, id := range c.unit {
			delete(c.links, id)
		}
		return err
	}
	if _, err := c.dst.Lstat(tmp); errors.Is(err, fs.ErrNotExist) {
		return nil // a special file: nothing was built
	}
	if err := c.dst.Rename(tmp, name); err != nil {
		c.forceRemove(tmp)
		return mapFSErr(err)
	}
	// Hard link targets recorded under the temporary name now live at name.
	for _, id := range c.unit {
		if p, ok := c.links[id]; ok {
			c.links[id] = name + strings.TrimPrefix(p, tmp)
		}
	}
	return nil
}

// forceRemove removes a half-built entry, making directories accessible
// first: a copied directory may carry a mode that forbids its own removal.
func (c *copier) forceRemove(rel string) {
	if c.dst.RemoveAll(rel) == nil {
		return
	}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		fi, err := c.dst.Lstat(p)
		if err != nil || !fi.IsDir() || depth > maxMaxDepth+1 {
			return
		}
		_ = c.dst.Chmod(p, 0o700)
		if d, err := c.dst.Open(p); err == nil {
			names, _ := d.Readdirnames(-1)
			d.Close()
			for _, n := range names {
				walk(path.Join(p, n), depth+1)
			}
		}
	}
	walk(rel, 0)
	_ = c.dst.RemoveAll(rel)
}

func (c *copier) bump(cur string) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	c.entries++
	if c.entries > c.o.MaxEntries {
		return invalid("more than %d entries", c.o.MaxEntries)
	}
	c.progress(cur, false)
	return nil
}

// node copies the source entry srcRel to dstRel.
func (c *copier) node(srcRel, dstRel string, depth int) error {
	if err := c.bump(srcRel); err != nil {
		return err
	}
	fi, err := c.src.Lstat(srcRel)
	if err != nil {
		return mapFSErr(err)
	}
	st, _ := statOf(fi)
	switch m := fi.Mode(); {
	case m.IsDir():
		return c.dir(srcRel, dstRel, depth, fi, st)
	case m.IsRegular():
		return c.file(srcRel, dstRel, fi, st)
	case m&os.ModeSymlink != 0:
		return c.symlink(srcRel, dstRel, fi, st)
	}
	c.res.Skipped++
	return nil
}

func (c *copier) dir(srcRel, dstRel string, depth int, fi os.FileInfo, st fileStat) error {
	if depth > c.o.MaxDepth {
		return invalid("%s: directories nested deeper than %d", srcRel, c.o.MaxDepth)
	}
	if st.Dev != c.srcDev && !c.o.CrossFilesystem {
		return invalid("%s is on another filesystem than the source (set cross_filesystem to copy it)", srcRel)
	}
	if st.id() == c.dstID {
		return invalid("%s is the destination directory: the destination lies inside the source", srcRel)
	}
	sf, err := c.src.OpenFile(srcRel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer sf.Close()
	if err := sameInode(sf, st); err != nil {
		return err
	}
	if err := c.dst.Mkdir(dstRel, 0o700); err != nil {
		return mapFSErr(err)
	}
	c.res.Dirs++
	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		ents, rerr := sf.ReadDir(256)
		for _, e := range ents {
			n := e.Name()
			if err := c.node(path.Join(srcRel, n), path.Join(dstRel, n), depth+1); err != nil {
				return err
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return mapFSErr(rerr)
		}
	}
	df, err := c.dst.OpenFile(dstRel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer df.Close()
	return c.applyMeta(sf, df, fi, dstRel)
}

// sameInode checks that an opened file is the inode that was examined, so a
// path swapped in between cannot redirect the copy.
func sameInode(f *os.File, want fileStat) error {
	fi, err := f.Stat()
	if err != nil {
		return mapFSErr(err)
	}
	got, ok := statOf(fi)
	if !ok || got.id() != want.id() {
		return api.Errorf(api.CodeConflict, "source changed while it was copied")
	}
	return nil
}

func (c *copier) file(srcRel, dstRel string, fi os.FileInfo, st fileStat) error {
	if st.Nlink > 1 {
		if first, ok := c.links[st.id()]; ok {
			if err := c.dst.Link(first, dstRel); err != nil {
				return mapFSErr(err)
			}
			c.res.HardLinks++
			return nil
		}
		if len(c.links) >= c.o.MaxHardLinks {
			return invalid("more than %d distinct hard-linked files", c.o.MaxHardLinks)
		}
	}
	sf, err := c.src.OpenFile(srcRel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer sf.Close()
	if err := sameInode(sf, st); err != nil {
		return err
	}
	df, err := c.dst.OpenFile(dstRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return mapFSErr(err)
	}
	defer df.Close()
	if err := c.copyData(sf, df, fi.Size()); err != nil {
		return err
	}
	if err := c.applyMeta(sf, df, fi, dstRel); err != nil {
		return err
	}
	c.res.Files++
	if st.Nlink > 1 {
		c.links[st.id()] = dstRel
		c.unit = append(c.unit, st.id())
	}
	return nil
}

func (c *copier) symlink(srcRel, dstRel string, fi os.FileInfo, st fileStat) error {
	target, err := c.src.Readlink(srcRel)
	if err != nil {
		return mapFSErr(err)
	}
	if err := c.dst.Symlink(target, dstRel); err != nil {
		return mapFSErr(err)
	}
	if err := c.dst.Lchown(dstRel, int(st.UID), int(st.GID)); err != nil && !c.noChown {
		return mapFSErr(err)
	}
	// The times of a symlink are set through its parent directory with
	// AT_SYMLINK_NOFOLLOW, never through the link.
	parent, err := c.dst.OpenFile(path.Dir(dstRel), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return mapFSErr(err)
	}
	defer parent.Close()
	if err := setLinkTimes(parent, path.Base(dstRel), st.Atime, fi.ModTime()); err != nil {
		c.res.MetaSkipped++
	}
	c.res.Symlinks++
	return nil
}

// copyData copies size bytes, keeping holes: only the data extents reported
// by SEEK_DATA/SEEK_HOLE are read and written, and the file is then
// truncated to its length. A filesystem without SEEK_DATA gets a plain copy.
func (c *copier) copyData(sf, df *os.File, size int64) error {
	off := int64(0)
	sparse := true
	for off < size {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		start, end := off, size
		if sparse {
			d, err := sf.Seek(off, seekData)
			switch {
			case errors.Is(err, syscall.ENXIO):
				off = size // only a hole is left
				continue
			case err != nil:
				sparse = false // not supported here: copy everything
			default:
				h, herr := sf.Seek(d, seekHole)
				if herr != nil || h > size {
					h = size
				}
				start, end = d, h
			}
		}
		for pos := start; pos < end; {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			n := int64(len(c.buf))
			if end-pos < n {
				n = end - pos
			}
			r, rerr := sf.ReadAt(c.buf[:n], pos)
			if r > 0 {
				if _, werr := df.WriteAt(c.buf[:r], pos); werr != nil {
					return mapFSErr(werr)
				}
				pos += int64(r)
				c.res.Bytes += int64(r)
				c.progress("", false)
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					end = pos // the file shrank under us
					break
				}
				return mapFSErr(rerr)
			}
		}
		off = end
	}
	if err := df.Truncate(size); err != nil {
		return mapFSErr(err)
	}
	return nil
}

// applyMeta gives the destination the source's mode, owner, extended
// attributes, times and flags, in that order (flags last: an immutable flag
// would block the rest).
func (c *copier) applyMeta(sf, df *os.File, fi os.FileInfo, dstRel string) error {
	st, _ := statOf(fi)
	if err := df.Chown(int(st.UID), int(st.GID)); err != nil && !c.noChown {
		return mapFSErr(err)
	}
	// chmod after chown: chown clears setuid and setgid.
	if err := df.Chmod(fi.Mode()); err != nil {
		return mapFSErr(err)
	}
	c.res.MetaSkipped += int64(copyXattrs(sf, df))
	if err := c.dst.Chtimes(dstRel, st.Atime, fi.ModTime()); err != nil {
		return mapFSErr(err)
	}
	if st.Flags != 0 {
		if err := copyFlags(df, st.Flags); err != nil {
			c.res.MetaSkipped++
		}
	}
	return nil
}
