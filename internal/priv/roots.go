package priv

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"jailops.net/jailops/internal/sys/zfs"
)

// MaxStorageRoots bounds the number of storage roots, static and registered.
const MaxStorageRoots = 64

// rootEntry is one storage root. Mount is the absolute mountpoint of the
// dataset as ZFS reported it when the root was verified; every file path the
// helper accepts below the root is checked against it. Err is set when the
// root failed verification: it is kept (so it is not lost from the storage
// file) but allows nothing.
type rootEntry struct {
	Dataset string
	Mount   string
	Static  bool // fixed in priv.conf, cannot be unregistered
	Err     string
}

func (e rootEntry) active() bool { return e.Err == "" }

// rootSet is the set of storage roots. Copies of a Config share one rootSet.
type rootSet struct {
	mu   sync.RWMutex
	list []rootEntry // sorted by dataset
}

func newRootSet() *rootSet { return &rootSet{} }

func (s *rootSet) all() []rootEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.list)
}

func (s *rootSet) active() []rootEntry {
	var out []rootEntry
	for _, e := range s.all() {
		if e.active() {
			out = append(out, e)
		}
	}
	return out
}

func (s *rootSet) set(list []rootEntry) {
	list = slices.Clone(list)
	sort.Slice(list, func(i, j int) bool { return list[i].Dataset < list[j].Dataset })
	s.mu.Lock()
	s.list = list
	s.mu.Unlock()
}

// mounts returns the mountpoints of the active roots.
func (s *rootSet) mounts() []string {
	var out []string
	for _, e := range s.active() {
		out = append(out, e.Mount)
	}
	return out
}

// dsInside reports whether ds is root or below it.
func dsInside(ds, root string) bool { return ds == root || strings.HasPrefix(ds, root+"/") }

func (c Config) checkRootName(ds string) error {
	if err := zfs.ValidateDataset(ds); err != nil {
		return invalid("storage root %q: %v", ds, err)
	}
	if len(ds) > 200 {
		return invalid("storage root %q: name too long", ds)
	}
	if !strings.Contains(ds, "/") && !c.AllowPoolRoot {
		return invalid("storage root %q is a pool; that needs allow-pool-root", ds)
	}
	return nil
}

func checkRootOverlap(roots []string) error {
	if len(roots) > MaxStorageRoots {
		return invalid("too many storage roots (limit %d)", MaxStorageRoots)
	}
	for i, a := range roots {
		for _, b := range roots[i+1:] {
			if dsInside(a, b) || dsInside(b, a) {
				return invalid("storage roots %q and %q overlap", a, b)
			}
		}
	}
	return nil
}

// rootOf returns the active root that holds ds (a dataset name, no snapshot).
// Roots never overlap, so there is at most one.
func (c Config) rootOf(ds string) (rootEntry, bool) {
	for _, e := range c.reg.active() {
		if dsInside(ds, e.Dataset) {
			return e, true
		}
	}
	return rootEntry{}, false
}

// inRoot requires ds to live in exactly one registered, active storage root.
func (c Config) inRoot(ds string) error {
	if _, ok := c.rootOf(ds); ok {
		return nil
	}
	return forbidden("dataset %q is outside every registered storage root", ds)
}

// isRootDataset reports whether ds is itself a storage root.
func (c Config) isRootDataset(ds string) bool {
	for _, e := range c.reg.all() {
		if e.Dataset == ds {
			return true
		}
	}
	return false
}

// Roots returns the datasets of the active storage roots, sorted.
func (c Config) Roots() []string {
	var out []string
	for _, e := range c.reg.active() {
		out = append(out, e.Dataset)
	}
	return out
}

// Pools returns the pools of the active storage roots, sorted.
func (c Config) Pools() []string {
	var out []string
	for _, e := range c.reg.active() {
		p, _, _ := strings.Cut(e.Dataset, "/")
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// inMounts reports whether the clean absolute path p is a mountpoint of an
// active root or below one.
func (c Config) inMounts(p string) bool {
	for _, m := range c.reg.mounts() {
		if within(m, p) {
			return true
		}
	}
	return false
}

// isMountRoot reports whether p is exactly the mountpoint of an active root.
func (c Config) isMountRoot(p string) bool { return slices.Contains(c.reg.mounts(), p) }

// mountBaseDesc names the mount roots for error messages.
func (c Config) mountBaseDesc() string {
	m := c.reg.mounts()
	if len(m) == 0 {
		return "any registered storage root"
	}
	return strings.Join(m, ", ")
}

// ---- storage file ----

const (
	maxStorageFileBytes = 64 << 10
	storageFileHeader   = "# JailOps storage roots registered at run time.\n# Written by jailops-priv (storage.register). Edit only while it is stopped, or send SIGHUP.\n"
)

// parseStorageFile parses the storage file: "root = <dataset>" lines, blank
// lines and "#" comments. Duplicates and overlaps are errors.
func (c Config) parseStorageFile(b []byte) ([]string, error) {
	if len(b) > maxStorageFileBytes {
		return nil, invalid("storage file larger than %d bytes", maxStorageFileBytes)
	}
	var roots []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k != "root" {
			return nil, invalid("storage file line %d: expected root = <dataset>", n)
		}
		if err := c.checkRootName(v); err != nil {
			return nil, fmt.Errorf("storage file line %d: %w", n, err)
		}
		if slices.Contains(roots, v) {
			return nil, invalid("storage file line %d: %q is listed twice", n, v)
		}
		roots = append(roots, v)
	}
	if err := sc.Err(); err != nil {
		return nil, invalid("storage file: %v", err)
	}
	if err := checkRootOverlap(roots); err != nil {
		return nil, err
	}
	return roots, nil
}

func renderStorageFile(roots []string) []byte {
	roots = slices.Clone(roots)
	sort.Strings(roots)
	var b bytes.Buffer
	b.WriteString(storageFileHeader)
	for _, r := range roots {
		fmt.Fprintf(&b, "root = %s\n", r)
	}
	return b.Bytes()
}

// systemMountPoints are host directories no storage root may be mounted on
// or above: mounting a root there would shadow the running system.
var systemMountPoints = []string{"/", "/boot", "/etc", "/usr", "/var", "/usr/local", "/usr/local/etc", "/var/run", "/tmp", "/dev", "/bin", "/sbin", "/lib", "/libexec", "/root"}

// systemTrees are host directories a storage root may not be mounted inside either: the helper writes below a root
// as root, so a root there would let the daemon write system files. A root may lie elsewhere in /usr or /var
// (/usr/jails).
var systemTrees = []string{"/boot", "/etc", "/root", "/dev", "/bin", "/sbin", "/lib", "/libexec", "/rescue", "/proc",
	"/var/run", "/var/db", "/var/cron", "/var/at", "/var/log", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
	"/usr/local/etc", "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/usr/local/libexec"}

// helperDirs are the helper's own directories: no root may be mounted on, above or inside them.
func (c Config) helperDirs() []string {
	var out []string
	for _, d := range []string{c.ConfDir, filepath.Dir(c.HelperPath), c.HelperPath, filepath.Dir(c.StorageFile), c.HostDir, c.WireGuardDir, c.PkgKeysDir, c.KeyringDir} {
		if d != "" && d != "/" {
			out = append(out, d)
		}
	}
	return out
}

// overlapsSystem reports whether m, the mountpoint of a storage root, shadows (equals, or is an ancestor of) a
// system path or a directory of the helper, or lies inside a system tree or a directory of the helper.
func (c Config) overlapsSystem(m string) bool {
	if c.shadowsSystem(m) {
		return true
	}
	for _, s := range systemTrees {
		if within(s, m) {
			return true
		}
	}
	return false
}

// shadowsSystem is the check of a dataset below a root, whose mountpoint the operator may have put outside the
// root's tree (the daemon's state dataset in /var/db/jailops): it may not shadow a system path, nor overlap a
// directory of the helper in either direction.
func (c Config) shadowsSystem(m string) bool {
	if m == "/" {
		return true
	}
	for _, s := range systemMountPoints {
		if within(m, s) {
			return true
		}
	}
	for _, d := range c.helperDirs() {
		if within(m, d) || within(d, m) {
			return true
		}
	}
	return false
}
