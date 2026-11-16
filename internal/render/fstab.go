package render

import (
	"fmt"
	"strings"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// FstabVolume binds a data dataset's mountpoint on the host into the jail.
type FstabVolume struct {
	Source   string // absolute host path of the dataset mountpoint
	Target   string // absolute path inside the jail
	ReadOnly bool
}

// FstabInput describes the mounts of one jail.
type FstabInput struct {
	OS      api.OS
	Root    string // absolute jail root on the host
	Volumes []FstabVolume
	// ShmSize is the tmpfs size for /dev/shm of Linux jails ("512M"); the
	// default is 256M.
	ShmSize string
	// DevfsRuleset is the private devfs ruleset of a Linux jail's /dev; 0
	// mounts devfs with the system default.
	DevfsRuleset int
}

// LinuxCompat is the Linuxulator emulation path below the jail root. It
// holds a nullfs mirror of the root (see Fstab).
const LinuxCompat = "compat/linux"

// LinuxShmDir is the mount point of the tmpfs of /dev/shm, reached through the
// nullfs mirror. LinuxShmBacking is the directory behind it in the real tree,
// relative to the jail root: it must exist before the first start because
// devfs refuses to create it (the mirror does not show the devfs mount).
const (
	LinuxShmDir     = LinuxCompat + "/dev/shm"
	LinuxShmBacking = "dev/shm"
)

// Fstab renders the fstab consumed by jail(8) mount.fstab. Linux jails get
// the Linuxulator mounts in dependency order. UNVERIFIED: the option sets
// (late, linrdlnk) and the mount order on FreeBSD 15.
func Fstab(in FstabInput) (string, error) {
	if err := validate.AbsPath("root", in.Root); err != nil {
		return "", err
	}
	var b builder
	b.line("%s", Header)
	b.line("# device mountpoint fstype options dump pass")
	if in.Root == "/" {
		return "", fmt.Errorf("render: jail root must not be /")
	}
	root := strings.TrimSuffix(in.Root, "/")
	switch in.OS {
	case api.OSFreeBSD:
	case api.OSLinux:
		shm := in.ShmSize
		if shm == "" {
			shm = "256M"
		}
		n, err := validate.ParseSize(shm)
		if err != nil {
			return "", err
		}
		for _, m := range LinuxMounts(root, in.DevfsRuleset, n) {
			opts := "rw,late"
			if m.Options != "" {
				opts += "," + m.Options
			}
			b.line("%s %s %s %s 0 0", m.Source, m.Target, m.Type, opts)
		}
	default:
		return "", fmt.Errorf("render: unknown os %q", in.OS)
	}
	for i, v := range in.Volumes {
		if err := validate.AbsPath(fmt.Sprintf("volumes[%d].source", i), v.Source); err != nil {
			return "", err
		}
		if err := validate.AbsPath(fmt.Sprintf("volumes[%d].target", i), v.Target); err != nil {
			return "", err
		}
		mode := "rw"
		if v.ReadOnly {
			mode = "ro"
		}
		b.line("%s %s%s nullfs %s 0 0", v.Source, root, v.Target, mode)
	}
	return b.result()
}

// LinuxMount is one mount of a Linux jail: mount -t <Type> [-o <Options>]
// <Source> <Target>.
type LinuxMount struct {
	Type, Source, Target, Options string
}

// LinuxMounts returns the mounts of a Linux jail in the verified order on
// FreeBSD 15.1: devfs (private ruleset), fdescfs, a nullfs mirror of the
// root on compat/linux, tmpfs on its dev/shm, linprocfs, linsysfs. devfs
// refuses to create /dev/shm and the Linuxulator resolves paths through
// compat/linux first (a create below it fails with ENOENT once the directory
// exists), so the mirror makes creates land in the real tree and the tmpfs
// provides /dev/shm through it. root has no trailing slash.
func LinuxMounts(root string, devfsRuleset int, shmBytes uint64) []LinuxMount {
	dev := ""
	if devfsRuleset != 0 {
		dev = fmt.Sprintf("ruleset=%d", devfsRuleset)
	}
	return []LinuxMount{
		{"devfs", "devfs", root + "/dev", dev},
		{"fdescfs", "fdescfs", root + "/dev/fd", "linrdlnk"},
		{"nullfs", root, root + "/" + LinuxCompat, ""},
		{"tmpfs", "tmpfs", root + "/" + LinuxShmDir, fmt.Sprintf("size=%d,mode=1777", shmBytes)},
		{"linprocfs", "linprocfs", root + "/proc", ""},
		{"linsysfs", "linsysfs", root + "/sys", ""},
	}
}

// LinuxDevfsRuleArgv returns the `devfs rule -s <n> ...` argument lists that
// load the ruleset of a Linux jail into the kernel under the number n: the
// rules of LinuxDevfsRuleset, and of the image build jail.
func LinuxDevfsRuleArgv(n int, devices []string) ([][]string, error) {
	s := fmt.Sprint(n)
	out := [][]string{{"devfs", "rule", "-s", s, "add", "hide"}}
	paths := append([]string(nil), linuxDevfsNodes...)
	for _, d := range devices {
		p, ok := devfsPaths[d]
		if !ok {
			return nil, fmt.Errorf("render: device %q is not on the devfs allow-list", d)
		}
		paths = append(paths, p...)
	}
	for _, p := range paths {
		out = append(out, []string{"devfs", "rule", "-s", s, "add", "path", p, "unhide"})
	}
	return out, nil
}
