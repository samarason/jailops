package priv

import (
	"context"
	"jailops.net/jailops/internal/render"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Rules for building images and wiring Linux jails from the host. Every
// binary is a fixed absolute path, every argument is validated, no shell is
// involved, every path is below a registered storage root (or the state
// directory where a work area is meant) and every jail named is a managed
// jail (its conf file exists). UNVERIFIED on FreeBSD beyond the forms
// verified on the 15.1 test host and recorded in the design.

// DefaultFetchHosts are the hosts fetch may download from.
var DefaultFetchHosts = []string{"dl-cdn.alpinelinux.org", "pkg.freebsd.org", "pkg.jailops.net", "deb.debian.org", "archive.ubuntu.com", "ports.ubuntu.com"}

// Devfs rulesets JailOps may define or mount: numbers below 100 belong to the
// stock devfs.rules and are left alone (4 may be mounted, not changed).
const (
	DevfsRulesetMin = 100
	DevfsRulesetMax = 65535
)

var (
	reFetchURL   = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/[A-Za-z0-9._~/+%:@-]{0,400}$`)
	reHostName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	reChmodMode  = regexp.MustCompile(`^[0-7]{3,4}$`)
	reMountMode  = regexp.MustCompile(`^mode=[0-7]{3,4}$`)
	reMountSize  = regexp.MustCompile(`^size=[0-9]{1,15}[kKmMgG]?$`)
	reMountRule  = regexp.MustCompile(`^ruleset=[0-9]{1,5}$`)
	reDevfsGlob  = regexp.MustCompile(`^[a-z0-9*?_./-]{1,64}$`)
	reDevfsName  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reApkArg     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+@:=/<>~-]{0,127}$`)
	reNumber     = regexp.MustCompile(`^[0-9]{1,5}$`)
	apkSubs      = []string{"add", "update", "upgrade", "del", "info", "verify", "--version"}
	apkFlags     = []string{"--no-cache", "-q", "--quiet", "--update-cache", "-U", "--simulate", "-s", "--no-progress", "-v", "--verbose", "-a", "--available", "--no-interactive"}
	mountTypes   = []string{"nullfs", "tmpfs", "devfs", "fdescfs", "linprocfs", "linsysfs"}
	simpleMounts = []string{"ro", "rw", "noatime", "nosuid", "noexec"}
)

// ---- fetch ----

// EffectiveFetchHosts returns the hosts fetch may download from.
func (c Config) EffectiveFetchHosts() []string { return c.fetchHosts() }

func (c Config) fetchHosts() []string {
	if len(c.FetchHosts) > 0 {
		return c.FetchHosts
	}
	return DefaultFetchHosts
}

func (c Config) checkFetchURL(raw string) error {
	if !reFetchURL.MatchString(raw) || strings.Contains(raw, "..") || false {
		return forbidden("fetch: url %q is not acceptable", raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return forbidden("fetch: url %q is not acceptable", raw)
	}
	if !slices.Contains(c.fetchHosts(), u.Hostname()) {
		return forbidden("fetch: host %q is not on the allow-list (%s)", u.Hostname(), strings.Join(c.fetchHosts(), ", "))
	}
	for _, seg := range strings.Split(u.Path, "/")[1:] {
		if seg == "." || seg == ".." || (seg == "" && !strings.HasSuffix(u.Path, "/")) {
			return forbidden("fetch: url %q is not acceptable", raw)
		}
	}
	return nil
}

// customFetch accepts only: fetch -o <file> <https url on an allowed host>.
func customFetch(c Config, _ bool, args []string) error {
	if len(args) != 3 || args[0] != "-o" {
		return forbidden("fetch: only -o <file> <url> is accepted")
	}
	if err := c.checkRulePath(pathState, args[1]); err != nil {
		return err
	}
	return c.checkFetchURL(args[2])
}

// ---- tar ----

// customTar accepts "tar -tzf <file>" and "tar -C <root> -xpzf <file>" (the
// second is verified by listing the archive first, verifyTar), and the one
// archive a generation switch makes: "tar -C <root> -cf <work>/old-etc.tar|
// new-etc.tar ./etc" with the archive inside a ".merge-*" directory below a
// storage root, the baseline and the target /etc of the three-way merge.
func customTar(c Config, _ bool, args []string) error {
	switch {
	case len(args) == 5 && args[0] == "-C" && args[2] == "-cf" && args[4] == "./etc":
		if err := c.checkRulePath(pathJailTree, args[1]); err != nil {
			return err
		}
		if err := c.checkRulePath(pathState, args[3]); err != nil {
			return err
		}
		if b := filepath.Base(args[3]); b != "old-etc.tar" && b != "new-etc.tar" {
			return forbidden("tar: the archive of a merge is old-etc.tar or new-etc.tar, not %q", b)
		}
		if !strings.HasPrefix(filepath.Base(filepath.Dir(args[3])), ".merge-") {
			return forbidden("tar: the archive of a merge goes in a .merge-* directory")
		}
		return nil
	case len(args) == 2 && args[0] == "-tzf":
		return c.checkRulePath(pathState, args[1])
	case len(args) == 4 && args[0] == "-C" && args[2] == "-xpzf":
		if err := c.checkRulePath(pathJailTree, args[1]); err != nil {
			return err
		}
		return c.checkRulePath(pathState, args[3])
	}
	return forbidden("tar: only -tzf <file>, -C <root> -xpzf <file> and -C <root> -cf <merge dir>/old-etc.tar|new-etc.tar ./etc are accepted")
}

// checkMember refuses an archive member that is absolute or climbs out.
func checkMember(name string) error {
	if name == "" || len(name) > maxPath || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") {
		return forbidden("tar: member %q is not acceptable", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return forbidden("tar: member %q climbs out of the destination", name)
		}
	}
	return nil
}

// verifyTar lists the archive and refuses it when any member is absolute or
// contains "..": the extraction never runs on such an archive.
func verifyTar(ctx context.Context, l *Local, args []string) error {
	if len(args) != 4 {
		return nil
	}
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "/usr/bin/tar", Args: []string{"-tzf", args[3]}, Timeout: 900 * time.Second, MaxOutput: 64 << 20})
	if err != nil {
		return err
	}
	if res.Truncated {
		return forbidden("tar: the archive has too many members to verify")
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		if err := checkMember(line); err != nil {
			return err
		}
	}
	return nil
}

// ---- chmod ----

// customChmod accepts "chmod <octal mode> <path>..." with no setuid or
// setgid bit, paths below a storage root.
func customChmod(c Config, _ bool, args []string) error {
	if len(args) < 2 || len(args) > 33 || !reChmodMode.MatchString(args[0]) {
		return forbidden("chmod: only an octal mode and 1 to 32 paths are accepted")
	}
	if m := args[0]; len(m) == 4 && m[0] != '0' && m[0] != '1' {
		return forbidden("chmod: mode %s has a setuid or setgid bit", m)
	}
	for _, p := range args[1:] {
		if err := c.checkRulePath(pathJailTree, p); err != nil {
			return err
		}
	}
	return nil
}

// verifyChmod refuses a path with a symbolic link in it: chmod follows links, and an image archive can contain one
// that points out of the image root.
func verifyChmod(ctx context.Context, l *Local, args []string) error {
	for _, p := range args[1:] {
		// a tree a running jail controls can change under the call: chmod is for the roots of images and of jails that are stopped
		if name := l.runningJailAt(ctx, p); name != "" {
			return forbidden("chmod: %q is in the tree of the running jail %s", p, name)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return invalid("chmod: %v", err)
		}
		if real != filepath.Clean(p) {
			return forbidden("chmod: %q is or passes through a symbolic link (%s)", p, real)
		}
	}
	return nil
}

// ---- jails: paths and names ----

// jailOfRoot returns the key of the jail whose root dataset path p lies
// strictly below: <mount>/projects/<project>/jails/<name>/root/....
func (c Config) jailOfRoot(p string) (string, error) {
	if !cleanAbs(p) {
		return "", forbidden("path %q is not a clean absolute path", p)
	}
	best := ""
	for _, m := range c.reg.mounts() {
		if within(m, p) && len(m) > len(best) {
			best = m
		}
	}
	if best == "" {
		return "", forbidden("path %q is outside every registered storage root", p)
	}
	rel, _ := filepath.Rel(best, p)
	parts := strings.Split(rel, "/")
	if len(parts) < 6 || parts[0] != "projects" || parts[2] != "jails" || parts[4] != "root" {
		return "", forbidden("path %q is not below the root of a jail", p)
	}
	jn := JailName{Project: parts[1], Name: parts[3]}
	if _, err := ParseJailName(jn.Internal()); err != nil {
		return "", forbidden("path %q is not below the root of a jail", p)
	}
	return jn.Internal(), nil
}

var reStagingGen = regexp.MustCompile(`^staging-g[0-9]+$`)

// inImageStaging reports whether p lies strictly below an image build root,
// <mount>/images/<image>/staging-g<N>/..., where the build jail of an image
// mounts devfs.
func (c Config) inImageStaging(p string) bool {
	if !cleanAbs(p) {
		return false
	}
	for _, m := range c.reg.mounts() {
		if !within(m, p) {
			continue
		}
		rel, _ := filepath.Rel(m, p)
		parts := strings.Split(rel, "/")
		if len(parts) >= 4 && parts[0] == "images" && reStagingGen.MatchString(parts[2]) && validate.Name("image", parts[1]) == nil {
			return true
		}
	}
	return false
}

// checkJailRootPath validates a mount point: below the root of a managed
// jail, symlinks resolved.
func (l *Local) checkJailRootPath(p string) error {
	if l.cfg.inImageStaging(p) {
		return l.cfg.checkRulePath(pathJailTree, p)
	}
	key, err := l.cfg.jailOfRoot(p)
	if err != nil {
		return err
	}
	if err := (jailGuard{l}).managed(key); err != nil {
		return err
	}
	return l.cfg.checkRulePath(pathJailTree, p)
}

// ---- mount, umount ----

func (c Config) checkMountOptions(typ, opts string) error {
	if opts == "" || len(opts) > 200 {
		return invalid("mount: invalid options")
	}
	for _, o := range strings.Split(opts, ",") {
		switch {
		case slices.Contains(simpleMounts, o):
		case o == "late", typ == "fdescfs" && o == "linrdlnk": // the options the Linux dev layout uses (render/fstab.go)
		case typ == "tmpfs" && (reMountSize.MatchString(o) || reMountMode.MatchString(o)):
			if strings.HasPrefix(o, "mode=") && len(o) == 9 && o[5] != '0' && o[5] != '1' {
				return forbidden("mount: %s has a setuid or setgid bit", o)
			}
		case typ == "devfs" && reMountRule.MatchString(o):
			n, _ := strconv.Atoi(strings.TrimPrefix(o, "ruleset="))
			if n != 4 && !c.devfsRulesetOK(n) {
				return forbidden("mount: devfs ruleset %d is not allowed", n)
			}
		default:
			return forbidden("mount: option %q is not allowed", o)
		}
	}
	return nil
}

func (c Config) devfsRulesetOK(n int) bool {
	return n >= DevfsRulesetMin && n <= DevfsRulesetMax || slices.Contains(c.Admin.DevfsRulesets, n)
}

// customMount accepts: mount -t <type> [-o <options>] <device> <path>. The
// device of every type but nullfs is the type name; a nullfs source is below
// a storage root or, with the admin assertion, below an admin-host-mount directory (the mount a volume of a host
// directory gives a running jail again). The path is checked against the jail in verifyMount.
func customMount(c Config, admin bool, args []string) error {
	if len(args) < 4 || args[0] != "-t" || !slices.Contains(mountTypes, args[1]) {
		return forbidden("mount: only -t <%s> is accepted", strings.Join(mountTypes, "|"))
	}
	typ, rest := args[1], args[2:]
	if rest[0] == "-o" {
		if len(rest) < 4 {
			return invalid("mount: -o needs a value")
		}
		if err := c.checkMountOptions(typ, rest[1]); err != nil {
			return err
		}
		rest = rest[2:]
	}
	if len(rest) != 2 {
		return invalid("mount: expected <device> <path>")
	}
	if typ == "nullfs" {
		if err := c.checkRulePath(pathJailTree, rest[0]); err != nil && !(admin && c.hostMountSource(rest[0])) {
			return err
		}
	} else if rest[0] != typ {
		return invalid("mount: the device of a %s mount is %q", typ, typ)
	}
	if !cleanAbs(rest[1]) {
		return forbidden("mount: path %q is not a clean absolute path", rest[1])
	}
	return nil
}

// hostMountSource reports whether p is below a directory of admin-host-mount.
func (c Config) hostMountSource(p string) bool {
	for _, r := range c.Admin.HostMountRoots {
		if within(r, p) {
			return true
		}
	}
	return false
}

func verifyMount(_ context.Context, l *Local, args []string) error {
	if i := slices.Index(args, "nullfs"); i == 1 && len(args) >= 4 {
		// a source of the host's own directories is held to the allowed directory it lies below, links and all
		src := args[len(args)-2]
		for _, r := range l.cfg.Admin.HostMountRoots {
			if within(r, src) {
				if err := plainBelow(r, src); err != nil {
					return err
				}
			}
		}
	}
	return l.checkJailRootPath(args[len(args)-1])
}

// customUmount accepts: umount [-f] <path>.
func customUmount(c Config, _ bool, args []string) error {
	if len(args) > 0 && args[0] == "-f" {
		args = args[1:]
	}
	if len(args) != 1 || !cleanAbs(args[0]) {
		return forbidden("umount: only [-f] <path> is accepted")
	}
	return nil
}

// verifyUmount takes a path that is a mount point of the host as it is listed, and no other: umount(8) resolves the
// path, so a path that is a link a jail put in its tree would unmount whatever the link points at (a host file system).
// A mount point cannot be replaced while it is mounted, so what the list shows now is what umount will resolve.
func verifyUmount(ctx context.Context, l *Local, args []string) error {
	p := args[len(args)-1]
	if err := l.checkJailRootPath(p); err != nil {
		return err
	}
	if mps := l.mountPoints(ctx); mps != nil {
		for _, mp := range mps {
			if mp == p {
				return nil
			}
		}
		return api.Errorf(api.CodeNotFound, "umount: %s is not a mount point", p)
	}
	return nil
}

// ---- jail ----

// reBuildJail is the name of the short-lived jail an image build runs apk in.
var reBuildJail = regexp.MustCompile(`^jobuild-[a-z0-9][a-z0-9-]{0,60}-g[0-9]{1,6}$`)

// imageStagingRoot reports whether p is exactly an image build root,
// <mount>/images/<image>/staging-g<N>.
func (c Config) imageStagingRoot(p string) bool {
	if !cleanAbs(p) {
		return false
	}
	for _, m := range c.reg.mounts() {
		if !within(m, p) {
			continue
		}
		rel, _ := filepath.Rel(m, p)
		parts := strings.Split(rel, "/")
		if len(parts) == 3 && parts[0] == "images" && reStagingGen.MatchString(parts[2]) && validate.Name("image", parts[1]) == nil {
			return true
		}
	}
	return false
}

// customBuildJail accepts the two forms the image builder uses for its
// build jail, for an admin only (the daemon's system actor):
//
//	jail -c name=<jobuild-..> path=<staging root> host.hostname=<name> persist ip4=inherit ip6=inherit devfs_ruleset=<n> exec.clean
//	jail -r <jobuild-..>
func customBuildJail(c Config, admin bool, args []string) error {
	if !admin {
		return forbidden("jail: the build jail of an image needs the admin assertion")
	}
	if len(args) == 2 && args[0] == "-r" {
		if !reBuildJail.MatchString(args[1]) {
			return forbidden("jail: %q is not a build jail", args[1])
		}
		return nil
	}
	if len(args) != 9 || args[0] != "-c" {
		return forbidden("jail: argument list of a build jail is not accepted")
	}
	name := strings.TrimPrefix(args[1], "name=")
	if args[1] != "name="+name || !reBuildJail.MatchString(name) {
		return forbidden("jail: %q is not a build jail name", args[1])
	}
	root := strings.TrimPrefix(args[2], "path=")
	if args[2] != "path="+root || !c.imageStagingRoot(root) {
		return forbidden("jail: path %q is not an image build root", args[2])
	}
	if err := c.checkRulePath(pathJailTree, root); err != nil {
		return err
	}
	rs := strings.TrimPrefix(args[7], "devfs_ruleset=")
	n, err := strconv.Atoi(rs)
	if args[7] != "devfs_ruleset="+rs || err != nil || !reNumber.MatchString(rs) || n < DevfsRulesetMin || n > DevfsRulesetMax {
		return forbidden("jail: %q is not an accepted devfs ruleset", args[7])
	}
	if args[3] != "host.hostname="+name || args[4] != "persist" || args[5] != "ip4=inherit" || args[6] != "ip6=inherit" || args[8] != "exec.clean" {
		return forbidden("jail: the build jail takes exactly its fixed parameters")
	}
	return nil
}

// customJail accepts: jail -c|-r -f <conf> [<name>] (flags in any order), and
// the fixed forms of the build jail (customBuildJail).
func customJail(c Config, admin bool, args []string) error {
	if (len(args) == 2 && args[0] == "-r" && !strings.HasPrefix(args[1], "-")) || (len(args) > 1 && args[0] == "-c" && strings.HasPrefix(args[1], "name=")) {
		return customBuildJail(c, admin, args)
	}
	var verb, conf, name string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case (a == "-c" || a == "-r") && verb == "":
			verb = a
		case a == "-f" && conf == "" && i+1 < len(args):
			i++
			conf = args[i]
		case !strings.HasPrefix(a, "-") && name == "" && verb != "":
			name = a
		default:
			return forbidden("jail: argument %q is not allowed", a)
		}
	}
	if verb == "" || conf == "" {
		return forbidden("jail: -c or -r and -f <conf> are required")
	}
	if !cleanAbs(conf) || !within(c.ConfDir, conf) || conf == c.ConfDir {
		return forbidden("jail: conf %q is not in %s", conf, c.ConfDir)
	}
	return nil
}

func verifyJail(ctx context.Context, l *Local, args []string) error {
	if (len(args) == 2 && args[0] == "-r") || (len(args) > 1 && args[0] == "-c" && strings.HasPrefix(args[1], "name=")) {
		return nil // the build jail forms were checked in full by customBuildJail
	}
	var conf, name string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-f":
			i++
			conf = args[i]
		case !strings.HasPrefix(a, "-"):
			name = a
		}
	}
	key := jailNameOfConf(l.cfg.ConfDir, conf)
	if key == "" || (name != "" && name != key) {
		return forbidden("jail: %q is not the conf of %q", conf, name)
	}
	_, err := jailGuard{l}.confPathFor(ctx, conf, key)
	return err
}

// ---- devfs ----

// customDevfs accepts the rules JailOps writes into its private rulesets:
//
//	devfs rule -s <n> add hide|unhide
//	devfs rule -s <n> add include <m>
//	devfs rule -s <n> add path <glob> hide|unhide|include <m>|mode <octal>|user <name>|group <name>
func customDevfs(c Config, admin bool, args []string) error {
	bad := func() error {
		return forbidden("devfs: rule %q is not in the accepted grammar", strings.Join(args, " "))
	}
	if len(args) == 4 && args[0] == "rule" && args[1] == "-s" && args[3] == "delset" { // drops a ruleset the build jail loaded
		if !admin {
			return forbidden("devfs: deleting a ruleset needs the admin assertion")
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || !reNumber.MatchString(args[2]) || n < DevfsRulesetMin || n > DevfsRulesetMax {
			return forbidden("devfs: ruleset %q must be between %d and %d", args[2], DevfsRulesetMin, DevfsRulesetMax)
		}
		return nil
	}
	if len(args) < 5 || args[0] != "rule" || args[1] != "-s" || args[3] != "add" || len(args) > 9 {
		return bad()
	}
	n, err := strconv.Atoi(args[2])
	if err != nil || !reNumber.MatchString(args[2]) || n < DevfsRulesetMin || n > DevfsRulesetMax {
		return forbidden("devfs: ruleset %q must be between %d and %d", args[2], DevfsRulesetMin, DevfsRulesetMax)
	}
	r := args[4:]
	switch {
	case len(r) == 1 && r[0] == "hide":
		return nil
	case len(r) == 1 && r[0] == "unhide":
		return forbidden("devfs: a bare unhide would expose every device; name the path")
	case len(r) == 2 && r[0] == "include" && reNumber.MatchString(r[1]):
		return nil
	case len(r) >= 3 && r[0] == "path":
		g := r[1]
		if !reDevfsGlob.MatchString(g) || strings.HasPrefix(g, "/") || strings.Contains(g, "..") {
			return bad()
		}
		a := r[2:]
		switch {
		case len(a) == 1 && a[0] == "hide":
			return nil
		case len(a) == 1 && a[0] == "unhide":
			if !render.DevfsUnhidable(g) {
				return forbidden("devfs: %q is not a device JailOps may unhide", g)
			}
			return nil
		case len(a) == 2 && a[0] == "include" && reNumber.MatchString(a[1]):
			return nil
		case len(a) == 2 && a[0] == "mode" && reChmodMode.MatchString(a[1]) && (len(a[1]) == 3 || a[1][0] == '0'):
			return nil
		case len(a) == 2 && (a[0] == "user" || a[0] == "group") && reDevfsName.MatchString(a[1]):
			return nil
		}
	}
	return bad()
}

// ---- debootstrap ----

var (
	reDebArch   = regexp.MustCompile(`^(arm64|amd64|armhf|i386|riscv64|ppc64el|s390x)$`)
	reDebSuite  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	reDebMirror = regexp.MustCompile(`^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,200})?$`)
)

// customDebootstrap accepts exactly the form the image builder writes:
//
//	debootstrap --arch=<arch> --variant=minbase --keyring=<file> <suite> <staging root> [<https mirror>]
//
// The release signature is always checked (a keyring is required, there is no way to skip it), the mirror must be
// https, and the target is an image build root.
func customDebootstrap(c Config, admin bool, args []string) error {
	if !admin {
		return forbidden("debootstrap: building an image needs the admin assertion")
	}
	if len(args) != 5 && len(args) != 6 {
		return forbidden("debootstrap: argument list is not accepted")
	}
	if a := strings.TrimPrefix(args[0], "--arch="); a == args[0] || !reDebArch.MatchString(a) {
		return forbidden("debootstrap: %q is not an accepted architecture", args[0])
	}
	if args[1] != "--variant=minbase" {
		return forbidden("debootstrap: only --variant=minbase is accepted")
	}
	key := strings.TrimPrefix(args[2], "--keyring=")
	if key == args[2] || !cleanAbs(key) {
		return forbidden("debootstrap: --keyring=<file> is required and checks the release signature")
	}
	if err := c.checkKeyring(key); err != nil {
		return err
	}
	if !reDebSuite.MatchString(args[3]) {
		return forbidden("debootstrap: %q is not a suite name", args[3])
	}
	if !c.imageStagingRoot(args[4]) {
		return forbidden("debootstrap: %q is not an image build root", args[4])
	}
	if err := c.checkRulePath(pathJailTree, args[4]); err != nil {
		return err
	}
	if len(args) == 6 {
		if !reDebMirror.MatchString(args[5]) {
			return forbidden("debootstrap: mirror %q must be an https URL", args[5])
		}
		host := strings.TrimPrefix(args[5], "https://")
		if i := strings.IndexAny(host, "/:"); i >= 0 {
			host = host[:i]
		}
		if !c.pkgHostAllowed(strings.ToLower(host), true) {
			return forbidden("debootstrap: mirror host %s is not in fetch-host of priv.conf", host)
		}
	}
	return nil
}

// ---- jexec apk ----

// customJexec accepts: jexec <jail> /sbin/apk <add|update|upgrade|del|info|verify|--version> [args].
func customJexec(c Config, _ bool, args []string) error {
	if len(args) > 3 && args[1] == "/sbin/apk" && args[2] == "--no-interactive" { // the one option allowed before the subcommand
		args = append([]string{args[0], args[1]}, args[3:]...)
	}
	if len(args) < 3 || args[1] != "/sbin/apk" || !slices.Contains(apkSubs, args[2]) {
		return forbidden("jexec: only <jail> /sbin/apk <%s> is accepted", strings.Join(apkSubs, "|"))
	}
	// the image builder runs apk in its build jail (jobuild-<image>-g<N>), which is not a <project>_<name> key
	if !reBuildJail.MatchString(args[0]) {
		if err := ValidJailName(args[0]); err != nil {
			return err
		}
	}
	if len(args) > 3+64 {
		return invalid("jexec: too many arguments")
	}
	for _, a := range args[3:] {
		if !slices.Contains(apkFlags, a) && !reApkArg.MatchString(a) {
			return forbidden("jexec: apk argument %q is not allowed", a)
		}
	}
	return nil
}

func verifyJexec(_ context.Context, l *Local, args []string) error {
	if reBuildJail.MatchString(args[0]) {
		return nil
	}
	return jailGuard{l}.managed(args[0])
}

// ---- ifconfig and route ----

// checkJailIface checks the form of an interface name in a jail's vnet; verifyIfconfig and verifyRoute read the
// interface there and require JailOps's marker before the command runs.
func (c Config) checkJailIface(name string) error { return ifconfig.ValidateIfName(name) }

func parseAddr(s string, v6 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is6() != v6 || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, invalid("invalid address %q", s)
	}
	return a, nil
}

func parseBits(s string, max int) error {
	n, err := strconv.Atoi(s)
	if err != nil || !reNumber.MatchString(s) || n < 0 || n > max {
		return invalid("invalid prefix length %q", s)
	}
	return nil
}

// customIfconfig accepts (only in the vnet of a managed jail; epairs of the host are made by the typed
// net.* operations, which mark them, never by a command line):
//
//	ifconfig -j <jail> <iface>
//	ifconfig -j <jail> <owned iface> up|down
//	ifconfig -j <jail> <owned iface> description <JailOps description>
//	ifconfig -j <jail> <owned iface> mtu <n>
//	ifconfig -j <jail> <owned iface> inet <addr>[/<n>] [prefixlen <n>|netmask <mask>] [up] [alias|-alias]
//	ifconfig -j <jail> <owned iface> inet6 <addr> [prefixlen <n>] [alias|-alias]
func customIfconfig(c Config, _ bool, args []string) error {
	switch {
	case len(args) == 3 && args[0] == "-j":
		// read-only: the state of one interface in the jail's vnet (its description is repaired from it)
		if err := ValidJailName(args[1]); err != nil {
			return err
		}
		return c.checkJailIface(args[2])
	case len(args) >= 4 && args[0] == "-j":
		if err := ValidJailName(args[1]); err != nil {
			return err
		}
		if err := c.checkJailIface(args[2]); err != nil {
			return err
		}
		return checkIfconfigJail(args[3:])
	}
	return forbidden("ifconfig: %q is not an accepted form", strings.Join(args, " "))
}

func checkIfconfigJail(r []string) error {
	bad := func() error { return forbidden("ifconfig: %q is not an accepted form", strings.Join(r, " ")) }
	switch {
	case len(r) == 1 && (r[0] == "up" || r[0] == "down"):
		return nil
	case len(r) == 2 && r[0] == "description":
		return checkIfaceDesc(r[1], false)
	case len(r) == 2 && r[0] == "mtu":
		n, err := strconv.Atoi(r[1])
		if err != nil || !reNumber.MatchString(r[1]) || n < MinMTU || n > MaxMTU {
			return invalid("invalid mtu %q", r[1])
		}
		return nil
	case len(r) >= 2 && (r[0] == "inet" || r[0] == "inet6"):
		v6 := r[0] == "inet6"
		addr, bits, hasSlash := strings.Cut(r[1], "/")
		if _, err := parseAddr(addr, v6); err != nil {
			return err
		}
		max := 32
		if v6 {
			max = 128
			if hasSlash {
				return forbidden("ifconfig: inet6 takes <addr> prefixlen <n>, not <addr>/<n>")
			}
		}
		if hasSlash {
			if err := parseBits(bits, max); err != nil {
				return err
			}
		}
		rest := r[2:]
		sawLen := hasSlash
		for len(rest) > 0 {
			switch {
			case rest[0] == "prefixlen" && len(rest) >= 2 && !sawLen:
				if err := parseBits(rest[1], max); err != nil {
					return err
				}
				sawLen = true
				rest = rest[2:]
			case rest[0] == "netmask" && len(rest) >= 2 && !v6 && !sawLen:
				if _, err := parseAddr(rest[1], false); err != nil {
					return err
				}
				sawLen = true
				rest = rest[2:]
			case rest[0] == "up" && !v6 && len(rest) == 1, (rest[0] == "alias" || rest[0] == "-alias") && len(rest) == 1:
				rest = rest[1:]
			default:
				return bad()
			}
		}
		return nil
	}
	return bad()
}

// verifyIfconfig runs in the helper before the command: the jail is managed and, for a form that changes the
// interface, the interface carries JailOps's marker in the jail's vnet (read there, never taken from the request).
func verifyIfconfig(ctx context.Context, l *Local, args []string) error {
	if len(args) < 3 || args[0] != "-j" {
		return forbidden("ifconfig: only the -j forms are accepted")
	}
	if err := (jailGuard{l}).managed(args[1]); err != nil {
		return err
	}
	if len(args) == 3 {
		return nil // reading one interface
	}
	return l.ifOwnedInJail(ctx, args[1], args[2])
}

// customRoute accepts: route -j <jail> add|delete [-inet6] default|<host> <gateway>.
//
// It also accepts the route to a /32 jail's gateway: route -j <jail> add -host <ipv4> -interface <if of JailOps> and
// route -j <jail> delete -host <ipv4>.
func customRoute(c Config, _ bool, args []string) error {
	if len(args) >= 5 && args[0] == "-j" && args[3] == "-host" && (args[2] == "add" || args[2] == "delete") {
		if err := ValidJailName(args[1]); err != nil {
			return err
		}
		if _, err := parseAddr(args[4], false); err != nil {
			return err
		}
		if args[2] == "delete" && len(args) == 5 {
			return nil
		}
		if args[2] == "add" && len(args) == 7 && args[5] == "-interface" {
			return c.checkJailIface(args[6])
		}
		return forbidden("route: expected -host <ipv4> -interface <interface>")
	}
	if len(args) < 5 || args[0] != "-j" || (args[2] != "add" && args[2] != "delete") {
		return forbidden("route: only -j <jail> add|delete ... is accepted")
	}
	if err := ValidJailName(args[1]); err != nil {
		return err
	}
	r := args[3:]
	v6 := false
	if r[0] == "-inet6" {
		v6, r = true, r[1:]
	}
	if len(r) != 2 {
		return forbidden("route: expected default|<host> <gateway>")
	}
	if r[0] != "default" {
		if _, err := parseAddr(r[0], v6); err != nil {
			return err
		}
	}
	gw, zone, hasZone := strings.Cut(r[1], "%")
	if hasZone {
		if !v6 || c.checkJailIface(zone) != nil {
			return invalid("invalid gateway %q", r[1])
		}
		a, err := parseAddr(gw, true)
		if err != nil || !a.IsLinkLocalUnicast() {
			return invalid("invalid gateway %q", r[1])
		}
		return nil
	}
	_, err := parseAddr(gw, v6)
	return err
}

// verifyRoute: the jail is managed, and an interface the route names (-interface, or the zone of a link-local
// gateway) carries JailOps's marker in the jail's vnet.
func verifyRoute(ctx context.Context, l *Local, args []string) error {
	if err := (jailGuard{l}).managed(args[1]); err != nil {
		return err
	}
	iface := ""
	if len(args) == 7 && args[5] == "-interface" {
		iface = args[6]
	} else if _, zone, ok := strings.Cut(args[len(args)-1], "%"); ok {
		iface = zone
	}
	if iface == "" {
		return nil
	}
	return l.ifOwnedInJail(ctx, args[1], iface)
}

// runningJailAt returns the name of the running jail whose root path p lies in, "" when there is none.
func (l *Local) runningJailAt(ctx context.Context, p string) string {
	if l == nil || l.d.Jails == nil {
		return ""
	}
	list, err := l.d.Jails.List(ctx)
	if err != nil {
		return ""
	}
	real := filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(real); err == nil {
		real = r
	}
	for _, j := range list {
		if j.Path == "" {
			continue
		}
		jp := filepath.Clean(j.Path)
		if r, err := filepath.EvalSymlinks(jp); err == nil {
			jp = r
		}
		if within(jp, real) || within(jp, filepath.Clean(p)) {
			return j.Name
		}
	}
	return ""
}
