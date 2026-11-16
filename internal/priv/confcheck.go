package priv

import (
	"context"
	"fmt"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	blockOpenRE = regexp.MustCompile(`^([A-Za-z0-9_-]{1,64}) \{$`)
	paramRE     = regexp.MustCompile(`^([a-z][a-z0-9_.]{0,63})(?: = (.+))?;$`)
	quotedRE    = regexp.MustCompile(`^"([^"\\;$\x00-\x1f]*)"$`)
	intRE       = regexp.MustCompile(`^-?[0-9]{1,9}$`)
	hostnameRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253})$`)
	whereNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	osreleaseRE = regexp.MustCompile(`^[0-9]+\.[0-9]+-[A-Za-z0-9_]+$`)
	fsOptsRE    = regexp.MustCompile(`^[a-z0-9_]+(=[A-Za-z0-9_]+)?(,[a-z0-9_]+(=[A-Za-z0-9_]+)?)*$`)
)

// checkConfContent validates what is written into ConfDir (jail.conf and
// fstab files) and into jail directories (fstab files). Other paths are not
// content-checked.
func (l *Local) checkConfContent(ctx context.Context, r resolved, path string, data []byte) error {
	base := filepath.Base(path)
	inConf := within(l.cfg.ConfDir, filepath.Clean(path))
	switch {
	case strings.HasSuffix(base, ".conf") && inConf:
		// Every start of a jail rewrites its jail.conf. The delegation lines an administrator admitted stay admitted
		// while they are unchanged; a new or changed one needs the administrator again.
		if b, err := l.ReadFile(ctx, path); err == nil && delegationLines(string(data)) == delegationLines(string(b)) {
			ctx = context.WithValue(ctx, delegationKept{}, true)
		}
		return l.cfg.checkJailConf(ctx, jailNameOfConf(l.cfg.ConfDir, path), string(data))
	case base == "fstab" || strings.HasSuffix(base, ".fstab"):
		// A file that is rewritten unchanged, as every start of a jail does, keeps the host mounts an administrator
		// admitted; a new or changed one needs the administrator again. The operator's allow-list applies to both.
		var existing string
		if b, err := l.ReadFile(ctx, path); err == nil {
			existing = string(b)
		}
		if err := l.cfg.checkFstab(ctx, string(data), existing); err != nil {
			return err
		}
		return l.cfg.checkFstabPaths(string(data), "")
	case inConf:
		return forbidden("only .conf and .fstab files may be written to %s", l.cfg.ConfDir)
	}
	return nil
}

// jailNameOfConf derives the jail name from <dir>/<name>.conf or
// <dir>/<name>/jail.conf; "" when the layout does not match.
func jailNameOfConf(dir, path string) string {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return ""
	}
	if n, ok := strings.CutSuffix(rel, ".conf"); ok && !strings.Contains(n, "/") {
		return n
	}
	if d, f := filepath.Split(rel); f == "jail.conf" {
		return strings.TrimSuffix(d, "/")
	}
	return ""
}

func unquote(v string) (string, bool) {
	m := quotedRE.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// CheckJailConf validates the text of a jail.conf as the renderer produces it:
// exactly one block named like the jail, one parameter per line, only the
// listed parameters, and nothing that could expand a variable except the fixed
// hook command lines. Anything dangerous needs the admin assertion and an
// AdminPolicy entry.
func (c Config) checkJailConf(ctx context.Context, name, text string) error {
	if name == "" {
		return invalid("jail.conf must be named <name>.conf or <name>/jail.conf")
	}
	if err := ValidJailName(name); err != nil {
		return err
	}
	if len(text) > 64<<10 {
		return invalid("jail.conf too large")
	}
	admin := isAdmin(ctx)
	var open, closed, hasVnet, hasPath bool
	for i, line := range strings.Split(text, "\n") {
		ln := i + 1
		line = strings.TrimRight(line, "\r")
		t := strings.TrimLeft(line, "\t")
		switch {
		case strings.TrimSpace(t) == "" || strings.HasPrefix(t, "#"):
			continue
		case closed:
			return invalid("jail.conf line %d: text after the block", ln)
		case !open:
			m := blockOpenRE.FindStringSubmatch(t)
			if m == nil || m[1] != name || line != t {
				return invalid("jail.conf line %d: expected the block %q", ln, name+" {")
			}
			open = true
			continue
		case t == "}" && line == t:
			closed = true
			continue
		case !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t"):
			return invalid("jail.conf line %d: parameters are indented with one tab", ln)
		}
		m := paramRE.FindStringSubmatch(t)
		if m == nil {
			return invalid("jail.conf line %d: not a parameter line", ln)
		}
		key, val := m[1], m[2]
		hasVal := strings.Contains(t, " = ")
		if err := c.checkJailParam(ctx, name, key, val, hasVal, admin); err != nil {
			return fmt.Errorf("jail.conf line %d: %w", ln, err)
		}
		hasVnet = hasVnet || key == "vnet" && !hasVal
		hasPath = hasPath || key == "path"
	}
	switch {
	case !open || !closed:
		return invalid("jail.conf has no complete block")
	case !hasVnet:
		return forbidden("jail.conf must set vnet; shared-IP jails are not supported")
	case !hasPath:
		return invalid("jail.conf has no path")
	}
	return nil
}

func (c Config) checkJailParam(ctx context.Context, name, key, val string, hasVal, admin bool) error {
	bare := func() error {
		if hasVal {
			return invalid("%s takes no value", key)
		}
		return nil
	}
	str := func() (string, error) {
		if !hasVal {
			return "", invalid("%s needs a value", key)
		}
		s, ok := unquote(val)
		if !ok {
			return "", invalid("%s: value must be a quoted string without $ ; or backslash", key)
		}
		return s, nil
	}
	num := func() (int, error) {
		if !hasVal || !intRE.MatchString(val) {
			return 0, invalid("%s needs a number", key)
		}
		n, _ := strconv.Atoi(val)
		return n, nil
	}
	hook := func(phase string) error {
		if !hasVal {
			return invalid("%s needs a value", key)
		}
		want := fmt.Sprintf("%q", c.HelperPath+" hook "+phase+" ${name}")
		if val != want {
			return forbidden("%s must be exactly %s", key, want)
		}
		return nil
	}
	switch key {
	case "path":
		s, err := str()
		if err != nil {
			return err
		}
		if !filepath.IsAbs(s) || filepath.Clean(s) != s || c.isMountRoot(s) || !c.inMounts(s) {
			return c.notBelowMount(s)
		}
		return c.checkJailRoot(name, s)
	case "host.hostname":
		s, err := str()
		if err != nil {
			return err
		}
		if !hostnameRE.MatchString(s) {
			return invalid("invalid hostname %q", s)
		}
		return nil
	case "env.jailops_jail", "env.jailops_project", "env.jailops_host":
		// where the jail is: names only, read by the jail as lines of the sysctl security.jail.env
		s, err := str()
		if err != nil {
			return err
		}
		if !whereNameRE.MatchString(s) {
			return invalid("%s: %q is not a name", key, s)
		}
		return nil
	case "vnet", "mount.devfs", "persist", "exec.clean":
		return bare()
	case "vnet.interface":
		if !hasVal {
			return invalid("vnet.interface needs a value")
		}
		for _, part := range strings.Split(val, ", ") {
			s, ok := unquote(part)
			if !ok {
				return invalid("vnet.interface: bad value")
			}
			if err := c.epairEndName(s); err != nil {
				return err
			}
		}
		return nil
	case "devfs_ruleset":
		n, err := num()
		if err != nil {
			return err
		}
		if n != 4 && !(n >= DevfsRulesetMin && n <= DevfsRulesetMax) && !(admin && slices.Contains(c.Admin.DevfsRulesets, n)) {
			// the private range holds only rulesets defined through the helper's devfs grammar
			return forbidden("devfs ruleset %d needs the admin assertion and an allow-list entry", n)
		}
		return nil
	case "mount.fstab":
		s, err := str()
		if err != nil {
			return err
		}
		if !filepath.IsAbs(s) || filepath.Clean(s) != s || !within(c.ConfDir, s) {
			return forbidden("fstab %q is outside the allowed roots", s)
		}
		return nil
	case "enforce_statfs":
		n, err := num()
		if err != nil {
			return err
		}
		if n == 1 && c.delegationAllowed(ctx, admin) {
			return nil // a jail that may mount its delegated dataset
		}
		if n != 2 {
			return c.rawParam(admin, key)
		}
		return nil
	case "zfs.dataset":
		s, err := str()
		if err != nil {
			return err
		}
		if !c.delegationAllowed(ctx, admin) || !slices.Contains(c.delegatedDatasetNames(name), s) {
			return forbidden("zfs.dataset must be the delegated dataset of this jail, and needs the admin assertion and admin-zfs-delegation in priv.conf")
		}
		return nil
	case "securelevel":
		n, err := num()
		if err != nil {
			return err
		}
		if n < 0 || n > 3 {
			return c.rawParam(admin, key)
		}
		return nil
	case "osrelease":
		s, err := str()
		if err != nil {
			return err
		}
		if !osreleaseRE.MatchString(s) {
			return invalid("invalid osrelease %q", s)
		}
		return nil
	case "exec.prestart", "exec.poststart", "exec.prestop", "exec.poststop":
		return hook(strings.TrimPrefix(key, "exec."))
	case "exec.start":
		if val != `"/bin/sh /etc/rc"` {
			return c.rawParam(admin, key)
		}
		return nil
	case "exec.stop":
		if val != `"/bin/sh /etc/rc.shutdown jail"` {
			return c.rawParam(admin, key)
		}
		return nil
	case "stop.timeout":
		n, err := num()
		if err != nil {
			return err
		}
		if n < 1 || n > api.MaxStopTimeout {
			return invalid("stop.timeout must be between 1 and %d seconds", api.MaxStopTimeout)
		}
		return nil
	case "exec.consolelog":
		// the output of the exec.* commands goes to this host file, not to the pipes of jail(8)'s caller
		if val != `"`+render.ConsoleLog+`"` {
			return forbidden("%s must be exactly %q", key, render.ConsoleLog)
		}
		return nil
	case "sysvmsg", "sysvsem", "sysvshm":
		// new: System V IPC of the jail's own; inherit (the host's) is for the allow-list
		if val != "new" {
			return c.rawParam(admin, key)
		}
		return nil
	}
	if flag, ok := strings.CutPrefix(key, "allow."); ok {
		if err := bare(); err != nil {
			return err
		}
		if c.delegationAllowed(ctx, admin) && (flag == "mount" || flag == "mount.zfs") {
			return nil
		}
		if !admin || !slices.Contains(c.Admin.AllowFlags, flag) {
			return forbidden("allow.%s needs the admin assertion and an allow-list entry", flag)
		}
		return nil
	}
	if err := c.rawParam(admin, key); err != nil {
		return err
	}
	if hasVal && !intRE.MatchString(val) {
		if _, ok := unquote(val); !ok {
			return invalid("%s: unsafe value", key)
		}
	}
	return nil
}

func (c Config) rawParam(admin bool, key string) error {
	if admin && slices.Contains(c.Admin.RawJailParams, key) {
		return nil
	}
	return forbidden("jail parameter %s needs the admin assertion and an allow-list entry", key)
}

var fstabTypes = map[string]bool{"devfs": true, "tmpfs": true, "fdescfs": true, "linprocfs": true, "linsysfs": true, "procfs": true, "nullfs": true}

// checkFstab validates a jail fstab. Mount points must be below a storage
// root's mountpoint. A nullfs source must be the root of a volume of a storage (or, for a Linux jail, the jail's own
// root at compat/linux), or, with the admin assertion, below an AdminPolicy host mount root.
func (c Config) checkFstab(ctx context.Context, text, existing string) error {
	if len(text) > 64<<10 {
		return invalid("fstab too large")
	}
	if err := c.checkFstabNesting(text); err != nil {
		return err
	}
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) != 6 {
			return invalid("fstab line %d: want 6 fields", i+1)
		}
		dev, mp, typ, opts := f[0], f[1], f[2], f[3]
		if !fstabTypes[typ] {
			return forbidden("fstab line %d: filesystem type %q is not allowed", i+1, typ)
		}
		if !fsOptsRE.MatchString(opts) {
			return invalid("fstab line %d: invalid options", i+1)
		}
		for _, n := range f[4:] {
			if n != "0" && n != "1" && n != "2" {
				return invalid("fstab line %d: invalid dump or pass", i+1)
			}
		}
		if !cleanAbs(mp) || !c.inMounts(mp) {
			return forbidden("fstab line %d: mount point %q is outside %s", i+1, mp, c.mountBaseDesc())
		}
		if typ != "nullfs" {
			if dev != typ {
				return invalid("fstab line %d: device of a %s mount must be %q", i+1, typ, typ)
			}
			continue
		}
		if !cleanAbs(dev) {
			return invalid("fstab line %d: invalid source %q", i+1, dev)
		}
		if c.volumeRoot(dev) || c.linuxMirror(dev, mp) {
			continue
		}
		if c.inMounts(dev) {
			return forbidden("fstab line %d: %q is not the root of a volume: only volumes are mounted into a jail from a storage", i+1, dev)
		}
		listed := false
		for _, r := range c.Admin.HostMountRoots {
			listed = listed || within(r, dev)
		}
		admitted := isAdmin(ctx)
		if !admitted {
			for _, e := range parseFstab(existing) {
				admitted = admitted || e.line == strings.Join(f, " ")
			}
		}
		if !(listed && admitted) {
			return forbidden("fstab line %d: host mount of %q needs the admin assertion and an allow-list entry", i+1, dev)
		}
	}
	return nil
}

// volumeRoot reports whether p is exactly the mountpoint of a volume: <storage mount>/projects/<project>/volumes/<name>.
func (c Config) volumeRoot(p string) bool {
	for _, m := range c.reg.mounts() {
		if !within(m, p) {
			continue
		}
		rel, err := filepath.Rel(m, p)
		if err != nil {
			return false
		}
		s := strings.Split(rel, "/")
		if len(s) == 4 && jailTreeDepth(rel) == 4 {
			return true
		}
	}
	return false
}

// linuxMirror reports whether a nullfs line mirrors a jail's root at its own compat/linux, the mount of a Linux jail.
func (c Config) linuxMirror(dev, mp string) bool {
	if mp != dev+"/compat/linux" {
		return false
	}
	for _, m := range c.reg.mounts() {
		if !within(m, dev) {
			continue
		}
		rel, err := filepath.Rel(m, dev)
		if err == nil && len(strings.Split(rel, "/")) == 5 && jailTreeDepth(rel) == 5 && filepath.Base(rel) == "root" {
			return true
		}
	}
	return false
}

func cleanAbs(p string) bool {
	// no path the helper is asked about holds two dots in a row, even inside a name (a clean path has no ".." element, and
	// this keeps the rule simple to audit)
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n\t ") && !strings.Contains(p, "..")
}

var reJailRoot = regexp.MustCompile(`^(/.+)/projects/([^/]+)/jails/([^/]+)/root$`)

// checkJailRoot says that the path of a jail is the root of that jail and no other place: <storage mount>/projects/
// <project>/jails/<name>/root, where the jail is called <project>_<name>, and that it reaches that place without a
// symbolic link. jail(8) follows a link in path (the jail's root would be whatever it points at, the host's / for
// one), so the lexical form is not enough: the check resolves the path as it is now, and runs again when the jail is
// started.
func (c Config) checkJailRoot(name, p string) error {
	m := reJailRoot.FindStringSubmatch(p)
	if m == nil || !c.isMountRoot(m[1]) || name != m[2]+"_"+m[3] {
		return forbidden("the path of jail %s is %s/projects/<project>/jails/<name>/root of a storage root, not %q", name, c.mountBaseDesc(), p)
	}
	if err := plainBelow(m[1], p); err != nil {
		return forbidden("the path of jail %s: %v", name, err)
	}
	return nil
}

// checkFstabNesting refuses a mount point below the mount point of a volume or a host directory (and two mounts on one
// mount point). Until jail(8) has mounted the first, the second path is a path of the jail's own tree; afterwards it
// is a path inside the volume, which another jail (or this one) can write to: a symbolic link there would carry the
// second mount to wherever it points, over a directory of the host. Only what the helper itself lays out is nested: a
// Linux jail's compat/linux mirror of its own root with the file systems below it, and devfs with fdescfs.
func (c Config) checkFstabNesting(text string) error {
	type mnt struct {
		dev, mp, typ string
		line         int
	}
	var all []mnt
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 6 && !strings.HasPrefix(f[0], "#") {
			all = append(all, mnt{f[0], f[1], f[2], i + 1})
		}
	}
	for _, in := range all {
		for _, out := range all {
			if in.line == out.line || out.typ != "nullfs" || c.linuxMirror(out.dev, out.mp) {
				continue
			}
			if in.mp == out.mp {
				return forbidden("fstab line %d: mount point %q is mounted twice (line %d)", in.line, in.mp, out.line)
			}
			if within(out.mp, in.mp) {
				return forbidden("fstab line %d: mount point %q is inside the mount point %q of line %d: nothing is mounted below a volume", in.line, in.mp, out.mp, out.line)
			}
		}
	}
	return nil
}
