package render

import (
	"fmt"
	"sort"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// HelperCommand is the fixed privileged helper invoked by jail hooks. It
// receives only a phase and the jail name as jail.conf expands ${name}.
// UNVERIFIED: that jail.conf expands ${name} inside exec.* strings, and that
// jailops-priv grows a "hook" subcommand.
const HelperCommand = "/usr/local/libexec/jailops-priv hook"

// DefaultDevfsRuleset is devfsrules_jail from the stock FreeBSD devfs.rules.
const DefaultDevfsRuleset = 4

// AllowList is the set of allow.* parameters jail.conf may carry; the
// argument names omit the "allow." prefix.
var AllowList = map[string]bool{
	"set_hostname": true, "sysvipc": true, "raw_sockets": true, "chflags": true,
	"mlock": true, "reserved_ports": true, "read_msgbuf": true, "socket_af": true,
	"mount": true, "mount.devfs": true, "mount.fdescfs": true, "mount.nullfs": true,
	"mount.procfs": true, "mount.tmpfs": true, "mount.zfs": true,
}

// JailConfInput is everything the per-jail jail.conf depends on.
type JailConfInput struct {
	Name     string
	Path     string // absolute jail root
	Hostname string
	OS       api.OS
	// Interfaces are the jail-side interface names moved into the vnet.
	Interfaces []string
	// DevfsRuleset defaults to DefaultDevfsRuleset when zero.
	DevfsRuleset int
	// EnforceStatfs defaults to 2.
	EnforceStatfs *int
	// SecureLevel is omitted when nil.
	SecureLevel *int
	OSRelease   string // optional, e.g. "15.1-RELEASE"
	Allow       []string
	// FstabPath, when set, becomes mount.fstab.
	FstabPath string
	// SysVIPC gives the jail System V IPC namespaces of its own (sysvmsg,
	// sysvsem, sysvshm = new); never inherit, which would share the host's.
	SysVIPC bool
	// ZFSDataset is the dataset handed to the jail (zfs_delegation): jail(8) runs `zfs jail` on it at the start and
	// `zfs unjail` at the stop. It needs allow.mount.zfs and enforce_statfs below 2, which the caller sets.
	ZFSDataset string
	// Where is the jail's name, its project and the short name of its host. They become the jail parameters
	// env.jailops_jail, env.jailops_project and env.jailops_host, which the jail reads as lines of the sysctl
	// security.jail.env (EnvScript); the keys are prefixed because any tool may write that buffer. A value that is
	// empty has no parameter.
	Where api.PromptContext
	// StopTimeout is the number of seconds jail(8) waits after exec.stop before it kills the jail (stop.timeout);
	// zero leaves jail(8)'s default of ten.
	StopTimeout int
}

// ConsoleLog is where jail(8) sends the output of the exec.* commands of a
// jail, instead of the pipes of whoever ran jail -c or jail -r: a daemon an rc
// script starts keeps its descriptors open, and the caller would wait for the
// end of that output for ever. ${name} is the jail's name.
const ConsoleLog = "/var/log/jailops/jail_${name}_console.log"

// JailConf renders the jail.conf of one jail.
func JailConf(in JailConfInput) (string, error) {
	var b builder
	if err := validate.JailKey("name", in.Name); err != nil {
		return "", err
	}
	if err := validate.AbsPath("path", in.Path); err != nil {
		return "", err
	}
	host := in.Hostname
	if host == "" {
		host = in.Name
	}
	if err := validate.Hostname("hostname", host); err != nil {
		return "", err
	}
	if in.OS != api.OSFreeBSD && in.OS != api.OSLinux {
		return "", fmt.Errorf("render: unknown os %q", in.OS)
	}
	linux := in.OS == api.OSLinux
	rs := in.DevfsRuleset
	if rs == 0 {
		rs = DefaultDevfsRuleset
	}
	if rs < 1 || rs > 65535 {
		return "", fmt.Errorf("render: devfs ruleset %d out of range", rs)
	}
	es := 2
	if in.EnforceStatfs != nil {
		es = *in.EnforceStatfs
	}
	if es < 0 || es > 2 {
		return "", fmt.Errorf("render: enforce_statfs %d out of range", es)
	}
	if in.SecureLevel != nil && (*in.SecureLevel < -1 || *in.SecureLevel > 3) {
		return "", fmt.Errorf("render: securelevel %d out of range", *in.SecureLevel)
	}
	var ifs []string
	for _, i := range in.Interfaces {
		if err := validate.IfName("interface", i); err != nil {
			return "", err
		}
		q, _ := quoted("interface", i)
		ifs = append(ifs, q)
	}
	allow := append([]string(nil), in.Allow...)
	sort.Strings(allow)
	for i, a := range allow {
		if !AllowList[a] {
			return "", fmt.Errorf("render: allow.%s is not on the allow-list", a)
		}
		if i > 0 && allow[i-1] == a {
			return "", fmt.Errorf("render: duplicate allow.%s", a)
		}
		if a == "sysvipc" && in.SysVIPC {
			return "", fmt.Errorf("render: allow.sysvipc shares the host's System V IPC and contradicts sysvipc")
		}
	}
	path, err := quoted("path", in.Path)
	if err != nil {
		return "", err
	}
	hq, err := quoted("hostname", host)
	if err != nil {
		return "", err
	}

	b.line("%s", Header)
	b.line("%s {", in.Name)
	b.line("\tpath = %s;", path)
	b.line("\thost.hostname = %s;", hq)
	for _, e := range []struct{ key, val string }{{"env." + api.EnvKeyJail, in.Where.Jail}, {"env." + api.EnvKeyProject, in.Where.Project}, {"env." + api.EnvKeyHost, in.Where.Host}} {
		if v := api.NameChars(e.val); v != "" {
			q, err := quoted(e.key, v)
			if err != nil {
				return "", err
			}
			b.line("\t%s = %s;", e.key, q)
		}
	}
	b.line("\tvnet;")
	if len(ifs) > 0 {
		b.line("\tvnet.interface = %s;", join(ifs, ", "))
	}
	if linux {
		// UNVERIFIED: Linux jails mount devfs from the fstab (Linuxulator
		// layout) and then need no mount.devfs; the ruleset below is only
		// enforced for devfs mounts made by jail(8) itself.
		b.line("\tdevfs_ruleset = %d;", rs)
	} else {
		b.line("\tdevfs_ruleset = %d;", rs)
		b.line("\tmount.devfs;")
	}
	if in.FstabPath != "" {
		if err := validate.AbsPath("fstab", in.FstabPath); err != nil {
			return "", err
		}
		q, _ := quoted("fstab", in.FstabPath)
		b.line("\tmount.fstab = %s;", q)
	}
	b.line("\texec.clean;")
	b.line("\texec.prestart = \"%s prestart ${name}\";", HelperCommand)
	b.line("\texec.poststart = \"%s poststart ${name}\";", HelperCommand)
	b.line("\texec.prestop = \"%s prestop ${name}\";", HelperCommand)
	b.line("\texec.poststop = \"%s poststop ${name}\";", HelperCommand)
	b.line("\texec.consolelog = \"%s\";", ConsoleLog)
	if !linux {
		b.line("\texec.start = \"/bin/sh /etc/rc\";")
		b.line("\texec.stop = \"/bin/sh /etc/rc.shutdown jail\";")
	}
	if in.StopTimeout > 0 {
		b.line("\tstop.timeout = %d;", in.StopTimeout)
	}
	b.line("\tenforce_statfs = %d;", es)
	if in.SecureLevel != nil {
		b.line("\tsecurelevel = %d;", *in.SecureLevel)
	}
	if in.OSRelease != "" {
		if err := validate.OSRelease("osrelease", in.OSRelease); err != nil {
			return "", err
		}
		q, _ := quoted("osrelease", in.OSRelease)
		b.line("\tosrelease = %s;", q)
	}
	for _, a := range allow {
		b.line("\tallow.%s;", a)
	}
	if in.ZFSDataset != "" {
		q, err := quoted("zfs.dataset", in.ZFSDataset)
		if err != nil {
			return "", err
		}
		b.line("\tzfs.dataset = %s;", q)
	}
	if in.SysVIPC {
		// UNVERIFIED on FreeBSD: that a server (PostgreSQL) in a vnet jail runs with these.
		b.line("\tsysvmsg = new;")
		b.line("\tsysvsem = new;")
		b.line("\tsysvshm = new;")
	}
	if linux {
		// UNVERIFIED: a Linux jail has no FreeBSD init, so it must persist
		// without processes until JailOps removes it.
		b.line("\tpersist;")
	}
	b.line("}")
	return b.result()
}

func join(s []string, sep string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}
