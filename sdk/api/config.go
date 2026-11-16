package api

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file is the one place configuration keys exist (design section 8.3).
// A key is a dotted name that maps to a field of the typed JailSpec; the CLI,
// the web UI, jailops-sync and the daemon all go through ConfigKeys,
// ApplyConfig and ExpandedConfig. The typed spec stays canonical: a key is a
// way to read and write it, not a second data model.

// Profile is a named, reusable set of configuration keys and devices. Devices
// are keys too (nic.eth1.network, disk.data.quota, ...). A profile belongs to
// a project; the profiles of the reserved project "host" are visible to every
// project.
type Profile struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     ProfileSpec `json:"spec"`
}

// ProfileSpec holds the keys of a profile.
type ProfileSpec struct {
	// Comment is what the profile is for.
	Comment string `json:"comment,omitempty"`
	// Config maps keys of the registry that are allowed in a profile to values.
	Config map[string]string `json:"config,omitempty"`
}

// HostProfileProject is the reserved project name that selects host-level
// profiles (?project=host). Only a global admin writes them.
const HostProfileProject = "host"

// KindProfile is the kind of Profile objects.
const KindProfile Kind = "Profile"

// ConfigKey describes one key of the registry.
type ConfigKey struct {
	// Name is the dotted key; "<device>", "<name>" and "<var>" stand for the
	// name of a device or variable.
	Name string `json:"name"`
	// Type is string, int, bool, size, rate, list, enum, address, mac, listen
	// or device (a key that adds or removes a whole device).
	Type        string   `json:"type"`
	Values      []string `json:"values,omitempty"`
	Description string   `json:"description"`
	Example     string   `json:"example,omitempty"`
	// RestartRequired says that a change takes effect at the next start of
	// the jail. The daemon never restarts a jail on its own.
	RestartRequired bool `json:"restart_required"`
	// Profile says whether the key may appear in a profile.
	Profile bool `json:"profile"`
	// Admin marks keys that need the admin role (device nodes).
	Admin bool `json:"admin,omitempty"`
	// Global marks keys that need a global administrator: a published port takes traffic the host would otherwise get.
	Global bool `json:"global,omitempty"`
	// Path is the location in the typed spec, for example "resources.cpu".
	Path string `json:"path"`
}

type ckey struct {
	ConfigKey
	get   func(s *JailSpec, dev string) (string, bool)
	set   func(s *JailSpec, dev, v string) error
	unset func(s *JailSpec, dev string)
}

var (
	macRE  = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	rateRE = regexp.MustCompile(`^[1-9][0-9]{0,8}[KMGkmg]?$`)            // a rate in bits per second: 10M is 10 Mbit/s (decimal units)
	sizeRE = regexp.MustCompile(`^[1-9][0-9]*([KMGTPkmgtp](iB|B)?|B)?$`) // the sizes the server takes; it stores them as bytes
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	envRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// DevfsAllowList lists the device nodes a jail may be given.
var DevfsAllowList = []string{"tun", "tap", "pf", "bpf", "fuse", "dri"}

func cfgErr(key, format string, a ...any) *Error {
	return Errorf(CodeInvalid, format, a...).WithDetail("key", key)
}

func atoiRange(key, v string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, cfgErr(key, "%s: %q must be a number between %d and %d", key, v, lo, hi)
	}
	return n, nil
}

func parseBool(key, v string) (bool, error) {
	switch v {
	case "true", "yes", "on", "1":
		return true, nil
	case "false", "no", "off", "0":
		return false, nil
	}
	return false, cfgErr(key, "%s: %q is not true or false", key, v)
}

func checkSize(key, v string) error {
	if !sizeRE.MatchString(v) {
		return cfgErr(key, "%s: %q is not a size such as 512M or 2G", key, v)
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func checkAddr(key, v string, v4 bool) error {
	if v == "auto" || v == "none" {
		return nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil || a.Is4() != v4 || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return cfgErr(key, "%s: %q is not auto, none or a unicast %s address", key, v, map[bool]string{true: "IPv4", false: "IPv6"}[v4])
	}
	return nil
}

func checkListen(key, v string) error {
	host, port, ok := strings.Cut(v, ":")
	if strings.Contains(port, ":") {
		i := strings.LastIndex(v, ":")
		host, port = strings.Trim(v[:i], "[]"), v[i+1:]
	} else if !ok {
		return cfgErr(key, "%s: %q must be host:port or :port", key, v)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return cfgErr(key, "%s: %q is not an address of the host", key, host)
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return cfgErr(key, "%s: %q is not a port", key, port)
	}
	return nil
}

// ---- device lookup ----

func normalizeDevices(s *JailSpec) {
	for i := range s.Network {
		if s.Network[i].Name == "" {
			s.Network[i].Name = fmt.Sprintf("eth%d", i)
		}
	}
}

// NormalizeDevices gives every network attachment the name "eth<index>" when
// it has none. Volumes are named already.
func NormalizeDevices(s *JailSpec) { normalizeDevices(s) }

func nic(s *JailSpec, d string, create bool) *NetworkAttach {
	normalizeDevices(s)
	for i := range s.Network {
		if s.Network[i].Name == d {
			return &s.Network[i]
		}
	}
	if !create {
		return nil
	}
	s.Network = append(s.Network, NetworkAttach{Name: d})
	return &s.Network[len(s.Network)-1]
}

func disk(s *JailSpec, d string, create bool) *VolumeAttach {
	for i := range s.Volumes {
		if s.Volumes[i].Name == d {
			return &s.Volumes[i]
		}
	}
	if !create {
		return nil
	}
	s.Volumes = append(s.Volumes, VolumeAttach{Name: d})
	return &s.Volumes[len(s.Volumes)-1]
}

func devfs(s *JailSpec, d string, create bool) *DevfsDevice {
	for i := range s.Devfs {
		if s.Devfs[i].Name == d {
			return &s.Devfs[i]
		}
	}
	if !create {
		return nil
	}
	s.Devfs = append(s.Devfs, DevfsDevice{Name: d})
	return &s.Devfs[len(s.Devfs)-1]
}

func proxy(s *JailSpec, d string, create bool) *ProxyDevice {
	for i := range s.Proxy {
		if s.Proxy[i].Name == d {
			return &s.Proxy[i]
		}
	}
	if !create {
		return nil
	}
	s.Proxy = append(s.Proxy, ProxyDevice{Name: d})
	return &s.Proxy[len(s.Proxy)-1]
}

func deviceField[T any](dev string, find func(*JailSpec, string, bool) *T,
	get func(*T) string, set func(*T, string), clear func(*T)) (func(*JailSpec, string) (string, bool),
	func(*JailSpec, string, string) error, func(*JailSpec, string)) {
	return func(s *JailSpec, d string) (string, bool) {
			p := find(s, d, false)
			if p == nil {
				return "", false
			}
			v := get(p)
			return v, v != ""
		}, func(s *JailSpec, d, v string) error {
			if !IsName(d, 31) {
				return cfgErr(dev+"."+d, "%q is not a device name (lower case letters, digits and '-')", d)
			}
			set(find(s, d, true), v)
			return nil
		}, func(s *JailSpec, d string) {
			if p := find(s, d, false); p != nil {
				clear(p)
			}
		}
}

// ---- the registry ----

var registry = buildRegistry()

func buildRegistry() []ckey {
	var r []ckey
	add := func(k ckey) { r = append(r, k) }
	str := func(name, path, desc, example string, restart, profile bool, get func(*JailSpec) *string, check func(string) error) {
		add(ckey{ConfigKey: ConfigKey{Name: name, Type: "string", Description: desc, Example: example, RestartRequired: restart, Profile: profile, Path: path},
			get: func(s *JailSpec, _ string) (string, bool) { v := *get(s); return v, v != "" },
			set: func(s *JailSpec, _, v string) error {
				if check != nil {
					if err := check(v); err != nil {
						return cfgErr(name, "%s: %v", name, err)
					}
				}
				*get(s) = v
				return nil
			},
			unset: func(s *JailSpec, _ string) { *get(s) = "" }})
	}
	num := func(name, path, desc, example string, lo, hi int, restart bool, get func(*JailSpec) *int) {
		add(ckey{ConfigKey: ConfigKey{Name: name, Type: "int", Description: desc, Example: example, RestartRequired: restart, Profile: true, Path: path},
			get: func(s *JailSpec, _ string) (string, bool) {
				if v := *get(s); v != 0 {
					return strconv.Itoa(v), true
				}
				return "", false
			},
			set: func(s *JailSpec, _, v string) error {
				n, err := atoiRange(name, v, lo, hi)
				if err != nil {
					return err
				}
				*get(s) = n
				return nil
			},
			unset: func(s *JailSpec, _ string) { *get(s) = 0 }})
	}
	size := func(name, path, desc, example string, restart bool, get func(*JailSpec) *string) {
		add(ckey{ConfigKey: ConfigKey{Name: name, Type: "size", Description: desc, Example: example, RestartRequired: restart, Profile: true, Path: path},
			get: func(s *JailSpec, _ string) (string, bool) { v := *get(s); return v, v != "" },
			set: func(s *JailSpec, _, v string) error {
				if err := checkSize(name, v); err != nil {
					return err
				}
				*get(s) = v
				return nil
			},
			unset: func(s *JailSpec, _ string) { *get(s) = "" }})
	}
	list := func(name, path, desc, example string, restart, profile bool, get func(*JailSpec) *[]string, item func(string) error) {
		add(ckey{ConfigKey: ConfigKey{Name: name, Type: "list", Description: desc, Example: example, RestartRequired: restart, Profile: profile, Path: path},
			get: func(s *JailSpec, _ string) (string, bool) { v := strings.Join(*get(s), ","); return v, v != "" },
			set: func(s *JailSpec, _, v string) error {
				l := splitList(v)
				for _, x := range l {
					if item != nil {
						if err := item(x); err != nil {
							return cfgErr(name, "%s: %v", name, err)
						}
					}
				}
				*get(s) = l
				return nil
			},
			unset: func(s *JailSpec, _ string) { *get(s) = nil }})
	}
	nameCheck := func(v string) error {
		if !IsName(v, MaxName) {
			return fmt.Errorf("%q is not a name (lower case letters, digits and '-')", v)
		}
		return nil
	}

	str("image", "image", "Image reference: name, name@alias or name#gN. The image name cannot change on a living jail.", "freebsd-15-1", true, false,
		func(s *JailSpec) *string { return &s.Image }, func(v string) error {
			if v == "" || strings.ContainsAny(v, " \t\n/") {
				return fmt.Errorf("%q is not an image reference", v)
			}
			return nil
		})
	str("storage", "storage", "Storage the jail's datasets live on: a storage granted to the project. Fixed when the jail is created; a profile may supply it.", "default", true, true,
		func(s *JailSpec) *string { return &s.Storage }, func(v string) error { return nameCheck(v) })
	str("hostname", "hostname", "Hostname inside the jail (the jail name when empty).", "web.example.org", true, false,
		func(s *JailSpec) *string { return &s.Hostname }, func(v string) error {
			if len(v) > 253 || !hostRE.MatchString(v) {
				return fmt.Errorf("%q is not a DNS name", v)
			}
			return nil
		})
	list("profiles", "profiles", "Profiles merged into this jail, in order; later ones override earlier ones.", "base,web", true, false,
		func(s *JailSpec) *[]string { return &s.Profiles }, nameCheck)
	num("limits.cpu", "resources.cpu", "CPU cores the jail may use: more is slowed down to that share (rctl pcpu); needs kern.racct.enable=1.", "2", 0, 4096, true, func(s *JailSpec) *int { return &s.Resources.CPU })
	size("limits.memory", "resources.memory", "Anonymous memory the jail may reserve in total (rctl swapuse): an allocation beyond it fails and nothing is killed; needs kern.racct.enable=1.", "2G", true, func(s *JailSpec) *string { return &s.Resources.Memory })
	num("limits.pids", "resources.pids", "Processes the jail may have (rctl maxproc): fork fails beyond it; needs kern.racct.enable=1.", "500", 0, 4194304, true, func(s *JailSpec) *int { return &s.Resources.PIDs })
	size("limits.disk", "resources.disk", "ZFS quota of the jail's container: its root, persistent datasets, volumes and snapshots together.", "20G", false, func(s *JailSpec) *string { return &s.Resources.Disk })
	size("limits.disk_reservation", "resources.disk_reservation", "ZFS reservation of the jail's container.", "5G", false, func(s *JailSpec) *string { return &s.Resources.DiskReservation })
	num("limits.states", "resources.states", "Pf states each rule of the jail's firewall may create, so that one jail cannot fill the host's state table; 0 is the host's default.", "20000", 0, 10000000, false, func(s *JailSpec) *int { return &s.Resources.States })
	add(ckey{ConfigKey: ConfigKey{Name: "boot.autostart", Type: "bool", Description: "Start the jail when the host starts.", Example: "true", Profile: true, Path: "boot.autostart"},
		get: func(s *JailSpec, _ string) (string, bool) { return "true", s.Boot.Autostart },
		set: func(s *JailSpec, _, v string) error {
			b, err := parseBool("boot.autostart", v)
			s.Boot.Autostart = b
			return err
		},
		unset: func(s *JailSpec, _ string) { s.Boot.Autostart = false }})
	num("boot.priority", "boot.priority", "Start order: lower starts first.", "10", -1000, 1000, false, func(s *JailSpec) *int { return &s.Boot.Priority })
	num("boot.stop_timeout", "boot.stop_timeout", "Seconds the jail has to shut down by itself, after its stop command, before it is killed; 0 is the system's ten seconds. A database that needs a minute to close says 60. Written into the jail's configuration at its start.", "60", 0, MaxStopTimeout, true, func(s *JailSpec) *int { return &s.Boot.StopTimeout })
	list("boot.depends", "boot.depends", "Jails of the project that must run first.", "db,cache", false, false,
		func(s *JailSpec) *[]string { return &s.Boot.Depends }, nameCheck)
	add(ckey{ConfigKey: ConfigKey{Name: "update.strategy", Type: "enum", Values: []string{string(UpdateRebase), string(UpdateInPlace), string(UpdateManual)},
		Description: "How the jail follows its image.", Example: "rebase", Profile: true, Path: "update.strategy"},
		get: func(s *JailSpec, _ string) (string, bool) { return string(s.Update.Strategy), s.Update.Strategy != "" },
		set: func(s *JailSpec, _, v string) error {
			switch UpdateStrategy(v) {
			case UpdateRebase, UpdateInPlace, UpdateManual:
				s.Update.Strategy = UpdateStrategy(v)
				return nil
			}
			return cfgErr("update.strategy", "update.strategy: %q must be rebase, inplace or manual", v)
		},
		unset: func(s *JailSpec, _ string) { s.Update.Strategy = "" }})
	str("update.window", "update.window", "Maintenance window of automatic updates.", "sun 03:00", false, true, func(s *JailSpec) *string { return &s.Update.Window }, nil)
	str("update.healthcheck", "update.healthcheck", "Command run in the jail after an update.", "/usr/local/bin/check", false, true,
		func(s *JailSpec) *string { return &s.Update.Healthcheck }, nil)
	add(ckey{ConfigKey: ConfigKey{Name: "shell", Type: "string", Example: "bash", Profile: true, Path: "shell",
		Description: "Shell that `jailops shell` and the console start: bash, sh or a path inside the jail (/bin/sh when empty). New FreeBSD jails get bash. A management setting; /etc/passwd is not touched. `jailops jail shell-setup` installs bash when it is missing."},
		get: func(s *JailSpec, _ string) (string, bool) { return s.Shell, s.Shell != "" },
		set: func(s *JailSpec, _, v string) error {
			v = ShellPath(v)
			if !strings.HasPrefix(v, "/") || len(v) > 255 || strings.ContainsAny(v, " \t\r\n\x00") || strings.Contains(v, "..") {
				return cfgErr("shell", "shell: %q is not bash, sh or an absolute path without spaces inside the jail", v)
			}
			s.Shell = v
			return nil
		},
		unset: func(s *JailSpec, _ string) { s.Shell = "" }})
	str("prompt", "prompt", "Bash prompt of a FreeBSD jail, for every user: default (user@jail in colour, then in grey [project/host], then the directory), short (the same without the grey tag), none (no prompt, the variables stay), or a PS1 text such as \\u@\\h [{project}/{host}]:\\w\\$ with bash's escapes (no ', ` or $ other than \\$: nothing in it runs; \\e or \\033 start a colour) and the words {jail}, {project} and {host}, which read the variables JAILOPS_JAIL, JAILOPS_PROJECT and JAILOPS_HOST that every interactive bash of the jail has. A user's own ~/.bashrc wins. Written into "+PromptFile+" at once in a running jail, else at its next start.", "default", false, true,
		func(s *JailSpec) *string { return &s.Prompt }, CheckPrompt)
	add(ckey{ConfigKey: ConfigKey{Name: "updates.mode", Type: "enum", Values: []string{"manual", "notify", "managed"}, Profile: true, Path: "update.mode",
		Description: "manual: nothing happens unless you run it. notify: check on the schedule and report. managed: check and apply on the schedule. Off (manual) by default.", Example: "notify"},
		get: func(s *JailSpec, _ string) (string, bool) { return string(s.Update.Mode), s.Update.Mode != "" },
		set: func(s *JailSpec, _, v string) error {
			switch UpdateMode(v) {
			case UpdateModeManual, UpdateModeNotify, UpdateModeManaged:
				s.Update.Mode = UpdateMode(v)
				return nil
			}
			return cfgErr("updates.mode", "updates.mode: %q must be manual, notify or managed", v)
		},
		unset: func(s *JailSpec, _ string) { s.Update.Mode = "" }})
	str("updates.schedule", "update.schedule", "Five-field cron expression of notify and managed updates.", "0 3 * * 0", false, true,
		func(s *JailSpec) *string { return &s.Update.Schedule }, func(v string) error {
			if len(strings.Fields(v)) != 5 {
				return fmt.Errorf("%q is not a five-field cron expression", v)
			}
			return nil
		})
	boolKey := func(name, path, desc string, get func(*JailSpec) *bool) {
		add(ckey{ConfigKey: ConfigKey{Name: name, Type: "bool", Description: desc, Example: "true", Profile: true, Path: path},
			get: func(s *JailSpec, _ string) (string, bool) { return "true", *get(s) },
			set: func(s *JailSpec, _, v string) error {
				b, err := parseBool(name, v)
				*get(s) = b
				return err
			},
			unset: func(s *JailSpec, _ string) { *get(s) = false }})
	}
	add(ckey{ConfigKey: ConfigKey{Name: "sysvipc", Type: "bool", Example: "true", RestartRequired: true, Profile: true, Path: "sysvipc",
		Description: "System V message queues, semaphores and shared memory of the jail's own (separate from the host's); some servers, PostgreSQL among them, need them."},
		get: func(s *JailSpec, _ string) (string, bool) { return "true", s.SysVIPC },
		set: func(s *JailSpec, _, v string) error {
			b, err := parseBool("sysvipc", v)
			s.SysVIPC = b
			return err
		},
		unset: func(s *JailSpec, _ string) { s.SysVIPC = false }})
	add(ckey{ConfigKey: ConfigKey{Name: "zfs.delegation", Type: "bool", Example: "true", RestartRequired: true, Path: "zfs_delegation",
		Description: "Global administrators only. Hands the jail a ZFS dataset of its own, <container>/delegated: root in the jail can create datasets, snapshots and mounts below it, outside the rules JailOps applies to the jail's data. The host's priv.conf must allow it (admin-zfs-delegation)."},
		get: func(s *JailSpec, _ string) (string, bool) { return "true", s.Delegate },
		set: func(s *JailSpec, _, v string) error {
			b, err := parseBool("zfs.delegation", v)
			s.Delegate = b
			return err
		},
		unset: func(s *JailSpec, _ string) { s.Delegate = false }})
	boolKey("updates.packages", "update.packages", "Update the packages inside the jail (pkg or apk, from the host).", func(s *JailSpec) *bool { return &s.Update.Packages })
	boolKey("updates.os", "update.os", "Move the jail to a newer image generation (root swap).", func(s *JailSpec) *bool { return &s.Update.OS })
	add(ckey{ConfigKey: ConfigKey{Name: "updates.reboot", Type: "enum", Values: []string{"manual", "auto"}, Profile: true, Path: "update.reboot",
		Description: "Whether a jail restart that an update needs is applied automatically (auto) or left to you (manual, the default).", Example: "manual"},
		get: func(s *JailSpec, _ string) (string, bool) { return string(s.Update.Reboot), s.Update.Reboot != "" },
		set: func(s *JailSpec, _, v string) error {
			switch UpdateReboot(v) {
			case RebootManual, RebootAuto:
				s.Update.Reboot = UpdateReboot(v)
				return nil
			}
			return cfgErr("updates.reboot", "updates.reboot: %q must be manual or auto", v)
		},
		unset: func(s *JailSpec, _ string) { s.Update.Reboot = "" }})
	list("firewall.policies", "firewall.policies", "Firewall policies of the jail's anchor, in the order they are rendered after the project's.", "postgres,ssh-office", false, true,
		func(s *JailSpec) *[]string { return &s.Firewall.Policies }, nameCheck)
	list("firewall.tags", "firewall.tags", "Tags that firewall rules refer to.", "web,public", false, true,
		func(s *JailSpec) *[]string { return &s.Firewall.Tags }, nameCheck)
	list("packages", "packages", "Cannot be set when a jail is created yet: a create that sets it is refused. Install packages with the provisioning packages step.", "nginx,curl", true, true, func(s *JailSpec) *[]string { return &s.Packages }, nil)
	add(ckey{ConfigKey: ConfigKey{Name: "env.<var>", Type: "string", Description: "Environment variable of the jail's services.", Example: "env.TZ=UTC", RestartRequired: true, Profile: true, Path: "env.<var>"},
		get: func(s *JailSpec, d string) (string, bool) { v, ok := s.Env[d]; return v, ok },
		set: func(s *JailSpec, d, v string) error {
			if !envRE.MatchString(d) {
				return cfgErr("env."+d, "env.%s: %q is not a variable name", d, d)
			}
			if strings.ContainsRune(v, 0) {
				return cfgErr("env."+d, "env.%s: the value contains a NUL byte", d)
			}
			if s.Env == nil {
				s.Env = map[string]string{}
			}
			s.Env[d] = v
			return nil
		},
		unset: func(s *JailSpec, d string) { delete(s.Env, d) }})

	// nic devices
	devKey := func(name, typ, desc, example string, restart, profile, admin bool, path string,
		get func(*JailSpec, string) (string, bool), set func(*JailSpec, string, string) error, unset func(*JailSpec, string)) {
		add(ckey{ConfigKey: ConfigKey{Name: name, Type: typ, Description: desc, Example: example, RestartRequired: restart, Profile: profile, Admin: admin, Global: strings.HasPrefix(name, "proxy."), Path: path},
			get: get, set: set, unset: unset})
	}
	field := func(find func(*JailSpec, string, bool) *NetworkAttach, check func(string) error, get func(*NetworkAttach) *string, key string) (func(*JailSpec, string) (string, bool), func(*JailSpec, string, string) error, func(*JailSpec, string)) {
		return func(s *JailSpec, d string) (string, bool) {
				p := find(s, d, false)
				if p == nil {
					return "", false
				}
				v := *get(p)
				return v, v != ""
			}, func(s *JailSpec, d, v string) error {
				if !IsName(d, 31) {
					return cfgErr("nic."+d+"."+key, "%q is not a device name", d)
				}
				if check != nil {
					if err := check(v); err != nil {
						return cfgErr("nic."+d+"."+key, "nic.%s.%s: %v", d, key, err)
					}
				}
				*get(find(s, d, true)) = v
				return nil
			}, func(s *JailSpec, d string) {
				if p := find(s, d, false); p != nil {
					*get(p) = ""
				}
			}
	}
	devKey("nic.<device>", "device", "A network interface; set it to a network name to add it, unset it to remove it.", "nic.eth1=lan", true, true, false, "network[<device>]",
		func(s *JailSpec, d string) (string, bool) {
			if p := nic(s, d, false); p != nil {
				return p.Network, true
			}
			return "", false
		}, func(s *JailSpec, d, v string) error {
			if !IsName(d, 31) {
				return cfgErr("nic."+d, "%q is not a device name", d)
			}
			nic(s, d, true).Network = v
			return nil
		}, func(s *JailSpec, d string) {
			normalizeDevices(s)
			for i := range s.Network {
				if s.Network[i].Name == d {
					s.Network = append(s.Network[:i], s.Network[i+1:]...)
					return
				}
			}
		})
	g, st, un := field(nic, func(v string) error { return nameCheck(v) }, func(p *NetworkAttach) *string { return &p.Network }, "network")
	devKey("nic.<device>.network", "string", "Network the interface attaches to.", "lan", true, true, false, "network[<device>].network", g, st, un)
	g, st, un = field(nic, func(v string) error { return checkAddr("ipv4", v, true) }, func(p *NetworkAttach) *string { return &p.IPv4 }, "ipv4")
	devKey("nic.<device>.ipv4", "address", "IPv4 address: auto, none or a fixed address.", "auto", true, false, false, "network[<device>].ipv4", g, st, un)
	g, st, un = field(nic, func(v string) error { return checkAddr("ipv6", v, false) }, func(p *NetworkAttach) *string { return &p.IPv6 }, "ipv6")
	devKey("nic.<device>.ipv6", "address", "IPv6 address: auto, none or a fixed address.", "auto", true, false, false, "network[<device>].ipv6", g, st, un)
	g, st, un = field(nic, func(v string) error {
		if !macRE.MatchString(v) {
			return fmt.Errorf("%q is not a lower case MAC address", v)
		}
		return nil
	}, func(p *NetworkAttach) *string { return &p.MAC }, "mac")
	devKey("nic.<device>.mac", "mac", "MAC address (derived from the jail UUID when empty).", "02:00:00:00:00:01", true, false, false, "network[<device>].mac", g, st, un)
	devKey("nic.<device>.mtu", "int", "MTU of the interface; 0 takes the network's.", "1500", true, true, false, "network[<device>].mtu",
		func(s *JailSpec, d string) (string, bool) {
			if p := nic(s, d, false); p != nil && p.MTU != 0 {
				return strconv.Itoa(p.MTU), true
			}
			return "", false
		}, func(s *JailSpec, d, v string) error {
			if !IsName(d, 31) {
				return cfgErr("nic."+d+".mtu", "%q is not a device name", d)
			}
			n, err := atoiRange("nic."+d+".mtu", v, 576, 9216)
			if err != nil {
				return err
			}
			nic(s, d, true).MTU = n
			return nil
		}, func(s *JailSpec, d string) {
			if p := nic(s, d, false); p != nil {
				p.MTU = 0
			}
		})
	rate := func(v string) error {
		if !rateRE.MatchString(v) {
			return fmt.Errorf("%q is not a rate in bits per second such as 10M", v)
		}
		return nil
	}
	g, st, un = field(nic, rate, func(p *NetworkAttach) *string { return &p.Egress }, "egress")
	devKey("nic.<device>.egress", "rate", "Rate limit of what the jail sends through the device, in bits per second: 10M is 10 Mbit/s. Enforced by a dummynet pipe of the host.", "10M", false, true, false, "network[<device>].egress", g, st, un)
	g, st, un = field(nic, rate, func(p *NetworkAttach) *string { return &p.Ingress }, "ingress")
	devKey("nic.<device>.ingress", "rate", "Rate limit of what the jail receives through the device, in bits per second: 10M is 10 Mbit/s. Enforced by a dummynet pipe of the host.", "10M", false, true, false, "network[<device>].ingress", g, st, un)

	// disk devices
	devKey("disk.<device>", "device", "A volume of the project attached to the jail: <device> is the name of the volume; set it to the mount path to attach it, unset it to detach it.", "disk.data=/var/db", true, true, false, "volumes[<device>]",
		func(s *JailSpec, d string) (string, bool) {
			if p := disk(s, d, false); p != nil {
				return p.Mount, true
			}
			return "", false
		}, func(s *JailSpec, d, v string) error {
			if !IsName(d, 31) {
				return cfgErr("disk."+d, "%q is not a device name", d)
			}
			disk(s, d, true).Mount = v
			return nil
		}, func(s *JailSpec, d string) {
			for i := range s.Volumes {
				if s.Volumes[i].Name == d {
					s.Volumes = append(s.Volumes[:i], s.Volumes[i+1:]...)
					return
				}
			}
		})
	dfield := func(key string, check func(string) error, get func(*VolumeAttach) *string) (func(*JailSpec, string) (string, bool), func(*JailSpec, string, string) error, func(*JailSpec, string)) {
		return func(s *JailSpec, d string) (string, bool) {
				p := disk(s, d, false)
				if p == nil {
					return "", false
				}
				v := *get(p)
				return v, v != ""
			}, func(s *JailSpec, d, v string) error {
				if !IsName(d, 31) {
					return cfgErr("disk."+d+"."+key, "%q is not a device name", d)
				}
				if err := check(v); err != nil {
					return cfgErr("disk."+d+"."+key, "disk.%s.%s: %v", d, key, err)
				}
				*get(disk(s, d, true)) = v
				return nil
			}, func(s *JailSpec, d string) {
				if p := disk(s, d, false); p != nil {
					*get(p) = ""
				}
			}
	}
	g, st, un = dfield("mount", func(v string) error {
		if !strings.HasPrefix(v, "/") || strings.Contains(v, "..") || v == "/" {
			return fmt.Errorf("%q is not an absolute path inside the jail", v)
		}
		return nil
	}, func(p *VolumeAttach) *string { return &p.Mount })
	devKey("disk.<device>.mount", "string", "Where the volume is mounted inside the jail.", "/var/db", true, true, false, "volumes[<device>].mount", g, st, un)
	devKey("disk.<device>.read_only", "bool", "Attach the volume read-only.", "true", true, true, false, "volumes[<device>].read_only",
		func(s *JailSpec, d string) (string, bool) {
			p := disk(s, d, false)
			return "true", p != nil && p.ReadOnly
		}, func(s *JailSpec, d, v string) error {
			b, err := parseBool("disk."+d+".read_only", v)
			if err != nil {
				return err
			}
			if !IsName(d, 31) {
				return cfgErr("disk."+d+".read_only", "%q is not a device name", d)
			}
			disk(s, d, true).ReadOnly = b
			return nil
		}, func(s *JailSpec, d string) {
			if p := disk(s, d, false); p != nil {
				p.ReadOnly = false
			}
		})

	// devfs devices
	devKey("devfs.<name>.device", "enum", "A device node exposed through an allow-listed devfs ruleset.", "tun", true, true, true, "devfs[<name>].device",
		func(s *JailSpec, d string) (string, bool) {
			p := devfs(s, d, false)
			if p == nil {
				return "", false
			}
			return p.Device, p.Device != ""
		}, func(s *JailSpec, d, v string) error {
			if !IsName(d, 31) {
				return cfgErr("devfs."+d+".device", "%q is not a device name", d)
			}
			for _, a := range DevfsAllowList {
				if a == v {
					devfs(s, d, true).Device = v
					return nil
				}
			}
			return cfgErr("devfs."+d+".device", "devfs.%s.device: %q is not on the allow-list (%s)", d, v, strings.Join(DevfsAllowList, ", "))
		}, func(s *JailSpec, d string) {
			for i := range s.Devfs {
				if s.Devfs[i].Name == d {
					s.Devfs = append(s.Devfs[:i], s.Devfs[i+1:]...)
					return
				}
			}
		})
	r[len(r)-1].Values = DevfsAllowList

	// proxy devices
	devKey("proxy.<name>.listen", "listen", "Host address and port the jail's port is forwarded on.", ":8080", false, true, true, "proxy[<name>].listen",
		func(s *JailSpec, d string) (string, bool) {
			p := proxy(s, d, false)
			if p == nil {
				return "", false
			}
			return p.Listen, p.Listen != ""
		}, func(s *JailSpec, d, v string) error {
			if !IsName(d, 31) {
				return cfgErr("proxy."+d+".listen", "%q is not a device name", d)
			}
			if err := checkListen("proxy."+d+".listen", v); err != nil {
				return err
			}
			proxy(s, d, true).Listen = v
			return nil
		}, func(s *JailSpec, d string) {
			for i := range s.Proxy {
				if s.Proxy[i].Name == d {
					s.Proxy = append(s.Proxy[:i], s.Proxy[i+1:]...)
					return
				}
			}
		})
	devKey("proxy.<name>.jail_port", "int", "Port inside the jail.", "80", false, true, true, "proxy[<name>].jail_port",
		func(s *JailSpec, d string) (string, bool) {
			p := proxy(s, d, false)
			if p == nil || p.JailPort == 0 {
				return "", false
			}
			return strconv.Itoa(p.JailPort), true
		}, func(s *JailSpec, d, v string) error {
			n, err := atoiRange("proxy."+d+".jail_port", v, 1, 65535)
			if err != nil {
				return err
			}
			if !IsName(d, 31) {
				return cfgErr("proxy."+d+".jail_port", "%q is not a device name", d)
			}
			proxy(s, d, true).JailPort = n
			return nil
		}, func(s *JailSpec, d string) {
			if p := proxy(s, d, false); p != nil {
				p.JailPort = 0
			}
		})
	devKey("proxy.<name>.proto", "enum", "tcp or udp.", "tcp", false, true, true, "proxy[<name>].proto",
		func(s *JailSpec, d string) (string, bool) {
			p := proxy(s, d, false)
			if p == nil {
				return "", false
			}
			return p.Proto, p.Proto != ""
		}, func(s *JailSpec, d, v string) error {
			if v != "tcp" && v != "udp" {
				return cfgErr("proxy."+d+".proto", "proxy.%s.proto: %q must be tcp or udp", d, v)
			}
			if !IsName(d, 31) {
				return cfgErr("proxy."+d+".proto", "%q is not a device name", d)
			}
			proxy(s, d, true).Proto = v
			return nil
		}, func(s *JailSpec, d string) {
			if p := proxy(s, d, false); p != nil {
				p.Proto = ""
			}
		})
	r[len(r)-1].Values = []string{"tcp", "udp"}
	return r
}

// ConfigKeys returns every key of the registry, sorted by name.
func ConfigKeys() []ConfigKey {
	out := make([]ConfigKey, len(registry))
	for i, k := range registry {
		out[i] = k.ConfigKey
		out[i].Values = append([]string(nil), k.Values...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// lookup finds the registry entry of a concrete key and the device or
// variable name it carries.
func lookup(key string) (*ckey, string, bool) {
	parts := strings.Split(key, ".")
	for i := range registry {
		k := &registry[i]
		if k.Name == "env.<var>" {
			if len(parts) >= 2 && parts[0] == "env" {
				return k, strings.Join(parts[1:], "."), true
			}
			continue
		}
		tp := strings.Split(k.Name, ".")
		if len(tp) != len(parts) {
			continue
		}
		dev, ok := "", true
		for j, seg := range tp {
			switch {
			case strings.HasPrefix(seg, "<"):
				dev = parts[j]
			case seg != parts[j]:
				ok = false
			}
		}
		if ok {
			return k, dev, true
		}
	}
	return nil, "", false
}

// ConfigKeyFor returns the registry entry of a key and the device or variable
// name it carries.
func ConfigKeyFor(key string) (ConfigKey, string, bool) {
	k, dev, ok := lookup(key)
	if !ok {
		return ConfigKey{}, "", false
	}
	return k.ConfigKey, dev, true
}

// ApplyConfig sets and unsets keys on spec. It is atomic: on an error spec is
// unchanged. It returns the keys, sorted, that changed a value and need a
// restart to take effect. Unsetting a device key (nic.eth1) removes the
// device; unsetting a field resets it.
func ApplyConfig(spec *JailSpec, set map[string]string, unset []string) (restartRequired []string, err error) {
	work := *spec
	work.Network = append([]NetworkAttach(nil), spec.Network...)
	work.Volumes = append([]VolumeAttach(nil), spec.Volumes...)
	work.Devfs = append([]DevfsDevice(nil), spec.Devfs...)
	work.Proxy = append([]ProxyDevice(nil), spec.Proxy...)
	work.Profiles = append([]string(nil), spec.Profiles...)
	work.Packages = append([]string(nil), spec.Packages...)
	work.Boot.Depends = append([]string(nil), spec.Boot.Depends...)
	work.Firewall.Tags = append([]string(nil), spec.Firewall.Tags...)
	if spec.Env != nil {
		work.Env = map[string]string{}
		for k, v := range spec.Env {
			work.Env[k] = v
		}
	}
	normalizeDevices(&work)
	restart := map[string]bool{}
	apply := func(key string, f func(k *ckey, dev string) error) error {
		k, dev, ok := lookup(key)
		if !ok {
			return cfgErr(key, "unknown configuration key %q", key).WithHint("jailops config keys lists them")
		}
		before := ConfigValues(work)
		if err := f(k, dev); err != nil {
			return err
		}
		if k.RestartRequired && !equalFlat(before, ConfigValues(work)) {
			restart[key] = true
		}
		return nil
	}
	ukeys := append([]string(nil), unset...)
	sort.Strings(ukeys)
	for _, key := range ukeys {
		if err := apply(key, func(k *ckey, dev string) error { k.unset(&work, dev); return nil }); err != nil {
			return nil, err
		}
	}
	skeys := make([]string, 0, len(set))
	for key := range set {
		skeys = append(skeys, key)
	}
	sort.Strings(skeys)
	for _, key := range skeys {
		v := set[key]
		if err := apply(key, func(k *ckey, dev string) error { return k.set(&work, dev, v) }); err != nil {
			return nil, err
		}
	}
	*spec = work
	for k := range restart {
		restartRequired = append(restartRequired, k)
	}
	sort.Strings(restartRequired)
	return restartRequired, nil
}

func equalFlat(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// ConfigValues flattens a spec to the keys that are set, with their values.
// Devices appear by name; a device that exists with no field set appears as
// its device key.
func ConfigValues(spec JailSpec) map[string]string {
	s := spec
	s.Network = append([]NetworkAttach(nil), spec.Network...)
	normalizeDevices(&s)
	out := map[string]string{}
	for i := range registry {
		k := &registry[i]
		switch {
		case k.Name == "env.<var>":
			for n := range s.Env {
				v, _ := k.get(&s, n)
				out["env."+n] = v
			}
		case strings.Contains(k.Name, "<device>"):
			var names []string
			switch {
			case strings.HasPrefix(k.Name, "nic."):
				for _, d := range s.Network {
					names = append(names, d.Name)
				}
			case strings.HasPrefix(k.Name, "disk."):
				for _, d := range s.Volumes {
					names = append(names, d.Name)
				}
			}
			for _, n := range names {
				if v, ok := k.get(&s, n); ok {
					out[strings.Replace(k.Name, "<device>", n, 1)] = v
				}
			}
		case strings.Contains(k.Name, "<name>"):
			var names []string
			switch {
			case strings.HasPrefix(k.Name, "devfs."):
				for _, d := range s.Devfs {
					names = append(names, d.Name)
				}
			case strings.HasPrefix(k.Name, "proxy."):
				for _, d := range s.Proxy {
					names = append(names, d.Name)
				}
			}
			for _, n := range names {
				if v, ok := k.get(&s, n); ok {
					out[strings.Replace(k.Name, "<name>", n, 1)] = v
				}
			}
		default:
			if v, ok := k.get(&s, ""); ok {
				out[k.Name] = v
			}
		}
	}
	return out
}

// ProfileSpecAsJail applies a profile's keys to an empty spec. Keys that are
// not valid in a profile are ignored here (profiles are validated when they
// are stored).
func ProfileSpecAsJail(p Profile) JailSpec {
	var s JailSpec
	keys := make([]string, 0, len(p.Spec.Config))
	for k := range p.Spec.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if k, dev, ok := lookup(key); ok && k.Profile {
			_ = k.set(&s, dev, p.Spec.Config[key])
		}
	}
	return s
}

// ValidateProfile checks the keys of a profile: every key must exist, be
// allowed in a profile and have a valid value.
func ValidateProfile(p ProfileSpec) error {
	keys := make([]string, 0, len(p.Config))
	for k := range p.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var s JailSpec
	for _, key := range keys {
		k, dev, ok := lookup(key)
		if !ok {
			return cfgErr(key, "unknown configuration key %q", key)
		}
		if !k.Profile {
			return cfgErr(key, "%s cannot be set in a profile", key)
		}
		if err := k.set(&s, dev, p.Config[key]); err != nil {
			return err
		}
	}
	return nil
}

// ExpandedConfig merges profiles into a jail's own spec. profiles are given in
// the order the jail lists them; later profiles override earlier ones and the
// jail's own keys and devices override them all, device by device and name by
// name. The result carries the profile devices after the jail's own (so the
// indices of the jail's own interfaces stay put). sources maps every key that
// is set to "jail" or to the name of the profile it came from.
func ExpandedConfig(spec JailSpec, profiles []Profile) (JailSpec, map[string]string) {
	own := ConfigValues(spec)
	merged := map[string]string{}
	sources := map[string]string{}
	for _, p := range profiles {
		for k, v := range ConfigValues(ProfileSpecAsJail(p)) {
			merged[k] = v
			sources[k] = p.Metadata.Name
		}
	}
	out := spec
	out.Network = append([]NetworkAttach(nil), spec.Network...)
	out.Volumes = append([]VolumeAttach(nil), spec.Volumes...)
	out.Devfs = append([]DevfsDevice(nil), spec.Devfs...)
	out.Proxy = append([]ProxyDevice(nil), spec.Proxy...)
	out.Packages = append([]string(nil), spec.Packages...)
	if spec.Env != nil {
		out.Env = map[string]string{}
		for k, v := range spec.Env {
			out.Env[k] = v
		}
	}
	normalizeDevices(&out)
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, mine := own[key]; mine {
			continue // the jail's own value wins
		}
		if k, dev, ok := lookup(key); ok {
			_ = k.set(&out, dev, merged[key])
		}
	}
	for k := range own {
		sources[k] = "jail"
	}
	for k := range ConfigValues(out) {
		if _, ok := sources[k]; !ok {
			sources[k] = "jail"
		}
	}
	// Keys the profiles set but the jail overrode keep the jail as source (above).
	return out, sources
}

var _ = time.Second

// JailExpanded is a jail whose spec has its profiles merged in, with the
// source ("jail" or a profile name) of every key that is set
// (GET /api/v1/jails/<name>?expanded=true).
type JailExpanded struct {
	Jail    Jail              `json:"jail"`
	Sources map[string]string `json:"sources"`
}

// ConfigChange is the body of POST /api/v1/jails/<name>/config.
type ConfigChange struct {
	Set   map[string]string `json:"set,omitempty"`
	Unset []string          `json:"unset,omitempty"`
}
