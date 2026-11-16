package render

import (
	"fmt"
	"sort"

	"jailops.net/jailops/sdk/api"
)

// devfsPaths maps an allow-listed device to the devfs paths it unhides.
var devfsPaths = map[string][]string{
	"tun":  {"tun*"},
	"tap":  {"tap*"},
	"pf":   {"pf"},
	"bpf":  {"bpf*"},
	"fuse": {"fuse"},
	"dri":  {"dri", "dri/*"},
	// zfs is not on the allow-list a user can name: a jail with zfs_delegation gets it (SpecDevfsDevices), because
	// `zfs` inside the jail talks to the kernel through /dev/zfs.
	"zfs": {"zfs"},
}

// devfsOrder fixes the bit of every allow-listed device in a ruleset number: the number of a ruleset is
// DevfsRulesetBase plus the bits of its devices, plus DevfsLinuxOffset for a Linux jail, so two different sets of
// devices never share a number and a number says what its ruleset holds.
var devfsOrder = []string{"bpf", "dri", "fuse", "pf", "tap", "tun", "zfs"}

const (
	// DevfsRulesetBase is the first number of the private rulesets; the stock ones (1 to 5) are below it.
	DevfsRulesetBase = 5000
	// DevfsLinuxOffset separates the rulesets of Linux jails from those of FreeBSD jails.
	DevfsLinuxOffset = 1 << 7
	// BuildDevfsRuleset is the ruleset of the Linux image build jail, which no jail shares.
	BuildDevfsRuleset = DevfsRulesetBase + 2*DevfsLinuxOffset
)

// devfsNumber is the number of the ruleset of a set of devices; names are sorted and unique.
func devfsNumber(linux bool, names []string) int {
	n := DevfsRulesetBase
	for _, name := range names {
		for bit, d := range devfsOrder {
			if d == name {
				n += 1 << bit
			}
		}
	}
	if linux {
		n += DevfsLinuxOffset
	}
	return n
}

// devfsNames checks a list of devices against api.DevfsAllowList and returns it sorted and unique.
func devfsNames(devices []string) ([]string, error) {
	set := map[string]bool{}
	for _, d := range devices {
		if _, ok := devfsPaths[d]; !ok {
			return nil, fmt.Errorf("render: device %q is not on the devfs allow-list", d)
		}
		set[d] = true
	}
	var names []string
	for d := range set {
		names = append(names, d)
	}
	sort.Strings(names)
	return names, nil
}

// DevfsRuleset returns the devfs ruleset of a FreeBSD jail that is given device nodes: its number and the
// `devfs rule -s <n> ...` argument lists that load it into the kernel, in order. The base is the stock jail ruleset
// (include the stock sets that hide everything and unhide the basic and login devices), then the allow-listed
// devices. A jail without devices uses the stock ruleset DefaultDevfsRuleset and loads nothing. Only devices on
// api.DevfsAllowList are rendered; anything else is an error, so a path can never be injected. The number is the
// one of jail.conf's devfs_ruleset, and the root helper loads the rules before the jail is created: a number that
// nobody loaded would show the jail the whole of the host's /dev.
func DevfsRuleset(devices []string) (int, [][]string, error) {
	names, err := devfsNames(devices)
	if err != nil {
		return 0, nil, err
	}
	if len(names) == 0 {
		return DefaultDevfsRuleset, nil, nil
	}
	n := devfsNumber(false, names)
	s := fmt.Sprint(n)
	rules := [][]string{
		{"devfs", "rule", "-s", s, "add", "include", "1"}, // hide everything
		{"devfs", "rule", "-s", s, "add", "include", "2"}, // the basic devices
		{"devfs", "rule", "-s", s, "add", "include", "3"}, // the login devices
	}
	for _, d := range names {
		for _, p := range devfsPaths[d] {
			rules = append(rules, []string{"devfs", "rule", "-s", s, "add", "path", p, "unhide"})
		}
	}
	return n, rules, nil
}

// SpecDevfsDevices lists the devices a jail's devfs ruleset holds: the ones its spec names, and zfs when the jail has
// zfs_delegation (jail(8) attaches the delegated dataset, and the jail's zfs needs /dev/zfs).
func SpecDevfsDevices(sp api.JailSpec) []string {
	out := DevfsDevices(sp.Devfs)
	if sp.Delegate {
		out = append(out, "zfs")
	}
	return out
}

// DevfsDevices lists the device nodes of a jail's devfs devices.
func DevfsDevices(devs []api.DevfsDevice) []string {
	var out []string
	for _, d := range devs {
		out = append(out, d.Device)
	}
	return out
}

// linuxDevfsNodes are the device nodes a Linux userland needs. UNVERIFIED:
// a reasoned minimum, not a tested one (it ran under prototype 6).
var linuxDevfsNodes = []string{"null", "zero", "full", "random", "urandom", "tty", "ptmx", "pts", "pts/*", "fd", "fd/*", "stdin", "stdout", "stderr", "console"}

// DevfsUnhidable reports whether a devfs path glob is one a JailOps ruleset may unhide: a node of a Linux
// userland or a path of an allow-listed device. The helper accepts no other `unhide`.
func DevfsUnhidable(glob string) bool {
	for _, n := range linuxDevfsNodes {
		if n == glob {
			return true
		}
	}
	for _, ps := range devfsPaths {
		for _, p := range ps {
			if p == glob {
				return true
			}
		}
	}
	// the stock ruleset's own basic nodes
	switch glob {
	case "null", "zero", "random", "urandom", "stdin", "stdout", "stderr", "fd", "fd/*", "pts", "pts/*":
		return true
	}
	return false
}

// LinuxDevfsRuleset returns the private devfs ruleset of a Linux jail: its number and the argument lists that load
// it: hide everything, unhide the nodes of a Linux userland, then the allow-listed devices the jail was given.
func LinuxDevfsRuleset(devices []string) (int, [][]string, error) {
	names, err := devfsNames(devices)
	if err != nil {
		return 0, nil, err
	}
	n := devfsNumber(true, names)
	rules, err := LinuxDevfsRuleArgv(n, names)
	return n, rules, err
}
