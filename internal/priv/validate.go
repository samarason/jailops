package priv

import (
	"context"
	"jailops.net/jailops/internal/ipam"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

func forbidden(format string, a ...any) error { return api.Errorf(api.CodeForbidden, format, a...) }

// notBelowMount refuses a path outside the storage root, and says where the storage root is set.
func (c Config) notBelowMount(p string) error {
	return api.Errorf(api.CodeForbidden, "path %q is not below %s", p, c.mountBaseDesc()).
		WithHint("mount-base of priv.conf says where the storage root is mounted: when the images and jails live elsewhere, set mount-base and mount_base of jailopsd.yaml to that directory (zfs get -r mountpoint <storage-root> shows it) and restart jailops_priv and jailopsd")
}
func forbiddenBusy(format string, a ...any) error { return api.Errorf(api.CodeBusy, format, a...) }
func invalid(format string, a ...any) error       { return api.Errorf(api.CodeInvalid, format, a...) }

// ---- ZFS ----

// dsPart returns the dataset part of a dataset, snapshot or bookmark name.
func dsPart(name string) string {
	if i := strings.IndexAny(name, "@#"); i >= 0 {
		return name[:i]
	}
	return name
}

// zfsName validates name syntactically and requires it to live under one
// registered storage root. It returns the kind.
func (c Config) zfsName(name string) (zfs.Kind, error) {
	k, err := zfs.ValidateAny(name)
	if err != nil {
		return k, err
	}
	if err := c.inRoot(dsPart(name)); err != nil {
		return k, err
	}
	return k, nil
}

func (c Config) zfsDataset(name string) error {
	if err := zfs.ValidateDataset(name); err != nil {
		return err
	}
	return c.inRoot(name)
}

func (c Config) zfsSnapshot(name string) error {
	if err := zfs.ValidateSnapshot(name); err != nil {
		return err
	}
	return c.inRoot(dsPart(name))
}

func (c Config) zfsNames(names []string) error {
	if len(names) == 0 || len(names) > c.Limits.MaxNames {
		return invalid("expected between 1 and %d names", c.Limits.MaxNames)
	}
	for _, n := range names {
		if _, err := c.zfsName(n); err != nil {
			return err
		}
	}
	return nil
}

// nativeProps is the set of native ZFS properties a request may set.
var nativeProps = map[string]bool{
	"compression": true, "quota": true, "refquota": true, "reservation": true,
	"refreservation": true, "recordsize": true, "atime": true, "relatime": true,
	"readonly": true, "copies": true, "dedup": true, "sync": true, "logbias": true,
	"primarycache": true, "secondarycache": true, "snapdir": true, "aclmode": true,
	"aclinherit": true, "acltype": true, "xattr": true, "canmount": true,
	"mountpoint": true, "volblocksize": true, "checksum": true, "encryption": true,
	"keyformat": true, "keylocation": true, "setuid": true, "exec": true,
	"volmode": true, "normalization": true, "utf8only": true, "casesensitivity": true,
	"pbkdf2iters": true, "volsize": true, "special_small_blocks": true, "devices": true,
}

// neverProps can never be set through the helper: they export data to the
// network or hand a dataset to a jail behind the helper's back.
var neverProps = map[string]bool{"sharenfs": true, "sharesmb": true, "jailed": true, "shareiscsi": true}

var sizeRE = regexp.MustCompile(`^([0-9]{1,15})([KMGTP]?)$`)

// parseBytes parses "10G" or "1048576" strictly (binary units, no fractions).
func parseBytes(s string) (uint64, bool) {
	m := sizeRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	shift := strings.Index("KMGTP", m[2]) + 1
	if m[2] == "" {
		shift = 0
	}
	if shift > 0 {
		if n > (^uint64(0))>>(10*uint(shift)) {
			return 0, false
		}
		n <<= 10 * uint(shift)
	}
	return n, true
}

func (c Config) checkSize(what, v string) error {
	n, ok := parseBytes(v)
	if !ok || n == 0 || n > c.Limits.MaxVolumeBytes {
		return invalid("%s %q is not a size between 1 byte and %d bytes", what, v, c.Limits.MaxVolumeBytes)
	}
	return nil
}

// zfsProps validates property names and values. Mounting is the dangerous
// part: a mountpoint outside the storage roots would mount a dataset over a host
// directory.
func (c Config) zfsProps(ctx context.Context, m map[string]string) error {
	if len(m) > c.Limits.MaxProps {
		return invalid("too many properties (limit %d)", c.Limits.MaxProps)
	}
	for k, v := range m {
		if err := zfs.ValidateProperty(k); err != nil {
			return err
		}
		if err := zfs.ValidatePropValue(v); err != nil {
			return err
		}
		if strings.Contains(k, ":") {
			continue // user property
		}
		if neverProps[k] {
			return forbidden("property %s cannot be set through the helper", k)
		}
		if !nativeProps[k] && !(isAdmin(ctx) && hasStr(c.Admin.ZFSProps, k)) {
			return forbidden("property %s is not on the allow-list", k)
		}
		switch k {
		case "mountpoint":
			if v != "none" && v != "legacy" {
				if !filepath.IsAbs(v) || filepath.Clean(v) != v || !c.inMounts(v) {
					return forbidden("mountpoint %q is outside %s", v, c.mountBaseDesc())
				}
				// mounted over a root's own directory, a dataset would replace its mode 0700 with its own: the
				// jails' setuid programs below would be in reach of every user of the host
				if c.isMountRoot(v) {
					return forbidden("mountpoint %q is the mountpoint of a storage root", v)
				}
			}
		case "devices":
			// device nodes are made by devfs; a dataset never serves them
			if v != "off" {
				return forbidden("devices=%s: datasets of JailOps keep devices=off", v)
			}
		case "keylocation":
			if v != "prompt" {
				p, ok := strings.CutPrefix(v, "file://")
				if !ok || !filepath.IsAbs(p) || filepath.Clean(p) != p || !within(c.StateDir, p) {
					return forbidden("keylocation %q is outside %s", v, c.StateDir)
				}
			}
		case "quota", "refquota", "reservation", "refreservation":
			if v != "none" && v != "0" {
				if err := c.checkSize(k, v); err != nil {
					return err
				}
			}
		case "volsize":
			if err := c.checkSize(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c Config) zfsPropNames(names []string) error {
	if len(names) > c.Limits.MaxProps {
		return invalid("too many properties (limit %d)", c.Limits.MaxProps)
	}
	for _, n := range names {
		if err := zfs.ValidateProperty(n); err != nil {
			return err
		}
	}
	return nil
}

// within reports whether p is root or below it, lexically. Both must be clean
// absolute paths.
func within(root, p string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// ---- interfaces ----

// epairEndName checks the name of an interface a jail.conf moves into the jail's vnet (vnet.interface): an end of an
// epair JailOps names (ipam.EpairNames: "jo" and the jail's hash). This is a check of
// the name's form, not of ownership: jail(8) moves the interface itself, after the prestart hook created it, and a
// jail.conf must never name the uplink or another interface of the host. Who owns the interface is the kernel's
// description, checked when the jail is created (jailGuard.Create).
func (c Config) epairEndName(name string) error {
	if err := ifconfig.ValidateIfName(name); err != nil {
		return err
	}
	if ipam.IsEpairName(name) {
		return nil
	}
	return forbidden("vnet.interface %q is not an epair end JailOps names", name)
}

// checkIfaceDesc accepts only a description JailOps writes: "jailops ..." (or the "jailops:<id>" marker of earlier
// releases) of at most 64 letters, digits and " ._:/=()-". Clearing (empty) is accepted where allowClear is set.
func checkIfaceDesc(d string, allowClear bool) error {
	if d == "" && allowClear {
		return nil
	}
	if !render.ValidIfaceDesc(d) || !render.IsJailOpsDesc(d) {
		return invalid("interface description %q is not one JailOps writes (\"jailops ...\", at most %d of A-Z a-z 0-9 and %q)", d, render.IfaceDescMax, render.IfaceDescCharset)
	}
	return nil
}

var macRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func validMAC(m string) error {
	if !macRE.MatchString(m) {
		return invalid("invalid MAC address %q", m)
	}
	return nil
}

func (c Config) checkRoute(ctx context.Context, r ifconfig.Route) error {
	if r.Interface != "" {
		// ownership is the kernel's word, checked by the caller (netGuard.route)
		if err := ifconfig.ValidateIfName(r.Interface); err != nil {
			return err
		}
	}
	if r.Gateway != "" || r.Interface == "" {
		if !(isAdmin(ctx) && c.Admin.Routes) {
			return forbidden("routes through a gateway need the admin assertion and AdminPolicy.Routes")
		}
	}
	if r.Dest == "default" && !(isAdmin(ctx) && c.Admin.Routes) {
		return forbidden("the helper does not change the host default route")
	}
	if r.Dest != "default" {
		bits := -1
		if p, err := netip.ParsePrefix(r.Dest); err == nil {
			bits = p.Bits()
			if p.Addr().Is4() && bits < 32 || p.Addr().Is6() && bits < 128 {
				if !(isAdmin(ctx) && c.Admin.Routes) {
					return forbidden("only host routes may be added without the admin assertion")
				}
			}
		}
	}
	return nil
}

// ---- pf ----

func checkAnchor(a string) error {
	if err := pfctl.ValidateAnchor(a); err != nil {
		return err
	}
	if !strings.HasPrefix(a, AnchorPrefix) || len(a) == len(AnchorPrefix) {
		return forbidden("pf anchor %q is outside %s", a, strings.TrimSuffix(AnchorPrefix, "/")+"/")
	}
	return nil
}

var pfBanned = regexp.MustCompile(`(?i)^\s*(include|load\s+anchor|set\s|options\s)|\bfile\s+"`)

// checkRuleset refuses rulesets that read other files or change global
// options. The admin assertion with AdminPolicy.RawPF lifts the refusal.
func (c Config) checkRuleset(ctx context.Context, rs string) error {
	if len(rs) > pfctl.MaxRulesetBytes {
		return invalid("ruleset larger than %d bytes", pfctl.MaxRulesetBytes)
	}
	if strings.ContainsRune(rs, 0) {
		return invalid("ruleset contains a NUL byte")
	}
	if isAdmin(ctx) && c.Admin.RawPF {
		return nil
	}
	for _, l := range strings.Split(rs, "\n") {
		if pfBanned.MatchString(l) {
			return forbidden("ruleset line %q needs the admin assertion", strings.TrimSpace(l))
		}
	}
	return nil
}
