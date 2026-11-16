// Package validate checks user-supplied specs and names. Validators return
// *api.Error with Code api.CodeInvalid and Detail["field"] naming the field.
// Other packages (notably render) rely on these shapes to keep configuration
// files free of injected syntax.
package validate

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Invalid builds a CodeInvalid error naming field.
func Invalid(field, format string, args ...any) *api.Error {
	return api.Errorf(api.CodeInvalid, format, args...).WithDetail("field", field)
}

var (
	labelRE    = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	ifnameRE   = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)
	kindWordRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	ruleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	pkgRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)
	envKeyRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	macRE      = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	osrelRE    = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}(-[A-Za-z0-9]{1,16}(-p[0-9]{1,4})?)?$`)
)

// Name validates a name a user chooses (jail, network, storage, volume, policy, profile, ...): api.NamePattern, at
// most 63 characters.
func Name(field, s string) error { return NameMax(field, s, api.MaxName) }

// NameMax validates a name by api.NamePattern with a limit of its own (a derived name sets it).
func NameMax(field, s string, max int) error {
	if !api.IsName(s, max) {
		return Invalid(field, "%s %q must be lower case letters, digits and hyphens, start with a letter, not end in a hyphen, at most %d characters", field, s, max)
	}
	return nil
}

// JailName validates a jail name.
func JailName(s string) error {
	if err := Name("name", s); err != nil {
		return err
	}
	if s == "host" { // host.PROJECT.internal is the host as the jails see it
		return Invalid("name", "name %q is the name of the host in the names of the jails; choose another", s)
	}
	return nil
}

// Hostname validates a DNS hostname of at most 253 characters.
func Hostname(field, s string) error {
	if s == "" || len(s) > 253 {
		return Invalid(field, "%s must be 1-253 characters", field)
	}
	for _, l := range strings.Split(s, ".") {
		if !labelRE.MatchString(l) {
			return Invalid(field, "%s %q is not a valid DNS name", field, s)
		}
	}
	return nil
}

// IfName validates a FreeBSD interface name as JailOps accepts it
// (lower case letters and digits, at most 15 characters).
func IfName(field, s string) error {
	if !ifnameRE.MatchString(s) {
		return Invalid(field, "%s %q is not a valid interface name (a lowercase letter, then lowercase letters and digits, 15 at most)", field, s)
	}
	return nil
}

// SetName validates the name of a new address set: lower case letters, digits and hyphens, at most 29 characters (its
// table in pf is "s_" and the name with the hyphens written as underscores, see SetTable).
func SetName(field, s string) error { return NameMax(field, s, MaxSetName) }

// MaxSetName is the longest name of an address set: its table in pf, "s_" and the name, has at most 31 characters.
const MaxSetName = 29

// SetTable is the name of the pf table of an address set: pf names have no hyphen.
func SetTable(name string) string { return "s_" + strings.ReplaceAll(name, "-", "_") }

// Tag validates a firewall tag.
func Tag(field, s string) error { return NameMax(field, s, 24) }

// RuleName validates a free-form rule label.
func RuleName(field, s string) error {
	if !ruleNameRE.MatchString(s) {
		return Invalid(field, "%s %q must match ^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$", field, s)
	}
	return nil
}

// MAC validates a lower-case colon separated MAC address.
func MAC(field, s string) error {
	if !macRE.MatchString(s) {
		return Invalid(field, "%s %q must be lower case aa:bb:cc:dd:ee:ff", field, s)
	}
	b0, _ := strconv.ParseUint(s[:2], 16, 8)
	if b0&1 != 0 {
		return Invalid(field, "%s %q is a multicast address", field, s)
	}
	return nil
}

// OSRelease validates a jail osrelease such as "15.0-RELEASE" or "14.2-RELEASE-p3".
func OSRelease(field, s string) error {
	if !osrelRE.MatchString(s) {
		return Invalid(field, "%s %q is not a release such as 15.0-RELEASE", field, s)
	}
	return nil
}

// AbsPath validates an absolute path restricted to a conservative character
// set, without "." or ".." segments. Such a path needs no quoting in
// jail.conf, fstab or shell.
func AbsPath(field, s string) error {
	if len(s) == 0 || len(s) > 1024 || s[0] != '/' {
		return Invalid(field, "%s must be an absolute path", field)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/._+@:=,-", c) >= 0
		if !ok {
			return Invalid(field, "%s contains the unsupported character %q", field, string(c))
		}
	}
	if s != "/" {
		for _, seg := range strings.Split(s[1:], "/") {
			if seg == "" || seg == "." || seg == ".." {
				return Invalid(field, "%s must be a clean path without empty, '.' or '..' segments", field)
			}
		}
	}
	return nil
}

// ImageRef is a parsed image reference.
type ImageRef struct {
	Name string
	// Alias is the movable alias ("stable"); empty when Generation or the
	// default alias is meant.
	Alias string
	// Generation is the pinned generation number; zero when not pinned.
	Generation int
	Pinned     bool
}

// ParseImageRef parses "name", "name@alias" or "name#g<N>".
func ParseImageRef(s string) (ImageRef, error) {
	const f = "image"
	if s == "" {
		return ImageRef{}, Invalid(f, "an image is required: name one with --image NAME")
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		name, gen := s[:i], s[i+1:]
		if !api.IsName(name, api.MaxName) {
			return ImageRef{}, Invalid(f, "image name %q is invalid", name)
		}
		if len(gen) < 2 || gen[0] != 'g' || len(gen) > 10 || (gen[1] == '0') {
			return ImageRef{}, Invalid(f, "generation %q must look like g3", gen)
		}
		n, err := strconv.Atoi(gen[1:])
		if err != nil || n < 1 || gen[1] == '+' || gen[1] == '-' {
			return ImageRef{}, Invalid(f, "generation %q must look like g3", gen)
		}
		return ImageRef{Name: name, Generation: n, Pinned: true}, nil
	}
	name, alias, has := strings.Cut(s, "@")
	if !api.IsName(name, api.MaxName) {
		return ImageRef{}, Invalid(f, "image reference %q is invalid (--image NAME, NAME@alias or NAME#gN)", s)
	}
	if has && !api.IsName(alias, 32) {
		return ImageRef{}, Invalid(f, "image alias %q is invalid", alias)
	}
	return ImageRef{Name: name, Alias: alias}, nil
}

// String formats the reference canonically.
func (r ImageRef) String() string {
	switch {
	case r.Pinned:
		return fmt.Sprintf("%s#g%d", r.Name, r.Generation)
	case r.Alias != "":
		return r.Name + "@" + r.Alias
	}
	return r.Name
}

// ParseRate parses a rate in bits per second: "10M" is 10 Mbit/s, "1G" 1 Gbit/s, "500K" 500 kbit/s, "64000" 64 kbit/s.
// Units are decimal (K=1000), as network rates are. Zero is rejected.
func ParseRate(s string) (uint64, error) {
	t, mult := s, uint64(1)
	if t != "" {
		switch t[len(t)-1] {
		case 'K', 'k':
			mult = 1000
		case 'M', 'm':
			mult = 1000 * 1000
		case 'G', 'g':
			mult = 1000 * 1000 * 1000
		}
		if mult != 1 {
			t = t[:len(t)-1]
		}
	}
	if t == "" || len(t) > 9 || t[0] == '0' {
		return 0, Invalid("rate", "rate %q is not a rate in bits per second such as 10M", s)
	}
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return 0, Invalid("rate", "rate %q is not a rate in bits per second such as 10M", s)
		}
	}
	n, _ := strconv.ParseUint(t, 10, 64)
	return n * mult, nil
}

// ParseSize parses "512M", "2G", "100" (bytes), optionally with a trailing
// "B" or "iB". Units are binary (K=1024). Zero is rejected.
func ParseSize(s string) (uint64, error) {
	t := s
	switch {
	case strings.HasSuffix(t, "iB"):
		t = t[:len(t)-2]
		if t == "" || t[len(t)-1] < 'A' {
			return 0, Invalid("size", "size %q is invalid", s)
		}
	case strings.HasSuffix(t, "B"):
		t = t[:len(t)-1]
	}
	mult := uint64(1)
	if t != "" {
		switch t[len(t)-1] {
		case 'K', 'k':
			mult = 1 << 10
		case 'M', 'm':
			mult = 1 << 20
		case 'G', 'g':
			mult = 1 << 30
		case 'T', 't':
			mult = 1 << 40
		case 'P', 'p':
			mult = 1 << 50
		}
		if mult != 1 {
			t = t[:len(t)-1]
		}
	}
	if t == "" || len(t) > 18 {
		return 0, Invalid("size", "size %q is invalid", s)
	}
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return 0, Invalid("size", "size %q is invalid", s)
		}
	}
	n, _ := strconv.ParseUint(t, 10, 64)
	if n == 0 {
		return 0, Invalid("size", "size %q must be greater than zero", s)
	}
	if n > ^uint64(0)/mult {
		return 0, Invalid("size", "size %q is too large", s)
	}
	return n * mult, nil
}

// MaxSizeBytes is the largest quota, reservation or volume size the privileged helper sets (16 TiB, its fixed limit).
const MaxSizeBytes = 16 << 40

// CanonicalSize parses a size the way ParseSize does and returns it as decimal bytes, the one form ZFS, the helper and
// the jail lifecycle all accept and the form `zfs get -p` reports, so a stored value compares equal to what is
// observed. A size above MaxSizeBytes is refused here and not when the helper sees it.
func CanonicalSize(field, s string) (string, error) {
	n, err := ParseSize(s)
	if err != nil {
		return "", Invalid(field, "%s %q is not a size such as 512M, 4G or 4GiB", field, s).
			WithHint("a size is a whole number of bytes with an optional unit K, M, G, T or P (binary, 1K = 1024)")
	}
	if n > MaxSizeBytes {
		return "", Invalid(field, "%s %q is larger than 16T, the largest size the helper sets", field, s)
	}
	return strconv.FormatUint(n, 10), nil
}

// addr parses an IP address without zone.
func addr(field, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return netip.Addr{}, Invalid(field, "%s %q is not a valid IP address", field, s)
	}
	return a, nil
}
