package validate

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"

	"unicode"
	"unicode/utf8"
)

// MaxRawLen bounds a raw PF fragment.
const MaxRawLen = 64 << 10

// FirewallReport is what validation learned besides errors.
type FirewallReport struct {
	// RequiresAdmin is set when the policy contains a raw PF fragment.
	RequiresAdmin bool
	Reasons       []string
}

// FirewallPolicySpec validates a policy. A raw fragment is syntactically
// screened here only; pfctl -n has the last word before loading.
func FirewallPolicySpec(s api.FirewallPolicySpec) (FirewallReport, error) {
	var rep FirewallReport
	for _, d := range []struct{ f, v string }{{"default_in", s.DefaultIn}, {"default_out", s.DefaultOut}} {
		switch d.v {
		case "allow", "deny":
		case "":
			return rep, Invalid(d.f, "%s is required: allow or deny (a policy says its defaults)", d.f)
		default:
			return rep, Invalid(d.f, "%s %q must be allow or deny", d.f, d.v)
		}
	}
	if len(s.Rules) > api.MaxPolicyRules {
		return rep, Invalid("rules", "a policy has at most %d rules, not %d: split it into several policies", api.MaxPolicyRules, len(s.Rules))
	}
	if err := Comment("comment", s.Comment); err != nil {
		return rep, err
	}
	for i, r := range s.Rules {
		if err := rule(fmt.Sprintf("rules[%d]", i), r); err != nil {
			return rep, err
		}
	}
	if s.Raw != "" {
		if len(s.Raw) > MaxRawLen {
			return rep, Invalid("raw", "raw fragment is larger than %d bytes", MaxRawLen)
		}
		for i := 0; i < len(s.Raw); i++ {
			c := s.Raw[i]
			if c == 0 || c < 0x20 && c != '\n' && c != '\t' && c != '\r' {
				return rep, Invalid("raw", "raw fragment contains a control character")
			}
		}
		rep.RequiresAdmin = true
		rep.Reasons = append(rep.Reasons, "raw PF fragment")
	}
	return rep, nil
}

// PolicyNames checks a list of policy names, of a jail or of a project: each is a name and none is listed twice.
func PolicyNames(field string, names []string) error {
	seen := map[string]bool{}
	for i, n := range names {
		f := fmt.Sprintf("%s[%d]", field, i)
		if err := Name(f, n); err != nil {
			return err
		}
		if seen[n] {
			return Invalid(f, "%s: policy %q is listed twice", field, n)
		}
		seen[n] = true
	}
	return nil
}

// CommentMax is the longest comment on a firewall object: a rule, a policy, an address set or one of its entries.
const CommentMax = 200

// Comment checks the comment of a firewall object: one line of printable text of at most CommentMax characters, valid
// UTF-8, without control, bidirectional or zero-width characters (a review tool shows what is there), line or paragraph
// separators, double quotes or backslashes. The comment becomes a comment line of the PF ruleset: a backslash at the end of
// a line would continue the comment onto the next line, which would then be part of it (a rule that is gone), and the
// helper refuses a ruleset line with `file "` in it, comment or not.
func Comment(field, c string) error {
	if n := utf8.RuneCountInString(c); n > CommentMax {
		return Invalid(field, "the comment is %d characters, at most %d", n, CommentMax)
	}
	if api.HasUnsafeText(c, "") || strings.ContainsFunc(c, func(r rune) bool { return unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) }) {
		return Invalid(field, "the comment must be one line of printable text")
	}
	if strings.ContainsAny(c, "\"\\") {
		return Invalid(field, "the comment may not contain a double quote or a backslash: it becomes a comment line of the PF ruleset")
	}
	return nil
}

func rule(f string, r api.FirewallRule) error {
	if err := Comment(f+".comment", r.Comment); err != nil {
		return err
	}
	if r.Name != "" {
		if err := RuleName(f+".name", r.Name); err != nil {
			return err
		}
	}
	switch r.Action {
	case "allow", "deny":
	default:
		return Invalid(f+".action", "action %q must be allow or deny", r.Action)
	}
	switch r.Direction {
	case "in", "out":
	default:
		return Invalid(f+".direction", "direction %q must be in or out", r.Direction)
	}
	switch r.Proto {
	case "", "tcp", "udp", "icmp", "icmp6":
	default:
		return Invalid(f+".proto", "proto %q must be tcp, udp, icmp or icmp6", r.Proto)
	}
	if len(r.Ports) > 0 && r.Proto != "tcp" && r.Proto != "udp" {
		return Invalid(f+".ports", "ports need proto tcp or udp")
	}
	for _, p := range r.Ports {
		if _, _, err := ParsePortSpec(p); err != nil {
			return Invalid(f+".ports", "port %q is invalid", p)
		}
	}
	// A rule belongs to the jail that has the policy: an inbound rule is always to the jail itself and an outbound rule
	// always from it, so a policy that several jails share never names the jail's own address.
	switch {
	case r.Direction == "in" && len(r.To) > 0:
		return Invalid(f+".to", "an inbound rule is always to the jail itself: leave out to, and say who may connect with from")
	case r.Direction == "out" && len(r.From) > 0:
		return Invalid(f+".from", "an outbound rule is always from the jail itself: leave out from, and say where it may go with to")
	}
	for _, e := range []struct {
		n string
		l []string
	}{{"from", r.From}, {"to", r.To}} {
		for _, a := range e.l {
			if err := ValidateEndpoint(a); err != nil {
				return Invalid(f+"."+e.n, "%s", err.Error())
			}
		}
	}
	if rd := r.Redirect; rd != nil {
		if r.Direction != "in" {
			return Invalid(f+".redirect", "redirect is allowed on inbound rules only")
		}
		if r.Action != "allow" {
			return Invalid(f+".redirect", "redirect needs action allow")
		}
		if r.Proto != "tcp" && r.Proto != "udp" {
			return Invalid(f+".redirect", "redirect needs proto tcp or udp")
		}
		if len(r.Ports) > 0 {
			return Invalid(f+".ports", "ports must be empty when redirect is set; the redirect names the ports")
		}
		if len(r.To) > 0 {
			return Invalid(f+".to", "to must be empty when redirect is set; the destination is the jail")
		}
		if rd.HostPort < 1 || rd.HostPort > 65535 || rd.JailPort < 1 || rd.JailPort > 65535 {
			return Invalid(f+".redirect", "redirect ports must be between 1 and 65535")
		}
		if rd.Listen != "" {
			a, err := netip.ParseAddr(rd.Listen)
			if err != nil || a.Zone() != "" || a.IsMulticast() || a.IsUnspecified() || a.IsLoopback() {
				return Invalid(f+".redirect.listen", "listen %q is not a unicast address of the host", rd.Listen)
			}
		}
	}
	return nil
}

// ParsePortSpec parses "80" or "8000-8100".
func ParsePortSpec(s string) (lo, hi int, err error) {
	a, b, isRange := strings.Cut(s, "-")
	if !isRange {
		b = a
	}
	conv := func(x string) (int, error) {
		if x == "" || len(x) > 5 {
			return 0, fmt.Errorf("bad port")
		}
		for i := 0; i < len(x); i++ {
			if x[i] < '0' || x[i] > '9' {
				return 0, fmt.Errorf("bad port")
			}
		}
		n, _ := strconv.Atoi(x)
		if n < 1 || n > 65535 {
			return 0, fmt.Errorf("port out of range")
		}
		return n, nil
	}
	if lo, err = conv(a); err != nil {
		return
	}
	if hi, err = conv(b); err != nil {
		return
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("range ends before it starts")
	}
	return lo, hi, nil
}

// EndpointKind classifies a from/to entry.
type EndpointKind int

const (
	EndpointAny EndpointKind = iota
	EndpointAddr
	EndpointSet
	EndpointTag
	EndpointJail
	// EndpointHost is the host itself: its own addresses.
	EndpointHost
)

// ReferenceKinds names the kinds of a reference, as they are written before the colon.
const ReferenceKinds = "host, jail:NAME, set:NAME or tag:NAME"

// ParseEndpoint classifies a from/to entry: "any", an address or CIDR, "jail:<name>" (a jail of the project),
// "set:<name>" (an address set of the project) or "tag:<tag>" (the jails of the project with that firewall tag). For
// EndpointAddr the canonical text is in value. A reference is always kind:name; "@" is not used.
func ParseEndpoint(s string) (kind EndpointKind, value string, err error) {
	switch {
	case s == "any":
		return EndpointAny, "any", nil
	case s == "host":
		return EndpointHost, "host", nil
	case strings.HasPrefix(s, "@"):
		n := strings.TrimPrefix(s, "@")
		return 0, "", fmt.Errorf("%q: @ is not used: write jail:%s, set:%s or tag:%s", s, n, n, n)
	case strings.HasPrefix(s, "jail:"):
		if !api.IsName(s[5:], MaxJailName) {
			return 0, "", fmt.Errorf("jail reference %q is invalid: jail:NAME names a jail of the project", s)
		}
		return EndpointJail, s[5:], nil
	case strings.HasPrefix(s, "set:"):
		if !api.IsName(s[4:], MaxSetName) {
			return 0, "", fmt.Errorf("set reference %q is invalid: set:NAME names an address set of the project", s)
		}
		return EndpointSet, s[4:], nil
	case strings.HasPrefix(s, "tag:"):
		if e := Tag("tag", s[4:]); e != nil {
			return 0, "", fmt.Errorf("tag reference %q is invalid", s)
		}
		return EndpointTag, s[4:], nil
	}
	if strings.Contains(s, "/") {
		p, e := netip.ParsePrefix(s)
		if e != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return 0, "", fmt.Errorf("%q is not a valid CIDR", s)
		}
		return EndpointAddr, p.Masked().String(), nil
	}
	a, e := netip.ParseAddr(s)
	if e != nil || a.Zone() != "" || a.Is4In6() {
		if kind, _, ok := strings.Cut(s, ":"); ok && kindWordRE.MatchString(kind) {
			return 0, "", fmt.Errorf("%q has an unknown kind %q: a reference is %s", s, kind, ReferenceKinds)
		}
		return 0, "", fmt.Errorf("%q is not a valid address, or a reference: %s", s, ReferenceKinds)
	}
	return EndpointAddr, a.String(), nil
}

// ValidateEndpoint checks one from/to entry.
func ValidateEndpoint(s string) error {
	_, _, err := ParseEndpoint(s)
	return err
}

// AddressSetSpec validates an address set.
func AddressSetSpec(s api.AddressSetSpec) error {
	if len(s.Addresses) > api.MaxAddressSetMembers {
		return Invalid("addresses", "an address set has at most %d members, not %d: use prefixes (a CIDR covers many addresses) or several sets", api.MaxAddressSetMembers, len(s.Addresses))
	}
	for _, e := range s.Addresses {
		k, _, err := ParseEndpoint(e.Address)
		if err != nil {
			return Invalid("addresses", "address set member %q: %v", e.Address, err)
		}
		if k != EndpointAddr && k != EndpointSet && k != EndpointJail {
			return Invalid("addresses", "address set member %q must be an address, a CIDR, jail:NAME or set:NAME", e.Address)
		}
		if err := Comment("addresses", e.Comment); err != nil {
			return Invalid("addresses", "the comment of %q: %v", e.Address, err)
		}
	}
	if err := Comment("comment", s.Comment); err != nil {
		return err
	}
	return nil
}

// FlattenSet expands the address set name with the sets (set:NAME) and the jails (jail:NAME) it names into canonical,
// sorted, de-duplicated address/CIDR strings. jails maps a jail to its addresses; a jail that is not in it has none
// (a reference to a jail that is gone matches nobody). A set that does not exist, or a cycle, is an error.
func FlattenSet(name string, sets map[string]api.AddressSetSpec, jails map[string][]string) ([]string, error) {
	seen := map[string]bool{}
	var walk func(n string, path []string) error
	var out []string
	walk = func(n string, path []string) error {
		for _, p := range path {
			if p == n {
				return Invalid("addresses", "address set cycle: %s -> %s", strings.Join(path, " -> "), n)
			}
		}
		s, ok := sets[n]
		if !ok {
			return Invalid("addresses", "address set %q does not exist (a rule or a set names set:%s)", n, n)
		}
		if seen[n] {
			return nil
		}
		path = append(path, n)
		for _, e := range s.Addresses {
			k, v, err := ParseEndpoint(e.Address)
			if err != nil || (k != EndpointAddr && k != EndpointSet && k != EndpointJail) {
				return Invalid("addresses", "address set %q member %q must be an address, a CIDR, jail:NAME or set:NAME", n, e.Address)
			}
			switch k {
			case EndpointSet:
				if err := walk(v, path); err != nil {
					return err
				}
			case EndpointJail:
				out = append(out, jails[v]...)
			default:
				out = append(out, v)
			}
		}
		// A set reached again through another path is flattened once; the
		// cycle check above only fires for sets on the current path.
		seen[n] = true
		return nil
	}
	if err := walk(name, nil); err != nil {
		return nil, err
	}
	return CanonicalAddrs(out), nil
}

// CanonicalAddrs sorts and de-duplicates address and CIDR strings.
func CanonicalAddrs(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	uniq := out[:0]
	for i, s := range out {
		if i == 0 || s != out[i-1] {
			uniq = append(uniq, s)
		}
	}
	return uniq
}
