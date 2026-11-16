package render

import (
	"net/netip"
	"strings"

	"jailops.net/jailops/internal/validate"
)

// The stages of an anchor, in the order the renderer writes them. A rule says which stage it belongs to, so that a
// reader of a verdict knows what decided it.
const (
	StageIPv6Control = "ipv6-control"  // router advertisements and redirects, duplicate address detection
	StageAntispoof   = "antispoof"     // the jail's own source addresses
	StageNeighbour   = "neighbour"     // neighbour discovery and the ICMPv6 errors that always pass
	StageOwnAddrs    = "own-addresses" // only the jail's own addresses reach it
	StagePolicy      = "policy"        // a rule of a policy
	StageRaw         = "raw"           // a raw PF fragment of a policy
	StageIsolation   = "isolation"     // the subnets of other projects
	StageHost        = "host"          // the host: closed to the jail unless a rule opened it
	StageDefault     = "default"       // the defaults of the anchor
	StageClosed      = "closed"        // a jail with a link and no address: nothing goes in or out
)

// Anchor is a rendered anchor: its lines, and for every filter rule among them what it matches. The rules are in the
// order they are loaded and pf takes the first match (every one is quick), so whoever walks Rules in order decides
// as pf does. Text is what is loaded.
type Anchor struct {
	Name  string
	Lines []string
	Rules []Rule
}

// Text is the ruleset as it is loaded.
func (a *Anchor) Text() string { return strings.Join(a.Lines, "\n") }

// FormatAnchor prints an anchor: the text that is loaded into pf.
func FormatAnchor(a *Anchor) string { return a.Text() }

// RuleKind tells a filter rule from a place in the anchor that the structured rules cannot describe.
type RuleKind string

const (
	// RuleFilter is a pass or block rule with a match.
	RuleFilter RuleKind = "filter"
	// RuleRaw marks a raw PF fragment: its rules are the administrator's text, not described here. A walk that reaches
	// it before a decision cannot say what pf does.
	RuleRaw RuleKind = "raw"
	// RuleDisabled marks a rule of a policy that is switched off: it is a comment line of the anchor, not a rule. It is
	// kept so that a walk can say that a disabled rule would have matched; its addresses are not resolved (From and To
	// match anything), it keeps the interface, direction, protocol and ports of the rule.
	RuleDisabled RuleKind = "disabled"
)

// Rule is one filter rule of an anchor.
type Rule struct {
	Kind RuleKind
	// Line is the index in Anchor.Lines of the rule's text.
	Line int
	// Action is "pass" or "block".
	Action string
	// Dir is the pf direction: "in" (what the jail sends, on its link) or "out" (what leaves the host on the jail's link).
	Dir string
	// Family is "inet", "inet6" or "" for both.
	Family string
	// Proto is "", "tcp", "udp", "icmp" or "icmp6".
	Proto string
	// ICMPTypes are the ICMP types the rule matches, as pf prints them (names, or numbers); empty matches every type.
	ICMPTypes []string
	From, To  Match
	// Ports are the destination ports; empty matches every port. The ranges are inclusive.
	Ports  []PortRange
	Origin Origin
}

// Match is a from or to address of a rule: any address, the addresses of a list or a table, or everything except them.
// An empty list that is not Any matches nothing (a table without members).
type Match struct {
	Any      bool
	Negate   bool
	Prefixes []netip.Prefix
	// Tables are the names of the pf tables the match names, for a reader of a trace ("s_postgresql_allow": the name postgresql-allow with the hyphen written as an underscore).
	Tables []string
}

// Contains says whether an address is matched.
func (m Match) Contains(a netip.Addr) bool {
	if m.Any {
		return true
	}
	in := false
	for _, p := range m.Prefixes {
		if p.Contains(a) {
			in = true
			break
		}
	}
	return in != m.Negate
}

// PortRange is an inclusive range of ports.
type PortRange struct{ Lo, Hi uint16 }

// Origin says where a rule comes from, for the trace of a verdict.
type Origin struct {
	Stage string
	// Policy is the name of the policy of a rule of the stage policy or raw.
	Policy        string
	ProjectPolicy bool
	// Managed is set for the policy of an app (managed by app access).
	Managed bool
	// RuleNo is the number of the rule in its policy (1 is the first), as the anchor's heading counts them.
	RuleNo   int
	RuleName string
	Comment  string
}

// prefixOf reads an address or a CIDR as a prefix.
func prefixOf(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), true
	}
	return netip.Prefix{}, false
}

func prefixesOf(items []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range items {
		if p, ok := prefixOf(s); ok {
			out = append(out, p)
		}
	}
	return out
}

func anyMatch() Match { return Match{Any: true} }

func listMatch(items []string) Match { return Match{Prefixes: prefixesOf(items)} }

func addrMatch(addrs []netip.Addr) Match { return Match{Prefixes: prefixesOf(addrStrings(addrs))} }

// portRanges reads the ports of a rule.
func portRanges(ports []string) []PortRange {
	var out []PortRange
	for _, p := range ports {
		lo, hi, err := validate.ParsePortSpec(p)
		if err != nil {
			continue
		}
		out = append(out, PortRange{Lo: uint16(lo), Hi: uint16(hi)})
	}
	return out
}

// endpointMatch is endpoints for a structured rule: the same entries read the same way, as a Match. The bool is false
// when the user listed entries and none applies to the family.
func endpointMatch(entries []string, f family, def []netip.Addr, in *PFInput) (Match, bool) {
	if len(entries) == 0 {
		if def == nil {
			return anyMatch(), true
		}
		return addrMatch(def), true
	}
	var m Match
	any := false
	for _, e := range entries {
		k, v, err := validate.ParseEndpoint(e)
		if err != nil {
			return Match{}, false
		}
		switch k {
		case validate.EndpointAny:
			return anyMatch(), true
		case validate.EndpointSet:
			any = true
			m.Tables = append(m.Tables, validate.SetTable(v))
			if members, err := validate.FlattenSet(v, in.Sets, in.Jails); err == nil {
				m.Prefixes = append(m.Prefixes, prefixesOf(members)...)
			}
		case validate.EndpointHost:
			any = true
			m.Tables = append(m.Tables, HostTable)
			m.Prefixes = append(m.Prefixes, addrMatch(uniqAddrs(in.Host)).Prefixes...)
		case validate.EndpointJail:
			any = true
			m.Tables = append(m.Tables, "j_"+strings.ReplaceAll(v, "-", "_"))
			m.Prefixes = append(m.Prefixes, prefixesOf(validate.CanonicalAddrs(in.Jails[v]))...)
		case validate.EndpointTag:
			any = true
			m.Tables = append(m.Tables, "t_"+strings.ReplaceAll(v, "-", "_"))
			m.Prefixes = append(m.Prefixes, addrMatch(uniqAddrs(in.TagMembers[v])).Prefixes...)
		case validate.EndpointAddr:
			if isV4Text(v) == (f.kw == "inet") {
				any = true
				if p, ok := prefixOf(v); ok {
					m.Prefixes = append(m.Prefixes, p)
				}
			}
		}
	}
	if !any {
		return Match{}, false
	}
	return m, true
}
