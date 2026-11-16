package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Anchor names. Project names are lowercase letters, digits and "-", so a
// component with a dot is reserved for JailOps itself (verified on FreeBSD:
// pfctl refuses to modify anchors whose name begins with an underscore).
const (
	AnchorRoot   = "jailops"
	AnchorShared = "jailops/shared.pf"
)

// JailAnchor returns the anchor path of a jail given its project-qualified
// key: "web_nginx" is "jailops/web/nginx". A key without a project belongs to
// no project and gets "jailops/<key>", an anchor no jail uses (a name to test
// rules under).
func JailAnchor(key string) string {
	p, n, ok := strings.Cut(key, "_")
	if !ok || p == "" || n == "" {
		return AnchorRoot + "/" + key
	}
	return JailAnchorFor(p, n)
}

// JailAnchorFor returns the anchor path jailops/<project>/<jail>.
func JailAnchorFor(project, name string) string { return ProjectAnchor(project) + "/" + name }

// ProjectAnchor returns the parent anchor of a project's jail anchors.
func ProjectAnchor(project string) string { return AnchorRoot + "/" + project }

// ProjectAnchorRules returns the ruleset of a project's parent anchor: it
// makes PF evaluate the jail anchors below it: the wildcard anchor rule inside "jailops/<project>" evaluates
// "jailops/<project>/*" when the top level wildcard ("jailops/*") evaluates the project anchor.
func ProjectAnchorRules() string {
	return "anchor \"*\"\n"
}

// NetAnchor returns the anchor path holding the NAT rules of a network.
func NetAnchor(network string) string { return AnchorRoot + "/net." + network }

// AnchorLines returns the line the administrator adds to pf.conf once. JailOps never edits pf.conf. The anchors hold
// the filter rules and the translation options of the jails and networks (match ... nat-to and rdr-to), so one anchor
// line is all pf.conf needs; it must stand before any quick rule that should not decide first.
func AnchorLines() string {
	return "anchor \"jailops/*\"\n"
}

// NotAnyTable is the table of the addresses an allow rule to "any" does not reach: the host's own addresses and the
// subnets of the other projects.
const NotAnyTable = "not_any"

// notAnyMembers are the members of NotAnyTable.
func notAnyMembers(in *PFInput) []string {
	members := addrStrings(uniqAddrs(in.Host))
	for _, p := range in.Foreign {
		members = append(members, p.Masked().String())
	}
	sort.Strings(members)
	return members
}

// notAnyMatch is the structured form of "to ! <not_any>".
func notAnyMatch(in *PFInput) Match {
	return Match{Negate: true, Prefixes: prefixesOf(notAnyMembers(in)), Tables: []string{NotAnyTable}}
}

// HostTable is the table of the host's own addresses, which every anchor defines: the endpoint "host" of a rule, and the
// destination the anchor closes to the jail unless a rule opens it.
const HostTable = "host"

// AllowedSourceTable is the per-jail table of source addresses the jail may
// use (its own and fe80::/10). Every anchor defines the tables it uses.
const AllowedSourceTable = "jail_addrs"

// PFInput is the input of PFAnchor.
type PFInput struct {
	Jail string
	// MaxStates limits the states each pass rule of the jail may create (pf "keep state (max N)"); 0 sets no limit.
	MaxStates int
	// Shaping are the devices of the jail that have a bandwidth limit: the anchor sends what they send and what they
	// receive into dummynet pipes with dnpipe on match rules, which every later pass rule of the anchor inherits.
	Shaping []Shape
	// Interfaces are the host ends of the jail's epairs: each is the jail's own routed link, so everything the jail
	// sends arrives on it and everything for the jail (from the host, from another jail, from the internet) leaves
	// the host on it. Rules are attached to them: direction "in" of a rule means traffic into the jail (PF "out" on
	// the host end), "out" means traffic from the jail (PF "in").
	Interfaces []string
	// Addresses are the jail's own addresses. It must not be empty.
	Addresses []netip.Addr
	// LinkLocal are the jail's own link-local addresses (one per interface, formed by the kernel from the MAC
	// JailOps sets: ipam.LinkLocalFromMAC). With them the jail may use only its own link-local addresses as the source
	// of neighbour discovery and receive only its own; without them the whole of fe80::/10 is allowed.
	LinkLocal []netip.Addr
	// Host are the host's own addresses: the table <host> and the endpoint "host" of a rule. After the rules of the policies
	// the anchor closes them to the jail, except ICMP and the DNS of DNS (a jail never reaches a service of the host that no
	// rule names).
	Host []netip.Addr
	// DNS are the addresses of the host the jail's resolver asks (the network's gateway when the host resolves only
	// through loopback): udp and tcp port 53 to them stay open.
	DNS []netip.Addr
	// Tags are the jail's own tags (rendered as a comment only).
	Tags []string
	// TagMembers maps a tag to the addresses of every jail that has it.
	TagMembers map[string][]netip.Addr
	// DefaultIn and DefaultOut are the defaults of the anchor, "allow" or "deny". They come last. The caller works
	// them out from the policies (the strictest wins); an empty inbound default is deny and an empty outbound default
	// is allow.
	DefaultIn, DefaultOut string
	// Policies are rendered into the anchor in this order, each under its own heading and with its own rule
	// numbers: the project's policies, then the managed access policy, then the jail's own. Their defaults are not
	// used: DefaultIn and DefaultOut are.
	Policies []PFPolicy
	// Proxy are the inbound redirects of the jail's proxy devices, rendered after the policies.
	Proxy []api.FirewallRule
	Sets  map[string]api.AddressSetSpec
	// Jails maps a jail of the project to its addresses, for jail:NAME in a rule or in an address set. A jail that is
	// not in it has none: a reference to it matches nobody.
	Jails map[string][]string
	// Uplink is the interface redirects are applied on; required when a
	// rule has a redirect.
	Uplink string
	// Antispoof adds an antispoof rule for the jail interfaces.
	Antispoof bool
	// AllowRaw must be set by the caller after checking the admin role; a
	// raw fragment is otherwise refused.
	AllowRaw bool
	// Foreign are the subnets of the networks that belong to other projects. Nothing from them reaches the jail, and
	// the jail reaches nothing in them, unless a rule of a policy says so first (projects are isolated from each
	// other by default; a shared service lives in a project of its own and is opened by rules).
	Foreign []netip.Prefix
}

// PFPolicy is one policy of an anchor.
type PFPolicy struct {
	// Name is the name of the policy. Project is set for a policy the project names: its heading says so.
	Name    string
	Project bool
	Policy  api.FirewallPolicySpec
	// AllowRaw allows its raw fragment, as PFInput.AllowRaw does for all.
	AllowRaw bool
	// Managed is set for the policy of an app: managed by app access, not by the administrator.
	Managed bool
}

// heading is the comment line that opens the policy in the anchor.
func (p PFPolicy) heading() string {
	if p.Project {
		return "project policy " + p.Name
	}
	return "policy " + p.Name
}

type family struct {
	kw    string // inet, inet6
	addrs []netip.Addr
}

// PFAnchor renders the ruleset of anchor jailops/<jail>: BuildAnchor, printed.
func PFAnchor(in PFInput) (string, error) {
	a, err := BuildAnchor(in)
	if err != nil {
		return "", err
	}
	return FormatAnchor(a), nil
}

// closedAnchor is the anchor of a jail whose links have no address (a network entry of "none"): such a jail has no
// source address it may use and nothing is addressed to it, so nothing goes in or out. It is still an anchor: a jail
// with an interface and no anchor would be open to the host's rules alone.
func closedAnchor(in PFInput) *Anchor {
	var b builder
	ifs := list(in.Interfaces)
	b.line("%s", Header)
	b.line("# anchor %s", JailAnchor(in.Jail))
	b.line("# the jail has no address on its links: nothing goes in or out")
	b.rule(Rule{Action: "block", Dir: "in", From: anyMatch(), To: anyMatch(), Origin: Origin{Stage: StageClosed}},
		"block drop in quick on %s all", ifs)
	b.rule(Rule{Action: "block", Dir: "out", From: anyMatch(), To: anyMatch(), Origin: Origin{Stage: StageClosed}},
		"block drop out quick on %s all", ifs)
	out, _ := b.result()
	return &Anchor{Name: JailAnchor(in.Jail), Lines: strings.Split(out, "\n"), Rules: b.rules}
}

// BuildAnchor builds the anchor jailops/<jail>: its text and the structured form of its filter rules. Rules are
// first-match (every typed rule is "quick"); defaults come last. Tables for
// address sets and tags are defined inside the anchor so that one load is
// atomic. The text and the rules are made by the same code, line by line, so a walk over Rules is a walk over what
// is loaded.
func BuildAnchor(in PFInput) (*Anchor, error) {
	if err := validate.JailKey("jail", in.Jail); err != nil {
		return nil, err
	}
	if len(in.Interfaces) == 0 {
		return nil, fmt.Errorf("render: pf anchor needs at least one interface")
	}
	for _, i := range in.Interfaces {
		if err := validate.IfName("interface", i); err != nil {
			return nil, err
		}
	}
	for _, d := range []struct{ f, v string }{{"default_in", in.DefaultIn}, {"default_out", in.DefaultOut}} {
		if d.v != "" && d.v != "allow" && d.v != "deny" {
			return nil, validate.Invalid(d.f, "%s %q must be allow or deny", d.f, d.v)
		}
	}
	// sections are the policies and the proxy devices in the order they are rendered
	type section struct {
		heading, comment, raw string
		rules                 []api.FirewallRule
		origin                Origin
	}
	var sections []section
	var all []api.FirewallRule
	for _, p := range in.Policies {
		if err := validate.Name("policy", p.Name); err != nil {
			return nil, err
		}
		spec := p.Policy
		spec.DefaultIn, spec.DefaultOut = "deny", "allow" // the anchor's defaults are checked above; only the rules, the comment and the raw fragment are rendered
		if _, err := validate.FirewallPolicySpec(spec); err != nil {
			return nil, err
		}
		if p.Policy.Raw != "" && !p.AllowRaw && !in.AllowRaw {
			return nil, api.Errorf(api.CodeForbidden, "raw PF fragments require the admin role")
		}
		sections = append(sections, section{heading: p.heading(), comment: p.Policy.Comment, raw: p.Policy.Raw, rules: p.Policy.Rules,
			origin: Origin{Stage: StagePolicy, Policy: p.Name, ProjectPolicy: p.Project, Managed: p.Managed}})
		all = append(all, p.Policy.Rules...)
	}
	if len(in.Proxy) > 0 {
		sections = append(sections, section{heading: "proxy devices", rules: in.Proxy, origin: Origin{Stage: StagePolicy, Policy: "proxy devices"}})
		all = append(all, in.Proxy...)
	}
	for _, t := range in.Tags {
		if err := validate.Tag("tag", t); err != nil {
			return nil, err
		}
	}
	addrs := uniqAddrs(in.Addresses)
	if len(addrs) == 0 {
		return closedAnchor(in), nil
	}
	var fams []family
	for _, kw := range []string{"inet", "inet6"} {
		f := family{kw: kw}
		for _, a := range addrs {
			if a.Is4() == (kw == "inet") && a.IsValid() && a.Zone() == "" {
				f.addrs = append(f.addrs, a)
			}
		}
		if len(f.addrs) > 0 {
			fams = append(fams, f)
		}
	}
	ifs := list(in.Interfaces)

	// Collect referenced tables.
	setRefs, tagRefs, jailRefs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range all {
		for _, e := range append(append([]string(nil), r.From...), r.To...) {
			k, v, err := validate.ParseEndpoint(e)
			if err != nil {
				return nil, err
			}
			switch k {
			case validate.EndpointSet:
				setRefs[v] = true
			case validate.EndpointTag:
				tagRefs[v] = true
			case validate.EndpointJail:
				jailRefs[v] = true
			}
		}
	}
	// A set names jails and other sets: their tables are needed by the rules of the policies, the set's own table
	// holds the addresses flattened. A jail named by a rule gets its own table.

	var b builder
	b.line("%s", Header)
	b.line("# anchor %s", JailAnchor(in.Jail))
	if len(in.Tags) > 0 {
		tags := append([]string(nil), in.Tags...)
		sort.Strings(tags)
		b.line("# tags: %s", strings.Join(tags, " "))
	}

	for _, n := range sortedKeys(setRefs) {
		members, err := validate.FlattenSet(n, in.Sets, in.Jails)
		if err != nil {
			return nil, err
		}
		// what each member is, for whoever reads the loaded anchor in a review (a comment line: nothing else reads it; the
		// comments are one line of printable text, checked when the set is made)
		if c := in.Sets[n].Comment; c != "" {
			b.line("# set %s: %s", n, pfComment(c))
		}
		for _, e := range in.Sets[n].Addresses {
			if e.Comment != "" {
				b.line("# set %s: %s %s", n, e.Address, pfComment(e.Comment))
			}
		}
		b.line("%s", tableLine(validate.SetTable(n), members))
	}
	for _, n := range sortedKeys(jailRefs) {
		b.line("%s", tableLine("j_"+strings.ReplaceAll(n, "-", "_"), validate.CanonicalAddrs(in.Jails[n])))
	}
	b.line("# the host's own addresses (a jail reaches none of them unless a rule says so)")
	b.line("%s", tableLine(HostTable, addrStrings(uniqAddrs(in.Host))))
	b.line("# what an allow rule to any does not reach: the host and the networks of other projects (name them to open them)")
	b.line("%s", tableLine(NotAnyTable, notAnyMembers(&in)))
	for _, n := range sortedKeys(tagRefs) {
		var members []string
		for _, a := range uniqAddrs(in.TagMembers[n]) {
			members = append(members, a.String())
		}
		b.line("%s", tableLine("t_"+strings.ReplaceAll(n, "-", "_"), members))
	}

	// Bandwidth limits: what the jail sends arrives on its own link and goes into the egress pipe of the device; what is
	// sent to the jail leaves the host on the same link and goes into the ingress pipe. The first number of dnpipe
	// shapes the direction of the rule, the second the reverse direction of the same state, so a connection is shaped
	// the same way whichever side opens it. The pipes are inherited by the pass rules that match the packets after
	// these rules.
	for _, sh := range in.Shaping {
		if sh.Egress == 0 && sh.Ingress == 0 {
			continue
		}
		b.line("# bandwidth limit of %s: what the jail sends goes through pipe %d, what it receives through pipe %d", sh.Iface, sh.Egress, sh.Ingress)
		b.line("match in on %s all dnpipe (%d, %d)", sh.Iface, sh.Egress, sh.Ingress)
		b.line("match out on %s all dnpipe (%d, %d)", sh.Iface, sh.Ingress, sh.Egress)
	}

	// Translation rules come before filter rules.
	rdrRules := func(rules []api.FirewallRule) error {
		for i, r := range rules {
			if r.Redirect == nil || r.Disabled {
				continue
			}
			if err := validate.IfName("uplink", in.Uplink); err != nil {
				return fmt.Errorf("render: rules[%d] has a redirect and needs a valid uplink: %w", i, err)
			}
			b.line("# rdr %s", ruleLabel(i, r))
			ruleComment(&b, r)
			for _, f := range fams {
				from, ok := endpoints(r.From, f, nil)
				if !ok {
					continue
				}
				to := "(" + in.Uplink + ")"
				if l := r.Redirect.Listen; l != "" {
					a, err := netip.ParseAddr(l)
					if err != nil {
						return fmt.Errorf("render: rules[%d]: listen address %q: %w", i, l, err)
					}
					if a.Is4() != (f.kw == "inet") {
						continue
					}
					to = a.String()
				}
				b.line("match in on %s %s proto %s from %s to %s port %d rdr-to %s port %d",
					in.Uplink, f.kw, r.Proto, from, to, r.Redirect.HostPort, f.addrs[0], r.Redirect.JailPort)
				// The packet that comes out of the translation is passed here, by a rule of its own that carries the
				// label every stateful pass rule gets. The state of the connection belongs to this rule, so that the
				// reconcile loop ends it when the forward is removed (pfctl -k label); a state made by pf's default
				// rule has no label to end it by. The forward is the allow rule of its policy: it admits what it names.
				b.line("pass in quick on %s %s proto %s from %s to %s port %d",
					in.Uplink, f.kw, r.Proto, from, f.addrs[0], r.Redirect.JailPort)
			}
		}
		return nil
	}
	for _, sec := range sections {
		if err := rdrRules(sec.rules); err != nil {
			return nil, err
		}
	}
	own6 := famAddrs(fams, "inet6")
	ll := linkLocals(in.LinkLocal)
	// The jail's own sources for IPv6 control traffic: its addresses and its own link-local addresses (the whole of
	// fe80::/10 when the planner could not derive them).
	src6 := append(addrStrings(own6), llStrings(ll)...)
	if len(ll) == 0 {
		src6 = append(src6, "fe80::/10")
	}
	// The table of the jail's own addresses: the only sources it may use, and the only destinations that reach it. It
	// holds its link-local address (fe80::/10 when unknown), or IPv6 neighbour discovery breaks. A negated address
	// list ("from ! { a b }") is a pf syntax error; a negated table is not, and the anchor defines the table it names
	// (verified on FreeBSD 15.1).
	jailMembers := append(addrStrings(addrs), llStrings(ll)...)
	if len(ll) == 0 {
		jailMembers = append(jailMembers, "fe80::/10")
	}
	b.line("%s", tableLine(AllowedSourceTable, jailMembers))
	jailTable := func(neg bool) Match {
		return Match{Negate: neg, Prefixes: prefixesOf(jailMembers), Tables: []string{AllowedSourceTable}}
	}
	// icmp6 is a rule of the IPv6 control and neighbour stages: a filter rule on proto icmp6 with the given types
	icmp6 := func(stage, act, dir string, from, to Match, types ...string) Rule {
		return Rule{Action: act, Dir: dir, Family: "inet6", Proto: "icmp6", ICMPTypes: types, From: from, To: to, Origin: Origin{Stage: stage}}
	}
	if len(own6) > 0 {
		// IPv6 control traffic. A jail is never a router: no router advertisement or redirect leaves it. The unspecified
		// address :: cannot be a member of a table (pf accepts it and stores nothing), so duplicate address detection
		// (a neighbour solicitation to a solicited-node group) has a rule of its own before the antispoof block.
		b.rule(icmp6(StageIPv6Control, "block", "in", anyMatch(), anyMatch(), "routeradv", "redir"),
			"block in quick on %s inet6 proto icmp6 from any to any icmp6-type { routeradv, redir }", ifs)
		b.rule(icmp6(StageIPv6Control, "pass", "in", listMatch([]string{"::"}), listMatch([]string{"ff02::1:ff00:0/104"}), "neighbrsol"),
			"pass in quick on %s inet6 proto icmp6 from :: to ff02::1:ff00:0/104 icmp6-type neighbrsol", ifs)
	}
	if in.Antispoof {
		b.rule(Rule{Action: "block", Dir: "in", From: jailTable(true), To: anyMatch(), Origin: Origin{Stage: StageAntispoof}},
			"block in quick on %s from ! <%s> to any", ifs, AllowedSourceTable)
	}
	if len(own6) > 0 {
		// pf cannot read the target of a neighbour message, so a jail's advertisement for another jail's address cannot
		// be told from its own. What can be said is said: only its own addresses are the source, an advertisement never
		// goes to a multicast group (an unsolicited one would reach every jail and the host), and only messages
		// addressed to the jail's own addresses and solicited-node groups reach it. Unicast messages between jails of
		// one network stay possible: see docs/networking-ipv6.md.
		from6 := listStr(src6)
		src6m := listMatch(src6)
		b.rule(icmp6(StageNeighbour, "block", "in", anyMatch(), listMatch([]string{"ff02::/16"}), "neighbradv"),
			"block in quick on %s inet6 proto icmp6 from any to ff02::/16 icmp6-type neighbradv", ifs)
		b.rule(icmp6(StageNeighbour, "pass", "in", src6m, anyMatch(), "neighbrsol", "neighbradv"),
			"pass in quick on %s inet6 proto icmp6 from %s to any icmp6-type { neighbrsol, neighbradv }", ifs, from6)
		b.rule(icmp6(StageNeighbour, "pass", "in", src6m, listMatch([]string{"ff02::/16"}), "listenrep", "listendone", "143"),
			"pass in quick on %s inet6 proto icmp6 from %s to ff02::/16 icmp6-type { listenrep, listendone, 143 }", ifs, from6)
		b.rule(icmp6(StageNeighbour, "pass", "in", src6m, anyMatch(), "unreach", "toobig", "timex", "paramprob"),
			"pass in quick on %s inet6 proto icmp6 from %s to any icmp6-type { unreach, toobig, timex, paramprob }", ifs, from6)
		// the host forwarding from a jail to a neighbour on the same interface would send a redirect; a jail has no
		// on-link neighbour and must not learn one
		b.rule(icmp6(StageNeighbour, "block", "out", anyMatch(), anyMatch(), "redir", "routeradv"),
			"block out quick on %s inet6 proto icmp6 from any to any icmp6-type { redir, routeradv }", ifs)
		b.rule(icmp6(StageNeighbour, "pass", "out", anyMatch(), listMatch(ndDests(own6, ll)), "neighbrsol", "neighbradv"),
			"pass out quick on %s inet6 proto icmp6 from any to %s icmp6-type { neighbrsol, neighbradv }", ifs, listStr(ndDests(own6, ll)))
		b.rule(icmp6(StageNeighbour, "pass", "out", anyMatch(), anyMatch(), "unreach", "toobig", "timex", "paramprob"),
			"pass out quick on %s inet6 proto icmp6 from any to any icmp6-type { unreach, toobig, timex, paramprob }", ifs)
	}
	// Only the jail's own addresses reach it: an address it adds for itself (an alias) receives nothing, and no
	// broadcast (DHCP) or multicast other than neighbour discovery gets in.
	b.rule(Rule{Action: "block", Dir: "out", From: anyMatch(), To: jailTable(true), Origin: Origin{Stage: StageOwnAddrs}},
		"block drop out quick on %s from any to ! <%s>", ifs, AllowedSourceTable)
	if len(famAddrs(fams, "inet")) > 0 {
		b.rule(Rule{Action: "block", Dir: "out", Family: "inet", Proto: "icmp", ICMPTypes: []string{"redir"}, From: anyMatch(), To: anyMatch(), Origin: Origin{Stage: StageOwnAddrs}},
			"block drop out quick on %s inet proto icmp from any to any icmp-type redir", ifs)
	}

	// Deny wins over allow, whatever the order of the policies: when any policy has an enabled deny rule, the deny rules of
	// all the policies come first, then the allow rules (every rule is quick, so the first match decides). Each group
	// keeps the policy order and the rule order, and the headings and the rule numbers are those of the policies. An
	// anchor without a deny rule is written policy by policy, as it always was.
	denyFirst := hasEnabledDeny(all, false)
	shown := map[int]bool{}
	head := func(i int) {
		sec := sections[i]
		b.line("# %s", sec.heading)
		if sec.comment != "" && !shown[i] {
			b.line("#   %s", pfComment(sec.comment))
		}
		shown[i] = true
	}
	want := ""
	if denyFirst {
		want = "allow"
		b.line("# deny rules of all policies: they win over every allow rule, whatever the order of the policies")
		for i, sec := range sections {
			if !hasAction(sec.rules, "deny") {
				continue
			}
			head(i)
			filterRules(&b, &in, sec.origin, sec.rules, fams, ifs, false, "deny")
		}
		b.line("# allow rules of the policies, in the order of the policies")
	}
	for i, sec := range sections {
		if denyFirst && shown[i] && sec.raw == "" && !hasAction(sec.rules, "allow") {
			continue
		}
		head(i)
		filterRules(&b, &in, sec.origin, sec.rules, fams, ifs, false, want)
		if sec.raw != "" {
			b.rule(Rule{Kind: RuleRaw, Origin: Origin{Stage: StageRaw, Policy: sec.origin.Policy, ProjectPolicy: sec.origin.ProjectPolicy, Managed: sec.origin.Managed}},
				"%s", rawBegin)
			b.line("%s", strings.TrimRight(strings.ReplaceAll(sec.raw, "\r\n", "\n"), "\n"))
			b.line("%s", rawEnd)
		}
	}

	// The host is closed to the jail after the rules of its policies, as the other projects are: a jail that reaches the
	// host's sshd or its API is a jail that can attack the machine it runs on. What stays open is ping and the resolver
	// the network points the jail at.
	hostM := Match{Prefixes: addrMatch(uniqAddrs(in.Host)).Prefixes, Tables: []string{HostTable}}
	b.line("# the host: closed unless a rule above opened it; ping and the network's resolver stay open")
	for _, f := range fams {
		proto := "icmp"
		if f.kw == "inet6" {
			proto = "icmp6"
		}
		b.rule(Rule{Action: "pass", Dir: "in", Family: f.kw, Proto: proto, From: anyMatch(), To: hostM, Origin: Origin{Stage: StageHost}},
			"pass in quick on %s %s proto %s from any to <%s>", ifs, f.kw, proto, HostTable)
	}
	for _, f := range fams {
		var dns []netip.Addr
		for _, a := range uniqAddrs(in.DNS) {
			if a.Is4() == (f.kw == "inet") {
				dns = append(dns, a)
			}
		}
		if len(dns) == 0 {
			continue
		}
		for _, proto := range []string{"tcp", "udp"} {
			b.rule(Rule{Action: "pass", Dir: "in", Family: f.kw, Proto: proto, From: anyMatch(), To: addrMatch(dns), Ports: []PortRange{{Lo: 53, Hi: 53}}, Origin: Origin{Stage: StageHost}},
				"pass in quick on %s %s proto %s from any to %s port 53", ifs, f.kw, proto, listStr(addrStrings(dns)))
		}
	}
	b.rule(Rule{Action: "block", Dir: "in", From: anyMatch(), To: hostM, Origin: Origin{Stage: StageHost}},
		"block drop in quick on %s from any to <%s>", ifs, HostTable)

	if len(in.Foreign) > 0 {
		fp := make([]string, 0, len(in.Foreign))
		for _, p := range in.Foreign {
			fp = append(fp, p.Masked().String())
		}
		sort.Strings(fp)
		b.line("%s", tableLine("foreign", fp))
		b.line("# other projects: closed unless a rule above opened it")
		foreign := Match{Prefixes: append([]netip.Prefix(nil), in.Foreign...), Tables: []string{"foreign"}}
		for i := range foreign.Prefixes {
			foreign.Prefixes[i] = foreign.Prefixes[i].Masked()
		}
		b.rule(Rule{Action: "block", Dir: "out", From: foreign, To: anyMatch(), Origin: Origin{Stage: StageIsolation}},
			"block drop out quick on %s from <foreign> to any", ifs)
		b.rule(Rule{Action: "block", Dir: "in", From: anyMatch(), To: foreign, Origin: Origin{Stage: StageIsolation}},
			"block drop in quick on %s from any to <foreign>", ifs)
	}
	b.line("# defaults: final (quick), so that no rule of the host's own pf.conf after the anchor line changes them")
	inAct, outAct := "block drop", "pass"
	if in.DefaultIn == "allow" {
		inAct = "pass"
	}
	if in.DefaultOut == "deny" {
		outAct = "block drop"
	}
	act := func(s string) string {
		if strings.HasPrefix(s, "block") {
			return "block"
		}
		return "pass"
	}
	b.rule(Rule{Action: act(inAct), Dir: "out", From: anyMatch(), To: anyMatch(), Origin: Origin{Stage: StageDefault}},
		"%s out quick on %s all", inAct, ifs)
	b.rule(Rule{Action: act(outAct), Dir: "in", From: anyMatch(), To: anyMatch(), Origin: Origin{Stage: StageDefault}},
		"%s in quick on %s all", outAct, ifs)
	out, err := b.result()
	if err != nil {
		return nil, err
	}
	return &Anchor{Name: JailAnchor(in.Jail), Lines: strings.Split(labelPassRules(JailAnchor(in.Jail), out, in.MaxStates), "\n"), Rules: b.rules}, nil
}

var (
	tableDefRE = regexp.MustCompile(`(?m)^table\s+<([A-Za-z][A-Za-z0-9_]*)>[^{\n]*\{([^}]*)\}`)
	tableUseRE = regexp.MustCompile(`<([A-Za-z][A-Za-z0-9_]*)>`)
)

// labelPassRules puts a label on every stateful pass rule of an anchor. The label is a hash of the anchor's name, the
// rule's text, the members of the tables the rule names, and everything that comes before the rule in the anchor
// (every rule above it, with the members of their tables). It is the same for as long as the rule means the same
// thing at the same place, and different as soon as it does not: a rule removed, a port changed, an address taken out
// of a set, or a deny put in front of it, which changes what the rule lets through. The reconciler kills the states of
// labels that are gone after it loads an anchor: pf keeps the states of a rule that was removed, and a flow that is no
// longer allowed would go on until it ended. The price is that a rule inserted in the middle of an anchor ends the
// flows of the pass rules below it, which then have to reconnect.
//
// Every pass rule of the jail also gets "keep state (if-bound)", and with maxStates above 0 "keep state (max N, if-bound)":
// the rule may create at most N states, so one jail cannot fill the state table of the host. The limit is per rule.
// rawBegin and rawEnd are the comment lines that enclose the administrator's raw fragment in an anchor.
const (
	rawBegin = "# raw fragment (admin)"
	rawEnd   = "# end of raw fragment (admin)"
)

func labelPassRules(anchor, text string, maxStates int) string {
	tables := map[string]string{}
	for _, m := range tableDefRE.FindAllStringSubmatch(text, -1) {
		tables[m[1]] = strings.Join(strings.Fields(m[2]), " ")
	}
	var out strings.Builder
	raw := false                           // the administrator's raw fragment is passed on untouched
	above := sha256.Sum256([]byte(anchor)) // what comes before: a running hash of the rules seen so far
	for _, ln := range strings.Split(text, "\n") {
		// The fragment is the lines between its two markers, whatever comments it has itself: a comment of the
		// administrator's must not turn the labelling on for the rules that follow it (a rule that says keep state would
		// get a second one, which pf refuses to load).
		switch ln {
		case rawBegin:
			raw = true
		case rawEnd:
			raw = false
		}
		rule := strings.TrimSpace(ln) != "" && !strings.HasPrefix(ln, "#") && !strings.HasPrefix(ln, "table ")
		if rule {
			uses := ""
			for _, m := range tableUseRE.FindAllStringSubmatch(ln, -1) {
				if body, ok := tables[m[1]]; ok {
					uses += m[1] + "=" + body + "\n"
				}
			}
			if !raw && strings.HasPrefix(ln, "pass ") && !strings.Contains(ln, " no state") && !strings.Contains(ln, " label ") {
				h := sha256.New()
				h.Write(above[:])
				h.Write([]byte(ln + "\n" + uses))
				ln += ` label "` + pfctl.LabelPrefix + hex.EncodeToString(h.Sum(nil))[:12] + `"`
			}
			next := sha256.New()
			next.Write(above[:])
			next.Write([]byte(ln + "\n" + uses))
			copy(above[:], next.Sum(nil))
			// The state options come after the label is made, so that changing the limit does not change a label, which
			// would end the running flows of the rule. Every state is bound to its interface: a connection is judged
			// again at every hop of the host (in on the sender's link, out on the receiver's), and a floating state
			// that the first hop made would carry it through the second without that hop's rules looking at it.
			if !raw && strings.HasPrefix(ln, "pass ") && !strings.Contains(ln, " no state") {
				if maxStates > 0 {
					ln += fmt.Sprintf(" keep state (max %d, if-bound)", maxStates)
				} else {
					ln += " keep state (if-bound)"
				}
			}
		}
		out.WriteString(ln)
		out.WriteString("\n")
	}
	return strings.TrimSuffix(out.String(), "\n")
}

// pfComment makes a text safe as the rest of a PF comment line even when nothing checked it before (validate.Comment
// does, on every path that stores a spec): a line break, a backslash (which continues a comment onto the next line, so the
// rule after it would be part of it), a double quote, a control, bidirectional or zero-width character and a line or
// paragraph separator each become a blank.
func pfComment(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\\' || r == '"' || r == 0x2028 || r == 0x2029 || api.UnsafeRune(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, " "))
}

// ruleComment writes what the rule is for as a comment line under its header, for whoever reads the loaded anchor.
func ruleComment(b *builder, r api.FirewallRule) {
	if r.Comment != "" {
		b.line("#   %s", pfComment(r.Comment))
	}
}

func ruleLabel(i int, r api.FirewallRule) string {
	head := fmt.Sprintf("rule %d", i+1)
	if r.Disabled {
		head += " (disabled)"
	}
	if r.Name != "" {
		return head + ": " + r.Name
	}
	return head
}

func tableLine(name string, members []string) string {
	if len(members) == 0 {
		return fmt.Sprintf("table <%s> persist", name)
	}
	return fmt.Sprintf("table <%s> persist { %s }", name, strings.Join(members, ", "))
}

// endpoints renders a from/to list for one address family. def is used when
// the list is empty (nil means "any"). The bool is false when the user listed
// entries but none applies to this family.
func endpoints(entries []string, f family, def []netip.Addr) (string, bool) {
	if len(entries) == 0 {
		if def == nil {
			return "any", true
		}
		parts := make([]string, len(def))
		for i, a := range def {
			parts[i] = a.String()
		}
		return listStr(parts), true
	}
	var parts []string
	for _, e := range entries {
		k, v, err := validate.ParseEndpoint(e)
		if err != nil {
			return "", false // validated earlier; defensive
		}
		switch k {
		case validate.EndpointAny:
			return "any", true
		case validate.EndpointSet:
			parts = append(parts, "<s_"+v+">")
		case validate.EndpointHost:
			parts = append(parts, "<"+HostTable+">")
		case validate.EndpointJail:
			parts = append(parts, "<j_"+strings.ReplaceAll(v, "-", "_")+">")
		case validate.EndpointTag:
			parts = append(parts, "<t_"+strings.ReplaceAll(v, "-", "_")+">")
		case validate.EndpointAddr:
			if isV4Text(v) == (f.kw == "inet") {
				parts = append(parts, v)
			}
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return listStr(parts), true
}

func isV4Text(s string) bool { return !strings.Contains(s, ":") }

func listStr(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func list(items []string) string { return listStr(items) }

func portList(ports []string) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		lo, hi, _ := validate.ParsePortSpec(p)
		if lo == hi {
			out[i] = fmt.Sprint(lo)
		} else {
			out[i] = fmt.Sprintf("%d:%d", lo, hi)
		}
	}
	return listStr(out)
}

func uniqAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if a.IsValid() {
			out = append(out, a.WithZone("").Unmap())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	u := out[:0]
	for i, a := range out {
		if i == 0 || a != out[i-1] {
			u = append(u, a)
		}
	}
	return u
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PFNet renders the anchor of a network (NetAnchor(name)): the NAT rule when the network has one. Nothing else: the
// traffic of the jails is judged by their own anchors, on the jails' own links. The translation uses the first
// address of the uplink (":0" leaves its aliases out), so that the source address of a jail's connections does not
// change from one connection to the next.
func PFNet(name string, spec api.NetworkSpec) (string, error) {
	if err := validate.Name("network", name); err != nil {
		return "", err
	}
	if err := validate.NetworkSpec(spec); err != nil {
		return "", err
	}
	var b builder
	b.line("%s", Header)
	b.line("# anchor %s", NetAnchor(name))
	if spec.IPv4 != nil && spec.IPv4.NAT {
		p, err := netip.ParsePrefix(spec.IPv4.Subnet)
		if err != nil {
			return "", err
		}
		b.line("match out on %s inet from %s to ! %s nat-to (%s:0)", spec.Uplink, p.Masked(), p.Masked(), spec.Uplink)
	}
	return b.result()
}

// hasEnabledDeny says whether any of the rules is an enabled deny rule; onlyIn looks at the rules for traffic into the
// jail only.
func hasEnabledDeny(rules []api.FirewallRule, onlyIn bool) bool {
	for _, r := range rules {
		if r.Action == "deny" && !r.Disabled && !(onlyIn && r.Direction == "out") {
			return true
		}
	}
	return false
}

// hasAction says whether a policy has a rule of the action "allow" or "deny", enabled or not: a disabled rule is
// shown, as a comment line, in the group of its action.
func hasAction(rules []api.FirewallRule, action string) bool {
	for _, r := range rules {
		if (r.Action == "deny") == (action == "deny") {
			return true
		}
	}
	return false
}

// filterRules renders the typed filter rules of one policy, and records each as a structured rule. ifs are the
// interfaces the rules stand on; onlyIn keeps the rules for traffic into the jail. want is "deny" or "allow" to render
// only the rules of that action, "" for all of them in their order. A disabled rule is a comment line, not a rule.
func filterRules(b *builder, in *PFInput, org Origin, rules []api.FirewallRule, fams []family, ifs string, onlyIn bool, want string) {
	for i, r := range rules {
		if onlyIn && r.Direction == "out" {
			continue
		}
		if want != "" && (r.Action == "deny") != (want == "deny") {
			continue
		}
		if r.Disabled {
			dir := "out" // traffic into the jail leaves the host-side end
			if r.Direction == "out" {
				dir = "in"
			}
			sr := Rule{Kind: RuleDisabled, Line: b.n, Dir: dir, Proto: r.Proto, From: anyMatch(), To: anyMatch(), Ports: portRanges(r.Ports), Origin: org}
			sr.Origin.RuleNo, sr.Origin.RuleName, sr.Origin.Comment = i+1, r.Name, r.Comment
			b.rules = append(b.rules, sr)
		}
		b.line("# %s", ruleLabel(i, r))
		ruleComment(b, r)
		if r.Disabled {
			continue
		}
		act, pfAct := "pass", "pass"
		if r.Action == "deny" {
			act, pfAct = "block drop", "block"
		}
		dir, own := "out", "to" // traffic into the jail leaves the host-side end
		if r.Direction == "out" {
			dir, own = "in", "from"
		}
		for _, f := range fams {
			if r.Proto == "icmp" && f.kw != "inet" || r.Proto == "icmp6" && f.kw != "inet6" {
				continue
			}
			var from, to string
			var ok1, ok2 bool
			var mFrom, mTo Match
			if own == "to" {
				from, ok1 = endpoints(r.From, f, nil)
				to, ok2 = endpoints(r.To, f, f.addrs)
				mFrom, _ = endpointMatch(r.From, f, nil, in)
				mTo, _ = endpointMatch(r.To, f, f.addrs, in)
			} else {
				from, ok1 = endpoints(r.From, f, f.addrs)
				to, ok2 = endpoints(r.To, f, nil)
				mFrom, _ = endpointMatch(r.From, f, f.addrs, in)
				mTo, _ = endpointMatch(r.To, f, nil, in)
				// "any" as the destination of an allow rule is every address but the host's and those of the other
				// projects: a jail that may reach "the internet" does not thereby reach the host's sshd or the jails of
				// another project (name them to open them). A deny rule keeps "any": it may deny more, never less.
				if r.Action == "allow" && to == "any" {
					to, mTo = "! <"+NotAnyTable+">", notAnyMatch(in)
				}
			}
			if !ok1 || !ok2 {
				continue
			}
			sr := Rule{Action: pfAct, Dir: dir, Family: f.kw, Proto: r.Proto, From: mFrom, To: mTo, Origin: org}
			sr.Origin.RuleNo, sr.Origin.RuleName, sr.Origin.Comment = i+1, r.Name, r.Comment
			var sb strings.Builder
			sb.WriteString(act + " " + dir)
			if r.Log {
				sb.WriteString(" log")
			}
			fmt.Fprintf(&sb, " quick on %s %s", ifs, f.kw)
			if r.Proto != "" {
				sb.WriteString(" proto " + r.Proto)
			}
			fmt.Fprintf(&sb, " from %s to %s", from, to)
			if r.Redirect != nil {
				// the filter sees the translated destination
				to2 := f.addrs[0].String()
				sb.Reset()
				fmt.Fprintf(&sb, "%s %s", act, dir)
				if r.Log {
					sb.WriteString(" log")
				}
				fmt.Fprintf(&sb, " quick on %s %s proto %s from %s to %s port %d", ifs, f.kw, r.Proto, from, to2, r.Redirect.JailPort)
				sr.To = addrMatch(f.addrs[:1])
				sr.Ports = []PortRange{{Lo: uint16(r.Redirect.JailPort), Hi: uint16(r.Redirect.JailPort)}}
			} else if len(r.Ports) > 0 {
				sb.WriteString(" port " + portList(r.Ports))
				sr.Ports = portRanges(r.Ports)
			}
			b.rule(sr, "%s", sb.String())
		}
	}
}

func llStrings(in []netip.Addr) []string { return addrStrings(in) }

// linkLocals keeps the link-local addresses of a list.
func linkLocals(in []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range uniqAddrs(in) {
		if a.Is6() && a.IsLinkLocalUnicast() {
			out = append(out, a)
		}
	}
	return out
}

// solicitedNode returns the solicited-node multicast address of a unicast address (RFC 4291, 2.7.1).
func solicitedNode(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 11: 0x01, 12: 0xff, 13: b[13], 14: b[14], 15: b[15]})
}

// ndDests are the destinations neighbour discovery messages may have when they reach the jail: its own addresses and
// link-local addresses and their solicited-node groups (the whole solicited-node range and fe80::/10 when the
// link-local addresses are unknown).
func ndDests(own, ll []netip.Addr) []string {
	var out []string
	all := append(append([]netip.Addr(nil), own...), ll...)
	out = append(out, addrStrings(all)...)
	if len(ll) == 0 {
		out = append(out, "fe80::/10", "ff02::1:ff00:0/104")
		return out
	}
	seen := map[netip.Addr]bool{}
	for _, a := range all {
		if g := solicitedNode(a); !seen[g] {
			seen[g] = true
			out = append(out, g.String())
		}
	}
	return out
}

func addrStrings(in []netip.Addr) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = a.String()
	}
	return out
}

func famAddrs(fams []family, kw string) []netip.Addr {
	for _, f := range fams {
		if f.kw == kw {
			return f.addrs
		}
	}
	return nil
}

// tagName turns a jail key into a PF tag.
func tagName(key string) string {
	var sb strings.Builder
	sb.WriteString("jo_")
	for _, c := range key {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
			sb.WriteRune(c)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}
