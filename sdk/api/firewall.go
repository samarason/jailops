package api

// FirewallPolicy is a declarative set of rules rendered into one PF anchor
// per jail ("jailops/<project>/<jail>"). jailops never owns the host's pf.conf; the
// administrator adds the anchor lines once.
type FirewallPolicy struct {
	Metadata ObjectMeta         `json:"metadata"`
	Spec     FirewallPolicySpec `json:"spec"`
}

// FirewallPolicySpec holds the rules of a policy.
type FirewallPolicySpec struct {
	// Comment says what the policy is for: what a reviewer of the firewall reads first (one line, at most 200 characters, no double quotes or backslashes).
	Comment string `json:"comment,omitempty"`
	// DefaultIn and DefaultOut apply when no rule matches: "allow" or "deny". A policy always says both.
	DefaultIn  string         `json:"default_in"`
	DefaultOut string         `json:"default_out"`
	Rules      []FirewallRule `json:"rules,omitempty"`
	// Raw is a PF fragment. It requires the admin role and is validated with
	// pfctl -n before it is loaded.
	Raw string `json:"raw,omitempty"`
}

// FirewallRule is one typed rule.
type FirewallRule struct {
	Name string `json:"name,omitempty"`
	// Comment says why the rule is there (one line, at most 200 characters, no double quotes or backslashes); it is a comment line of the rendered anchor.
	Comment   string   `json:"comment,omitempty"`
	Action    string   `json:"action"`          // allow, deny
	Direction string   `json:"direction"`       // in, out
	Proto     string   `json:"proto,omitempty"` // tcp, udp, icmp, icmp6
	From      []string `json:"from,omitempty"`  // addresses, @address-set, @jail, or tag:<tag>
	To        []string `json:"to,omitempty"`
	Ports     []string `json:"ports,omitempty"` // "80", "8000-8100"
	Log       bool     `json:"log,omitempty"`
	// Disabled switches the rule off without deleting it: it is validated and numbered like any other and shows in the
	// policy and as a comment line of the rendered anchor, but it is not loaded and lets nothing through or stops nothing.
	Disabled bool `json:"disabled,omitempty"`
	// Redirect rewrites the destination (rdr). Allowed on inbound rules only.
	Redirect *Redirect `json:"redirect,omitempty"`
}

// Redirect is a port forward to the jail.
type Redirect struct {
	// Listen is the host address the port is forwarded on; empty means the
	// uplink address.
	Listen   string `json:"listen,omitempty"`
	HostPort int    `json:"host_port"`
	JailPort int    `json:"jail_port"`
}

// AddressSet is a named list of addresses referenced as @name in rules.
type AddressSet struct {
	Metadata ObjectMeta     `json:"metadata"`
	Spec     AddressSetSpec `json:"spec"`
}

// AddressEntry is one member of an address set: an address, a CIDR or @name (a jail of the project, or another set),
// with what it is. The comment is what a reviewer of the firewall reads next to the set's name in a rule: at most 200
// characters, one line of printable text; it is not part of any rule.
type AddressEntry struct {
	Address string `json:"address"`
	Comment string `json:"comment,omitempty"`
}

// AddressSetSpec lists the members of an address set. A member @name is a jail of the project or another address
// set; cycles are rejected.
type AddressSetSpec struct {
	// Comment says what the set is (one line, at most 200 characters, no double quotes or backslashes).
	Comment   string         `json:"comment,omitempty"`
	Addresses []AddressEntry `json:"addresses"`
}

// Members is the text of every entry: what a rule or a table holds.
func (s AddressSetSpec) Members() []string {
	out := make([]string, len(s.Addresses))
	for i, e := range s.Addresses {
		out[i] = e.Address
	}
	return out
}

// Entries makes plain members into entries without comments.
func Entries(members ...string) []AddressEntry {
	out := make([]AddressEntry, len(members))
	for i, m := range members {
		out[i] = AddressEntry{Address: m}
	}
	return out
}

// Limits on the size of the firewall objects of a project. pf's table-entries limit is one for the whole kernel and every
// anchor holds its own copy of each table it names, so one project that makes huge address sets could stop every other
// project from loading an anchor. The limits are generous for any real policy.
const (
	// MaxPolicyRules is the number of rules of one policy.
	MaxPolicyRules = 500
	// MaxAddressSetMembers is the number of members of one address set.
	MaxAddressSetMembers = 5000
	// MaxPoliciesPerProject and MaxAddressSetsPerProject are the numbers of each kind in one project.
	MaxPoliciesPerProject    = 200
	MaxAddressSetsPerProject = 200
	// MaxSetMembersPerProject is the number of members of all the address sets of one project together.
	MaxSetMembersPerProject = 20000
)
