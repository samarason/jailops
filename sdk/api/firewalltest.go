package api

// FirewallTestRequest asks whether a new connection would pass the firewall (POST /api/v1/firewall/test).
type FirewallTestRequest struct {
	// From and To are a jail of the project (@web), a single address, or host (the host's own address on the
	// gateway of the jail's network). A set is not an endpoint: name a jail or an address.
	From string `json:"from"`
	To   string `json:"to"`
	// Proto is tcp (the default), udp, icmp or icmp6.
	Proto string `json:"proto,omitempty"`
	// Port is the destination port of tcp and udp.
	Port int `json:"port,omitempty"`
	// ICMPType is the ICMP type as pf names it (echoreq, echorep, ...). Without one, icmp and icmp6 are tested with an
	// echo request (ping) and the result says so.
	ICMPType string `json:"icmp_type,omitempty"`
	// Family limits the test to "4" or "6"; empty tests every family the two ends have in common.
	Family string `json:"family,omitempty"`
}

// Verdicts of a firewall test.
const (
	TestPass    = "pass"
	TestBlock   = "block"
	TestUnknown = "unknown"
)

// FirewallTestResult is the answer: one case per address pair, and the limits of the answer.
type FirewallTestResult struct {
	// Verdict covers the cases: block when any case is blocked, else unknown when any is, else pass.
	Verdict string             `json:"verdict"`
	Cases   []FirewallTestCase `json:"cases"`
	// Caveats say what the answer does not cover. A pass is a pass for a new connection, as far as these allow.
	Caveats []string `json:"caveats,omitempty"`
}

// FirewallTestCase is the test of one pair of addresses.
type FirewallTestCase struct {
	// Family is inet or inet6.
	Family   string `json:"family"`
	From     string `json:"from"`
	To       string `json:"to"`
	Proto    string `json:"proto"`
	Port     int    `json:"port,omitempty"`
	ICMPType string `json:"icmp_type,omitempty"`
	Verdict  string `json:"verdict"`
	// Hops are the anchors the packet meets, in order; the first one that blocks, or cannot decide, ends the walk.
	Hops []FirewallTestHop `json:"hops"`
}

// FirewallTestHop is what one anchor does with the packet.
type FirewallTestHop struct {
	// Side is source (what the jail sends) or destination (what reaches the jail).
	Side string `json:"side"`
	Jail string `json:"jail"`
	// Anchor is the pf anchor of the jail.
	Anchor string `json:"anchor"`
	// Direction is the pf direction on the host end of the jail's link: in (what the jail sends) or out (what leaves
	// the host for the jail).
	Direction string `json:"direction"`
	Verdict   string `json:"verdict"`
	// DecidedBy is the rule that decided; empty when the verdict is unknown.
	DecidedBy *FirewallTestRule `json:"decided_by,omitempty"`
	// Why says what could not be decided.
	Why string `json:"why,omitempty"`
	// Skipped are the rules the walk passed over that a reader would look for: a disabled rule the packet would have
	// met, and, when a deny rule decided, the allow rules that also match (a deny rule wins over every allow rule,
	// whatever the order of the policies).
	Skipped []FirewallTestSkipped `json:"skipped,omitempty"`
	// LoadedMatchesRendered says whether the rules loaded in pf for the anchor are the rendered ones: "true", "false",
	// or "unknown" when pf could not be asked. It compares the rule lines, not the members of the tables.
	LoadedMatchesRendered string `json:"loaded_matches_rendered,omitempty"`
}

// FirewallTestSkipped is a rule a walk passed over, and why.
type FirewallTestSkipped struct {
	Rule FirewallTestRule `json:"rule"`
	Why  string           `json:"why"`
}

// FirewallTestRule is a rule that decided a hop, with where it comes from.
type FirewallTestRule struct {
	// Stage is policy for a rule of a policy, default for the defaults of the anchor, isolation for the other
	// projects, and the names of the fixed stages (ipv6-control, antispoof, neighbour, own-addresses, closed, gateway).
	Stage string `json:"stage"`
	// Policy is the policy of a policy rule; ProjectPolicy is set when the project names it, Managed when it is the
	// policy of an app.
	Policy        string `json:"policy,omitempty"`
	ProjectPolicy bool   `json:"project_policy,omitempty"`
	Managed       bool   `json:"managed,omitempty"`
	// Rule is the number of the rule in its policy; Name and Comment are the rule's own.
	Rule    int    `json:"rule,omitempty"`
	Name    string `json:"name,omitempty"`
	Comment string `json:"comment,omitempty"`
	// PF is the rendered rule as loaded in pf.
	PF string `json:"pf"`
}
