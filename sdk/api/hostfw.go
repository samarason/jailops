package api

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Host management, module "firewall" (extension host_firewall; docs/appliance.md): the host's own packet filter.
// With the module enabled, and only then, JailOps owns /etc/pf.conf as a whole file rendered by the privileged
// helper from a HostFirewallSpec. GET /api/v1/host/firewall reads the state, PUT applies a spec. Every change is
// committed with a confirmation window (extension host_pending): it reverts itself unless it is confirmed with
// POST /api/v1/host/pending/confirm; GET /api/v1/host/pending says what waits, POST /api/v1/host/pending/revert
// undoes it at once.

// Templates of the host firewall.
const (
	// HostFirewallDefault blocks everything inbound except ssh, the console and what is always needed.
	HostFirewallDefault = "default"
	// HostFirewallOpen passes everything to the host (a host behind another firewall).
	HostFirewallOpen = "open"
	// HostFirewallCustom is the default template with the rows of Allow added.
	HostFirewallCustom = "custom-rules"
	// HostFirewallNATNone is the only NAT setting: the module renders no NAT of its own (the jails' NAT is in their
	// anchors).
	HostFirewallNATNone = "none"
)

// HostFirewallTemplates lists the templates.
var HostFirewallTemplates = []string{HostFirewallDefault, HostFirewallOpen, HostFirewallCustom}

// Limits of the firewall module and of commit confirmed.
const (
	MaxHostFirewallAllow      = 64
	MaxHostFirewallSets       = 16
	MaxHostFirewallSetMembers = 256
	MaxHostFirewallSources    = 32
	MaxHostFirewallPorts      = 16
	MaxHostFirewallComment    = 80
	MaxHostFirewallSSHPorts   = 4
	DefaultSSHPort            = 22
	// DefaultConfirmWithin is the confirmation window of a risky change, in seconds; MinConfirmWithin and
	// MaxConfirmWithin bound it.
	DefaultConfirmWithin = 120
	MinConfirmWithin     = 10
	MaxConfirmWithin     = 1800
)

// Outcomes of a pending change.
const (
	HostPendingConfirmed      = "confirmed"
	HostPendingReverted       = "reverted"         // by the revert route or command
	HostPendingTimedOut       = "timed_out"        // nobody confirmed before the deadline
	HostPendingRevertedAtBoot = "reverted_at_boot" // the host rebooted before a confirmation
	HostPendingRevertFailed   = "revert_failed"    // putting the snapshot back failed: see Detail
)

// HostFirewallSpec is the host's packet filter. It is one file rendered whole, so it is applied whole: a part left
// out takes its default, not the value applied before.
type HostFirewallSpec struct {
	// Template is default (block inbound except what is passed below), open (pass everything) or custom-rules
	// (default plus the rows of Allow). Empty means default.
	Template string `json:"template" yaml:"template"`
	// SSH is the ssh door: its ports (default 22) and who may use it (default: anywhere).
	SSH *HostFirewallSSH `json:"ssh,omitempty" yaml:"ssh,omitempty"`
	// Console is the door of the JailOps console and API: the port is the daemon's own (listen.https.address) and is
	// filled in by the daemon.
	Console *HostFirewallConsole `json:"console,omitempty" yaml:"console,omitempty"`
	// Allow are more ports to pass to the host (custom-rules only), at most 64.
	Allow []HostFirewallAllow `json:"allow,omitempty" yaml:"allow,omitempty"`
	// Sets are named lists of addresses and prefixes, used as @name in the source lists.
	Sets []HostFirewallSet `json:"sets,omitempty" yaml:"sets,omitempty"`
	// ICMP passes echo requests (ping). Neighbour discovery and the ICMP messages path MTU discovery needs are
	// passed always.
	ICMP bool `json:"icmp" yaml:"icmp"`
	// Logging logs what the final block rule drops (to pflog0).
	Logging bool `json:"logging,omitempty" yaml:"logging,omitempty"`
	// NAT is "none" (or empty): the module renders no NAT of its own.
	NAT string `json:"nat,omitempty" yaml:"nat,omitempty"`
	// ACME is the redirect of the CA's challenge port to the daemon, set by the daemon while the console's certificate
	// comes from ACME (docs/exposure.md); nil renders none.
	ACME *HostFirewallACME `json:"acme,omitempty" yaml:"acme,omitempty"`
}

// HostFirewallACME redirects the port an ACME challenge arrives on (80 for http-01, 443 for tls-alpn-01) to the
// daemon's unprivileged port on the loopback addresses. The helper renders it from these two values only.
type HostFirewallACME struct {
	Challenge ACMEChallenge `json:"challenge" yaml:"challenge"`
	// Port is the daemon's challenge listener (http-01) or its TLS listener (tls-alpn-01), 1024 to 65535.
	Port int `json:"port" yaml:"port"`
}

// HostFirewallSSH is the ssh door of the host.
type HostFirewallSSH struct {
	// Ports are the ports sshd listens on, 1 to 4 (default 22).
	Ports []int `json:"ports,omitempty" yaml:"ports,omitempty"`
	// AllowFrom are the sources (addresses, prefixes, @set); empty means anywhere.
	AllowFrom []string `json:"allow_from,omitempty" yaml:"allow_from,omitempty"`
}

// HostFirewallConsole is the door of the console and the API.
type HostFirewallConsole struct {
	// Port is the TLS port of the daemon, set by the daemon (0: it has no TLS listener, and there is no door).
	Port int `json:"port,omitempty" yaml:"port,omitempty"`
	// AllowFrom are the sources; empty means anywhere.
	AllowFrom []string `json:"allow_from,omitempty" yaml:"allow_from,omitempty"`
}

// HostFirewallAllow is one more door: a protocol, ports and sources.
type HostFirewallAllow struct {
	// Proto is tcp or udp.
	Proto string `json:"proto" yaml:"proto"`
	// Ports are "80" or "8000-8100", 1 to 16.
	Ports []string `json:"ports" yaml:"ports"`
	// From are the sources; empty means anywhere.
	From []string `json:"from,omitempty" yaml:"from,omitempty"`
	// Comment is a note of at most 80 characters, without quotes or line breaks; it becomes a comment line.
	Comment string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// HostFirewallSet is a named list of sources, rendered as a pf table.
type HostFirewallSet struct {
	// Name is a lower-case letter, then letters, digits or underscores, at most 24 characters.
	Name string `json:"name" yaml:"name"`
	// Members are addresses and prefixes, 1 to 256.
	Members []string `json:"members" yaml:"members"`
}

// HostFirewallRule is one rule of a firewall in plain words, for tables and summaries.
type HostFirewallRule struct {
	Action    string `json:"action"`    // pass or block
	Direction string `json:"direction"` // in or out
	Proto     string `json:"proto,omitempty"`
	Ports     string `json:"ports,omitempty"`
	// From is "any" or the sources, comma separated.
	From    string `json:"from,omitempty"`
	Comment string `json:"comment,omitempty"`
	// Fixed rules are part of every ruleset the module renders and cannot be turned off.
	Fixed bool `json:"fixed,omitempty"`
}

// HostFirewallStatus is how the host's firewall relates to JailOps.
type HostFirewallStatus struct {
	// Managed is true when both jailopsd.yaml and priv.conf enable the firewall module.
	Managed       bool `json:"managed"`
	ConfigEnabled bool `json:"config_enabled"`
	HelperEnabled bool `json:"helper_enabled"`
	// FileExists: /etc/pf.conf exists. FileManaged: it starts with the "# managed by jailops" header.
	FileExists  bool `json:"file_exists"`
	FileManaged bool `json:"file_managed"`
	// Drift names what changed outside JailOps since the last apply: "pf.conf", "pf_enable", "pf_rules".
	Drift []string `json:"drift,omitempty"`
	// Applied is what JailOps last applied, and AppliedAt when; nil when it never did.
	Applied   *HostFirewallSpec `json:"applied,omitempty"`
	AppliedAt *time.Time        `json:"applied_at,omitempty"`
	// PFEnabled says whether pf runs; omitted when it could not be asked.
	PFEnabled *bool `json:"pf_enabled,omitempty"`
	// Rules are the rules of Applied (or, before any apply, of the default spec) in plain words.
	Rules []HostFirewallRule `json:"rules"`
	// Warnings, such as ssh open to the world.
	Warnings []string `json:"warnings,omitempty"`
	// Pending is the change waiting for its confirmation, if any.
	Pending *HostPendingChange `json:"pending,omitempty"`
	// ConsolePort is the daemon's TLS port, which the console rule opens (0: none).
	ConsolePort int `json:"console_port"`
}

// HostFirewall is GET /api/v1/host/firewall. Spec is what was applied last, or the default spec before any apply:
// a hand-written pf.conf is not read back into fields.
type HostFirewall struct {
	Kind   Kind               `json:"kind"`
	Spec   HostFirewallSpec   `json:"spec"`
	Status HostFirewallStatus `json:"status"`
}

// HostFirewallApply is the body of PUT /api/v1/host/firewall.
type HostFirewallApply struct {
	Spec HostFirewallSpec `json:"spec"`
	// DryRun returns the diff, the rules and the actions and changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
	// ConfirmWithin is the confirmation window in seconds (default 120, 10 to 1800).
	ConfirmWithin int `json:"confirm_within,omitempty"`
	// ConfirmLockout accepts a change whose lock-out check cannot run because the caller's address is unknown (the unix
	// socket, a hub). The confirmation window still applies.
	ConfirmLockout bool `json:"confirm_lockout,omitempty"`
}

// HostPendingChange is a change that reverts itself at Deadline unless it is confirmed.
type HostPendingChange struct {
	ID       string    `json:"id"`
	Module   string    `json:"module"`
	Snapshot string    `json:"snapshot"`
	Created  time.Time `json:"created"`
	Deadline time.Time `json:"deadline"`
	// SecondsLeft is the time to the deadline when the answer was made (0 when it passed).
	SecondsLeft   int `json:"seconds_left"`
	ConfirmWithin int `json:"confirm_within"`
}

// HostPendingOutcome is how the last pending change ended.
type HostPendingOutcome struct {
	ID       string `json:"id"`
	Module   string `json:"module"`
	Snapshot string `json:"snapshot,omitempty"`
	// Outcome is confirmed, reverted, timed_out, reverted_at_boot or revert_failed.
	Outcome string    `json:"outcome"`
	Time    time.Time `json:"time"`
	Detail  string    `json:"detail,omitempty"`
}

// HostPending is GET /api/v1/host/pending and the answer of confirm and revert.
type HostPending struct {
	Pending *HostPendingChange  `json:"pending,omitempty"`
	Last    *HostPendingOutcome `json:"last,omitempty"`
}

// HostPendingAction is the body of POST /api/v1/host/pending/confirm and /revert. ID, when given, must name the
// pending change (so a confirmation meant for one change never confirms another).
type HostPendingAction struct {
	ID string `json:"id,omitempty"`
}

// MaxHostFWSetName is the longest name of an address set of the host firewall: its pf table is "jo_hf_" and the name.
const MaxHostFWSetName = 24

var (
	reHostPendingID = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// ValidHostPendingID accepts an empty id (any) or the form the helper makes.
func ValidHostPendingID(id string) error {
	if id == "" || reHostPendingID.MatchString(id) {
		return nil
	}
	return Errorf(CodeInvalid, "invalid pending change id %q", id).WithHint("use the id GET /api/v1/host/pending shows")
}

// ConfirmWindow checks a confirmation window in seconds; 0 is the default.
func ConfirmWindow(sec int) (int, error) {
	if sec == 0 {
		return DefaultConfirmWithin, nil
	}
	if sec < MinConfirmWithin || sec > MaxConfirmWithin {
		return 0, Errorf(CodeInvalid, "the confirmation window is %d to %d seconds, not %d", MinConfirmWithin, MaxConfirmWithin, sec)
	}
	return sec, nil
}

// hostSource is one parsed source: a prefix, or a set.
type hostSource struct {
	prefix netip.Prefix
	set    string
}

// parseHostSource accepts an address, a prefix or @set. Zones, mapped addresses and host bits are refused.
func parseHostSource(s string) (hostSource, error) {
	if name, ok := strings.CutPrefix(s, "@"); ok {
		if !IsName(name, MaxHostFWSetName) {
			return hostSource{}, Errorf(CodeInvalid, "%q is not a set name", s)
		}
		return hostSource{set: name}, nil
	}
	p, err := parseHostPrefix(s)
	return hostSource{prefix: p}, err
}

func parseHostPrefix(s string) (netip.Prefix, error) {
	bad := Errorf(CodeInvalid, "%q is not an address or a prefix", s).WithHint("an address such as 192.0.2.7 or 2001:db8::7, a prefix such as 192.0.2.0/24 or 2001:db8::/48, or @set")
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return netip.Prefix{}, bad
		}
		if p.Masked() != p {
			return netip.Prefix{}, Errorf(CodeInvalid, "prefix %s has host bits set (did you mean %s?)", s, p.Masked())
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() {
		return netip.Prefix{}, bad
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// canonSource is the canonical spelling: an address without its length, a masked prefix, or @set.
func canonSource(s string) string {
	src, err := parseHostSource(s)
	switch {
	case err != nil:
		return s
	case src.set != "":
		return "@" + src.set
	case src.prefix.IsSingleIP():
		return src.prefix.Addr().String()
	default:
		return src.prefix.String()
	}
}

// validSources checks one source list against the sets.
func (s HostFirewallSpec) validSources(what string, list []string) error {
	if len(list) > MaxHostFirewallSources {
		return Errorf(CodeInvalid, "%s: at most %d sources, not %d", what, MaxHostFirewallSources, len(list))
	}
	var seen []string
	for _, v := range list {
		src, err := parseHostSource(v)
		if err != nil {
			return Errorf(CodeInvalid, "%s: %s", what, err.(*Error).Message).WithHint(err.(*Error).Hint)
		}
		if src.set != "" && !slices.ContainsFunc(s.Sets, func(x HostFirewallSet) bool { return x.Name == src.set }) {
			return Errorf(CodeInvalid, "%s: set @%s is not defined", what, src.set).WithHint("define it under sets")
		}
		c := canonSource(v)
		if slices.Contains(seen, c) {
			return Errorf(CodeInvalid, "%s: %s is listed twice", what, v)
		}
		seen = append(seen, c)
	}
	return nil
}

// parsePortRange accepts "N" or "N-M" with 1 <= N < M <= 65535.
func parsePortRange(p string) (lo, hi int, err error) {
	bad := Errorf(CodeInvalid, "port %q is not a port (1-65535) or a range such as 8000-8100", p)
	a, b, isRange := strings.Cut(p, "-")
	lo, e1 := strconv.Atoi(a)
	if e1 != nil || a == "" || a[0] == '+' || lo < 1 || lo > 65535 || strconv.Itoa(lo) != a {
		return 0, 0, bad
	}
	hi = lo
	if isRange {
		h, e2 := strconv.Atoi(b)
		if e2 != nil || strconv.Itoa(h) != b || h <= lo || h > 65535 {
			return 0, 0, bad
		}
		hi = h
	}
	return lo, hi, nil
}

// validComment refuses what could end the comment line or confuse a reader: line breaks, other control
// characters, quotes and backslashes.
func validComment(c string) error {
	if len([]rune(c)) > MaxHostFirewallComment {
		return Errorf(CodeInvalid, "a comment is at most %d characters", MaxHostFirewallComment)
	}
	for _, r := range c {
		if unicode.IsControl(r) || r == '"' || r == '\'' || r == '\\' || r == '`' || !unicode.IsPrint(r) {
			return Errorf(CodeInvalid, "comment %q has a character that is not allowed (line breaks, quotes and backslashes are not)", c)
		}
	}
	return nil
}

// Validate checks the spec. It is run by the client, the daemon and again by the privileged helper.
func (s HostFirewallSpec) Validate() error {
	t := s.Template
	if t == "" {
		t = HostFirewallDefault
	}
	if !slices.Contains(HostFirewallTemplates, t) {
		return Errorf(CodeInvalid, "template %q is not one of %s", s.Template, strings.Join(HostFirewallTemplates, ", "))
	}
	if s.NAT != "" && s.NAT != HostFirewallNATNone {
		return Errorf(CodeUnsupported, "nat %q is not supported: the host firewall renders no NAT of its own", s.NAT).
			WithHint("leave nat out or set it to none; the jails' NAT comes from their networks")
	}
	if len(s.Sets) > MaxHostFirewallSets {
		return Errorf(CodeInvalid, "at most %d sets, not %d", MaxHostFirewallSets, len(s.Sets))
	}
	var names []string
	for _, set := range s.Sets {
		if !IsName(set.Name, MaxHostFWSetName) {
			return Errorf(CodeInvalid, "set name %q is not valid", set.Name).WithHint("lower case letters, digits and hyphens, starting with a letter, at most 24 characters")
		}
		if slices.Contains(names, set.Name) {
			return Errorf(CodeInvalid, "set %s is defined twice", set.Name)
		}
		names = append(names, set.Name)
		if len(set.Members) == 0 || len(set.Members) > MaxHostFirewallSetMembers {
			return Errorf(CodeInvalid, "set %s needs 1 to %d members, not %d", set.Name, MaxHostFirewallSetMembers, len(set.Members))
		}
		var seen []netip.Prefix
		for _, m := range set.Members {
			p, err := parseHostPrefix(m)
			if err != nil {
				return Errorf(CodeInvalid, "set %s: %s", set.Name, err.(*Error).Message)
			}
			if slices.Contains(seen, p) {
				return Errorf(CodeInvalid, "set %s: %s is listed twice", set.Name, m)
			}
			seen = append(seen, p)
		}
	}
	if ssh := s.SSH; ssh != nil {
		if len(ssh.Ports) > MaxHostFirewallSSHPorts {
			return Errorf(CodeInvalid, "ssh: at most %d ports, not %d", MaxHostFirewallSSHPorts, len(ssh.Ports))
		}
		var seen []int
		for _, p := range ssh.Ports {
			if p < 1 || p > 65535 {
				return Errorf(CodeInvalid, "ssh port %d is not a port (1-65535)", p)
			}
			if slices.Contains(seen, p) {
				return Errorf(CodeInvalid, "ssh port %d is listed twice", p)
			}
			seen = append(seen, p)
		}
		if err := s.validSources("ssh allow_from", ssh.AllowFrom); err != nil {
			return err
		}
	}
	if c := s.Console; c != nil {
		if c.Port < 0 || c.Port > 65535 {
			return Errorf(CodeInvalid, "console port %d is not a port", c.Port)
		}
		if err := s.validSources("console allow_from", c.AllowFrom); err != nil {
			return err
		}
	}
	if len(s.Allow) > 0 && t != HostFirewallCustom {
		return Errorf(CodeInvalid, "allow rows need the template custom-rules, not %s", t).WithHint("set template to custom-rules, or leave allow out")
	}
	if len(s.Allow) > MaxHostFirewallAllow {
		return Errorf(CodeInvalid, "at most %d allow rows, not %d", MaxHostFirewallAllow, len(s.Allow))
	}
	for i, a := range s.Allow {
		what := fmt.Sprintf("allow row %d", i+1)
		if a.Proto != "tcp" && a.Proto != "udp" {
			return Errorf(CodeInvalid, "%s: proto %q is not tcp or udp", what, a.Proto)
		}
		if len(a.Ports) == 0 || len(a.Ports) > MaxHostFirewallPorts {
			return Errorf(CodeInvalid, "%s: 1 to %d ports, not %d", what, MaxHostFirewallPorts, len(a.Ports))
		}
		var seen []string
		for _, p := range a.Ports {
			if _, _, err := parsePortRange(p); err != nil {
				return Errorf(CodeInvalid, "%s: %s", what, err.(*Error).Message)
			}
			if slices.Contains(seen, p) {
				return Errorf(CodeInvalid, "%s: port %s is listed twice", what, p)
			}
			seen = append(seen, p)
		}
		if err := s.validSources(what+" from", a.From); err != nil {
			return err
		}
		if err := validComment(a.Comment); err != nil {
			return Errorf(CodeInvalid, "%s: %s", what, err.(*Error).Message)
		}
	}
	if err := s.validACME(); err != nil {
		return err
	}
	if t == HostFirewallOpen && ((s.SSH != nil && len(s.SSH.AllowFrom) > 0) || (s.Console != nil && len(s.Console.AllowFrom) > 0)) {
		return Errorf(CodeInvalid, "the open template passes everything: ssh and console sources would have no effect").
			WithHint("use the default or custom-rules template to narrow ssh and the console")
	}
	return nil
}

// validACME checks the redirect of an ACME challenge: a known challenge, an unprivileged port that is no other door,
// and for tls-alpn-01 the console's own port.
func (s HostFirewallSpec) validACME() error {
	a := s.ACME
	if a == nil {
		return nil
	}
	if a.Challenge != ACMEHTTP01 && a.Challenge != ACMETLSALPN01 {
		return Errorf(CodeInvalid, "acme challenge %q is not http-01 or tls-alpn-01", a.Challenge)
	}
	if a.Port < 1024 || a.Port > 65535 {
		return Errorf(CodeInvalid, "acme port %d is not an unprivileged port (1024-65535)", a.Port)
	}
	console := 0
	if s.Console != nil {
		console = s.Console.Port
	}
	if a.Challenge == ACMETLSALPN01 && a.Port != console {
		return Errorf(CodeInvalid, "tls-alpn-01 redirects port 443 to the console's port (%d), not to %d", console, a.Port)
	}
	if a.Challenge == ACMEHTTP01 && (a.Port == console || (s.SSH != nil && slices.Contains(s.SSH.Ports, a.Port))) {
		return Errorf(CodeInvalid, "acme port %d is already the port of ssh or the console", a.Port)
	}
	return nil
}

// Canonical returns the spec with its defaults filled in (template default, ssh port 22, nat none) and every
// source in its canonical spelling. Call it after Validate.
func (s HostFirewallSpec) Canonical() HostFirewallSpec {
	out := HostFirewallSpec{Template: s.Template, ICMP: s.ICMP, Logging: s.Logging, NAT: HostFirewallNATNone}
	if out.Template == "" {
		out.Template = HostFirewallDefault
	}
	canon := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		c := make([]string, len(l))
		for i, v := range l {
			c[i] = canonSource(v)
		}
		return c
	}
	ssh := HostFirewallSSH{Ports: []int{DefaultSSHPort}}
	if s.SSH != nil {
		if len(s.SSH.Ports) > 0 {
			ssh.Ports = slices.Clone(s.SSH.Ports)
		}
		ssh.AllowFrom = canon(s.SSH.AllowFrom)
	}
	out.SSH = &ssh
	con := HostFirewallConsole{}
	if s.Console != nil {
		con = HostFirewallConsole{Port: s.Console.Port, AllowFrom: canon(s.Console.AllowFrom)}
	}
	out.Console = &con
	if s.ACME != nil {
		a := *s.ACME
		out.ACME = &a
	}
	for _, a := range s.Allow {
		out.Allow = append(out.Allow, HostFirewallAllow{Proto: a.Proto, Ports: slices.Clone(a.Ports), From: canon(a.From), Comment: strings.TrimSpace(a.Comment)})
	}
	for _, set := range s.Sets {
		m := make([]string, len(set.Members))
		for i, v := range set.Members {
			m[i] = canonSource(v)
		}
		out.Sets = append(out.Sets, HostFirewallSet{Name: set.Name, Members: m})
	}
	return out
}

// DefaultHostFirewall is the spec an apply without changes installs: the default template, ssh on 22 and the
// console from anywhere, ping passed.
func DefaultHostFirewall(consolePort int) HostFirewallSpec {
	return HostFirewallSpec{Template: HostFirewallDefault, ICMP: true, NAT: HostFirewallNATNone,
		SSH: &HostFirewallSSH{Ports: []int{DefaultSSHPort}}, Console: &HostFirewallConsole{Port: consolePort}}
}

// matches reports whether addr is one of the sources (empty: anywhere).
func (s HostFirewallSpec) matches(list []string, addr netip.Addr) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		src, err := parseHostSource(v)
		if err != nil {
			continue
		}
		if src.set == "" {
			if src.prefix.Contains(addr) {
				return true
			}
			continue
		}
		for _, set := range s.Sets {
			if set.Name != src.set {
				continue
			}
			for _, m := range set.Members {
				if p, err := parseHostPrefix(m); err == nil && p.Contains(addr) {
					return true
				}
			}
		}
	}
	return false
}

func portIn(ports []string, port int) bool {
	for _, p := range ports {
		if lo, hi, err := parsePortRange(p); err == nil && port >= lo && port <= hi {
			return true
		}
	}
	return false
}

// Admits reports whether the rules of the spec let a TCP connection from addr reach port on the host. It is what
// the lock-out check asks; call it on a canonical spec.
func (s HostFirewallSpec) Admits(addr netip.Addr, port int) bool {
	addr = addr.Unmap()
	if s.Template == HostFirewallOpen {
		return true
	}
	if s.SSH != nil && slices.Contains(s.SSH.Ports, port) && s.matches(s.SSH.AllowFrom, addr) {
		return true
	}
	if c := s.Console; c != nil && c.Port != 0 && c.Port == port && s.matches(c.AllowFrom, addr) {
		return true
	}
	if s.Template == HostFirewallCustom {
		for _, a := range s.Allow {
			if a.Proto == "tcp" && portIn(a.Ports, port) && s.matches(a.From, addr) {
				return true
			}
		}
	}
	return false
}

// AdmitsAdmin reports whether addr keeps a way in: an ssh port or the console port. It is false only when both are
// closed to it.
func (s HostFirewallSpec) AdmitsAdmin(addr netip.Addr) bool {
	if s.SSH != nil {
		for _, p := range s.SSH.Ports {
			if s.Admits(addr, p) {
				return true
			}
		}
	}
	return s.Console != nil && s.Console.Port != 0 && s.Admits(addr, s.Console.Port)
}

// worldOpen reports whether a source list admits every address of a family: it is empty, or it holds 0.0.0.0/0 or
// ::/0 itself or through a set.
func (s HostFirewallSpec) worldOpen(list []string) bool {
	if len(list) == 0 {
		return true
	}
	zero := func(v string) bool { p, err := parseHostPrefix(v); return err == nil && p.Bits() == 0 }
	for _, v := range list {
		if zero(v) {
			return true
		}
		if name, ok := strings.CutPrefix(v, "@"); ok {
			for _, set := range s.Sets {
				if set.Name == name && slices.ContainsFunc(set.Members, zero) {
					return true
				}
			}
		}
	}
	return false
}

// SSHOpenToWorld reports whether ssh is reachable from any address (the console warns about it).
func (s HostFirewallSpec) SSHOpenToWorld() bool {
	return s.Template == HostFirewallOpen || s.SSH == nil || s.worldOpen(s.SSH.AllowFrom)
}

// Warnings are the remarks about a canonical spec that are not errors.
func (s HostFirewallSpec) Warnings() []string {
	var w []string
	if s.SSHOpenToWorld() {
		w = append(w, "ssh is open to the world: narrow ssh allow_from to the addresses you administer from")
	}
	if s.Template == HostFirewallOpen {
		w = append(w, "the open template passes everything to the host; use it only behind another firewall")
	}
	if s.ACME != nil && s.ACME.Challenge == ACMETLSALPN01 && s.Template != HostFirewallOpen {
		w = append(w, "port 443 leads to the console from any address (the CA's addresses are not known): console allow_from does not narrow it")
	}
	return w
}

func fromWords(l []string) string {
	if len(l) == 0 {
		return "any"
	}
	return strings.Join(l, ", ")
}

func intsWords(p []int) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ", ")
}

// Rules lists the rules a canonical spec renders, in order, in plain words.
func (s HostFirewallSpec) Rules() []HostFirewallRule {
	fixed := func(action, dir, proto, ports, comment string) HostFirewallRule {
		return HostFirewallRule{Action: action, Direction: dir, Proto: proto, Ports: ports, From: "any", Comment: comment, Fixed: true}
	}
	out := []HostFirewallRule{
		fixed("pass", "in", "", "", "loopback (lo0 is not filtered)"),
		fixed("pass", "in", "", "", "the jails' own anchors (jailops/*) come first"),
	}
	if s.Template == HostFirewallOpen {
		out = append(out, fixed("pass", "in", "", "", "everything (open template)"))
	} else {
		block := fixed("block", "in", "", "", "everything not passed below")
		if s.Logging {
			block.Comment += ", logged"
		}
		out = append(out, block)
	}
	out = append(out,
		fixed("pass", "out", "", "", "everything the host sends, and the replies to it"),
		fixed("pass", "in", "icmp6", "", "neighbour discovery and router advertisements"),
		fixed("pass", "in", "icmp, icmp6", "", "path MTU discovery and ICMP errors"),
	)
	if a := s.ACME; a != nil {
		out = append(out, HostFirewallRule{Action: "pass", Direction: "in", Proto: "tcp", Ports: strconv.Itoa(ACMEChallengePort(a.Challenge)), From: "any",
			Comment: fmt.Sprintf("ACME %s challenges, redirected to the daemon's port %d", a.Challenge, a.Port)})
	}
	if s.Template == HostFirewallOpen {
		return out
	}
	if s.SSH != nil {
		out = append(out, HostFirewallRule{Action: "pass", Direction: "in", Proto: "tcp", Ports: intsWords(s.SSH.Ports), From: fromWords(s.SSH.AllowFrom), Comment: "ssh"})
	}
	if c := s.Console; c != nil && c.Port != 0 {
		out = append(out, HostFirewallRule{Action: "pass", Direction: "in", Proto: "tcp", Ports: strconv.Itoa(c.Port), From: fromWords(c.AllowFrom), Comment: "JailOps console and API"})
	}
	if s.Template == HostFirewallCustom {
		for _, a := range s.Allow {
			out = append(out, HostFirewallRule{Action: "pass", Direction: "in", Proto: a.Proto, Ports: strings.Join(a.Ports, ", "), From: fromWords(a.From), Comment: a.Comment})
		}
	}
	if s.ICMP {
		out = append(out, HostFirewallRule{Action: "pass", Direction: "in", Proto: "icmp, icmp6", From: "any", Comment: "ping (echo requests)"})
	}
	return out
}
