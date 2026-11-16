// Package fwsim answers "would this packet pass the anchor of a jail?" by walking the very list of rules the
// renderer loads into pf (render.Anchor.Rules). pf takes the first matching rule and every rule JailOps writes is
// quick, so the first rule in the list that matches decides. There is no second implementation of the policies: what
// is walked here is what was rendered from them.
//
// The answer is for a new connection. It says Unknown, and why, wherever it cannot decide: a raw PF fragment, an ICMP
// type the packet does not name, a packet no rule of the anchor matches (the host's own rules decide then).
package fwsim

import (
	"fmt"
	"net/netip"

	"jailops.net/jailops/internal/render"
)

// Verdict is what happens to a packet.
type Verdict string

const (
	Pass    Verdict = "pass"
	Block   Verdict = "block"
	Unknown Verdict = "unknown"
)

// Packet is the first packet of a connection.
type Packet struct {
	// Family is "inet" or "inet6".
	Family string
	// Proto is "tcp", "udp", "icmp" or "icmp6".
	Proto    string
	Src, Dst netip.Addr
	// DstPort is the destination port of tcp and udp; zero for the others.
	DstPort int
	// ICMPType is the ICMP type as pf names it ("echoreq", "neighbrsol", ...), for icmp and icmp6.
	ICMPType string
}

// Hook is the place in the host's pf where a packet meets an anchor: the pf direction on the host end of the jail's
// link. "in" is what the jail sends, "out" what leaves the host for the jail.
type Hook struct {
	Dir string // "in" or "out"
}

// Skip is a rule that a walk passed or did not use, and why: a disabled rule that would have matched, or an allow rule
// that matched but lost to a deny rule.
type Skip struct {
	Rule *render.Rule
	Why  string
}

// HopResult is what one anchor does with a packet at one hook.
type HopResult struct {
	Verdict Verdict
	// Rule is the rule that decided; nil when the verdict is Unknown.
	Rule *render.Rule
	// Text is the rendered PF text of the rule.
	Text string
	// Why says what could not be decided, when the verdict is Unknown.
	Why string
	// Skipped are the disabled rules that the packet would have met (by interface, direction, protocol and port; their
	// addresses are not resolved), and, when a deny rule decided, the allow rules of the policies that also match: a
	// deny rule wins over every allow rule, whatever the order of the policies.
	Skipped []Skip
}

// Evaluate walks the rules of an anchor for a packet at a hook and returns what the first matching rule says.
func Evaluate(a *render.Anchor, p Packet, h Hook) HopResult {
	var skipped []Skip
	for i := range a.Rules {
		r := &a.Rules[i]
		if r.Kind == render.RuleDisabled {
			if r.Dir == h.Dir && protoPortMatch(r, p) {
				skipped = append(skipped, Skip{Rule: r, Why: "disabled"})
			}
			continue
		}
		if r.Kind == render.RuleRaw {
			// the raw fragment stands between the typed rules and the defaults: whatever it says, it comes first
			return HopResult{Verdict: Unknown, Skipped: skipped, Why: fmt.Sprintf("the raw PF fragment of policy %s comes before the decision, and its rules are not evaluated", r.Origin.Policy)}
		}
		if r.Dir != h.Dir {
			continue
		}
		m, unknown := matches(r, p)
		if unknown {
			return HopResult{Verdict: Unknown, Skipped: skipped, Why: fmt.Sprintf("rule %q filters on ICMP types and the packet does not say which type it is (give an ICMP type)", a.Lines[r.Line])}
		}
		if !m {
			continue
		}
		v := Pass
		if r.Action == "block" {
			v = Block
		}
		res := HopResult{Verdict: v, Rule: r, Text: a.Lines[r.Line], Skipped: skipped}
		for j := i + 1; j < len(a.Rules); j++ {
			o := &a.Rules[j]
			if o.Dir != h.Dir {
				continue
			}
			switch {
			case o.Kind == render.RuleDisabled && protoPortMatch(o, p):
				// a disabled rule after the decision: the reader may be looking for it too
				res.Skipped = append(res.Skipped, Skip{Rule: o, Why: "disabled"})
			case v == Block && r.Origin.Stage == render.StagePolicy && o.Kind == render.RuleFilter && o.Action == "pass" && o.Origin.Stage == render.StagePolicy:
				// every deny rule of the policies comes before every allow rule: say which allow rules it won over
				if m, unknown := matches(o, p); m && !unknown {
					res.Skipped = append(res.Skipped, Skip{Rule: o, Why: "an allow rule that also matches: a deny rule wins over every allow rule, whatever the order of the policies"})
				}
			}
		}
		return res
	}
	return HopResult{Verdict: Unknown, Skipped: skipped, Why: "no rule of this anchor matches the packet: the rules of the host decide"}
}

// protoPortMatch says whether the protocol and the port of a packet fit a rule; the addresses are not looked at.
func protoPortMatch(r *render.Rule, p Packet) bool {
	if r.Family != "" && r.Family != p.Family {
		return false
	}
	if r.Proto != "" && r.Proto != p.Proto {
		return false
	}
	if len(r.Ports) > 0 && (p.Proto != "tcp" && p.Proto != "udp" || !inRanges(r.Ports, p.DstPort)) {
		return false
	}
	return true
}

// matches says whether a rule matches a packet. unknown is true when the rule filters on ICMP types and the packet
// names none.
func matches(r *render.Rule, p Packet) (match, unknown bool) {
	src, dst := p.Src.Unmap(), p.Dst.Unmap()
	if !protoPortMatch(r, p) || !r.From.Contains(src) || !r.To.Contains(dst) {
		return false, false
	}
	if len(r.ICMPTypes) > 0 {
		if p.ICMPType == "" {
			return false, true
		}
		if !hasType(r.ICMPTypes, p.ICMPType) {
			return false, false
		}
	}
	return true, false
}

func inRanges(rs []render.PortRange, port int) bool {
	for _, r := range rs {
		if port >= int(r.Lo) && port <= int(r.Hi) {
			return true
		}
	}
	return false
}

func hasType(types []string, t string) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}
