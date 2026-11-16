package render

import (
	"fmt"
	"net/netip"
	"strings"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Op is the kind of a plan step.
type Op string

// Plan operations. Names follow the ifconfig, route and pfctl concepts they
// map to; the executor lives in internal/sys.
const (
	OpRequireSysctl  Op = "sysctl.require"
	OpSetDescription Op = "iface.description"
	OpSetMTU         Op = "iface.mtu"
	OpSetMAC         Op = "iface.mac"
	OpAddAddr        Op = "iface.addr.add"
	OpRemoveAddr     Op = "iface.addr.remove"
	OpIfaceUp        Op = "iface.up"
	OpIfaceDown      Op = "iface.down"
	OpEpairCreate    Op = "epair.create"
	OpEpairDestroy   Op = "epair.destroy"
	OpAddHostRoute   Op = "route.host.add"
	OpDelHostRoute   Op = "route.host.delete"
	OpAddRejectRoute Op = "route.reject.add"
	OpDelRejectRoute Op = "route.reject.delete"
	OpNDPProxyAdd    Op = "ndproxy.add"
	OpNDPProxyDel    Op = "ndproxy.delete"
	OpLoadAnchor     Op = "pf.anchor.load"
	OpFlushAnchor    Op = "pf.anchor.flush"
	OpAddGatewayLink Op = "route.gateway.add"
	OpDelGatewayLink Op = "route.gateway.delete"
	OpAddDefaultRte  Op = "route.default.add"
	OpDelDefaultRte  Op = "route.default.delete"
)

// Phase says where a step runs.
type Phase string

const (
	// PhaseHost steps run in the host network stack.
	PhaseHost Phase = "host"
	// PhaseJail steps run inside the jail's vnet after the jail started.
	PhaseJail Phase = "jail"
)

// Step is one declarative action. It carries no state about the system.
type Step struct {
	Op    Op
	Phase Phase
	// Iface is the interface the step acts on (an epair end, the uplink).
	Iface string
	// Arg is the main argument: an address with prefix, a description, a
	// MAC, a member name, an anchor name or a "sysctl=value" pair.
	Arg string
	// Arg2 is a second argument: the jail-side name of an epair.
	Arg2 string
	// Inverse undoes the step. It is nil when the step is undone implicitly
	// by the inverse of an earlier step (for example, destroying an epair
	// removes its MAC) or cannot be undone (sysctl requirements).
	Inverse *Step
	Note    string
}

func step(op Op, iface, arg string) Step {
	return Step{Op: op, Phase: PhaseHost, Iface: iface, Arg: arg}
}

func with(s Step, inv Step) Step { s.Inverse = &inv; return s }

// Rollback returns the inverses of steps, in reverse order, skipping steps
// without one.
func Rollback(steps []Step) []Step {
	var out []Step
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Inverse != nil {
			out = append(out, *steps[i].Inverse)
		}
	}
	return out
}

// Describe returns a human readable approximation of the command a step
// maps to. It is documentation and golden-test output, not an argv.
// UNVERIFIED: syntax on FreeBSD 15.
func (s Step) Describe() string {
	pre := ""
	if s.Phase == PhaseJail {
		return s.describeJail()
	}
	switch s.Op {
	case OpRequireSysctl:
		return pre + "require sysctl " + s.Arg
	case OpSetDescription:
		if s.Arg == "" {
			return pre + "ifconfig " + s.Iface + " -description"
		}
		return pre + "ifconfig " + s.Iface + " description " + s.Arg
	case OpSetMTU:
		return pre + "ifconfig " + s.Iface + " mtu " + s.Arg
	case OpSetMAC:
		return pre + "ifconfig " + s.Iface + " ether " + s.Arg
	case OpAddAddr:
		return pre + "ifconfig " + s.Iface + " " + ifFamily(s.Arg) + " " + s.Arg + " alias"
	case OpRemoveAddr:
		return pre + "ifconfig " + s.Iface + " " + ifFamily(s.Arg) + " " + s.Arg + " -alias"
	case OpIfaceUp:
		return pre + "ifconfig " + s.Iface + " up"
	case OpIfaceDown:
		return pre + "ifconfig " + s.Iface + " down"
	case OpEpairCreate:
		return pre + "ifconfig epair create; rename ends to " + s.Iface + " and " + s.Arg
	case OpEpairDestroy:
		return pre + "ifconfig " + s.Iface + " destroy"
	case OpAddHostRoute:
		return pre + "route add " + afFlag(s.Arg) + " " + s.Arg + " -interface " + s.Iface
	case OpDelHostRoute:
		return pre + "route delete " + afFlag(s.Arg) + " " + s.Arg
	case OpAddRejectRoute:
		return pre + "route add " + afFlag(s.Arg) + " " + s.Arg + " " + loopbackOf(s.Arg) + " -reject"
	case OpDelRejectRoute:
		return pre + "route delete " + afFlag(s.Arg) + " " + s.Arg + " " + loopbackOf(s.Arg) + " -reject"
	case OpNDPProxyAdd:
		return pre + "ndproxy answer " + s.Arg + " on " + s.Iface
	case OpNDPProxyDel:
		return pre + "ndproxy withdraw " + s.Arg + " on " + s.Iface
	case OpLoadAnchor:
		return pre + "pfctl -a " + s.Arg + " -f <rendered>"
	case OpFlushAnchor:
		return pre + "pfctl -a " + s.Arg + " -F all"
	case OpAddGatewayLink:
		return pre + "route add -host " + s.Arg + " -interface " + s.Iface
	case OpDelGatewayLink:
		return pre + "route delete -host " + s.Arg
	case OpAddDefaultRte:
		return pre + "route add " + afFlag(s.Arg) + " default " + s.Arg
	case OpDelDefaultRte:
		return pre + "route delete " + afFlag(s.Arg) + " default"
	}
	return string(s.Op)
}

func ifFamily(arg string) string {
	if strings.Contains(arg, ":") {
		return "inet6"
	}
	return "inet"
}

func loopbackOf(arg string) string {
	if strings.Contains(arg, ":") {
		return "::1"
	}
	return "127.0.0.1"
}

func afFlag(arg string) string {
	if strings.Contains(arg, ":") {
		return "-inet6"
	}
	return "-inet"
}

// DescribePlan renders a plan, one line per step, for golden tests and logs.
func DescribePlan(steps []Step) string {
	var b strings.Builder
	for i, s := range steps {
		fmt.Fprintf(&b, "%02d %s\n", i+1, s.Describe())
	}
	return b.String()
}

// NetworkInput is the input of NetworkPlan.
type NetworkInput struct {
	// ID is the network's UUID.
	ID   string
	Name string
	Spec api.NetworkSpec
}

// NetworkPlan returns the ordered steps of a network: what the host needs before any jail attaches to it. A network
// has no interface of its own (every jail's attachment is a routed link, see AttachPlan): the plan asserts that the
// host forwards, rejects the addresses of the network's subnet that no jail has (so that a packet for an unallocated
// address is answered with an error and never sent out of the uplink to come back), and loads the network's anchor
// (the translation rule). It does not look at the system.
func NetworkPlan(in NetworkInput) ([]Step, error) {
	if err := validate.Name("network", in.Name); err != nil {
		return nil, err
	}
	if err := validate.NetworkSpec(in.Spec); err != nil {
		return nil, err
	}
	if err := validateID(in.ID); err != nil {
		return nil, err
	}
	s := in.Spec
	var out []Step
	req := func(kv, note string) {
		st := step(OpRequireSysctl, "", kv)
		st.Note = note
		out = append(out, st)
	}
	v6 := s.IPv6 != nil && s.IPv6.Mode != api.IPv6None
	if s.IPv4 != nil {
		req("net.inet.ip.forwarding=1", "jails reach the uplink and each other through the host")
	}
	if v6 {
		req("net.inet6.ip6.forwarding=1", "jails reach the uplink and each other through the host")
	}
	reject := func(prefix string) {
		p, _ := netip.ParsePrefix(prefix)
		a := p.Masked().String()
		out = append(out, with(step(OpAddRejectRoute, "", a), step(OpDelRejectRoute, "", a)))
	}
	if s.IPv4 != nil {
		reject(s.IPv4.Subnet)
	}
	if v6 && s.IPv6.Mode == api.IPv6Routed {
		// in proxy mode the subnet is on-link on the uplink: an address nobody has is simply not answered there
		reject(s.IPv6.Subnet)
	}
	a := NetAnchor(in.Name)
	out = append(out, with(step(OpLoadAnchor, "", a), step(OpFlushAnchor, "", a)))
	return out, nil
}

func validateID(id string) error {
	if id == "" || len(id) > 64 {
		return validate.Invalid("id", "id must be 1-64 characters")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return validate.Invalid("id", "id %q has unsupported characters", id)
		}
	}
	return nil
}

// AttachInput is the input of AttachPlan: one attachment of one jail.
type AttachInput struct {
	JailID   string // used for epair names
	JailUUID string // used to derive MAC addresses
	// Project, Jail and Network name the attachment in the interface descriptions.
	Project, Jail, Network string
	Index                  int // attachment index within the jail
	// MAC of the jail end; derived from JailUUID when empty.
	MAC string
	MTU int
	// IPv4 and IPv6 are the jail's address with the prefix length it
	// configures (ipam.GuestPrefixLen6 for IPv6); zero means none.
	IPv4, IPv6 netip.Prefix
	Gateway4   netip.Addr
	Gateway6   netip.Addr
	IPv6Mode   api.IPv6Mode
	Uplink     string
	// HostConfigured asks the plan to configure addresses and default
	// routes from the host after the jail started (Linux jails; FreeBSD
	// jails configure themselves through rc.conf). UNVERIFIED: whether
	// addresses set on the epair survive its move into the vnet.
	HostConfigured bool
}

// AttachPlan returns the steps that give one jail interface its routed link: an epair whose host end carries the
// gateway addresses of the network (the same /32 and fe80::1 on every jail's host end, each on its own link) and a host
// route to each of the jail's addresses through that end. Host-phase steps run before the jail starts (the jail-side
// end is moved into the vnet by jail.conf's vnet.interface); jail-phase steps run after.
func AttachPlan(in AttachInput) ([]Step, error) {
	if err := validateID(in.JailID); err != nil {
		return nil, err
	}
	host, jail, err := ipam.EpairNames(in.JailID, in.Index)
	if err != nil {
		return nil, err
	}
	hmac, err := ipam.DeriveMACN(in.JailUUID, in.Index, true)
	if err != nil {
		return nil, err
	}
	jmac := in.MAC
	if jmac == "" {
		if jmac, err = ipam.DeriveMACN(in.JailUUID, in.Index, false); err != nil {
			return nil, err
		}
	} else if err := validate.MAC("mac", jmac); err != nil {
		return nil, err
	}
	if in.MTU != 0 && (in.MTU < 576 || in.MTU > 9216) {
		return nil, validate.Invalid("mtu", "mtu out of range")
	}
	if in.IPv4.IsValid() && !in.IPv4.Addr().Is4() || in.IPv6.IsValid() && !in.IPv6.Addr().Is6() {
		return nil, validate.Invalid("address", "address family mismatch")
	}
	if in.Gateway4.IsValid() && !in.Gateway4.Is4() || in.Gateway6.IsValid() && !in.Gateway6.Is6() {
		return nil, validate.Invalid("gateway", "gateway family mismatch")
	}
	proxy := in.IPv6Mode == api.IPv6Proxy && in.IPv6.IsValid()
	if proxy {
		if err := validate.IfName("uplink", in.Uplink); err != nil {
			return nil, err
		}
	}

	var out []Step
	ep := step(OpEpairCreate, host, jail)
	ep.Arg2 = jail
	out = append(out, with(ep, step(OpEpairDestroy, host, "")))
	out = append(out, step(OpSetMAC, host, hmac), step(OpSetMAC, jail, jmac))
	out = append(out, with(step(OpSetDescription, host, JailIfaceDesc(in.Project, in.Jail, in.Network, true)), step(OpSetDescription, host, "")))
	if in.MTU != 0 {
		out = append(out, step(OpSetMTU, host, fmt.Sprint(in.MTU)), step(OpSetMTU, jail, fmt.Sprint(in.MTU)))
	}
	// The host's addresses on the jail's link: the network's gateway as a /32 (the jail reaches it by a host route
	// to it on its own link) and the link-local gateway fe80::1. The same addresses are on every jail's host end;
	// each end is a link of its own, so no two jails ever share a segment.
	if in.IPv4.IsValid() && in.Gateway4.IsValid() {
		a := netip.PrefixFrom(in.Gateway4, 32).String()
		out = append(out, with(step(OpAddAddr, host, a), step(OpRemoveAddr, host, a)))
	}
	if in.IPv6.IsValid() {
		a := netip.PrefixFrom(ipam.GatewayLinkLocal6, 64).String()
		out = append(out, with(step(OpAddAddr, host, a), step(OpRemoveAddr, host, a)))
	}
	out = append(out, with(step(OpIfaceUp, host, ""), step(OpIfaceDown, host, "")))
	// The route to each of the jail's addresses leaves through its own link. (A jail never shares a link with
	// another, so nothing a jail sends can change where the host sends the traffic of another jail.)
	for _, p := range []netip.Prefix{in.IPv4, in.IPv6} {
		if !p.IsValid() {
			continue
		}
		a := netip.PrefixFrom(p.Addr(), p.Addr().BitLen()).String()
		out = append(out, with(step(OpAddHostRoute, host, a), step(OpDelHostRoute, host, a)))
	}
	if proxy {
		out = append(out, with(step(OpNDPProxyAdd, in.Uplink, in.IPv6.Addr().String()), step(OpNDPProxyDel, in.Uplink, in.IPv6.Addr().String())))
	}
	j := func(op Op, iface, arg string) Step { s := step(op, iface, arg); s.Phase = PhaseJail; return s }
	// The jail end is described from the host once it is in the jail's vnet (ifconfig -j). Destroying the epair
	// removes it, so the step has no inverse.
	out = append(out, j(OpSetDescription, jail, JailIfaceDesc(in.Project, in.Jail, in.Network, false)))
	if in.HostConfigured {
		for _, p := range []netip.Prefix{in.IPv4, in.IPv6} {
			if p.IsValid() {
				out = append(out, with(j(OpAddAddr, jail, p.String()), j(OpRemoveAddr, jail, p.String())))
			}
		}
		out = append(out, with(j(OpIfaceUp, jail, ""), j(OpIfaceDown, jail, "")))
		for _, g := range []netip.Addr{in.Gateway4, in.Gateway6} {
			if !g.IsValid() {
				continue
			}
			if g.Is4() && in.IPv4.Bits() == 32 {
				// a /32 has no on-link gateway: the route to the gateway itself comes first
				out = append(out, with(j(OpAddGatewayLink, jail, g.String()), j(OpDelGatewayLink, jail, g.String())))
			}
			arg := g.String()
			if g.IsLinkLocalUnicast() {
				arg += "%" + jail
			}
			out = append(out, with(j(OpAddDefaultRte, jail, arg), j(OpDelDefaultRte, jail, arg)))
		}
	}
	return out, nil
}

// describeJail renders a jail-phase step as the host command that configures
// the jail's vnet from outside (the Linux userland has no usable tools).
func (s Step) describeJail() string {
	pre := "[host, jail] "
	switch s.Op {
	case OpAddAddr, OpRemoveAddr:
		p, err := netip.ParsePrefix(s.Arg)
		if err != nil {
			return pre + string(s.Op)
		}
		verb := "alias"
		if s.Op == OpRemoveAddr {
			verb = "-alias"
		}
		switch {
		case p.Addr().Is6():
			return fmt.Sprintf("%sifconfig -j <jail> %s inet6 %s prefixlen %d %s", pre, s.Iface, p.Addr(), p.Bits(), verb)
		case s.Op == OpAddAddr:
			return fmt.Sprintf("%sifconfig -j <jail> %s inet %s up", pre, s.Iface, p)
		}
		return fmt.Sprintf("%sifconfig -j <jail> %s inet %s %s", pre, s.Iface, p, verb)
	case OpSetDescription:
		return pre + "ifconfig -j <jail> " + s.Iface + " description " + s.Arg
	case OpIfaceUp:
		return pre + "ifconfig -j <jail> " + s.Iface + " up"
	case OpIfaceDown:
		return pre + "ifconfig -j <jail> " + s.Iface + " down"
	case OpAddGatewayLink:
		return pre + "route -j <jail> add -host " + s.Arg + " -interface " + s.Iface
	case OpDelGatewayLink:
		return pre + "route -j <jail> delete -host " + s.Arg
	case OpAddDefaultRte:
		if strings.Contains(s.Arg, ":") {
			return pre + "route -j <jail> add -inet6 default " + s.Arg
		}
		return pre + "route -j <jail> add default " + s.Arg
	case OpDelDefaultRte:
		if strings.Contains(s.Arg, ":") {
			return pre + "route -j <jail> delete -inet6 default"
		}
		return pre + "route -j <jail> delete default"
	}
	return pre + string(s.Op)
}
