// Package ifconfig manages epair interfaces, addresses and routes
// through ifconfig(8) and route(8), and reads interface state. It changes only
// interfaces JailOps owns: those whose description carries the JailOps marker
// (see Owns), which it writes itself when it creates an interface.
package ifconfig

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/sdk/api"
)

// Marker is the description JailOps gives an interface it creates, in the same operation, before the interface has
// the name it is created for. The reconcile loop replaces it with the readable text ("jailops jail=web/app net=lan (host side)"); every
// text JailOps writes starts with "jailops ", which HasMarker tests. Only root can set the description of an interface in the host's network stack, so the daemon cannot forge it.
const Marker = "jailops managed"

// HasMarker reports whether a description is one JailOps writes: it starts with "jailops ".
func HasMarker(desc string) bool {
	return strings.HasPrefix(desc, "jailops ")
}

// OwnedKinds are the interface kinds (their driver's group) JailOps creates and may change: epairs. A physical
// interface, a loopback, a tunnel, a bridge or a vlan is never owned, whatever its description says.
var OwnedKinds = []string{"epair"}

// Options configure how ownership is decided. There is nothing to set today; the type stays so that the clients keep
// one place to say it.
type Options struct{}

// Owns decides from the kernel's view of an interface (its kind and description, never a name or a claim of the
// caller) whether JailOps may change it, and returns the error that explains a refusal.
func (o Options) Owns(i Iface) error {
	kind := ""
	for _, g := range i.Groups {
		if slices.Contains(OwnedKinds, g) {
			kind = g
		}
	}
	if kind == "" {
		return api.Errorf(api.CodeForbidden, "interface %q is not managed by JailOps: JailOps changes only epairs it created (this one is in the groups %s)", i.Name, groupList(i.Groups))
	}
	if HasMarker(i.Description) {
		return nil
	}
	if i.Description != "" {
		return api.Errorf(api.CodeForbidden, "interface %q is not managed by JailOps: its description %q is not one JailOps writes", i.Name, i.Description)
	}
	return api.Errorf(api.CodeForbidden, "interface %q is not managed by JailOps: it has no JailOps description (JailOps marks every interface it creates and never takes one over by its name)", i.Name)
}

func groupList(g []string) string {
	if len(g) == 0 {
		return "(none)"
	}
	return strings.Join(g, ", ")
}

// CheckNewName checks the name of an interface JailOps is about to create: a valid interface name that does not have
// the form of a driver's interface (ipam.DriverLikeName), so that it can never be mistaken for a device the kernel
// makes. Whether the name is free is the kernel's answer at the creation itself.
func CheckNewName(name string) error {
	if err := ValidateIfName(name); err != nil {
		return err
	}
	if drv, ok := ipam.DriverLikeName(name); ok {
		return api.Errorf(api.CodeInvalid, "interface name %q has the form of the interfaces of the driver %q (%s, %s0, ...); JailOps does not create interfaces under such names", name, drv, drv, drv)
	}
	return nil
}

// Reader reads one interface from the kernel, in the host's network stack or in a jail's.
type Reader interface {
	// Show reads the interface name in the host's stack; an interface that does not exist is api.CodeNotFound.
	Show(ctx context.Context, name string) (Iface, error)
	// ShowInJail reads the interface name in the vnet of jail.
	ShowInJail(ctx context.Context, jail, name string) (Iface, error)
}

// owned reads name through r and checks that JailOps owns it.
func (o Options) owned(ctx context.Context, r Reader, name string) error {
	if err := ValidateIfName(name); err != nil {
		return err
	}
	i, err := r.Show(ctx, name)
	if err != nil {
		return err
	}
	return o.Owns(i)
}

// ownedInJail is owned for an interface in the vnet of jail.
func (o Options) ownedInJail(ctx context.Context, r Reader, jail, name string) error {
	if err := ValidateIfName(name); err != nil {
		return err
	}
	if err := ValidateJailRef(jail); err != nil {
		return err
	}
	i, err := r.ShowInJail(ctx, jail, name)
	if err != nil {
		return err
	}
	return o.Owns(i)
}

// one returns the single interface of `ifconfig <name>` output.
func one(out, name string) (Iface, error) {
	l := ParseIfconfig(out)
	if len(l) != 1 || l[0].Name != name {
		return Iface{}, api.Errorf(api.CodeInternal, "ifconfig %s: %s", name, fmt.Sprintf("unexpected output (%d interfaces)", len(l)))
	}
	return l[0], nil
}

// descOrMarker is the description to write: clearing it writes the marker, so that an interface of JailOps never
// loses the mark that makes it JailOps's.
func descOrMarker(d string) string {
	if d == "" {
		return Marker
	}
	return d
}

// ValidateIfName accepts FreeBSD interface names: a letter, then letters,
// digits, '_' and '.', at most 15 bytes (IFNAMSIZ is 16 with the NUL).
func ValidateIfName(n string) error {
	if n == "" || len(n) > 15 {
		return api.Errorf(api.CodeInvalid, "invalid interface name %q", n)
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !(letter || i > 0 && (c >= '0' && c <= '9' || c == '_' || c == '.')) {
			return api.Errorf(api.CodeInvalid, "invalid interface name %q", n)
		}
	}
	return nil
}

// ValidateJailRef accepts a jail name or numeric JID for `ifconfig vnet`.
func ValidateJailRef(j string) error {
	if j == "" || len(j) > 64 || j[0] == '-' {
		return api.Errorf(api.CodeInvalid, "invalid jail %q", j)
	}
	for i := 0; i < len(j); i++ {
		c := j[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return api.Errorf(api.CodeInvalid, "invalid jail %q", j)
		}
	}
	return nil
}

// ValidateDescription rejects control characters in an interface description.
func ValidateDescription(d string) error {
	if len(d) > 255 {
		return api.Errorf(api.CodeInvalid, "description too long")
	}
	for _, r := range d {
		if r < 0x20 || r == 0x7f {
			return api.Errorf(api.CodeInvalid, "invalid description")
		}
	}
	return nil
}

// Addr is an interface address.
type Addr struct {
	Prefix netip.Prefix // address with prefix length
}

// Member is a port of a bridge (read from the host's own bridges, never changed).
type Member struct {
	Name    string
	Flags   []string
	Private bool
}

// Iface is one entry of the interface list.
type Iface struct {
	Name        string
	Flags       []string // symbolic, e.g. UP, RUNNING
	MTU         int
	Description string
	MAC         string
	Inet        []netip.Prefix
	Inet6       []netip.Prefix
	Groups      []string
	Status      string
	Members     []Member
	// VlanParent and VlanTag are set on a vlan(4) interface: "vlan: 77 vlanproto: 802.1q vlanpcp: 0 parent interface: em0".
	VlanParent string
	VlanTag    int
}

// Up reports whether the UP flag is set.
func (i Iface) Up() bool {
	for _, f := range i.Flags {
		if f == "UP" {
			return true
		}
	}
	return false
}

// Route describes a route for RouteAdd and RouteDelete.
type Route struct {
	// Dest is "default" or an address or prefix; its family selects -inet
	// or -inet6.
	Dest string
	// Gateway is a next hop. Empty with Interface set means a link route
	// (-interface).
	Gateway   string
	Interface string
	// Reject makes a route that answers packets for the prefix with an error (route -reject through the loopback
	// address): Dest is a prefix, there is no Gateway and no Interface.
	Reject bool
}

// Client is the interface layer. A mutating call changes only an interface JailOps owns (Options.Owns, read from the
// kernel at the call); a create makes a new interface under a name that is free and not a driver's, marked in the same
// call.
type Client interface {
	List(ctx context.Context) ([]Iface, error)

	SetDescription(ctx context.Context, iface, desc string) error

	// EpairCreate creates a pair named <name>a and <name>b and returns both.
	EpairCreate(ctx context.Context, name string) (a, b string, err error)
	// EpairDestroy destroys the pair that iface (either end) belongs to.
	EpairDestroy(ctx context.Context, iface string) error
	// MoveToJail moves iface into the vnet of jail (name or JID).
	MoveToJail(ctx context.Context, iface, jail string) error
	// MoveFromJail takes iface back from the jail to the host.
	MoveFromJail(ctx context.Context, iface, jail string) error

	SetLink(ctx context.Context, iface string, up bool) error
	AddrAdd(ctx context.Context, iface string, prefix netip.Prefix) error
	AddrRemove(ctx context.Context, iface string, prefix netip.Prefix) error

	RouteAdd(ctx context.Context, r Route) error
	RouteDelete(ctx context.Context, r Route) error

	// IPv6Forwarding reads net.inet6.ip6.forwarding.
	IPv6Forwarding(ctx context.Context) (bool, error)
}

// routeArgs validates r and renders `-inet|-inet6 <dest> <gw>|-interface <if>`. The caller checks that JailOps owns
// the interface.
func routeArgs(r Route, del bool) ([]string, error) {
	if r.Reject {
		p, err := netip.ParsePrefix(r.Dest)
		if err != nil || r.Gateway != "" || r.Interface != "" || p.Addr().Zone() != "" || p.Addr().IsUnspecified() && p.Bits() == 0 {
			return nil, api.Errorf(api.CodeInvalid, "invalid reject route %q", r.Dest)
		}
		args := []string{famOf(p.Addr()), p.Masked().String()}
		if !del {
			args = append(args, loopback(p.Addr()), "-reject")
		}
		return args, nil
	}
	var fam string
	dest := r.Dest
	switch {
	case dest == "default":
		// the family follows the gateway
		if g, err := netip.ParseAddr(r.Gateway); err == nil {
			fam = famOf(g)
		} else if r.Interface != "" && r.Gateway == "" {
			return nil, api.Errorf(api.CodeInvalid, "default route over an interface needs an explicit family; give a gateway")
		}
	default:
		if p, err := netip.ParsePrefix(dest); err == nil {
			fam, dest = famOf(p.Addr()), p.Masked().String()
		} else if a, err := netip.ParseAddr(dest); err == nil && a.Zone() == "" {
			fam, dest = famOf(a), a.String()
		}
	}
	if fam == "" {
		return nil, api.Errorf(api.CodeInvalid, "invalid route %q via %q", r.Dest, r.Gateway)
	}
	args := []string{fam, dest}
	switch {
	case r.Gateway != "":
		g, err := netip.ParseAddr(r.Gateway)
		if err != nil || famOf(g) != fam {
			return nil, api.Errorf(api.CodeInvalid, "invalid gateway %q", r.Gateway)
		}
		args = append(args, g.String())
	case r.Interface != "":
		if err := ValidateIfName(r.Interface); err != nil {
			return nil, err
		}
		args = append(args, "-interface", r.Interface)
	default:
		return nil, api.Errorf(api.CodeInvalid, "route needs a gateway or an interface")
	}
	return args, nil
}

func loopback(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "127.0.0.1"
	}
	return "::1"
}

func famOf(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "-inet"
	}
	return "-inet6"
}
