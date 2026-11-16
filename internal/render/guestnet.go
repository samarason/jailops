package render

import (
	"fmt"
	"net/netip"
	"strings"

	"jailops.net/jailops/internal/validate"
)

// NetIface is one interface of a jail as the guest sees it.
type NetIface struct {
	// Name is the interface name inside the jail.
	Name string
	// IPv4 and IPv6 are the interface address with its prefix length; the
	// zero Prefix means none. In IPv6 proxy mode callers pass a /128.
	IPv4, IPv6 netip.Prefix
	// Gateway4 and Gateway6 are used only on the interface marked Default.
	// Gateway6 may be link-local; the scope is added from Name.
	Gateway4, Gateway6 netip.Addr
	// Default marks the interface that owns the default routes. When no
	// interface is marked, the first one with a gateway does.
	Default bool
	MTU     int
}

// NetInput is the guest network configuration.
type NetInput struct {
	Hostname string
	Ifaces   []NetIface
	DNS      []netip.Addr
	Search   []string
}

func (in NetInput) check() error {
	if err := validate.Hostname("hostname", in.Hostname); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, f := range in.Ifaces {
		if err := validate.IfName(fmt.Sprintf("ifaces[%d].name", i), f.Name); err != nil {
			return err
		}
		if seen[f.Name] {
			return fmt.Errorf("render: duplicate interface %q", f.Name)
		}
		seen[f.Name] = true
		if f.IPv4.IsValid() && (!f.IPv4.Addr().Is4() || f.IPv4.Bits() < 0) {
			return fmt.Errorf("render: ifaces[%d].ipv4 %v is not an IPv4 prefix", i, f.IPv4)
		}
		if f.IPv6.IsValid() && (!f.IPv6.Addr().Is6() || f.IPv6.Addr().Is4In6() || f.IPv6.Addr().Zone() != "") {
			return fmt.Errorf("render: ifaces[%d].ipv6 %v is not an IPv6 prefix", i, f.IPv6)
		}
		if f.Gateway4.IsValid() && !f.Gateway4.Is4() {
			return fmt.Errorf("render: ifaces[%d].gateway4 is not IPv4", i)
		}
		if f.Gateway6.IsValid() && (!f.Gateway6.Is6() || f.Gateway6.Is4In6() || f.Gateway6.Zone() != "") {
			return fmt.Errorf("render: ifaces[%d].gateway6 is not IPv6 without zone", i)
		}
		if f.Gateway4.IsValid() && !f.IPv4.IsValid() || f.Gateway6.IsValid() && !f.IPv6.IsValid() {
			return fmt.Errorf("render: ifaces[%d] has a gateway without an address", i)
		}
		if f.MTU != 0 && (f.MTU < 576 || f.MTU > 9216) {
			return fmt.Errorf("render: ifaces[%d].mtu out of range", i)
		}
	}
	return nil
}

// defaultIface returns the index of the interface owning default routes, or -1.
func (in NetInput) defaultIface() int {
	for i, f := range in.Ifaces {
		if f.Default {
			return i
		}
	}
	for i, f := range in.Ifaces {
		if f.Gateway4.IsValid() || f.Gateway6.IsValid() {
			return i
		}
	}
	return -1
}

func netmask4(bits int) string {
	m := uint32(0)
	if bits > 0 {
		m = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}

// RcConfFreeBSD renders the rc.conf fragment for a FreeBSD jail: static
// addresses, no router advertisements, explicit default routes.
//
// UNVERIFIED on FreeBSD 15: the exact ifconfig_<if>_ipv6 argument set
// ("-accept_rtadv"), ipv6_network_interfaces="none" suppressing IPv6, and
// ipv6_defaultrouter accepting "fe80::1%<if>".
func RcConfFreeBSD(in NetInput) (string, error) {
	if err := in.check(); err != nil {
		return "", err
	}
	var b builder
	b.line("%s", Header)
	b.line("hostname=\"%s\"", in.Hostname)
	var v6 []string
	for _, f := range in.Ifaces {
		mtu := ""
		if f.MTU != 0 {
			mtu = fmt.Sprintf(" mtu %d", f.MTU)
		}
		if f.IPv4.IsValid() {
			b.line("ifconfig_%s=\"inet %s netmask %s%s\"", f.Name, f.IPv4.Addr(), netmask4(f.IPv4.Bits()), mtu)
		} else if mtu != "" {
			b.line("ifconfig_%s=\"up%s\"", f.Name, mtu)
		} else {
			b.line("ifconfig_%s=\"up\"", f.Name)
		}
		if f.IPv6.IsValid() {
			v6 = append(v6, f.Name)
			b.line("ifconfig_%s_ipv6=\"inet6 %s prefixlen %d -accept_rtadv\"", f.Name, f.IPv6.Addr(), f.IPv6.Bits())
		}
	}
	if len(v6) == 0 {
		b.line("ipv6_network_interfaces=\"none\"")
	} else {
		b.line("ipv6_network_interfaces=\"%s\"", strings.Join(v6, " "))
	}
	b.line("rtsold_enable=\"NO\"")
	if d := in.defaultIface(); d >= 0 {
		f := in.Ifaces[d]
		if f.Gateway4.IsValid() {
			if f.IPv4.Bits() == 32 {
				// a /32 has no on-link gateway: the route to the gateway itself comes first (rc runs static_routes
				// before it adds defaultrouter)
				b.line("static_routes=\"gw\"")
				b.line("route_gw=\"-host %s -interface %s\"", f.Gateway4, f.Name)
			}
			b.line("defaultrouter=\"%s\"", f.Gateway4)
		}
		if f.Gateway6.IsValid() {
			gw := f.Gateway6.String()
			if f.Gateway6.IsLinkLocalUnicast() {
				gw += "%" + f.Name
			}
			b.line("ipv6_defaultrouter=\"%s\"", gw)
		}
	}
	return b.result()
}

// ResolvMarker starts the first line of a resolv.conf JailOps wrote. JailOps writes the file again only while the line
// is there: a jail that removes it (or has a file of its own) keeps its resolver configuration.
const ResolvMarker = "# written by JailOps"

// ResolvConf renders resolv.conf: up to three nameservers and an optional
// search list. It is shared by FreeBSD and Alpine guests.
func ResolvConf(dns []netip.Addr, search []string) (string, error) {
	if len(dns) > 3 {
		return "", fmt.Errorf("render: at most 3 nameservers are honoured")
	}
	if len(search) > 6 {
		return "", fmt.Errorf("render: at most 6 search domains are honoured")
	}
	var b builder
	b.line("%s. Remove this line to keep your own changes: JailOps rewrites the file only while it is here.", ResolvMarker)
	if len(search) > 0 {
		for _, s := range search {
			if err := validate.Hostname("search", s); err != nil {
				return "", err
			}
		}
		b.line("search %s", strings.Join(search, " "))
	}
	for _, d := range dns {
		if !d.IsValid() || d.Zone() != "" || d.IsUnspecified() || d.IsMulticast() {
			return "", fmt.Errorf("render: %v is not a usable nameserver", d)
		}
		b.line("nameserver %s", d)
	}
	return b.result()
}

// AlpineResolvConf renders /etc/resolv.conf of an Alpine jail.
func AlpineResolvConf(dns []netip.Addr, search []string) (string, error) {
	return ResolvConf(dns, search)
}

// AlpineInterfaces renders /etc/network/interfaces with static stanzas in
// ifupdown-ng syntax. The Linuxulator has no netlink, so nothing inside the
// jail can run ifup; JailOps configures the interfaces from the host and
// keeps this file as the declarative record the init wrapper and the guest
// tooling read. UNVERIFIED: who consumes this file, and whether ifupdown-ng
// accepts a link-local gateway without a scope here.
func AlpineInterfaces(in NetInput) (string, error) {
	if err := in.check(); err != nil {
		return "", err
	}
	var b builder
	b.line("%s", Header)
	b.line("auto lo")
	b.line("iface lo inet loopback")
	d := in.defaultIface()
	for i, f := range in.Ifaces {
		b.line("")
		b.line("auto %s", f.Name)
		if !f.IPv4.IsValid() && !f.IPv6.IsValid() {
			b.line("iface %s inet manual", f.Name)
			continue
		}
		if f.IPv4.IsValid() {
			b.line("iface %s inet static", f.Name)
			b.line("\taddress %s", f.IPv4)
			if i == d && f.Gateway4.IsValid() {
				if f.IPv4.Bits() == 32 {
					b.line("\tpost-up route add -host %s dev %s", f.Gateway4, f.Name) // a /32 has no on-link gateway
				}
				b.line("\tgateway %s", f.Gateway4)
			}
			if f.MTU != 0 {
				b.line("\tmtu %d", f.MTU)
			}
		}
		if f.IPv6.IsValid() {
			b.line("iface %s inet6 static", f.Name)
			b.line("\taddress %s", f.IPv6)
			if i == d && f.Gateway6.IsValid() {
				b.line("\tgateway %s", f.Gateway6)
			}
		}
	}
	return b.result()
}

// AlpineHostname renders /etc/hostname.
func AlpineHostname(host string) (string, error) {
	if err := validate.Hostname("hostname", host); err != nil {
		return "", err
	}
	return host + "\n", nil
}
