package ifconfig

import (
	"net/netip"
	"strings"
)

// RouteEntry is one line of the routing table (netstat -rnW).
type RouteEntry struct {
	// Dest is the destination: a host route is a /32 or a /128.
	Dest netip.Prefix
	// Iface is the interface the route leaves through.
	Iface string
	// Flags are the route's flags as netstat prints them ("UHS", "URS").
	Flags string
}

// Reject reports whether the route answers packets with an error (flag R).
func (r RouteEntry) Reject() bool { return strings.Contains(r.Flags, "R") }

// ParseRoutes reads the output of `netstat -rnW` (either family or both): one entry per route line that has a
// destination, flags and an interface. The header lines, the default routes and the link-local entries (they carry
// a zone) are left out.
func ParseRoutes(text string) []RouteEntry {
	var out []RouteEntry
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || !strings.HasPrefix(f[2], "U") {
			continue
		}
		dest := f[0]
		if strings.Contains(dest, "%") {
			continue
		}
		var p netip.Prefix
		if q, err := netip.ParsePrefix(dest); err == nil {
			p = q
		} else if a, err := netip.ParseAddr(dest); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			continue
		}
		iface := f[len(f)-1]
		if len(f) >= 7 || len(f) == 6 {
			iface = f[5]
		}
		out = append(out, RouteEntry{Dest: p.Masked(), Iface: iface, Flags: f[2]})
	}
	return out
}
