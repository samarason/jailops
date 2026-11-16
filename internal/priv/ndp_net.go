package priv

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/sdk/api"
)

func hardwareAddr(name string) ([6]byte, error) {
	var mac [6]byte
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return mac, api.Errorf(api.CodeNotFound, "interface %s: %v", name, err)
	}
	if len(ifi.HardwareAddr) != 6 {
		return mac, api.Errorf(api.CodeInvalid, "interface %s has no Ethernet address", name)
	}
	copy(mac[:], ifi.HardwareAddr)
	return mac, nil
}

// netstatTimeout bounds a read of the routing table: netstat(1) that does not answer must not hold the reconcile pass.
const netstatTimeout = 15 * time.Second

// hostRoutes reads the IPv6 routing table with netstat(1) and returns its /128 host routes. UNVERIFIED output format
// on other systems than FreeBSD 15.1, where a host route is printed as "<address>  link#N  UHS  <interface>".
func hostRoutes() (map[netip.Addr]string, error) { return ReadHostRoutes() }

// ReadHostRoutes is hostRoutes for callers outside the package: netstat(1) needs no privilege, so the daemon reads
// the table itself to find host routes of jails that no longer exist.
func ReadHostRoutes() (map[netip.Addr]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), netstatTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/netstat", "-rnW", "-f", "inet6").Output()
	if err != nil {
		return nil, api.Errorf(api.CodeInternal, "netstat: %v", err)
	}
	return parseHostRoutes(string(out)), nil
}

// parseHostRoutes picks the host routes (flag H) out of netstat -rn output: the first column is the destination, the
// last the interface.
func parseHostRoutes(text string) map[netip.Addr]string {
	routes := map[netip.Addr]string{}
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || !strings.Contains(f[2], "H") {
			continue
		}
		dest := strings.TrimSuffix(f[0], "/128")
		if i := strings.IndexByte(dest, '%'); i >= 0 {
			continue // a link-local destination: not an address of a jail
		}
		a, err := netip.ParseAddr(dest)
		if err != nil || !a.Is6() {
			continue
		}
		routes[a] = f[len(f)-1]
	}
	return routes
}

func localAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if ipn, ok := a.(*net.IPNet); ok {
			if ad, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ad.Unmap())
			}
		}
	}
	return out, nil
}

// ReadRoutes reads the routing table of both families with netstat(1) (no privilege needed): the routes with a
// destination, flags and an interface, as the reconcile loop looks for the host routes of the jails and the reject
// routes of the networks.
func ReadRoutes() ([]ifconfig.RouteEntry, error) {
	var out []ifconfig.RouteEntry
	for _, fam := range []string{"inet", "inet6"} {
		ctx, cancel := context.WithTimeout(context.Background(), netstatTimeout)
		b, err := exec.CommandContext(ctx, "/usr/bin/netstat", "-rnW", "-f", fam).Output()
		cancel()
		if err != nil {
			return nil, api.Errorf(api.CodeInternal, "netstat: %v", err)
		}
		out = append(out, ifconfig.ParseRoutes(string(b))...)
	}
	return out, nil
}
