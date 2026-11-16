package ndproxy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Exec runs an external command with an argument vector (never a shell). The
// caller supplies an implementation backed by internal/sys/run with a
// timeout; tests supply a fake. Output is combined stdout and stderr.
type Exec interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// RouteManager implements Routes with route(8) and ifconfig(8).
//
// UNVERIFIED: the command lines and the wording of their output match
// FreeBSD 15 documentation but have not been run there. Only the argument
// vectors and the output parsing are exercised by tests.
type RouteManager struct{ Exec Exec }

func validIface(n string) bool {
	if n == "" || len(n) > 15 || n[0] == '-' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func routeArgs(verb string, addr netip.Addr, iface string) []string {
	return []string{verb, "-inet6", netip.PrefixFrom(addr, 128).String(), "-interface", iface}
}

// Add runs `route add -inet6 <addr>/128 -interface <iface>`. If the route
// exists it is changed to use the interface.
func (r RouteManager) Add(ctx context.Context, addr netip.Addr, iface string) error {
	if !validIface(iface) || !ValidAddr(addr) {
		return api.Errorf(api.CodeInvalid, "bad route %s via %q", addr, iface)
	}
	out, err := r.Exec.Run(ctx, "route", routeArgs("add", addr, iface)...)
	if err != nil && strings.Contains(string(out), "File exists") {
		out, err = r.Exec.Run(ctx, "route", routeArgs("change", addr, iface)...)
	}
	if err != nil {
		return fmt.Errorf("route add %s: %w: %s", addr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove runs `route delete -inet6 <addr>/128 -interface <iface>`. A route
// that is already gone is not an error.
func (r RouteManager) Remove(ctx context.Context, addr netip.Addr, iface string) error {
	if !validIface(iface) || !ValidAddr(addr) {
		return api.Errorf(api.CodeInvalid, "bad route %s via %q", addr, iface)
	}
	out, err := r.Exec.Run(ctx, "route", routeArgs("delete", addr, iface)...)
	if err != nil && !strings.Contains(string(out), "not in table") {
		return fmt.Errorf("route delete %s: %w: %s", addr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureUplinkNotMember fails with api.CodeConflict if uplink is a member of
// a bridge of the host's own (the proxy needs the uplink to be a plain interface). It only reads: JailOps never
// modifies a bridge.
func (r RouteManager) EnsureUplinkNotMember(ctx context.Context, uplink string) error {
	if !validIface(uplink) {
		return api.Errorf(api.CodeInvalid, "bad interface %q", uplink)
	}
	out, err := r.Exec.Run(ctx, "ifconfig", "-g", "bridge")
	if err != nil {
		return fmt.Errorf("ifconfig -g bridge: %w", err)
	}
	for _, br := range strings.Fields(string(out)) {
		if !validIface(br) {
			continue
		}
		o, err := r.Exec.Run(ctx, "ifconfig", br)
		if err != nil {
			return fmt.Errorf("ifconfig %s: %w", br, err)
		}
		for _, m := range parseBridgeMembers(string(o)) {
			if m == uplink {
				return api.Errorf(api.CodeConflict, "uplink %s is a member of bridge %s", uplink, br).
					WithHint("remove the uplink from the bridge; the NDP proxy needs it to be a plain interface")
			}
		}
	}
	return nil
}

// parseBridgeMembers extracts member names from `ifconfig <bridge>` output
// ("\tmember: em0 flags=143<...>").
func parseBridgeMembers(out string) []string {
	var members []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "member:" {
			members = append(members, f[1])
		}
	}
	return members
}
