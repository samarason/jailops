package ifconfig

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Command implements Client over run.Runner.
type Command struct {
	R run.Runner
	O Options
}

var (
	_ Client = (*Command)(nil)
	_ Reader = (*Command)(nil)
)

// NewCommand returns a Client with the given options.
func NewCommand(r run.Runner, o Options) *Command { return &Command{R: r, O: o} }

func (c *Command) run(ctx context.Context, name string, args ...string) (string, error) {
	res, err := c.R.Run(ctx, run.Cmd{Name: name, Args: args, Timeout: 20 * time.Second})
	if err != nil {
		return "", mapErr(name, err)
	}
	return string(res.Stdout), nil
}

func mapErr(tool string, err error) error {
	ee, ok := run.IsExit(err)
	if !ok {
		return api.Errorf(api.CodeInternal, "%s: %v", tool, err)
	}
	msg := strings.TrimSpace(ee.Stderr)
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "does not exist"), strings.Contains(low, "interface not found"), strings.Contains(low, "no such"), strings.Contains(low, "not in table"):
		return api.Errorf(api.CodeNotFound, "%s: %s", tool, msg)
	case strings.Contains(low, "file exists"), strings.Contains(low, "already exists"):
		return api.Errorf(api.CodeAlreadyExists, "%s: %s", tool, msg)
	case strings.Contains(low, "busy"):
		return api.Errorf(api.CodeBusy, "%s: %s", tool, msg)
	}
	return api.Errorf(api.CodeInternal, "%s: %s", tool, msg)
}

// List implements Client with `ifconfig -a`.
func (c *Command) List(ctx context.Context) ([]Iface, error) {
	out, err := c.run(ctx, "ifconfig", "-a")
	if err != nil {
		return nil, err
	}
	return ParseIfconfig(out), nil
}

// Show implements Reader with `ifconfig <name>`.
func (c *Command) Show(ctx context.Context, name string) (Iface, error) {
	if err := ValidateIfName(name); err != nil {
		return Iface{}, err
	}
	out, err := c.run(ctx, "ifconfig", name)
	if err != nil {
		return Iface{}, err
	}
	return one(out, name)
}

// ShowInJail implements Reader with `ifconfig -j <jail> <name>`.
func (c *Command) ShowInJail(ctx context.Context, jail, name string) (Iface, error) {
	if err := ValidateIfName(name); err != nil {
		return Iface{}, err
	}
	if err := ValidateJailRef(jail); err != nil {
		return Iface{}, err
	}
	out, err := c.run(ctx, "ifconfig", "-j", jail, name)
	if err != nil {
		return Iface{}, err
	}
	return one(out, name)
}

// own checks, in the kernel, that JailOps owns every name (all names are validated before anything is read).
func (c *Command) own(ctx context.Context, names ...string) error {
	for _, n := range names {
		if err := ValidateIfName(n); err != nil {
			return err
		}
	}
	for _, n := range names {
		if err := c.O.owned(ctx, c, n); err != nil {
			return err
		}
	}
	return nil
}

// SetDescription implements Client. The description must be one JailOps writes, so the interface keeps its marker;
// an empty description writes Marker.
func (c *Command) SetDescription(ctx context.Context, iface, desc string) error {
	desc = descOrMarker(desc)
	if err := ValidateDescription(desc); err != nil {
		return err
	}
	if !HasMarker(desc) {
		return api.Errorf(api.CodeInvalid, "description %q would remove the JailOps marker (\"jailops ...\")", desc)
	}
	if err := c.own(ctx, iface); err != nil {
		return err
	}
	_, err := c.run(ctx, "ifconfig", iface, "description", desc)
	return err
}

// EpairCreate implements Client: `ifconfig epair create` prints "epairNa"; both ends are given the marker and then
// renamed to <name>a and <name>b (the kernel refuses a name that exists: an interface that exists under it is never
// touched, and the new pair is destroyed again; so no interface ever has the name without the marker, and none is taken
// over by its name). On failure the pair is destroyed. Verified on FreeBSD 15.2-PRERELEASE amd64, the descriptions included (they also survive the move of an
// end into a vnet and back).
func (c *Command) EpairCreate(ctx context.Context, name string) (string, string, error) {
	a, b := name+"a", name+"b"
	for _, n := range []string{a, b} {
		if err := CheckNewName(n); err != nil {
			return "", "", err
		}
	}
	out, err := c.run(ctx, "ifconfig", "epair", "create")
	if err != nil {
		return "", "", err
	}
	ta := strings.TrimSpace(out)
	if !strings.HasPrefix(ta, "epair") || !strings.HasSuffix(ta, "a") || ValidateIfName(ta) != nil {
		return "", "", api.Errorf(api.CodeInternal, "ifconfig epair create returned %q", ta)
	}
	tb := strings.TrimSuffix(ta, "a") + "b"
	cleanup := func(n string) { c.run(ctx, "ifconfig", n, "destroy") }
	for _, n := range []string{ta, tb} {
		if _, err := c.run(ctx, "ifconfig", n, "description", Marker); err != nil {
			cleanup(ta)
			return "", "", err
		}
	}
	if _, err := c.run(ctx, "ifconfig", tb, "name", b); err != nil {
		cleanup(ta)
		return "", "", err
	}
	if _, err := c.run(ctx, "ifconfig", ta, "name", a); err != nil {
		cleanup(b)
		return "", "", err
	}
	return a, b, nil
}

// EpairDestroy implements Client. Destroying one end removes both.
func (c *Command) EpairDestroy(ctx context.Context, iface string) error {
	if err := c.own(ctx, iface); err != nil {
		return err
	}
	_, err := c.run(ctx, "ifconfig", iface, "destroy")
	return err
}

// MoveToJail implements Client. The interface keeps its description in the jail's vnet.
func (c *Command) MoveToJail(ctx context.Context, iface, jail string) error {
	if err := ValidateJailRef(jail); err != nil {
		return err
	}
	if err := c.own(ctx, iface); err != nil {
		return err
	}
	_, err := c.run(ctx, "ifconfig", iface, "vnet", jail)
	return err
}

// MoveFromJail implements Client: `ifconfig <if> -vnet <jail>` run from the host, for an interface of JailOps in the
// jail's vnet (read there with ifconfig -j). Verified on FreeBSD 15.2-PRERELEASE amd64 (scripts/ifprobe).
func (c *Command) MoveFromJail(ctx context.Context, iface, jail string) error {
	if err := c.O.ownedInJail(ctx, c, jail, iface); err != nil {
		return err
	}
	_, err := c.run(ctx, "ifconfig", iface, "-vnet", jail)
	return err
}

// SetLink implements Client.
func (c *Command) SetLink(ctx context.Context, iface string, up bool) error {
	if err := c.own(ctx, iface); err != nil {
		return err
	}
	state := "down"
	if up {
		state = "up"
	}
	_, err := c.run(ctx, "ifconfig", iface, state)
	return err
}

func addrArgs(iface string, p netip.Prefix, verb string) []string {
	return append([]string{iface}, AddrWords(p, verb)...)
}

// AddrWords returns the ifconfig words that add (verb "alias") or remove
// ("-alias") an address. IPv6 takes "<addr> prefixlen <n>": the /n form
// was rejected on FreeBSD 15.1.
func AddrWords(p netip.Prefix, verb string) []string {
	if p.Addr().Is6() {
		return []string{"inet6", p.Addr().String(), "prefixlen", strconv.Itoa(p.Bits()), verb}
	}
	return []string{"inet", p.String(), verb}
}

func validPrefix(p netip.Prefix) error {
	if !p.IsValid() || p.Addr().Zone() != "" {
		return api.Errorf(api.CodeInvalid, "invalid address %q", p)
	}
	return nil
}

// AddrAdd implements Client.
func (c *Command) AddrAdd(ctx context.Context, iface string, p netip.Prefix) error {
	if err := validPrefix(p); err != nil {
		return err
	}
	if err := c.own(ctx, iface); err != nil {
		return err
	}
	_, err := c.run(ctx, "ifconfig", addrArgs(iface, p, "alias")...)
	return err
}

// AddrRemove implements Client.
func (c *Command) AddrRemove(ctx context.Context, iface string, p netip.Prefix) error {
	if err := validPrefix(p); err != nil {
		return err
	}
	if err := c.own(ctx, iface); err != nil {
		return err
	}
	_, err := c.run(ctx, "ifconfig", addrArgs(iface, p, "-alias")...)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "can't assign requested address") {
		// the address is not on the interface (SIOCDIFADDR answers EADDRNOTAVAIL): what was to be removed is gone
		return api.Errorf(api.CodeNotFound, "ifconfig: address %s is not on %s", p, iface)
	}
	return err
}

// RouteAdd implements Client.
func (c *Command) RouteAdd(ctx context.Context, r Route) error {
	a, err := c.routeArgs(ctx, r, false)
	if err != nil {
		return err
	}
	c.forgetNeighbor(ctx, r)
	_, err = c.run(ctx, "route", append([]string{"-n", "add"}, a...)...)
	return err
}

// routeArgs validates r and checks that JailOps owns its interface, if it names one.
func (c *Command) routeArgs(ctx context.Context, r Route, del bool) ([]string, error) {
	a, err := routeArgs(r, del)
	if err != nil {
		return nil, err
	}
	if r.Interface != "" && r.Gateway == "" {
		if err := c.own(ctx, r.Interface); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// forgetNeighbor drops the neighbor cache entry of an IPv6 host route's address. The kernel keeps the entry of a
// proxied jail address (static, a day long) after its route is gone; the next jail that is given the same address
// then cannot be reached from the host because the old hardware address is still cached. Best effort: an entry
// that is not there is the normal case.
func (c *Command) forgetNeighbor(ctx context.Context, r Route) {
	p, err := netip.ParsePrefix(r.Dest)
	if err != nil || !p.Addr().Is6() || p.Bits() != 128 {
		return
	}
	_, _ = c.run(ctx, "ndp", "-d", p.Addr().String())
}

// RouteDelete implements Client.
func (c *Command) RouteDelete(ctx context.Context, r Route) error {
	a, err := c.routeArgs(ctx, r, true)
	if err != nil {
		return err
	}
	_, err = c.run(ctx, "route", append([]string{"-n", "delete"}, a...)...)
	c.forgetNeighbor(ctx, r)
	return err
}

// IPv6Forwarding implements Client.
func (c *Command) IPv6Forwarding(ctx context.Context) (bool, error) {
	out, err := c.run(ctx, "sysctl", "-n", "net.inet6.ip6.forwarding")
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(out) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, api.Errorf(api.CodeInternal, "unexpected sysctl value %q", strings.TrimSpace(out))
}
