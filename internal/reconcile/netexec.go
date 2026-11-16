package reconcile

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// NetExec executes render.Step values against the system. Execution is
// idempotent: a step whose effect is already present succeeds. Satisfied lets
// the loop skip such steps and report drift without touching anything.
//
// UNVERIFIED on FreeBSD: every command line behind ifconfig.Client, route(8)
// and jexec(8).
type NetExec struct {
	Net  ifconfig.Client
	PF   pfctl.Client
	Run  run.Runner
	Jail jailos.Controller
	// Sysctl reads a sysctl value; when nil the runner is used.
	Sysctl func(ctx context.Context, name string) (string, error)
	// Anchors supplies the ruleset of an anchor named by OpLoadAnchor.
	Anchors map[string]string
}

// Exec runs one step. jail names the jail for PhaseJail steps.
func (e *NetExec) Exec(ctx context.Context, st render.Step, jail string) error {
	if st.Phase == render.PhaseJail {
		return e.execJail(ctx, st, jail)
	}
	switch st.Op {
	case render.OpRequireSysctl:
		return e.requireSysctl(ctx, st.Arg)
	case render.OpSetDescription:
		return e.Net.SetDescription(ctx, st.Iface, st.Arg)
	case render.OpSetMTU:
		if _, err := strconv.Atoi(st.Arg); err != nil {
			return validate.Invalid("mtu", "bad mtu %q", st.Arg)
		}
		return e.ifconfigCmd(ctx, st.Iface, "mtu", st.Arg)
	case render.OpSetMAC:
		if err := validate.MAC("mac", st.Arg); err != nil {
			return err
		}
		return e.ifconfigCmd(ctx, st.Iface, "ether", st.Arg)
	case render.OpAddAddr, render.OpRemoveAddr:
		p, err := netip.ParsePrefix(st.Arg)
		if err != nil {
			return validate.Invalid("address", "bad address %q", st.Arg)
		}
		if st.Op == render.OpAddAddr {
			return ignore(e.Net.AddrAdd(ctx, st.Iface, p), api.CodeAlreadyExists)
		}
		return ignore(e.Net.AddrRemove(ctx, st.Iface, p), api.CodeNotFound)
	case render.OpIfaceUp:
		return e.Net.SetLink(ctx, st.Iface, true)
	case render.OpIfaceDown:
		return ignore(e.Net.SetLink(ctx, st.Iface, false), api.CodeNotFound)
	case render.OpEpairCreate:
		base := strings.TrimSuffix(st.Iface, "a")
		_, _, err := e.Net.EpairCreate(ctx, base)
		return ignore(err, api.CodeAlreadyExists)
	case render.OpEpairDestroy:
		return ignore(e.Net.EpairDestroy(ctx, st.Iface), api.CodeNotFound)
	case render.OpAddHostRoute:
		return ignore(e.Net.RouteAdd(ctx, ifconfig.Route{Dest: st.Arg, Interface: st.Iface}), api.CodeAlreadyExists)
	case render.OpDelHostRoute:
		return ignore(e.Net.RouteDelete(ctx, ifconfig.Route{Dest: st.Arg, Interface: st.Iface}), api.CodeNotFound)
	case render.OpAddRejectRoute:
		return ignore(e.Net.RouteAdd(ctx, ifconfig.Route{Dest: st.Arg, Reject: true}), api.CodeAlreadyExists)
	case render.OpDelRejectRoute:
		return ignore(e.Net.RouteDelete(ctx, ifconfig.Route{Dest: st.Arg, Reject: true}), api.CodeNotFound)
	case render.OpNDPProxyAdd, render.OpNDPProxyDel:
		return nil // the proxy manager of the loop owns the answered set
	case render.OpLoadAnchor:
		rs, ok := e.Anchors[st.Arg]
		if !ok {
			return api.Errorf(api.CodeInternal, "no ruleset rendered for anchor %q", st.Arg)
		}
		return e.PF.Load(ctx, st.Arg, rs)
	case render.OpFlushAnchor:
		return ignore(e.PF.Flush(ctx, st.Arg), api.CodeNotFound)
	}
	return api.Errorf(api.CodeInternal, "unknown plan operation %q", st.Op)
}

func ignore(err error, code api.Code) error {
	if err != nil && api.IsCode(err, code) {
		return nil
	}
	return err
}

func (e *NetExec) ifconfigCmd(ctx context.Context, iface string, args ...string) error {
	if err := ifconfig.ValidateIfName(iface); err != nil {
		return err
	}
	if e.Run == nil {
		return api.Errorf(api.CodeUnsupported, "no command runner configured")
	}
	_, err := e.Run.Run(ctx, run.Cmd{Name: "ifconfig", Args: append([]string{iface}, args...), Timeout: 20 * time.Second})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			return api.Errorf(api.CodeInternal, "ifconfig %s %s: %s", iface, strings.Join(args, " "), strings.TrimSpace(ee.Stderr))
		}
		return api.Errorf(api.CodeInternal, "ifconfig: %v", err)
	}
	return nil
}

func (e *NetExec) requireSysctl(ctx context.Context, kv string) error {
	k, want, ok := strings.Cut(kv, "=")
	if !ok {
		return api.Errorf(api.CodeInternal, "bad sysctl requirement %q", kv)
	}
	var got string
	var err error
	if e.Sysctl != nil {
		got, err = e.Sysctl(ctx, k)
	} else {
		got, err = Sysctl(ctx, e.Run, k)
	}
	if err != nil {
		return err
	}
	if got != want {
		return api.Errorf(api.CodeUnverified, "sysctl %s is %q, JailOps needs %q", k, got, want).
			WithHint(fmt.Sprintf("run `sysctl %s=%s` and add it to /etc/sysctl.conf", k, want)).WithDetail("sysctl", k)
	}
	return nil
}

// Sysctl reads one sysctl value through the runner.
func Sysctl(ctx context.Context, r run.Runner, name string) (string, error) {
	if r == nil {
		return "", api.Errorf(api.CodeUnsupported, "no command runner configured")
	}
	out, err := run.Stdout(ctx, r, run.Cmd{Name: "sysctl", Args: []string{"-n", name}, Timeout: 10 * time.Second})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			return "", api.Errorf(api.CodeUnverified, "sysctl %s: %s", name, strings.TrimSpace(ee.Stderr))
		}
		return "", api.Errorf(api.CodeUnverified, "sysctl %s: %v", name, err)
	}
	return strings.TrimSpace(out), nil
}

// JailStepArgv returns the host-side command of a jail-phase step. A Linux
// jail has no usable ifconfig or route of its own, and addresses set before
// the epair moved into the vnet are lost, so the host configures the
// interface after the move with the -j forms (verified on FreeBSD 15.1):
//
//	ifconfig -j <jail> <if> inet <addr>/<n> up
//	ifconfig -j <jail> <if> inet6 <addr> prefixlen <n>
//	route -j <jail> add default <gw>
//	route -j <jail> add -inet6 default <gw>
func JailStepArgv(st render.Step, jail string) ([]string, error) {
	switch st.Op {
	case render.OpAddAddr, render.OpRemoveAddr:
		p, err := netip.ParsePrefix(st.Arg)
		if err != nil {
			return nil, validate.Invalid("address", "bad address %q", st.Arg)
		}
		verb := "alias"
		if st.Op == render.OpRemoveAddr {
			verb = "-alias"
		}
		w := ifconfig.AddrWords(p, verb)
		if st.Op == render.OpAddAddr && p.Addr().Is4() {
			w = []string{"inet", p.String(), "up"} // sets the first address and brings the link up
		}
		return append([]string{"ifconfig", "-j", jail, st.Iface}, w...), nil
	case render.OpSetDescription:
		if !render.ValidIfaceDesc(st.Arg) || st.Arg == "" {
			return nil, validate.Invalid("description", "bad interface description %q", st.Arg)
		}
		return []string{"ifconfig", "-j", jail, st.Iface, "description", st.Arg}, nil
	case render.OpIfaceUp:
		return []string{"ifconfig", "-j", jail, st.Iface, "up"}, nil
	case render.OpIfaceDown:
		return []string{"ifconfig", "-j", jail, st.Iface, "down"}, nil
	case render.OpAddGatewayLink, render.OpDelGatewayLink:
		a, err := netip.ParseAddr(st.Arg)
		if err != nil || !a.Is4() {
			return nil, validate.Invalid("gateway", "bad gateway %q", st.Arg)
		}
		if st.Op == render.OpDelGatewayLink {
			return []string{"route", "-j", jail, "delete", "-host", a.String()}, nil
		}
		return []string{"route", "-j", jail, "add", "-host", a.String(), "-interface", st.Iface}, nil
	case render.OpAddDefaultRte, render.OpDelDefaultRte:
		gw := st.Arg
		if a, _, ok := strings.Cut(gw, "%"); ok {
			gw = a
		}
		a, err := netip.ParseAddr(gw)
		if err != nil {
			return nil, validate.Invalid("gateway", "bad gateway %q", st.Arg)
		}
		verb := "add"
		if st.Op == render.OpDelDefaultRte {
			verb = "delete"
		}
		argv := []string{"route", "-j", jail, verb}
		if a.Is6() {
			argv = append(argv, "-inet6")
		}
		argv = append(argv, "default")
		if st.Op == render.OpAddDefaultRte {
			argv = append(argv, st.Arg)
		}
		return argv, nil
	}
	return nil, api.Errorf(api.CodeInternal, "operation %q cannot run for a jail", st.Op)
}

// execJail runs a jail-phase step from the host against the jail's vnet.
func (e *NetExec) execJail(ctx context.Context, st render.Step, jail string) error {
	if e.Run == nil {
		return api.Errorf(api.CodeUnsupported, "no command runner configured")
	}
	if err := ifconfig.ValidateIfName(st.Iface); err != nil {
		return err
	}
	if err := validate.JailKey("jail", jail); err != nil {
		return err
	}
	argv, err := JailStepArgv(st, jail)
	if err != nil {
		return err
	}
	_, err = e.Run.Run(ctx, run.Cmd{Name: argv[0], Args: argv[1:], Timeout: 20 * time.Second})
	if err != nil {
		low := strings.ToLower(err.Error())
		if ee, ok := run.IsExit(err); ok {
			low += " " + strings.ToLower(ee.Stderr)
		}
		if strings.Contains(low, "file exists") && st.Op == render.OpAddDefaultRte {
			return nil
		}
		return api.Errorf(api.CodeInternal, "%s: %v", strings.Join(argv, " "), err)
	}
	return nil
}

// Satisfied reports whether the step's effect is already present. Steps whose
// effect cannot be observed (sysctl checks, and routes when the routing table cannot be read) are never satisfied;
// they are idempotent.
func Satisfied(st render.Step, obs *Observed) bool {
	if obs == nil || st.Phase == render.PhaseJail {
		return false
	}
	i, exists := obs.Ifaces[st.Iface]
	switch st.Op {
	case render.OpEpairCreate:
		return exists
	case render.OpAddHostRoute, render.OpAddRejectRoute:
		p, err := netip.ParsePrefix(st.Arg)
		if err != nil || obs.Routes == nil {
			return false
		}
		return obs.HasRoute(p, st.Iface, st.Op == render.OpAddRejectRoute)
	case render.OpSetDescription:
		return exists && i.Description == st.Arg
	case render.OpSetMTU:
		n, _ := strconv.Atoi(st.Arg)
		return exists && i.MTU == n
	case render.OpSetMAC:
		return exists && strings.EqualFold(i.MAC, st.Arg)
	case render.OpAddAddr:
		p, err := netip.ParsePrefix(st.Arg)
		if err != nil || !exists {
			return false
		}
		for _, list := range [][]netip.Prefix{i.Inet, i.Inet6} {
			for _, q := range list {
				if q == p {
					return true
				}
			}
		}
		return false
	case render.OpIfaceUp:
		return exists && i.Up()
	case render.OpNDPProxyAdd, render.OpNDPProxyDel:
		return true
	}
	return false
}
