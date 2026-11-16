package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// What the host listens on, at the defaults of JailOps and of sshd: a forward must never take these ports, because the
// jail would answer instead of the host (the operator would be locked out, and what is typed to a fake sshd or console
// is read by the jail).
var defaultHostPorts = map[int]string{
	22:    "ssh",
	39110: "the JailOps console",
	39111: "the JailOps backup node",
}

// reservedHostPorts are the ports a published port of a jail may not take, with what listens there: the defaults above,
// the ports of the host firewall's ssh door, the console, the daemon's own listeners and the ACME challenge port while
// ACME is the certificate source.
func (s *Service) reservedHostPorts(ctx context.Context) map[int]string {
	out := map[int]string{}
	for p, what := range defaultHostPorts {
		out[p] = what
	}
	if s.d.ConsolePort > 0 {
		out[s.d.ConsolePort] = "the JailOps console"
	}
	if s.d.LogOwnPorts != nil {
		for _, p := range s.d.LogOwnPorts() {
			if _, ok := out[p]; !ok {
				out[p] = "a JailOps listener"
			}
		}
	}
	if fw, ok := s.d.Host.(HostFirewallSystem); ok && s.d.Host != nil {
		if st, err := fw.HostFirewallRead(ctx); err == nil && st.Applied != nil && st.Applied.SSH != nil {
			for _, p := range st.Applied.SSH.Ports {
				out[p] = "ssh"
			}
		}
	}
	if s.d.Certificates != nil {
		if r := s.d.Certificates.Redirect(); r != nil {
			out[api.ACMEChallengePort(r.Challenge)] = "the ACME challenge"
		}
	}
	return out
}

// hostAddrSet are the addresses of the host's interfaces.
func (s *Service) hostAddrSet() (map[netip.Addr]bool, error) {
	list := s.d.HostAddrs
	if list == nil {
		list = interfaceAddrs
	}
	addrs, err := list()
	if err != nil {
		return nil, err
	}
	set := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		set[a.Unmap()] = true
	}
	return set, nil
}

func interfaceAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}

// requireGlobalForForward refuses a caller that is not a global administrator: a published port takes traffic that
// would reach the host.
func requireGlobalForForward(ctx context.Context, what string) error {
	if isGlobalAdmin(ActorFrom(ctx)) {
		return nil
	}
	return api.Errorf(api.CodeForbidden, "%s is granted by a global administrator only", what).
		WithHint("a forward publishes a port of the host to the network and takes the traffic that would reach the host")
}

// checkForward refuses a published port that the host itself needs: a host port that some service of the host listens
// on, or a listen address that is not an address of this host. what names the rule or device for the message.
func (s *Service) checkForward(ctx context.Context, what, listen string, port int) error {
	if svc, ok := s.reservedHostPorts(ctx)[port]; ok {
		return invalid("%s: host port %d is where %s listens on this host: a forward there would take it over", what, port, svc)
	}
	if listen == "" {
		return nil
	}
	a, err := netip.ParseAddr(listen)
	if err != nil {
		return invalid("%s: listen address %q is not an address", what, listen)
	}
	set, err := s.hostAddrSet()
	if err != nil {
		return internal(err)
	}
	if !set[a.Unmap()] {
		return invalid("%s: listen address %s is not an address of this host: a forward publishes a port on an address the host has", what, listen)
	}
	return nil
}

// checkProxyDevices checks the proxy devices of an effective jail spec against checkForward.
func (s *Service) checkProxyDevices(ctx context.Context, who string, proxies []api.ProxyDevice) error {
	for _, p := range proxies {
		host, port, err := validate.ParseListen(p.Listen)
		if err != nil {
			return invalid("%s: proxy %q: %v", who, p.Name, err)
		}
		if err := s.checkForward(ctx, fmt.Sprintf("%s: proxy %q", who, p.Name), host, port); err != nil {
			return err
		}
	}
	return nil
}

// checkRedirectRules requires a global administrator for the port forwards of a policy and checks each against
// checkForward: a forward opens the host's own uplink to the network and takes traffic that would reach the host. A
// forward the stored policy (was) already has is not asked for again, so that an administrator of the project can edit the
// other rules of the policy; a forward that is new or changed is.
func (s *Service) checkRedirectRules(ctx context.Context, spec api.FirewallPolicySpec, was *api.FirewallPolicySpec) error {
	had := func(r api.FirewallRule) bool {
		if was == nil {
			return false
		}
		for _, o := range was.Rules {
			if o.Redirect != nil && *o.Redirect == *r.Redirect && o.Proto == r.Proto && slices.Equal(o.From, r.From) {
				return true
			}
		}
		return false
	}
	for i, r := range spec.Rules {
		if r.Redirect == nil {
			continue
		}
		if !had(r) {
			if err := requireGlobalForForward(ctx, fmt.Sprintf("rule %d, which forwards a host port into a jail", i+1)); err != nil {
				return err
			}
		}
		if err := s.checkForward(ctx, fmt.Sprintf("rule %d", i+1), r.Redirect.Listen, r.Redirect.HostPort); err != nil {
			return err
		}
	}
	return nil
}
