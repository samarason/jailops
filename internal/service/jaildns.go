package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// The nameservers of a jail's resolv.conf, in this order:
//  1. the dns of its networks, when one of them sets it;
//  2. else the host's own nameservers in /etc/resolv.conf that a jail can reach (not loopback, not link-local); the
//     jail reaches them like any other address, through the network's NAT or routing and its firewall policy;
//  3. else, when the host resolves only through loopback (a local cache such as unbound), the gateway address of the
//     jail's first network. That answers only when the administrator lets the cache listen there: JailOps never
//     changes the host's resolver and opens no port for it.
//
// JailOps writes a jail's /etc/resolv.conf only while the file is absent, empty or still has the line
// render.ResolvMarker that JailOps wrote into it: a jail whose file was edited (the line removed) or came with
// content of its own keeps it, at every start and at every change of the network's dns.

// hostResolvPath is the host's resolver configuration. It is world readable; the daemon reads it itself.
const hostResolvPath = "/etc/resolv.conf"

// hostFile reads a world-readable file of the host (resolv.conf, rc.conf, pf.conf) as the daemon's own user.
func (s *Service) hostFile(p string) ([]byte, error) {
	if s.d.HostFile != nil {
		return s.d.HostFile(p)
	}
	return os.ReadFile(p)
}

// hostNameservers reads the nameservers of the host's resolv.conf. usable are those a jail can reach (at most three,
// what the resolver uses); loopback says the host resolves through itself: a loopback or unspecified nameserver, or
// none at all, which the resolver takes as the local host.
func (s *Service) hostNameservers() (usable []netip.Addr, loopback bool, err error) {
	b, err := s.hostFile(hostResolvPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	seen := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		seen++
		a, err := netip.ParseAddr(f[1])
		switch {
		case err != nil:
		case a.IsLoopback() || a.IsUnspecified():
			loopback = true
		case a.Zone() != "" || a.IsLinkLocalUnicast() || a.IsMulticast():
		case len(usable) < 3 && !slices.Contains(usable, a.Unmap()):
			usable = append(usable, a.Unmap())
		}
	}
	return usable, loopback || seen == 0, nil
}

// gatewayResolver is the address of the host on a network that a jail can ask: the IPv4 gateway (the IPv6 gateway is
// link-local and would need a zone, which the resolv.conf of the jail cannot name usefully).
func gatewayResolver(spec api.NetworkSpec) (netip.Addr, bool) {
	if v4 := spec.IPv4; v4 != nil {
		if a, err := netip.ParseAddr(v4.Gateway); err == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// resolvers works out the nameservers of a jail on the given networks (in the order the jail attaches them).
func (s *Service) resolvers(nets []api.NetworkSpec) (api.DNSSource, []netip.Addr) {
	var own []netip.Addr
	for _, n := range nets {
		for _, ds := range n.DNS {
			if a, err := netip.ParseAddr(ds); err == nil && !slices.Contains(own, a) {
				own = append(own, a)
			}
		}
	}
	if len(own) > 0 {
		return api.DNSFromNetwork, own
	}
	if len(nets) == 0 {
		return api.DNSNone, nil
	}
	if s.unboundCached() { // the names of the jails are answered by the host's unbound at the gateway
		for _, n := range nets {
			if gw, ok := gatewayResolver(n); ok {
				return api.DNSFromGateway, []netip.Addr{gw}
			}
		}
	}
	host, loopback, err := s.hostNameservers()
	switch {
	case err != nil:
		return api.DNSNone, nil // doctor says why (network.dns)
	case len(host) > 0:
		return api.DNSFromHost, host
	case loopback:
		for _, n := range nets {
			if gw, ok := gatewayResolver(n); ok {
				return api.DNSFromGateway, []netip.Addr{gw}
			}
		}
	}
	return api.DNSNone, nil
}

// networkDNS is the resolver configuration of the jails of one network, for its status.
func (s *Service) networkDNS(name string, spec api.NetworkSpec) *api.NetworkDNS {
	src, addrs := s.resolvers([]api.NetworkSpec{spec})
	d := &api.NetworkDNS{Source: src}
	for _, a := range addrs {
		d.Nameservers = append(d.Nameservers, a.String())
	}
	if src == api.DNSFromGateway {
		if s.unboundCached() {
			s.fillNames(d)
		} else {
			d.Advice = gatewayDNSAdvice(name, spec)
		}
	}
	return d
}

// gatewayDNSAdvice says what the administrator has to do so that the jails of a network that ask its gateway get an
// answer. JailOps does none of it.
func gatewayDNSAdvice(name string, spec api.NetworkSpec) string {
	gw, ok := gatewayResolver(spec)
	if !ok {
		return ""
	}
	sub := spec.IPv4.Subnet
	return fmt.Sprintf("the host resolves names only through loopback (%s), so the jails of network %s ask the gateway %s; "+
		"JailOps changes nothing on the host: let the resolver listen there, for the base system's unbound a file "+
		"/var/unbound/conf.d/jails.conf with `server:`, `interface: 127.0.0.1`, `interface: ::1`, `interface: %s`, "+
		"`ip-transparent: yes` (it binds the address before the network exists at boot) and `access-control: %s allow`, "+
		"then `service local_unbound restart`; a jail whose policy denies outgoing traffic needs a rule for udp and tcp "+
		"port 53 to %s, and a host pf.conf that blocks traffic to the host itself one passing it in on the interfaces of the jails (the group epair); "+
		"or give the network nameservers of its own (`dns:` in jailops network edit %s)",
		hostResolvPath, name, gw, gw, sub, gw, name)
}

// keepsResolv says whether the jail's existing resolv.conf (at p, read through the file operations that stay inside
// the jail's root) is the jail's own: it has content and no longer the marker line JailOps wrote into it.
func (s *Service) keepsResolv(ctx context.Context, p string) bool {
	b, err := s.d.Files.ReadFile(ctx, p)
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, render.ResolvMarker) {
			return false
		}
	}
	return true
}

// liveResolv writes the resolv.conf of every running jail on a network again, after a change of its dns: the file
// is an ordinary file of the jail's root, and the resolver of the jail reads it again on its next query. A stopped
// jail gets it when it starts. It reports the jails it updated and those it could not.
func (s *Service) liveResolv(ctx context.Context, network string) (updated, failed []string) {
	run := s.runningJails(ctx)
	s.mu.RLock()
	var jails []api.Jail
	for k, e := range s.jails {
		if _, up := run[k]; !up {
			continue
		}
		for _, a := range e.jail.Spec.Network {
			if a.Network == network {
				jails = append(jails, cloneJail(e.jail))
				break
			}
		}
	}
	s.mu.RUnlock()
	slices.SortFunc(jails, func(a, b api.Jail) int { return strings.Compare(jailKey(a), jailKey(b)) })
	for _, j := range jails {
		show := jailDisplay(j.Metadata.Project, j.Metadata.Name)
		if err := s.writeJailResolv(ctx, j); err != nil {
			failed = append(failed, show+": "+err.Error())
			continue
		}
		updated = append(updated, show)
	}
	return updated, failed
}

// errKept is a jail that keeps its own resolv.conf.
var errKept = errors.New("its resolv.conf is its own (the line \"" + render.ResolvMarker + "\" is gone)")

// writeJailResolv renders and writes one running jail's resolv.conf under the jail's lock; a jail busy with another
// operation is left to its next start.
func (s *Service) writeJailResolv(ctx context.Context, j api.Jail) error {
	key := jailKey(j)
	unlock, err := s.locks.tryLock("update resolv.conf of "+key, jailLock(key))
	if err != nil {
		return errors.New("busy with another operation; it gets the change at its next start")
	}
	defer unlock()
	sets, err := s.allRefs(j.Metadata.Project)
	if err != nil {
		return err
	}
	b, err := s.buildJail(ctx, j, sets)
	if err != nil {
		return err
	}
	p := path.Join(s.rootMount(key), guestResolv)
	c, ok := b.guest[p]
	if !ok {
		return nil
	}
	if s.keepsResolv(ctx, p) {
		return errKept
	}
	return s.d.Files.WriteAtomic(ctx, p, []byte(c))
}

// doctorDNS reports, for every network a jail uses, where its jails get their nameservers from. A network whose jails
// ask the gateway is probed once a jail on it runs (the address exists only then): one query from the host to the
// gateway, with a short timeout.
func (s *Service) doctorDNS(ctx context.Context, c *checkSet) {
	nets, _ := s.netKind.list()
	used, running := map[string]bool{}, map[string]bool{}
	run := s.runningJails(ctx)
	s.mu.RLock()
	for k, e := range s.jails {
		_, up := run[k]
		for _, a := range e.jail.Spec.Network {
			used[a.Network] = true
			running[a.Network] = running[a.Network] || up
		}
	}
	s.mu.RUnlock()
	st, hint := api.DoctorOK, ""
	var lines []string
	worse := func(to api.DoctorStatus, h string) {
		if to == api.DoctorWarn && st != api.DoctorWarn {
			st, hint = to, h
		}
	}
	for _, o := range nets {
		name := o.Meta.Name
		if !used[name] {
			continue
		}
		d := s.networkDNS(name, o.Spec)
		ns := strings.Join(d.Nameservers, ", ")
		switch d.Source {
		case api.DNSFromNetwork:
			lines = append(lines, name+": "+ns+" (the network's dns)")
		case api.DNSFromHost:
			lines = append(lines, name+": "+ns+" (the host's nameservers in "+hostResolvPath+")")
		case api.DNSFromGateway:
			if !running[name] {
				lines = append(lines, name+": the gateway "+ns+" (not probed: no jail on it runs)")
				continue
			}
			ok, why := s.probeDNS(ctx, d.Nameservers[0])
			if ok {
				lines = append(lines, name+": the gateway "+ns+" answers DNS")
				continue
			}
			lines = append(lines, name+": the jails ask the gateway "+ns+" (the host resolves only through loopback), and "+why)
			worse(api.DoctorWarn, d.Advice)
		default:
			why := "the network has no gateway address a jail could ask"
			if _, loopback, err := s.hostNameservers(); err != nil {
				why = hostResolvPath + " cannot be read by the daemon: " + err.Error()
			} else if !loopback {
				why = hostResolvPath + " names no nameserver a jail can reach (link-local ones need the host's interface)"
			}
			lines = append(lines, name+": no nameserver, "+why)
			worse(api.DoctorWarn, "give the network nameservers: `dns: [192.0.2.53]` in jailops network edit "+name)
		}
	}
	if len(lines) == 0 {
		return
	}
	c.add("network.dns", st, strings.Join(lines, "; "), hint)
}

// probeDNS sends one query (". NS") to port 53 of addr and waits a second for the answer.
func (s *Service) probeDNS(ctx context.Context, addr string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	dial := s.d.DialJail
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "udp", net.JoinHostPort(addr, "53"))
	if err != nil {
		return false, "it cannot be reached: " + err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	id := uint16(time.Now().UnixNano())
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if _, err := conn.Write(q); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return false, "the host's packet filter refuses the host's own query (pf.conf wants `set skip on lo0`)"
		}
		return false, "the query could not be sent: " + err.Error()
	}
	b := make([]byte, 1500)
	n, err := conn.Read(b)
	switch {
	case err != nil:
		return false, "nothing answers DNS on " + addr + " port 53 (no answer within a second)"
	case n < 12 || b[0] != byte(id>>8) || b[1] != byte(id) || b[2]&0x80 == 0:
		return false, "what answers on " + addr + " port 53 is not DNS"
	}
	switch b[3] & 0x0f {
	case 0:
		return true, ""
	case 5:
		return false, "the resolver on " + addr + " refuses the query: its access control does not admit the network"
	default:
		return false, fmt.Sprintf("the resolver on %s answers with error %d (it cannot resolve names itself)", addr, b[3]&0x0f)
	}
}
