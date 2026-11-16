package service

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/mounts"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// Names for the jails through the host's resolver, the base system's local-unbound (docs/dns.md). Nothing is configured:
// when local_unbound is enabled and its conf.d is root's, the helper writes the names of the running jails there,
// NAME.PROJECT.internal, together with the lines unbound needs to answer the jails, and the jails ask the gateway with
// a search domain of their project. `unbound-conf =` (empty) in priv.conf turns it off, a path points it at another
// file (a plain unbound with unbound-control). Off or not set up, nothing here does anything.

// unboundState is what the service knows of it: whether it is on, and what the last write found.
type unboundState struct {
	mu      sync.Mutex
	known   bool
	enabled bool
	suffix  string   // the zone suffix of the names, as the helper has it
	forward []string // where the host resolver sends every other name
	recurse bool     // or it resolves them itself
	checked time.Time
	sig     string    // what the names were last written for
	synced  time.Time // and when
}

// unboundRecheck is how long the answer "is it on" is kept, and the longest the names go without a look.
const unboundRecheck = 10 * time.Minute

// unboundCached says whether the names are on, as last found (false until the first look): the render of a jail's
// resolv.conf asks it and must not wait for the helper.
func (s *Service) unboundCached() bool {
	s.unbound.mu.Lock()
	defer s.unbound.mu.Unlock()
	return s.unbound.known && s.unbound.enabled
}

// localUnboundEnabled says whether the host runs the base system's local-unbound (local_unbound_enable in rc.conf):
// the jails ask the gateway only when something answers there.
func (s *Service) localUnboundEnabled() bool {
	for _, f := range []string{"/etc/rc.conf.local", "/etc/rc.conf"} {
		b, err := s.hostFile(f)
		if err != nil {
			continue
		}
		on := false
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if v, ok := strings.CutPrefix(l, "local_unbound_enable="); ok {
				on = strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "YES")
			}
		}
		if on {
			return true
		}
	}
	return false
}

// namesOn says whether the names are on for what the helper found: it is available, and when it is the file of
// local-unbound that unbound runs.
func (s *Service) namesOn(st mounts.UnboundState) bool {
	return st.Enabled && (!st.Base || s.localUnboundEnabled())
}

// unboundOn asks the helper whether unbound-conf is set (every ten minutes at most). When the answer changes, the
// jails that run get the resolv.conf that goes with it.
func (s *Service) unboundOn(ctx context.Context) bool {
	u := &s.unbound
	u.mu.Lock()
	if u.known && time.Since(u.checked) < unboundRecheck {
		on := u.enabled
		u.mu.Unlock()
		return on
	}
	was, wasKnown := u.enabled, u.known
	u.mu.Unlock()
	st, err := s.d.Files.DNSUnbound(ctx, false)
	if err != nil {
		return was
	}
	u.mu.Lock()
	on := s.namesOn(st)
	u.known, u.enabled, u.checked = true, on, time.Now()
	u.suffix, u.forward, u.recurse = st.Suffix, st.Forward, st.Recurse
	u.mu.Unlock()
	if wasKnown && was != on {
		go s.liveResolvAll(s.baseCtx)
	}
	return on
}

// liveResolvAll writes the resolv.conf of every running jail again (the names went on or off).
func (s *Service) liveResolvAll(ctx context.Context) {
	nets, _ := s.netKind.list()
	for _, o := range nets {
		if up, failed := s.liveResolv(ctx, o.Meta.Name); len(up)+len(failed) > 0 {
			s.log.Info("resolv.conf written again for the names of the jails", "network", o.Meta.Name, "jails", len(up), "failed", len(failed))
		}
	}
}

// SyncDNS writes the names of the running jails for unbound when they changed: it is called after each pass of the
// reconcile loop, and does nothing but compare a short signature of what runs unless something changed (or ten
// minutes passed). A failure is logged and shown by doctor; it never stops a jail from starting.
func (s *Service) SyncDNS(ctx context.Context) {
	if s.d.Files == nil || !s.unboundOn(ctx) {
		return
	}
	sig := s.dnsSignature(ctx)
	u := &s.unbound
	u.mu.Lock()
	if sig == u.sig && time.Since(u.synced) < unboundRecheck {
		u.mu.Unlock()
		return
	}
	u.mu.Unlock()
	st, err := s.d.Files.DNSUnbound(ctx, true)
	switch {
	case err != nil:
		s.log.Warn("the names of the jails could not be written for unbound", "err", err)
		return
	case st.Control != "":
		s.log.Warn("unbound did not take the names of the jails", "file", st.Path, "unbound-control", st.Control)
	case st.Changed:
		s.log.Info("the names of the jails were written for unbound", "file", st.Path, "addresses", st.Names)
	}
	u.mu.Lock()
	if st.Control == "" {
		u.sig, u.synced = sig, time.Now()
	}
	u.mu.Unlock()
}

// dnsSignature is a short text of what the names depend on: the running jails with their addresses, and the networks
// they use. Two equal signatures mean the file the helper would write is the same.
func (s *Service) dnsSignature(ctx context.Context) string {
	run := s.runningJails(ctx)
	var parts []string
	s.mu.RLock()
	for k, e := range s.jails {
		if _, up := run[k]; !up {
			continue
		}
		for _, a := range e.jail.Spec.Network {
			parts = append(parts, k+" "+a.Network+" "+a.IPv4+" "+a.IPv6)
		}
	}
	s.mu.RUnlock()
	nets, _ := s.netKind.list()
	for _, o := range nets { // every network: the resolver listens on all of them, running jail or not
		line := "net " + o.Meta.Name
		if v4 := o.Spec.IPv4; v4 != nil {
			line += " " + v4.Subnet + " " + v4.Gateway
		}
		if v6 := o.Spec.IPv6; v6 != nil {
			line += " " + v6.Subnet + " " + string(v6.Mode)
		}
		parts = append(parts, line)
	}
	slices.Sort(parts)
	return strings.Join(parts, "\n")
}

// doctorUnbound reports the names of the jails: not used (the host resolver is not local-unbound, or is not set up),
// or on: the file is current, the control program answers and a lookup of a running jail's name at the gateway gives
// the jail's address; otherwise a warning with the one thing to do.
func (s *Service) doctorUnbound(ctx context.Context, c *checkSet) {
	if s.d.Files == nil {
		return
	}
	st, err := s.d.Files.DNSUnbound(ctx, false)
	if err != nil {
		c.add("dns.unbound", api.DoctorWarn, "the helper could not say: "+err.Error(), "")
		return
	}
	const notUsed = "the jails have no names: run jailops-setup, or sysrc local_unbound_enable=YES, local-unbound-setup and service local_unbound start"
	switch {
	case st.Path == "":
		c.add("dns.unbound", api.DoctorOK, "off (unbound-conf is empty in priv.conf)", "")
		return
	case st.Base && !s.localUnboundEnabled():
		if st.Reason != "" && !st.Enabled && strings.Contains(st.Reason, "not closed to others") {
			c.add("dns.unbound", api.DoctorWarn, "local-unbound is not enabled and "+st.Reason, "")
			return
		}
		c.add("dns.unbound", api.DoctorWarn, notUsed, "")
		return
	case !st.Enabled:
		c.add("dns.unbound", api.DoctorWarn, "the names are not on: "+st.Reason, "")
		return
	case !st.Current:
		c.add("dns.unbound", api.DoctorWarn, "the names in "+st.Path+" are not those of the running jails; the daemon writes them after its next pass", "wait a minute, or restart jailopsd")
		return
	case st.Control != "":
		hint := "unbound-control must answer: for local-unbound run local-unbound-setup and service local_unbound restart"
		c.add("dns.unbound", api.DoctorWarn, "the names are in "+st.Path+", but the resolver's control program does not answer: "+st.Control, hint)
		return
	case st.Sample == "" || len(st.Gateways) == 0:
		c.add("dns.unbound", api.DoctorOK, "on: no jail with an address runs yet; suffix "+st.Suffix+"; "+upstreamText(st), "")
		return
	}
	f := strings.Fields(st.Sample)
	name, want := f[0], f[1]
	got, why := s.lookupAt(ctx, st.Gateways[0], name)
	if !slices.Contains(got, want) {
		// no name and no address: the doctor is read by users of every project
		msg := "asking the gateway of a network for the name of a running jail does not give its address"
		if why != "" {
			msg += ": " + why
		}
		c.add("dns.unbound", api.DoctorWarn, msg, "the resolver has to listen on the gateway: service local_unbound restart (a new network needs one restart; JailOps does it itself when it writes the file); when another resolver than local-unbound owns port 53 there, stop it or give the network nameservers of its own")
		return
	}
	c.add("dns.unbound", api.DoctorOK, fmt.Sprintf("%d names for %d jails in %d projects; suffix %s; %s", st.Names, st.Jails, st.Projects, st.Suffix, upstreamText(st)), "")
}

// upstreamText says where the host's unbound sends every name that is not a jail's.
func upstreamText(st mounts.UnboundState) string {
	switch {
	case len(st.Forward) > 0:
		return "unbound forwards everything else to " + strings.Join(st.Forward, ", ")
	case st.Recurse:
		return "unbound resolves everything else from the root servers"
	}
	return "unbound's upstream is not known"
}

// lookupAt asks the resolver at addr (port 53) for the addresses of a name, with a short timeout.
func (s *Service) lookupAt(ctx context.Context, addr, name string) ([]string, string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dial := s.d.DialJail
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, net.JoinHostPort(addr, "53"))
	}}
	got, err := r.LookupHost(ctx, name)
	if err != nil {
		return nil, err.Error()
	}
	return got, ""
}

// dnsSearch is the search domain of a jail's resolv.conf: its project, when the names are on and the jail asks the
// gateway (a network with nameservers of its own is the administrator's choice and gets none).
func (s *Service) dnsSearch(src api.DNSSource, project string) []string {
	if src == api.DNSFromGateway && s.unboundCached() {
		return []string{render.UnboundZone(project, s.unbound.suffixNow())}
	}
	return nil
}

// suffixNow is the zone suffix of the names, as last reported by the helper.
func (u *unboundState) suffixNow() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.suffix
}

// fillNames puts what the names look like into the status of a network whose jails ask the gateway.
func (s *Service) fillNames(d *api.NetworkDNS) {
	u := &s.unbound
	u.mu.Lock()
	defer u.mu.Unlock()
	d.Suffix, d.Forward, d.Recurse = u.suffix, slices.Clone(u.forward), u.recurse
}
