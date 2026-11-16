package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// handleFirewallTest answers POST /api/v1/firewall/test. The fake has no renderer, so it reads the policies of the two
// jails directly (the project's policies, then the jail's own, in order; the first matching rule decides, else the
// strictest default); the daemon walks the rendered anchor. The shape of the answer is the daemon's.
func (s *Server) handleFirewallTest(w http.ResponseWriter, r *http.Request) {
	rc := s.info(r)
	var req api.FirewallTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, api.Errorf(api.CodeInvalid, "bad request body: %v", err))
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	var caveats []string
	switch req.Proto {
	case "tcp", "udp":
		if req.Port < 1 || req.Port > 65535 {
			writeErr(w, api.Errorf(api.CodeInvalid, "a %s test needs a port from 1 to 65535", req.Proto))
			return
		}
	case "icmp", "icmp6":
		if req.ICMPType == "" {
			req.ICMPType = "echoreq"
			caveats = append(caveats, "no ICMP type was given: the test is an echo request (ping); other types may meet other rules")
		}
	default:
		writeErr(w, api.Errorf(api.CodeInvalid, "proto %q must be tcp, udp, icmp or icmp6", req.Proto))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	end := func(text string) (*api.Jail, netip.Addr, string) {
		if name, ok := strings.CutPrefix(text, "jail:"); ok {
			if j := s.jails.items[s.jails.keyIn(rc.project, name)]; j != nil {
				var a netip.Addr
				if len(j.Status.Addresses) > 0 {
					a, _ = netip.ParseAddr(strings.SplitN(j.Status.Addresses[0], "/", 2)[0])
				}
				return j, a, text
			}
			return nil, netip.Addr{}, text
		}
		if text == "host" {
			return nil, netip.MustParseAddr("192.0.2.1"), text
		}
		a, _ := netip.ParseAddr(text)
		return nil, a, text
	}
	sj, sa, sl := end(req.From)
	dj, da, dl := end(req.To)
	if sj == nil && dj == nil {
		writeErr(w, api.Errorf(api.CodeInvalid, "neither end is a jail of this project: there is no anchor of this project to test"))
		return
	}
	if strings.HasPrefix(req.From, "jail:") && sj == nil {
		writeErr(w, api.Errorf(api.CodeNotFound, "jail %q not found", strings.TrimPrefix(req.From, "jail:")))
		return
	}
	if strings.HasPrefix(req.To, "jail:") && dj == nil {
		writeErr(w, api.Errorf(api.CodeNotFound, "jail %q not found", strings.TrimPrefix(req.To, "jail:")))
		return
	}
	fam := "inet"
	if da.Is6() {
		fam = "inet6"
	}
	if req.Proto == "icmp" && fam == "inet6" {
		writeErr(w, api.Errorf(api.CodeInvalid, "icmp is the IPv4 protocol").WithHint("test IPv6 with --proto icmp6"))
		return
	}
	if req.Proto == "icmp6" && fam == "inet" {
		writeErr(w, api.Errorf(api.CodeInvalid, "icmp6 is the IPv6 protocol").WithHint("test IPv4 with --proto icmp"))
		return
	}
	c := api.FirewallTestCase{Family: fam, From: sa.String(), To: da.String(), Proto: req.Proto, Port: req.Port, ICMPType: req.ICMPType, Verdict: api.TestPass}
	hop := func(side string, j *api.Jail, dir string) bool {
		h := s.fakeHop(rc.project, j, dir, req, sa, da)
		h.Side, h.Jail, h.Direction = side, j.Metadata.Name, dir
		h.Anchor = "jailops/" + rc.project + "/" + j.Metadata.Name
		c.Hops = append(c.Hops, h)
		c.Verdict = h.Verdict
		return h.Verdict == api.TestPass
	}
	ok := true
	if sj != nil {
		ok = hop("source", sj, "in")
	}
	if ok && dj != nil {
		hop("destination", dj, "out")
	}
	_ = sl
	_ = dl
	writeSync(w, 200, api.FirewallTestResult{Verdict: c.Verdict, Cases: []api.FirewallTestCase{c},
		Caveats: append(caveats, "the answer is for a new connection: a connection that is already open (pf keeps its state) is not asked about")})
}

// fakeHop evaluates the policies of one jail for one direction: "in" is what the jail sends (rules with direction out),
// "out" is what reaches it (rules with direction in).
func (s *Server) fakeHop(project string, j *api.Jail, pfDir string, req api.FirewallTestRequest, src, dst netip.Addr) api.FirewallTestHop {
	want := "in"
	if pfDir == "in" {
		want = "out"
	}
	var names []string
	var project1 []string
	if p := s.projects.items[s.projects.keyIn("", project)]; p != nil {
		project1 = p.Spec.FirewallPolicies
	}
	names = append(append(names, project1...), j.Spec.Firewall.Policies...)
	defaultDeny := false
	// every deny rule of the policies is looked at before any allow rule, and a disabled rule is not looked at
	for _, deny := range []bool{true, false} {
		for _, pn := range names {
			pol := s.policies.items[s.policies.keyIn(project, pn)]
			if pol == nil {
				continue
			}
			for i, rule := range pol.Spec.Rules {
				if rule.Disabled || (rule.Action == "deny") != deny {
					continue
				}
				if rule.Direction != want || rule.Proto != "" && rule.Proto != req.Proto || !portsMatch(rule.Ports, req.Port) {
					continue
				}
				other := src
				list := rule.From
				if want == "out" {
					other, list = dst, rule.To
				}
				if !s.fakeAddrIn(project, list, other) {
					continue
				}
				v := api.TestPass
				if rule.Action == "deny" {
					v = api.TestBlock
				}
				return api.FirewallTestHop{Verdict: v, DecidedBy: &api.FirewallTestRule{Stage: "policy", Policy: pn, ProjectPolicy: containsStr(project1, pn),
					Rule: i + 1, Name: rule.Name, Comment: rule.Comment, PF: fmt.Sprintf("%s %s quick (fake rule)", map[string]string{"allow": "pass", "deny": "block drop"}[rule.Action], pfDir)}}
			}
		}
	}
	for _, pn := range names {
		pol := s.policies.items[s.policies.keyIn(project, pn)]
		if pol == nil {
			continue
		}
		if want == "in" && pol.Spec.DefaultIn == "deny" || want == "out" && pol.Spec.DefaultOut == "deny" {
			defaultDeny = true
		}
	}
	v := api.TestPass
	if defaultDeny {
		v = api.TestBlock
	}
	return api.FirewallTestHop{Verdict: v, DecidedBy: &api.FirewallTestRule{Stage: "default", PF: fmt.Sprintf("%s %s quick all (fake default)", map[string]string{api.TestPass: "pass", api.TestBlock: "block drop"}[v], pfDir)}}
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func portsMatch(specs []string, port int) bool {
	if len(specs) == 0 {
		return true
	}
	for _, p := range specs {
		lo, hi, _ := strings.Cut(p, "-")
		a, _ := strconv.Atoi(lo)
		b := a
		if hi != "" {
			b, _ = strconv.Atoi(hi)
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// fakeAddrIn says whether an address is in a from or to list: any, an address or prefix, set:NAME or jail:NAME.
func (s *Server) fakeAddrIn(project string, list []string, a netip.Addr) bool {
	if len(list) == 0 {
		return true
	}
	for _, e := range list {
		switch {
		case e == "any":
			return true
		case strings.HasPrefix(e, "set:"):
			name := strings.TrimPrefix(e, "set:")
			if set := s.addrsets.items[s.addrsets.keyIn(project, name)]; set != nil {
				for _, m := range set.Spec.Addresses {
					if s.fakeAddrIn(project, []string{m.Address}, a) {
						return true
					}
				}
			}
		case strings.HasPrefix(e, "jail:"):
			name := strings.TrimPrefix(e, "jail:")
			if j := s.jails.items[s.jails.keyIn(project, name)]; j != nil {
				for _, ad := range j.Status.Addresses {
					if p, err := netip.ParsePrefix(ad); err == nil && p.Addr() == a {
						return true
					}
					if x, err := netip.ParseAddr(ad); err == nil && x == a {
						return true
					}
				}
			}
		default:
			if p, err := netip.ParsePrefix(e); err == nil && p.Contains(a) {
				return true
			}
			if x, err := netip.ParseAddr(e); err == nil && x == a {
				return true
			}
		}
	}
	return false
}
