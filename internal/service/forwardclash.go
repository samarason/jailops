package service

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// A forward is a host port that a proxy device of a jail or a redirect rule of one of the policies a jail is rendered
// with sends to the jail. Two jails that forward the same port leave the second one dead without a word (pf takes the
// first anchor that matches), so the second is refused when it is made, naming the first.
type forward struct {
	key    string // proto/listen/port, as proxyKey writes it
	jail   string // the qualified key of the jail that has it
	source string // "proxy NAME" or "rule N of policy NAME"
}

// policyOverride is a policy that is being stored: for the jails of its project it replaces the policy of that name.
type policyOverride struct {
	project, name string
	spec          api.FirewallPolicySpec
}

// forwardsOf lists the forwards a jail with the effective spec eff has: its proxy devices and the redirect rules of its
// policies (the project's mandatory ones and its own). ov, when set, replaces the spec of the policy it names.
func (s *Service) forwardsOf(project, jailKey string, eff api.JailSpec, ov *policyOverride) []forward {
	var out []forward
	for _, p := range eff.Proxy {
		if k, err := proxyKey(p.Listen, p.Proto); err == nil {
			out = append(out, forward{key: k, jail: jailKey, source: "proxy " + p.Name})
		}
	}
	var names []string
	if po, err := s.projKind.get(project); err == nil {
		names = append(names, po.Spec.FirewallPolicies...)
	}
	names = append(names, eff.Firewall.Policies...)
	for _, n := range names {
		var spec api.FirewallPolicySpec
		if ov != nil && ov.project == project && ov.name == n {
			spec = ov.spec
		} else {
			o, err := s.polKind.p(project).get(n)
			if err != nil {
				continue
			}
			spec = o.Spec
		}
		for i, r := range spec.Rules {
			if r.Redirect == nil || r.Disabled {
				continue
			}
			proto := r.Proto
			if proto == "" {
				proto = "tcp"
			}
			out = append(out, forward{key: proto + "/" + r.Redirect.Listen + "/" + strconv.Itoa(r.Redirect.HostPort), jail: jailKey,
				source: "rule " + strconv.Itoa(i+1) + " of policy " + n})
		}
	}
	return out
}

// clashOf returns the first forward of mine that another jail's forward takes, as an error that names both.
func clashOf(mine, others []forward) error {
	for _, m := range mine {
		for _, o := range others {
			if o.jail == m.jail || !portClash(m.key, o.key) {
				continue
			}
			_, name := validate.SplitQualified(o.jail)
			_, me := validate.SplitQualified(m.jail)
			return api.Errorf(api.CodeAlreadyExists, "host port %s is already forwarded to jail %q (%s): %s of jail %q would be dead, because the first forward wins",
				hostPortOf(m.key), name, o.source, m.source, me).
				WithDetail("jail", name).WithDetail("forward", o.source)
		}
	}
	return nil
}

// hostPortOf prints the key proto/listen/port as "tcp 8080" or "tcp 192.0.2.1:8080".
func hostPortOf(key string) string {
	first, last := strings.Index(key, "/"), strings.LastIndex(key, "/")
	if first < 0 || last <= first {
		return key
	}
	proto, host, port := key[:first], key[first+1:last], key[last+1:]
	if host == "" {
		return proto + " " + port
	}
	return proto + " " + host + ":" + port
}

// checkForwardClash refuses a jail whose forwards another jail already has.
func (s *Service) checkForwardClash(project, jailKey string, eff api.JailSpec) error {
	mine := s.forwardsOf(project, jailKey, eff, nil)
	if len(mine) == 0 {
		return nil
	}
	return clashOf(mine, s.otherForwards(jailKey, nil))
}

// otherForwards are the forwards of every jail but self, every project included (the uplink is one).
func (s *Service) otherForwards(self string, ov *policyOverride) []forward {
	s.mu.RLock()
	jails := make(map[string]api.Jail, len(s.jails))
	for k, e := range s.jails {
		if k != self {
			jails[k] = e.jail
		}
	}
	s.mu.RUnlock()
	keys := make([]string, 0, len(jails))
	for k := range jails {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []forward
	for _, k := range keys {
		j := jails[k]
		out = append(out, s.forwardsOf(j.Metadata.Project, k, s.effective(j), ov)...)
	}
	return out
}

// checkPolicyForwardClash refuses a policy whose redirect rules take a host port that a jail it is rendered with
// shares with another jail: the policy is the project's mandatory one (every jail of the project has it, so a second jail
// forwards the same port) or a jail's own policy, or another jail forwards the port already.
func (s *Service) checkPolicyForwardClash(ctx context.Context, name string, spec api.FirewallPolicySpec) error {
	has := false
	for _, r := range spec.Rules {
		has = has || r.Redirect != nil && !r.Disabled
	}
	if !has {
		return nil
	}
	p, err := s.access(ctx)
	if err != nil {
		return err
	}
	project := p.Meta.Name
	ov := &policyOverride{project: project, name: name, spec: spec}
	s.mu.RLock()
	users := map[string]api.Jail{}
	for k, e := range s.jails {
		if e.jail.Metadata.Project == project {
			users[k] = e.jail
		}
	}
	s.mu.RUnlock()
	var mine []forward
	for k, j := range users {
		for _, f := range s.forwardsOf(project, k, s.effective(j), ov) {
			if strings.HasSuffix(f.source, " of policy "+name) {
				mine = append(mine, f)
			}
		}
	}
	sort.Slice(mine, func(a, b int) bool { return mine[a].jail+mine[a].source < mine[b].jail+mine[b].source })
	return clashOf(mine, append(s.otherForwards("", ov), mine...))
}
