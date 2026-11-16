package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// What 'firewall validate --review' adds: the warnings a reviewer of the firewall would raise. They never change the
// exit status. The documents of the file are what is reviewed; the objects on the server say what else uses them.

// reviewInput is what the review reads: the documents of the file, and, when a server answered, what is there.
type reviewInput struct {
	pols       map[string]api.FirewallPolicySpec // the policies of the file
	sets       map[string]api.AddressSetSpec     // the address sets of the file
	allPols    map[string]api.FirewallPolicySpec // the policies of the file and of the server
	allSets    map[string]api.AddressSetSpec     // the address sets of the file and of the server
	jails      []api.Jail                        // the jails of the project, when a server answered
	projPols   []string                          // the mandatory policies of the project, when it could be read
	online     bool                              // a server answered
	projectSet bool                              // the project was read
}

// loadReview reads the objects the review compares the file with. Nothing is read offline.
func loadReview(ctx context.Context, c *sdk.Client, in *reviewInput) {
	pols, err := collect(c.Firewall().Policies().List(ctx))
	if err != nil {
		return
	}
	for _, p := range pols {
		if _, dup := in.allPols[p.Metadata.Name]; !dup {
			in.allPols[p.Metadata.Name] = p.Spec
		}
	}
	jails, err := collect(c.Jails().List(ctx))
	if err != nil {
		return
	}
	in.jails, in.online = jails, true
	if len(jails) > 0 {
		if pr, err := c.Projects().Get(ctx, jails[0].Metadata.Project); err == nil {
			in.projPols, in.projectSet = pr.Spec.FirewallPolicies, true
		}
	}
}

// reviewFindings lists the warnings.
func reviewFindings(in reviewInput) []finding {
	var out []finding
	warn := func(doc, f string, a ...any) {
		out = append(out, finding{doc, "warning", "review: " + fmt.Sprintf(f, a...)})
	}
	jailExists := func(n string) bool {
		return slices.ContainsFunc(in.jails, func(j api.Jail) bool { return j.Metadata.Name == n })
	}
	used := map[string]bool{} // the address sets some rule or set names
	note := func(entry string) {
		if n, ok := strings.CutPrefix(entry, "set:"); ok {
			used[n] = true
		}
	}
	for _, p := range in.allPols {
		for _, r := range p.Rules {
			for _, e := range slices.Concat(r.From, r.To) {
				note(e)
			}
		}
	}
	for _, s := range in.allSets {
		for _, e := range s.Addresses {
			note(e.Address)
		}
	}
	for _, name := range sortedKeys(in.pols) {
		p, doc := in.pols[name], "policy/"+name
		if p.Comment == "" {
			warn(doc, "the policy has no comment: say what it is for")
		}
		for i, r := range p.Rules {
			at := fmt.Sprintf("rules[%d]", i)
			if r.Name != "" {
				at += " (" + r.Name + ")"
			}
			if r.Comment == "" {
				warn(doc, "%s has no comment: say why it is there", at)
			}
			if r.Disabled {
				warn(doc, "%s is disabled: delete it, or switch it on", at)
			}
			if reviewBroad(r) {
				warn(doc, "%s is very broad: %s %s to or from any address, with no port", at, r.Action, r.Direction)
			}
			for _, e := range slices.Concat(r.From, r.To) {
				if n, ok := strings.CutPrefix(e, "jail:"); ok && in.online && !jailExists(n) {
					warn(doc, "%s names jail:%s, which does not exist: it matches nobody", at, n)
				}
			}
		}
		if in.online && in.projectSet && !reviewUsed(name, in) {
			warn(doc, "no jail and no project uses this policy")
		}
	}
	for _, name := range sortedKeys(in.sets) {
		s, doc := in.sets[name], "address-set/"+name
		if s.Comment == "" {
			warn(doc, "the address set has no comment: say what it is")
		}
		for _, e := range s.Addresses {
			if e.Comment == "" {
				warn(doc, "the member %s has no comment: say what it is", e.Address)
			}
			if n, ok := strings.CutPrefix(e.Address, "jail:"); ok && in.online && !jailExists(n) {
				warn(doc, "the member jail:%s does not exist: it matches nobody", n)
			}
		}
		if !used[name] {
			warn(doc, "no rule and no address set refers to set:%s", name)
		}
	}
	if !in.online {
		out = append(out, finding{"review", "warning", "review: no server answered, so it was not checked whether the jails named by jail: exist, whether a policy is used by a jail or by the project, or whether the sets are used by objects that are not in the file"})
	}
	return out
}

// reviewBroad says whether a rule is very broad: it allows traffic with any address, whatever the port.
func reviewBroad(r api.FirewallRule) bool {
	if r.Action != "allow" || len(r.Ports) > 0 || r.Proto == "icmp" || r.Proto == "icmp6" {
		return false
	}
	other := r.From
	if r.Direction == "out" {
		other = r.To
	}
	return len(other) == 0 || slices.Contains(other, "any")
}

// reviewUsed says whether a jail or the project uses the policy.
func reviewUsed(name string, in reviewInput) bool {
	if slices.Contains(in.projPols, name) {
		return true
	}
	return slices.ContainsFunc(in.jails, func(j api.Jail) bool { return slices.Contains(j.Spec.Firewall.Policies, name) })
}
