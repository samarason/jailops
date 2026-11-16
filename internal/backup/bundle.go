package backup

import (
	"encoding/json"
	"sort"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// ObjectSource resolves the objects a jail references, on the host.
type ObjectSource interface {
	Network(name string) (api.NetworkSpec, bool)
	Policy(name string) (api.FirewallPolicySpec, bool)
	AddressSet(name string) (api.AddressSetSpec, bool)
}

// NetworkNames returns the sorted unique networks a spec attaches; the bundle's
// Networks slice is in this order.
func NetworkNames(spec api.JailSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range spec.Network {
		if n.Network != "" && !seen[n.Network] {
			seen[n.Network] = true
			out = append(out, n.Network)
		}
	}
	sort.Strings(out)
	return out
}

func deepCopy[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic("backup: copy: " + err.Error())
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		panic("backup: copy: " + err.Error())
	}
	return out
}

func setRefs(p api.FirewallPolicySpec) []string {
	var refs []string
	for _, r := range p.Rules {
		for _, l := range [][]string{r.From, r.To} {
			for _, a := range l {
				if n, ok := strings.CutPrefix(a, "set:"); ok {
					refs = append(refs, n)
				}
			}
		}
	}
	return refs
}

// BuildBundle freezes a jail's restore closure: the spec, the image generation
// it uses and copies of every network, policy and address set it references,
// with the names of those objects in NetworkNames, PolicyNames and
// AddressSetNames, parallel to Networks, Policies and AddressSets. Frozen
// copies are deep copies; later changes to the live objects do not alter the
// bundle. The result is deterministic.
func BuildBundle(spec api.JailSpec, gen api.ImageGeneration, src ObjectSource, secretRefs []string) (api.RestoreBundle, error) {
	b := api.RestoreBundle{Spec: deepCopy(spec), ImageGeneration: gen.Name, ImageManifest: gen.Manifest}
	if gen.Name == "" || gen.Manifest == "" {
		return b, invalid("image generation needs a name and a manifest")
	}
	for _, n := range NetworkNames(spec) {
		ns, ok := src.Network(n)
		if !ok {
			return b, api.Errorf(api.CodeNotFound, "network %q referenced by the jail does not exist", n)
		}
		b.NetworkNames = append(b.NetworkNames, n)
		b.Networks = append(b.Networks, deepCopy(ns))
	}
	var pending []string
	for _, pn := range spec.Firewall.Policies {
		p, ok := src.Policy(pn)
		if !ok {
			return b, api.Errorf(api.CodeNotFound, "firewall policy %q referenced by the jail does not exist", pn)
		}
		b.PolicyNames = append(b.PolicyNames, pn)
		b.Policies = append(b.Policies, deepCopy(p))
		pending = append(pending, setRefs(p)...)
	}
	seen := map[string]api.AddressSetSpec{}
	for len(pending) > 0 {
		n := pending[0]
		pending = pending[1:]
		if _, dup := seen[n]; dup {
			continue
		}
		as, ok := src.AddressSet(n)
		if !ok {
			return b, api.Errorf(api.CodeNotFound, "address set %q referenced by the policy does not exist", n)
		}
		seen[n] = deepCopy(as)
		for _, m := range as.Members() { // a member set:NAME is another set; jail:NAME is a jail, not part of the closure
			if n, ok := strings.CutPrefix(m, "set:"); ok {
				pending = append(pending, n)
			}
		}
	}
	for n := range seen {
		b.AddressSetNames = append(b.AddressSetNames, n)
	}
	sort.Strings(b.AddressSetNames)
	for _, n := range b.AddressSetNames {
		b.AddressSets = append(b.AddressSets, seen[n])
	}
	for _, v := range spec.Volumes {
		b.Volumes = append(b.Volumes, v.Name)
	}
	sort.Strings(b.Volumes)
	b.SecretRefs = append([]string(nil), secretRefs...)
	sort.Strings(b.SecretRefs)
	return b, nil
}
