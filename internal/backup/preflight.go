package backup

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"

	"jailops.net/jailops/sdk/api"
)

// JailRef is a jail that already exists on the target host.
type JailRef struct {
	Name string
	UUID string
}

// HostState is what Preflight needs to know about the target host. Gathering
// it is the caller's job; Preflight itself is pure and changes nothing.
type HostState struct {
	// Generations maps a generation name ("freebsd-15.1#g3") to its manifest.
	Generations map[string]string
	Networks    map[string]api.NetworkSpec
	Policies    map[string]api.FirewallPolicySpec
	AddressSets map[string]api.AddressSetSpec
	// Volumes are the volumes of the target project. A backup holds a jail, not the volumes it attaches.
	Volumes map[string]bool
	Jails   map[string]JailRef // by name
	Leases  []api.Lease        // addresses in use
	Secrets map[string]bool    // sealed secrets present
	// KeyDomains are the master key domains this host holds, or can unwrap
	// from escrow with the recovery key.
	KeyDomains map[string]bool
}

// Preflight implements the restore closure rules (design section 9.7). It lists
// what is missing, what would change, and conflicts. Nothing executes.
// Everything creatable from the bundle goes to Missing and Changes; things
// that cannot be created (secrets, keys) also go to Errors. OK means no errors.
func Preflight(b api.Backup, req api.RestoreRequest, h HostState) api.RestorePreflight {
	var missing, changes, errs []string
	bundle := b.Spec.Bundle
	spec := bundle.Spec
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	miss := func(f string, a ...any) { missing = append(missing, fmt.Sprintf(f, a...)) }
	chg := func(f string, a ...any) { changes = append(changes, fmt.Sprintf(f, a...)) }

	target := b.Spec.Jail
	if req.As != "" {
		target = req.As
	}
	if !validID(target) {
		fail("invalid jail name %q", target)
	}
	// Name and identity.
	existing, taken := h.Jails[target]
	switch {
	case taken && !req.Replace:
		fail("a jail named %q already exists; use as=<new name> or replace", target)
	case taken && req.Replace:
		if req.As == "" && existing.UUID != "" && b.Spec.JailUUID != "" && existing.UUID != b.Spec.JailUUID {
			fail("jail %q has uuid %s, the backup is of %s; replace needs the same jail", target, existing.UUID, b.Spec.JailUUID)
		}
		chg("replace jail %q (its current datasets are snapshotted first)", target)
	default:
		chg("create jail %q", target)
	}
	if !req.Replace {
		chg("assign a new uuid to the restored jail")
	} else {
		chg("keep uuid %s", b.Spec.JailUUID)
	}

	// Image generation.
	if bundle.ImageGeneration == "" {
		fail("bundle names no image generation")
	} else if m, ok := h.Generations[bundle.ImageGeneration]; !ok {
		miss("image generation %s", bundle.ImageGeneration)
		chg("import image generation %s (manifest %s)", bundle.ImageGeneration, bundle.ImageManifest)
	} else if m != bundle.ImageManifest {
		fail("image generation %s exists with manifest %s, the backup needs %s", bundle.ImageGeneration, m, bundle.ImageManifest)
	}

	// Bundle completeness.
	netNames := NetworkNames(spec)
	if !slices.Equal(bundle.NetworkNames, netNames) || len(bundle.Networks) != len(netNames) {
		fail("bundle has networks %v (%d frozen) but the jail attaches %v", bundle.NetworkNames, len(bundle.Networks), netNames)
	}
	if len(bundle.AddressSets) != len(bundle.AddressSetNames) {
		fail("bundle has %d address sets but %d names", len(bundle.AddressSets), len(bundle.AddressSetNames))
	}
	if len(bundle.Policies) != len(bundle.PolicyNames) {
		fail("bundle has %d policies but %d names", len(bundle.Policies), len(bundle.PolicyNames))
	}
	for _, pn := range spec.Firewall.Policies {
		if !slices.Contains(bundle.PolicyNames, pn) {
			fail("bundle lacks firewall policy %q", pn)
		}
	}
	// The volumes a jail attaches belong to its project, not to the jail: a jail backup holds the attachments, and
	// each volume is a backup of its own. The caller (internal/hostbackup) marks the volumes it brings back or leaves
	// out as present; one that is neither must exist where the jail is restored (the jail does not start without it).
	for _, v := range spec.Volumes {
		if !h.Volumes[v.Name] {
			miss("volume %s (attached at %s)", v.Name, v.Mount)
			chg("volume %s is not in the project and no backup of it was found: the jail attaches it, and does not start until the volume exists", v.Name)
		}
	}

	// network_map must reference real names on both sides.
	inSpec := map[string]int{}
	for i, n := range netNames {
		inSpec[n] = i
	}
	keys := make([]string, 0, len(req.NetworkMap))
	for k := range req.NetworkMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := inSpec[k]; !ok {
			fail("network_map names %q, which the jail does not use", k)
		} else if _, ok := h.Networks[req.NetworkMap[k]]; !ok {
			fail("network_map sends %q to %q, which does not exist on the target", k, req.NetworkMap[k])
		}
	}

	// Networks and addresses.
	mapped := map[string]string{}
	for i, n := range netNames {
		local := n
		if m, ok := req.NetworkMap[n]; ok {
			local = m
		}
		mapped[n] = local
		hostNet, have := h.Networks[local]
		if !have {
			if _, wasMapped := req.NetworkMap[n]; !wasMapped && i < len(bundle.Networks) {
				miss("network %s", n)
				chg("create network %s from the frozen copy", n)
			}
			continue
		}
		if i < len(bundle.Networks) && !sameNetwork(hostNet, bundle.Networks[i]) && local == n {
			chg("network %s exists with a different definition; the existing one is used", n)
		}
	}
	leases := map[string]string{} // "net|addr" -> jail
	for _, l := range h.Leases {
		leases[l.Network+"|"+l.Address] = l.Jail
	}
	for _, a := range spec.Network {
		local := mapped[a.Network]
		hostNet, have := h.Networks[local]
		if !have {
			hostNet, have = netFromBundle(bundle, netNames, a.Network)
		}
		for _, addr := range []string{a.IPv4, a.IPv6} {
			if addr == "" || addr == "auto" || addr == "none" {
				continue
			}
			if !req.KeepIP {
				chg("address %s on %s is re-allocated from the target network", addr, local)
				continue
			}
			if have && !inNetwork(hostNet, addr) {
				fail("keep_ip: %s is outside network %s on the target", addr, local)
				continue
			}
			if owner, used := leases[local+"|"+addr]; used && !(req.Replace && owner == target) {
				fail("%s: address %s on %s is used by jail %q", api.CodeIPConflict, addr, local, owner)
				continue
			}
			chg("keep address %s on %s", addr, local)
		}
		if a.MAC != "" && !req.Replace {
			chg("clear fixed MAC %s; a new MAC is derived from the new uuid", a.MAC)
		}
	}

	// Firewall.
	for i, pn := range bundle.PolicyNames {
		if i >= len(bundle.Policies) || !slices.Contains(spec.Firewall.Policies, pn) {
			continue
		}
		if hp, ok := h.Policies[pn]; !ok {
			miss("firewall policy %s", pn)
			chg("create firewall policy %s from the frozen copy", pn)
		} else if !reflect.DeepEqual(hp, bundle.Policies[i]) {
			chg("firewall policy %s exists with different rules; the existing policy is used", pn)
		}
	}
	for i, n := range bundle.AddressSetNames {
		if i >= len(bundle.AddressSets) {
			break
		}
		if hs, ok := h.AddressSets[n]; !ok {
			miss("address set %s", n)
			chg("create address set %s from the frozen copy", n)
		} else if !reflect.DeepEqual(hs, bundle.AddressSets[i]) {
			chg("address set %s exists with different members; the existing set is used", n)
		}
	}

	// Secrets and keys cannot be created from the bundle.
	for _, s := range bundle.SecretRefs {
		if !h.Secrets[s] {
			miss("secret %s", s)
			fail("sealed secret %s is not present on the target", s)
		}
	}
	switch d := b.Spec.KeyDomain; {
	case d == "":
		fail("backup records no key domain; cannot tell which key decrypts it")
	case !h.KeyDomains[d]:
		miss("encryption key domain %s", d)
		fail("backup needs key domain %s, which the target does not hold; unwrap it from the escrow with the recovery key", d)
	}
	if b.Status.Failed {
		fail("backup %s failed verification (a chunk is missing or corrupt) and cannot be restored", b.Spec.Snapshot)
	}
	sort.Strings(missing)
	return api.RestorePreflight{OK: len(errs) == 0, Missing: missing, Changes: changes, Errors: errs}
}

func sameNetwork(a, b api.NetworkSpec) bool { return reflect.DeepEqual(a, b) }

func netFromBundle(b api.RestoreBundle, names []string, n string) (api.NetworkSpec, bool) {
	for i, nn := range names {
		if nn == n && i < len(b.Networks) {
			return b.Networks[i], true
		}
	}
	return api.NetworkSpec{}, false
}

func inNetwork(n api.NetworkSpec, addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	var cidr string
	switch {
	case a.Is4() && n.IPv4 != nil:
		cidr = n.IPv4.Subnet
	case a.Is6() && n.IPv6 != nil:
		cidr = n.IPv6.Subnet
	default:
		return false
	}
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Contains(a)
}
