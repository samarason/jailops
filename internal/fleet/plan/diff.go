package plan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/sdk/api"
)

// subsetDiff reports where `have` (the live object) does not satisfy `want`
// (the declared object). Only what the repository declares is compared:
// fields it leaves out are server-defaulted (layout, hostname, allocated
// addresses, ...) and are not drift. Three special cases:
//
//   - an "auto" address is satisfied by any allocated address;
//   - a sealed secret value is compared through the spec hash, not by value,
//     because a server need not return it;
//   - an empty declared map or list matches an absent one.
func subsetDiff(path string, want, have any, out *[]string) {
	switch w := want.(type) {
	case map[string]any:
		hm, _ := have.(map[string]any)
		keys := make([]string, 0, len(w))
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			wv := w[k]
			if isEmpty(wv) {
				continue
			}
			p := k
			if path != "" {
				p = path + "." + k
			}
			if sv, ok := wv.(string); ok && strings.HasPrefix(sv, secrets.SealedPrefix) {
				continue
			}
			hv, ok := hm[k]
			if !ok {
				*out = append(*out, fmt.Sprintf("%s: missing live, want %s", p, show(wv)))
				continue
			}
			subsetDiff(p, wv, hv, out)
		}
	case []any:
		hs, _ := have.([]any)
		if len(w) == 0 {
			return
		}
		if len(hs) != len(w) {
			*out = append(*out, fmt.Sprintf("%s: live %s, want %s", path, show(have), show(want)))
			return
		}
		for i := range w {
			subsetDiff(fmt.Sprintf("%s[%d]", path, i), w[i], hs[i], out)
		}
	case string:
		if strings.HasPrefix(w, secrets.SealedPrefix) {
			return
		}
		if hs, ok := have.(string); ok && w == "auto" && hs != "" {
			return
		}
		if !reflect.DeepEqual(want, have) {
			*out = append(*out, fmt.Sprintf("%s: live %s, want %s", path, show(have), show(want)))
		}
	default:
		if !reflect.DeepEqual(want, have) {
			*out = append(*out, fmt.Sprintf("%s: live %s, want %s", path, show(have), show(want)))
		}
	}
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	s := string(b)
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

// labelDiff reports declared labels the live object lacks or has changed.
func labelDiff(want, have map[string]string) []string {
	var out []string
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if hv, ok := have[k]; !ok {
			out = append(out, fmt.Sprintf("labels.%s: missing live, want %q", k, want[k]))
		} else if hv != want[k] {
			out = append(out, fmt.Sprintf("labels.%s: live %q, want %q", k, hv, want[k]))
		}
	}
	return out
}

// dangers lists the refuse-worthy parts of changing live into want. A delete
// passes want == nil. sync --apply refuses to run them without --force.
func dangers(kind api.Kind, live, want any) []string {
	var out []string
	del := want == nil
	switch kind {
	case api.KindJail:
		l := live.(api.JailSpec)
		if del {
			return []string{"deleting a jail destroys its data"}
		}
		w := want.(api.JailSpec)
		if l.Encrypted && !w.Encrypted {
			out = append(out, "jail encryption would be turned off")
		}
		for _, pn := range l.Firewall.Policies {
			if !slices.Contains(w.Firewall.Policies, pn) {
				out = append(out, fmt.Sprintf("firewall policy %q would be detached", pn))
			}
		}
		if li, wi := imageBase(l.Image), imageBase(w.Image); li != "" && wi != li {
			out = append(out, fmt.Sprintf("image changes from %q to %q (a different base; use a rollout to move between generations)", li, wi))
		}
	case api.KindVolume:
		if del {
			return []string{"deleting a volume destroys its files and its snapshots"}
		}
	case api.KindFirewallPolicy:
		l := live.(api.FirewallPolicySpec)
		if del {
			return []string{"deleting a firewall policy removes the protection of every jail that uses it"}
		}
		w := want.(api.FirewallPolicySpec)
		if len(l.Rules) > 0 && len(w.Rules) == 0 && w.Raw == "" {
			out = append(out, "firewall policy would have no rules")
		}
		if l.DefaultIn != "allow" && w.DefaultIn == "allow" {
			out = append(out, "default_in changes to allow (inbound opens)")
		}
	case api.KindAddressSet:
		l := live.(api.AddressSetSpec)
		if del {
			return []string{"deleting an address set silently empties every rule that references it"}
		}
		w := want.(api.AddressSetSpec)
		if len(l.Addresses) > 0 && len(w.Addresses) == 0 {
			out = append(out, "address set would become empty")
		}
	case api.KindNetwork:
		l := live.(api.NetworkSpec)
		if del {
			return []string{"deleting a network disconnects its jails"}
		}
		w := want.(api.NetworkSpec)
		if l.IPv4 != nil && w.IPv4 != nil && l.IPv4.Subnet != w.IPv4.Subnet {
			out = append(out, fmt.Sprintf("ipv4 subnet changes from %s to %s (renumbers jails)", l.IPv4.Subnet, w.IPv4.Subnet))
		}
		if l.IPv6 != nil && w.IPv6 != nil && l.IPv6.Subnet != w.IPv6.Subnet {
			out = append(out, fmt.Sprintf("ipv6 subnet changes from %s to %s (renumbers jails)", l.IPv6.Subnet, w.IPv6.Subnet))
		}
	case api.KindWireGuard:
		l := live.(api.WireGuardSpec)
		if del {
			return []string{"deleting a WireGuard tunnel removes its interface and its keys: every peer must be enrolled again"}
		}
		w := want.(api.WireGuardSpec)
		for _, p := range l.Peers {
			if !hasPeer(w, p.PublicKey) {
				out = append(out, fmt.Sprintf("peer %q (%s) would be removed from the tunnel", p.Name, p.PublicKey))
			}
		}
		if w.ListenPort != 0 && l.ListenPort != 0 && w.ListenPort != l.ListenPort {
			out = append(out, fmt.Sprintf("listen port changes from %d to %d (every peer's endpoint changes)", l.ListenPort, w.ListenPort))
		}
		if len(w.Address) > 0 && !slices.Equal(w.Address, l.Address) {
			out = append(out, fmt.Sprintf("tunnel address changes from %v to %v", l.Address, w.Address))
		}
	case api.KindProject:
		l := live.(api.ProjectSpec)
		if del {
			return []string{"deleting a project removes its grants and quotas"}
		}
		w := want.(api.ProjectSpec)
		for _, pn := range l.FirewallPolicies {
			if !slices.Contains(w.FirewallPolicies, pn) {
				out = append(out, fmt.Sprintf("the mandatory firewall policy %q would be removed", pn))
			}
		}
		for _, g := range l.Networks {
			if !hasNetworkGrant(w, g.Network) {
				out = append(out, fmt.Sprintf("the grant of network %q would be removed", g.Network))
			}
		}
		for _, g := range l.Storage {
			if !hasStorageGrant(w, g.Storage) {
				out = append(out, fmt.Sprintf("the grant of storage %q would be removed", g.Storage))
			}
		}
	case api.KindStorage:
		l := live.(api.StorageSpec)
		if del {
			return []string{"deleting a storage unregisters the dataset from JailOps"}
		}
		if w := want.(api.StorageSpec); l.Dataset != "" && l.Dataset != w.Dataset {
			out = append(out, fmt.Sprintf("the dataset changes from %s to %s", l.Dataset, w.Dataset))
		}
	case api.KindImage:
		if del {
			return []string{"deleting an image removes its generations"}
		}
	case api.KindBackupTarget:
		l := live.(api.BackupTargetSpec)
		if del {
			return []string{"deleting a backup target stops the backups that use it"}
		}
		w := want.(api.BackupTargetSpec)
		if l.Fingerprint != "" && l.Fingerprint != w.Fingerprint {
			out = append(out, "the pinned certificate of the backup node changes")
		}
	case api.KindBackupPolicy:
		l := live.(api.BackupPolicySpec)
		if del {
			return []string{"deleting a backup policy stops the backups it schedules"}
		}
		w := want.(api.BackupPolicySpec)
		if len(l.Targets) > 0 && len(w.Targets) == 0 {
			out = append(out, "backup policy would have no targets")
		}
		if len(l.Selector) > 0 && len(w.Selector) == 0 {
			out = append(out, "backup policy selector would match no jail")
		}
	}
	return out
}

func imageBase(ref string) string {
	if i := strings.IndexAny(ref, "@#"); i >= 0 {
		return ref[:i]
	}
	return ref
}

func hasNetworkGrant(p api.ProjectSpec, n string) bool {
	for _, g := range p.Networks {
		if g.Network == n || g.Network == "*" {
			return true
		}
	}
	return false
}

func hasPeer(w api.WireGuardSpec, key string) bool {
	for _, p := range w.Peers {
		if p.PublicKey == key {
			return true
		}
	}
	return false
}

func hasStorageGrant(p api.ProjectSpec, n string) bool {
	for _, g := range p.Storage {
		if g.Storage == n || g.Storage == "*" {
			return true
		}
	}
	return false
}
