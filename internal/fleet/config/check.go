package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/fleet/model"
	"jailops.net/jailops/internal/fleet/vault"
	"jailops.net/jailops/sdk/api"
)

// ImageName returns the image part of an image reference such as
// "freebsd-15.1@stable" or "freebsd-15.1#g3".
func ImageName(ref string) string {
	if i := strings.IndexAny(ref, "@#"); i >= 0 {
		return ref[:i]
	}
	return ref
}

// Check validates references and values across the repository. It collects
// every problem in one pass. Warnings (security-relevant but valid
// configuration) are stored in f.Warnings.
func (f *Fleet) Check() error {
	f.Warnings = nil
	var errs []error
	add := func(o *Object, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", o.Origin, fmt.Sprintf(format, args...)))
	}
	warn := func(o *Object, format string, args ...any) {
		f.Warnings = append(f.Warnings, fmt.Sprintf("RISK: %s: %s", o.Origin, fmt.Sprintf(format, args...)))
	}
	note := func(o *Object, format string, args ...any) {
		f.Warnings = append(f.Warnings, fmt.Sprintf("%s: %s", o.Origin, fmt.Sprintf(format, args...)))
	}

	// Every SOPS file needs a creation_rule, or nobody knows who may decrypt it.
	if f.SopsSecrets != nil {
		if err := vault.CheckCovered(f.Path, vault.SecretsRel); err != nil {
			errs = append(errs, err)
		}
	}
	for _, name := range f.HostNames() {
		if f.Remotes[name] != nil {
			if err := vault.CheckCovered(f.Path, vault.RemoteRel(name)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, name := range f.HostNames() {
		h := f.Hosts[name]
		if t := h.Spec.TokenSecret; t != "" && !f.Secrets[t] {
			errs = append(errs, fmt.Errorf("%s: token_secret %q: no secrets/%s.age", h.Origin, t, t))
		}
		if len(f.ObjectsFor(name)) == 0 {
			f.Warnings = append(f.Warnings, fmt.Sprintf("host %s declares no objects", name))
		}
	}
	if h := f.Meta.Hub; h != nil && h.TokenSecret != "" && !f.Secrets[h.TokenSecret] {
		errs = append(errs, fmt.Errorf("%s: hub token_secret %q: no secrets/%s.age", FleetFile, h.TokenSecret, h.TokenSecret))
	}
	for _, g := range f.GroupNames() {
		grp := f.Groups[g]
		if len(grp.Spec.Members) == 0 && len(grp.Spec.Selector) == 0 {
			errs = append(errs, fmt.Errorf("%s: group has neither members nor selector", grp.Origin))
			continue
		}
		hs, _ := f.ExpandHosts([]string{"@" + g})
		if len(hs) == 0 {
			f.Warnings = append(f.Warnings, fmt.Sprintf("group @%s matches no host", g))
		}
	}
	// A network belongs to one project: two projects granting the same network on one host is an error.
	holder := map[string]string{} // host/network -> project
	for _, pn := range f.ProjectNames() {
		pd := f.Projects[pn]
		for _, g := range pd.Spec.Networks {
			for _, h := range pd.Hosts {
				k := h + "/" + g.Network
				if other, ok := holder[k]; ok && other != pn {
					errs = append(errs, fmt.Errorf("%s: network %q is already granted to project %s on host %s: a network belongs to one project", pd.Origin, g.Network, other, h))
					continue
				}
				holder[k] = pn
			}
		}
	}
	for _, rn := range f.RolloutNames() {
		r := f.Rollouts[rn]
		if len(r.Spec.Hosts) > 0 {
			if _, err := f.ExpandHosts(r.Spec.Hosts); err != nil {
				errs = append(errs, fmt.Errorf("%s: hosts: %w", r.Origin, err))
			}
		}
	}

	// Per-host name tables for reference checks.
	tables := map[string]map[Key]*Object{}
	for _, h := range f.HostNames() {
		t := map[Key]*Object{}
		for _, o := range f.ObjectsFor(h) {
			t[o.Key()] = o
		}
		tables[h] = t
	}
	for _, rn := range f.RolloutNames() {
		r := f.Rollouts[rn]
		if p := r.Spec.Project; p == "" {
			errs = append(errs, fmt.Errorf("%s: a rollout names the project whose jails it upgrades (spec.project)", r.Origin))
		} else if f.Projects[p] == nil {
			errs = append(errs, fmt.Errorf("%s: project %q is not defined", r.Origin, p))
		}
	}

	for _, o := range f.Objects {
		// The daemon's name rules are narrower than the repository's file-name rule: a name it refuses fails at apply time.
		switch o.Kind {
		case api.KindJail, api.KindVolume, api.KindNetwork, api.KindFirewallPolicy, api.KindWireGuard, model.KindApp, api.KindAppAccess:
			if !api.IsName(o.Name, api.MaxName) {
				add(o, "%s name %q must follow %s (lowercase letters, digits and '-', starting with a letter, not ending in '-')", o.Kind, o.Name, api.NamePattern)
			}
		case api.KindAddressSet:
			if !api.IsName(o.Name, 29) {
				add(o, "address set name %q must follow %s (29 characters at most)", o.Name, api.NamePattern)
			}
		}
		for _, s := range o.SecretRefs {
			if IsSopsRef(s) {
				if !vault.PathExists(f.SopsSecrets, s) {
					add(o, "env refers to secret %q: no such path in %s", s, vault.SecretsRel)
				}
			} else if !f.Secrets[s] {
				add(o, "env refers to secret %q: no secrets/%s.age", s, s)
			}
		}
		// Reference checks are per host: a shared object must resolve on each
		// host it applies to.
		reported := map[string]bool{}
		missing := func(h string, kind api.Kind, project, name string, o *Object, what string) {
			if _, ok := tables[h][Key{kind, project, name}]; ok {
				return
			}
			key := fmt.Sprintf("%s/%s/%s", what, kind, name)
			if reported[key] {
				return
			}
			reported[key] = true
			add(o, "%s refers to unknown %s %q (not declared for host %s)", what, kind, name, h)
		}
		// set:NAME in a rule or as a member of a set is an address set of the project, declared for the host; jail:NAME
		// is a jail of the project, which may be made later (a reference to a jail that does not exist matches nobody)
		missingRef := func(h, project, ref string, o *Object, what string) {
			switch {
			case strings.HasPrefix(ref, "set:"):
				name := strings.TrimPrefix(ref, "set:")
				if _, ok := tables[h][Key{api.KindAddressSet, project, name}]; ok {
					return
				}
				key := fmt.Sprintf("%s/%s", what, ref)
				if reported[key] {
					return
				}
				reported[key] = true
				add(o, "%s refers to %s, which is not an address set declared for host %s", what, ref, h)
			case strings.HasPrefix(ref, "jail:"):
				name := strings.TrimPrefix(ref, "jail:")
				if _, ok := tables[h][Key{api.KindJail, project, name}]; ok {
					return
				}
				key := fmt.Sprintf("%s/%s", what, ref)
				if reported[key] {
					return
				}
				reported[key] = true
				warn(o, "%s refers to %s, which is not a jail declared for host %s: until it exists the reference matches nobody", what, ref, h)
			}
		}
		switch s := o.Spec.(type) {
		case api.JailSpec:
			f.checkJail(o, s, add, warn)
			pdef := f.Projects[o.Project]
			for _, h := range o.Hosts {
				if s.Image != "" {
					missing(h, api.KindImage, "", ImageName(s.Image), o, "image")
				}
				if len(s.Network) == 0 {
					add(o, "a jail needs a network: name one in spec.network or use a profile that has one")
				}
				for _, n := range s.Network {
					name := n.Network
					if name == "" {
						add(o, "a network device names no network: nothing is attached by default")
						continue
					}
					missing(h, api.KindNetwork, "", name, o, "network")
					if pdef != nil && !grantsNetwork(pdef.Spec, name) {
						add(o, "network %q is not granted to project %s", name, o.Project)
					}
				}
				if s.Storage == "" {
					add(o, "a jail needs a storage: name one in spec.storage or use a profile that has one")
				} else if s.Storage != "default" { // the host's built-in storage needs no declaration
					missing(h, api.KindStorage, "", s.Storage, o, "storage")
				}
				if pdef != nil {
					if s.Storage != "" && !grantsStorage(pdef.Spec, s.Storage) {
						add(o, "storage %q is not granted to project %s", s.Storage, o.Project)
					}
					if len(pdef.Spec.Images) > 0 && !slices.Contains(pdef.Spec.Images, ImageName(s.Image)) {
						add(o, "image %q is not in project %s's image allow-list", ImageName(s.Image), o.Project)
					}
				}
				for _, pn := range s.Firewall.Policies {
					missing(h, api.KindFirewallPolicy, o.Project, pn, o, "firewall policy")
					if pdef != nil && slices.Contains(pdef.Spec.FirewallPolicies, pn) {
						add(o, "firewall policy %q is a mandatory policy of project %s: it is rendered for every jail already; name policies of the jail's own", pn, o.Project)
					}
				}
				if seen := map[string]bool{}; len(s.Firewall.Policies) > 1 {
					for _, pn := range s.Firewall.Policies {
						if seen[pn] {
							add(o, "firewall policy %q is listed twice", pn)
						}
						seen[pn] = true
					}
				}
				for _, d := range s.Boot.Depends {
					missing(h, api.KindJail, o.Project, d, o, "boot.depends")
				}
				// a volume may have been made by hand: a jail that names one that is not declared is a warning
				for _, v := range s.Volumes {
					if _, ok := tables[h][Key{api.KindVolume, o.Project, v.Name}]; !ok {
						warn(o, "volumes refers to volume %q, which is not declared for host %s: it must exist there before the jail starts", v.Name, h)
					}
				}
			}
		case api.VolumeSpec:
			pdef := f.Projects[o.Project]
			if s.Encrypted {
				add(o, "an encrypted volume needs a passphrase you type: create it with 'jailops volume create --encrypted' instead of declaring it")
			}
			if s.IsHostDir() || s.Watch || s.Probe != "" || s.OnLoss != "" {
				if _, err := api.CheckHostDirVolume(s); err != nil && !s.Encrypted {
					add(o, "%v", err)
				}
				if s.IsHostDir() {
					note(o, "a volume of a host directory is made and attached by a global administrator, and the directory must be on a mount below an admin-host-mount directory of each host's priv.conf")
				}
			}
			for _, h := range o.Hosts {
				if s.Storage != "" && s.Storage != "default" {
					missing(h, api.KindStorage, "", s.Storage, o, "storage")
				}
				if pdef != nil && s.Storage != "" && !grantsStorage(pdef.Spec, s.Storage) {
					add(o, "storage %q is not granted to project %s", s.Storage, o.Project)
				}
			}
		case model.AppSpec:
			pdef := f.Projects[o.Project]
			for _, h := range o.Hosts {
				if _, dup := tables[h][Key{api.KindJail, o.Project, o.Name}]; dup {
					add(o, "a jail %q is declared too: an app is installed as its own jail", o.Name)
				}
				if s.Image != "" {
					missing(h, api.KindImage, "", ImageName(s.Image), o, "image")
				}
				if s.Network != "" {
					missing(h, api.KindNetwork, "", s.Network, o, "network")
					if pdef != nil && !grantsNetwork(pdef.Spec, s.Network) {
						add(o, "network %q is not granted to project %s", s.Network, o.Project)
					}
				}
				if s.Storage != "" && s.Storage != "default" {
					missing(h, api.KindStorage, "", s.Storage, o, "storage")
				}
				if pdef != nil && s.Storage != "" && !grantsStorage(pdef.Spec, s.Storage) {
					add(o, "storage %q is not granted to project %s", s.Storage, o.Project)
				}
			}
		case model.AppAccessSpec:
			for _, h := range o.Hosts {
				if _, ok := tables[h][Key{model.KindApp, o.Project, o.Name}]; !ok {
					note(o, "no App %q is declared for host %s: the grants apply only if it was installed there", o.Name, h)
				}
				for _, g := range s.Grants {
					c, _ := model.CanonicalSource(g.Source)
					t := tables[h]
					if name, ok := strings.CutPrefix(c, "jail:"); ok {
						_, jail := t[Key{api.KindJail, o.Project, name}]
						_, app := t[Key{model.KindApp, o.Project, name}]
						if !jail && !app {
							note(o, "source %s is neither a jail nor an app declared for host %s: it must exist there", c, h)
						}
					} else if name, ok := strings.CutPrefix(c, "set:"); ok {
						if _, set := t[Key{api.KindAddressSet, o.Project, name}]; !set {
							note(o, "source %s is not an address set declared for host %s: it must exist there", c, h)
						}
					}
				}
			}
		case api.FirewallPolicySpec:
			checkPolicy(o, s, add, warn)
			for _, h := range o.Hosts {
				for _, r := range s.Rules {
					for _, ref := range append(slices.Clone(r.From), r.To...) {
						missingRef(h, o.Project, ref, o, "rule")
					}
				}
			}
		case api.AddressSetSpec:
			checkAddressSet(o, s, add, warn)
			for _, h := range o.Hosts {
				for _, e := range s.Addresses {
					missingRef(h, o.Project, e.Address, o, "member")
				}
			}
			for _, h := range o.Hosts {
				sets := map[string]*Object{}
				for k, v := range tables[h] {
					if k.Kind == api.KindAddressSet && k.Project == o.Project {
						sets[k.Name] = v
					}
				}
				if cyc := setCycle(sets, o.Name, nil); cyc != "" {
					add(o, "address set cycle: %s", cyc)
					break
				}
			}
		case api.NetworkSpec:
			checkNetwork(o, s, add, warn)
		case api.WireGuardSpec:
			checkWireGuard(o, s, add)
			for _, h := range o.Hosts {
				for _, n := range s.Networks {
					missing(h, api.KindNetwork, "", n, o, "networks")
				}
			}
		case api.StorageSpec:
			if s.Dataset == "" || strings.HasPrefix(s.Dataset, "/") || !strings.Contains(s.Dataset, "/") {
				add(o, "spec.dataset is required and names a ZFS dataset such as tank/jailops")
			}
			if s.Encrypted {
				add(o, "spec.encrypted is reserved: native ZFS encryption is not implemented and the daemon refuses it")
			}
		case api.ProjectSpec:
			f.checkProject(o, s, tables, add, warn)
		case api.ImageSpec:
			if s.OS == "" || s.Release == "" || s.Arch == "" || s.Source.Type == "" {
				add(o, "spec.os, release, arch and source.type are required")
			}
		case api.BackupTargetSpec:
			switch s.Kind {
			case "node":
				if s.Address == "" {
					add(o, "a node target needs an address")
				} else if s.Fingerprint == "" {
					add(o, "a node target needs a pinned fingerprint")
				}
			case "directory":
				if s.Path == "" || !strings.HasPrefix(s.Path, "/") {
					add(o, "a directory target needs an absolute path")
				}
			default:
				add(o, "kind must be node or directory, got %q", s.Kind)
			}
		case api.BackupPolicySpec:
			if len(s.Targets) == 0 {
				add(o, "a backup policy needs at least one target")
			}
			if len(strings.Fields(s.Schedule)) != 5 {
				add(o, "schedule %q must be a five-field cron expression", s.Schedule)
			}
			if (s.Retention == api.RetentionPolicy{}) {
				add(o, "retention must keep something")
			}
			if len(s.Selector) == 0 {
				warn(o, "empty selector matches no jail; use the label \"all\" to match every jail")
			}
			for _, h := range o.Hosts {
				for _, t := range s.Targets {
					missing(h, api.KindBackupTarget, "", t, o, "target")
				}
			}
		}
	}
	// Two networks of one host may not overlap, in any project: the daemon refuses the second one at apply time.
	for _, h := range f.HostNames() {
		var nets []*Object
		for _, o := range f.ObjectsFor(h) {
			if o.Kind == api.KindNetwork {
				nets = append(nets, o)
			}
		}
		for i, a := range nets {
			for _, b := range nets[i+1:] {
				for _, pa := range networkPrefixes(a.Spec.(api.NetworkSpec)) {
					for _, pb := range networkPrefixes(b.Spec.(api.NetworkSpec)) {
						if pa.Overlaps(pb) {
							errs = append(errs, fmt.Errorf("%s: network %s (%s) overlaps network %s (%s) on host %s: subnets may not overlap", b.Origin, b.Name, pb, a.Name, pa, h))
						}
					}
				}
			}
		}
	}
	// Tunnels of one host may not share an interface, a listen port or overlapping addresses: the daemon refuses the second.
	for _, h := range f.HostNames() {
		var wgs []*Object
		for _, o := range f.ObjectsFor(h) {
			if o.Kind == api.KindWireGuard {
				wgs = append(wgs, o)
			}
		}
		for i, a := range wgs {
			sa := a.Spec.(api.WireGuardSpec)
			for _, b := range wgs[i+1:] {
				sb := b.Spec.(api.WireGuardSpec)
				if wgIface(a.Name, sa) == wgIface(b.Name, sb) {
					errs = append(errs, fmt.Errorf("%s: tunnel %s uses interface %s like tunnel %s on host %s", b.Origin, b.Name, wgIface(b.Name, sb), a.Name, h))
				}
				if wgPort(sa) != 0 && wgPort(sa) == wgPort(sb) {
					errs = append(errs, fmt.Errorf("%s: tunnel %s uses listen port %d like tunnel %s on host %s", b.Origin, b.Name, wgPort(sb), a.Name, h))
				}
				for _, pa := range wgPrefixes(sa.Address) {
					for _, pb := range wgPrefixes(sb.Address) {
						if pa.Overlaps(pb) {
							errs = append(errs, fmt.Errorf("%s: tunnel %s (%s) overlaps tunnel %s (%s) on host %s", b.Origin, b.Name, pb, a.Name, pa, h))
						}
					}
				}
			}
		}
	}
	// Storage datasets of one host may not be equal or nested: the daemon refuses the second one.
	for _, h := range f.HostNames() {
		var st []*Object
		for _, o := range f.ObjectsFor(h) {
			if o.Kind == api.KindStorage {
				st = append(st, o)
			}
		}
		for i, a := range st {
			for _, b := range st[i+1:] {
				da, db := a.Spec.(api.StorageSpec).Dataset, b.Spec.(api.StorageSpec).Dataset
				if da != "" && db != "" && (da == db || strings.HasPrefix(da, db+"/") || strings.HasPrefix(db, da+"/")) {
					errs = append(errs, fmt.Errorf("%s: storage %s (%s) overlaps storage %s (%s) on host %s: datasets may not be equal or nested", b.Origin, b.Name, db, a.Name, da, h))
				}
			}
		}
	}
	slices.Sort(f.Warnings)
	f.Warnings = slices.Compact(f.Warnings)
	return errors.Join(errs...)
}

func grantsNetwork(p api.ProjectSpec, n string) bool {
	for _, g := range p.Networks {
		if g.Network == n {
			return true
		}
	}
	return false
}

func grantsStorage(p api.ProjectSpec, n string) bool {
	for _, g := range p.Storage {
		if g.Storage == n || g.Storage == "*" {
			return true
		}
	}
	return false
}

func (f *Fleet) checkProject(o *Object, s api.ProjectSpec, tables map[string]map[Key]*Object, add func(*Object, string, ...any), warn func(*Object, string, ...any)) {
	if len(s.Networks) == 0 {
		warn(o, "project %s grants no network: its jails cannot attach to one", o.Name)
	}
	if len(s.Storage) == 0 {
		warn(o, "project %s grants no storage: it cannot hold jails", o.Name)
	}
	for _, g := range s.Networks {
		switch g.Network {
		case "":
			add(o, "a network grant needs a network")
		case "*":
			add(o, "networks are granted one by one: a network belongs to one project, so \"*\" is not allowed")
		}
	}
	for _, g := range s.Storage {
		if g.Storage == "" {
			add(o, "a storage grant needs a storage")
		}
	}
	if s.NewNetwork {
		add(o, "new_network is a create-time convenience of the CLI and is never stored: declare the network in shared/networks/ and grant it under networks")
	}
	if s.Quotas.Jails < 0 || s.Quotas.CPU < 0 || s.Quotas.PIDs < 0 || s.Quotas.Addresses < 0 {
		add(o, "quotas must not be negative")
	}
	if len(s.FirewallPolicies) == 0 {
		warn(o, "project %s has no mandatory firewall policy", o.Name)
	}
	for _, pn := range s.FirewallPolicies {
		for _, h := range o.Hosts {
			if _, ok := tables[h][Key{api.KindFirewallPolicy, o.Name, pn}]; !ok {
				add(o, "mandatory firewall policy %q is not declared in project %s for host %s", pn, o.Name, h)
				break
			}
		}
	}
}

func (f *Fleet) checkJail(o *Object, s api.JailSpec, add func(*Object, string, ...any), warn func(*Object, string, ...any)) {
	if s.Image == "" {
		add(o, "spec.image is required")
	}
	switch s.Update.Strategy {
	case "", api.UpdateRebase, api.UpdateInPlace, api.UpdateManual:
	default:
		add(o, "update.strategy %q is not rebase, inplace or manual", s.Update.Strategy)
	}
	for _, v := range s.Volumes {
		if !strings.HasPrefix(v.Mount, "/") {
			add(o, "volume %q: mount %q must be an absolute path", v.Name, v.Mount)
		}
	}
	for k, v := range s.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") {
			add(o, "env name %q is invalid", k)
		}
		if strings.HasPrefix(v, SecretPrefix) {
			if err := checkSecretRef(strings.TrimPrefix(v, SecretPrefix)); err != nil {
				add(o, "env %s: secret reference: %v", k, err)
			}
		}
	}
	if len(s.Firewall.Policies) == 0 {
		warn(o, "jail %s has no firewall policy", o.Name)
	}
	if s.Encrypted {
		add(o, "spec.encrypted is reserved: native ZFS encryption of jails is not implemented and the daemon refuses it")
	}
	if len(s.Packages) > 0 {
		add(o, "spec.packages is reserved and the daemon refuses it: install packages with spec.provision.packages")
	}
	if s.Delegate {
		warn(o, "zfs_delegation needs a global admin, and the host's priv.conf must allow it (admin-zfs-delegation): root in the jail then manages the dataset <container>/delegated outside JailOps' rules")
	}
}

// checkSecretRef checks the shape of a secret reference: a simple name for
// secrets/<name>.age, or a dotted path of simple segments for the SOPS file.
func checkSecretRef(ref string) error {
	if !IsSopsRef(ref) {
		return model.CheckSimpleName(ref)
	}
	for _, seg := range strings.Split(ref, ".") {
		if seg == "" || !secretSegment.MatchString(seg) {
			return fmt.Errorf("path %q: every segment is letters, digits, - or _", ref)
		}
	}
	return nil
}

var secretSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

func checkPolicy(o *Object, s api.FirewallPolicySpec, add func(*Object, string, ...any), warn func(*Object, string, ...any)) {
	for _, d := range []struct{ n, v string }{{"default_in", s.DefaultIn}, {"default_out", s.DefaultOut}} {
		switch d.v {
		case "allow", "deny":
		case "":
			add(o, "%s is required: allow or deny", d.n)
		default:
			add(o, "%s must be allow or deny, got %q", d.n, d.v)
		}
	}
	if s.DefaultIn == "allow" {
		warn(o, "default_in is allow: inbound traffic is open unless a rule denies it")
	}
	for i, r := range s.Rules {
		w := fmt.Sprintf("rules[%d]", i)
		if r.Action != "allow" && r.Action != "deny" {
			add(o, "%s: action must be allow or deny", w)
		}
		if r.Direction != "in" && r.Direction != "out" {
			add(o, "%s: direction must be in or out", w)
		}
		switch r.Proto {
		case "", "tcp", "udp", "icmp", "icmp6":
		default:
			add(o, "%s: proto %q is not tcp, udp, icmp or icmp6", w, r.Proto)
		}
		for _, p := range r.Ports {
			if !validPorts(p) {
				add(o, "%s: invalid port %q", w, p)
			}
		}
		if r.Redirect != nil {
			if r.Direction != "in" {
				add(o, "%s: redirect is allowed on inbound rules only", w)
			}
			if r.Redirect.HostPort < 1 || r.Redirect.HostPort > 65535 || r.Redirect.JailPort < 1 || r.Redirect.JailPort > 65535 {
				add(o, "%s: redirect ports must be 1-65535", w)
			}
		}
		for _, a := range append(slices.Clone(r.From), r.To...) {
			if a == "" {
				add(o, "%s: empty address", w)
			}
		}
		if r.Action == "allow" && r.Direction == "in" && len(r.From) == 0 {
			warn(o, "%s allows inbound traffic from anywhere", w)
		}
	}
	if s.Raw != "" {
		warn(o, "raw PF fragment needs the admin role and bypasses typed validation")
	}
}

func validPorts(p string) bool {
	lo, hi, isRange := strings.Cut(p, "-")
	n, err := strconv.Atoi(lo)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if !isRange {
		return true
	}
	m, err := strconv.Atoi(hi)
	return err == nil && m >= n && m <= 65535
}

func checkAddressSet(o *Object, s api.AddressSetSpec, add func(*Object, string, ...any), warn func(*Object, string, ...any)) {
	if len(s.Addresses) == 0 {
		warn(o, "address set %s is empty: rules that reference it match nothing", o.Name)
	}
	for _, e := range s.Addresses {
		a := e.Address
		if strings.HasPrefix(a, "jail:") || strings.HasPrefix(a, "set:") { // a jail or another set of the project: checked where the objects are known
			continue
		}
		if _, err := netip.ParsePrefix(a); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(a); err != nil {
			add(o, "address %q is neither an address nor a prefix", a)
		}
	}
}

// setCycle returns the path of a cycle of set:NAME members reachable from name, or "".
func setCycle(sets map[string]*Object, name string, stack []string) string {
	if i := slices.Index(stack, name); i >= 0 {
		return strings.Join(append(slices.Clone(stack[i:]), name), " -> ")
	}
	o := sets[name]
	if o == nil {
		return ""
	}
	s, _ := o.Spec.(api.AddressSetSpec)
	stack = append(slices.Clone(stack), name)
	var next []string
	for _, e := range s.Addresses { // a member set:NAME is followed (a jail has no members)
		if n, ok := strings.CutPrefix(e.Address, "set:"); ok {
			next = append(next, n)
		}
	}
	for _, inc := range next {
		if c := setCycle(sets, inc, stack); c != "" {
			return c
		}
	}
	return ""
}

func checkNetwork(o *Object, s api.NetworkSpec, add func(*Object, string, ...any), warn func(*Object, string, ...any)) {
	if s.IPv4 == nil && (s.IPv6 == nil || s.IPv6.Mode == api.IPv6None) {
		add(o, "a network needs ipv4 or ipv6")
	}
	if v := s.IPv4; v != nil {
		sub, err := netip.ParsePrefix(v.Subnet)
		if err != nil || !sub.Addr().Is4() {
			add(o, "ipv4.subnet %q is not an IPv4 prefix", v.Subnet)
		} else {
			if gw, err := netip.ParseAddr(v.Gateway); err != nil || !sub.Contains(gw) {
				add(o, "ipv4.gateway %q must be an address inside %s", v.Gateway, v.Subnet)
			}
			checkRange(o, "ipv4.range", v.Range, sub, add)
		}
		if v.NAT && s.Uplink == "" {
			add(o, "ipv4.nat needs an uplink")
		}
	}
	if v := s.IPv6; v != nil {
		switch v.Mode {
		case api.IPv6Routed, api.IPv6None, api.IPv6Proxy:
		default:
			add(o, "ipv6.mode must be routed, proxy or none")
		}
		if v.Mode == api.IPv6None {
			return
		}
		sub, err := netip.ParsePrefix(v.Subnet)
		if err != nil || !sub.Addr().Is6() {
			add(o, "ipv6.subnet %q is not an IPv6 prefix", v.Subnet)
			return
		}
		if sub != sub.Masked() {
			add(o, "ipv6.subnet %q has host bits set (want %s)", v.Subnet, sub.Masked())
		}
		lo, hi := 32, 126 // routed: a /32 to a /126
		if v.Mode == api.IPv6Proxy {
			lo, hi = 48, 120 // proxy: the helper accepts /48 to /120
		}
		if sub.Bits() < lo || sub.Bits() > hi {
			add(o, "ipv6.subnet %s: in %s mode the prefix length must be between /%d and /%d", sub, v.Mode, lo, hi)
		}
		checkRange(o, "ipv6.range", v.Range, sub, add)
		if v.Mode == api.IPv6Proxy {
			if s.Uplink == "" {
				add(o, "ipv6 proxy mode needs an uplink to answer neighbor solicitations on")
			}
		}
	}
}

// networkPrefixes lists the subnets a network claims.
func networkPrefixes(s api.NetworkSpec) []netip.Prefix {
	var out []netip.Prefix
	if s.IPv4 != nil {
		if p, err := netip.ParsePrefix(s.IPv4.Subnet); err == nil {
			out = append(out, p.Masked())
		}
	}
	if s.IPv6 != nil && s.IPv6.Mode != api.IPv6None {
		if p, err := netip.ParsePrefix(s.IPv6.Subnet); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func checkRange(o *Object, what, r string, sub netip.Prefix, add func(*Object, string, ...any)) {
	a, b, ok := strings.Cut(r, "-")
	lo, e1 := netip.ParseAddr(strings.TrimSpace(a))
	hi, e2 := netip.ParseAddr(strings.TrimSpace(b))
	if !ok || e1 != nil || e2 != nil || hi.Less(lo) {
		add(o, "%s %q must be an inclusive span \"a-b\"", what, r)
		return
	}
	if !sub.Contains(lo) || !sub.Contains(hi) {
		add(o, "%s %q is outside %s", what, r, sub)
	}
}

// wgIfaceRE is the daemon's rule for a tunnel's interface name.
var wgIfaceRE = regexp.MustCompile(`^wg[A-Za-z0-9_.-]{1,13}$`)

func wgIface(name string, s api.WireGuardSpec) string {
	if s.Interface != "" {
		return s.Interface
	}
	return "wg-" + name
}

func wgPort(s api.WireGuardSpec) int {
	if s.Mode == api.WireGuardServer && s.ListenPort == 0 {
		return api.DefaultWireGuardPort
	}
	return s.ListenPort
}

// wgPrefixes parses a tunnel's addresses (with their prefix) as networks; what does not parse is reported elsewhere.
func wgPrefixes(l []string) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range l {
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// wgKey reports whether s is a WireGuard public key: standard base64 of 32 bytes.
func wgKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && len(s) == 44
}

// checkWireGuard checks a tunnel offline the way the daemon will. Only servers are declarable: a client's private key
// comes from a join token on its own host and cannot be reproduced from a file. Private and preshared keys are never
// fields of a spec, so a file cannot carry one.
func checkWireGuard(o *Object, s api.WireGuardSpec, add func(*Object, string, ...any)) {
	switch s.Mode {
	case api.WireGuardServer:
	case api.WireGuardClient:
		add(o, "a WireGuard client cannot be declared: its private key comes from a join token on its own host (jailops wireguard join NAME --token-file TOKEN-FILE); declare the server and enroll the client with jailops wireguard peer add")
		return
	default:
		add(o, "spec.mode must be server (clients are made with jailops wireguard join)")
		return
	}
	if !wgIfaceRE.MatchString(wgIface(o.Name, s)) {
		add(o, "interface %q must start with \"wg\" and have at most 15 letters, digits, '_', '.' or '-' (set spec.interface for a long name)", wgIface(o.Name, s))
	}
	if s.PeerPublicKey != "" {
		add(o, "spec.peer_public_key is for a client; a server lists spec.peers")
	}
	if s.ListenPort < 0 || s.ListenPort > 65535 {
		add(o, "spec.listen_port %d is not a port", s.ListenPort)
	}
	if s.Keepalive < 0 || s.Keepalive > 3600 {
		add(o, "spec.keepalive must be 0 to 3600 seconds")
	}
	addrs := map[bool]int{}
	if len(s.Address) == 0 {
		add(o, "spec.address needs the tunnel's address with its prefix, for example 10.99.0.1/24")
	}
	var own []netip.Prefix
	for _, a := range s.Address {
		p, err := netip.ParsePrefix(a)
		if err != nil || p.Addr().Zone() != "" {
			add(o, "spec.address %q is not an address with a prefix length", a)
			continue
		}
		own = append(own, p)
		addrs[p.Addr().Is4()]++
	}
	if addrs[true] > 1 || addrs[false] > 1 {
		add(o, "spec.address holds at most one IPv4 and one IPv6 address")
	}
	for _, a := range s.AllowedIPs {
		if p, err := netip.ParsePrefix(a); err != nil || p != p.Masked() {
			add(o, "spec.allowed_ips %q must be a network (the pool peer addresses come from)", a)
		}
	}
	for _, d := range s.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			add(o, "spec.dns %q is not an address", d)
		}
	}
	names, keys := map[string]bool{}, map[string]bool{}
	var used []netip.Prefix
	for i, p := range s.Peers {
		f := fmt.Sprintf("spec.peers[%d]", i)
		if !api.IsName(p.Name, api.MaxName) {
			add(o, "%s.name %q must follow %s", f, p.Name, api.NamePattern)
		}
		if names[p.Name] {
			add(o, "%s: peer %q is listed twice", f, p.Name)
		}
		names[p.Name] = true
		if !wgKey(p.PublicKey) {
			add(o, "%s.public_key is not a WireGuard public key (base64 of 32 bytes)", f)
		} else if keys[p.PublicKey] {
			add(o, "%s: peer %q has the public key of another peer", f, p.Name)
		}
		keys[p.PublicKey] = true
		if len(p.AllowedIPs) == 0 {
			add(o, "%s.allowed_ips needs the peer's tunnel address, for example 10.99.0.2/32", f)
		}
		for _, a := range p.AllowedIPs {
			x, err := netip.ParsePrefix(a)
			if err != nil {
				if ad, aerr := netip.ParseAddr(a); aerr == nil {
					x, err = netip.PrefixFrom(ad, ad.BitLen()), nil
				}
			}
			if err != nil || x.Bits() == 0 {
				add(o, "%s.allowed_ips %q is not a peer address", f, a)
				continue
			}
			for _, u := range used {
				if u.Overlaps(x) {
					add(o, "%s.allowed_ips %s overlaps the address of another peer", f, x)
				}
			}
			for _, a := range own {
				if x.Contains(a.Addr()) {
					add(o, "%s.allowed_ips %s holds the server's own address", f, x)
				}
			}
			used = append(used, x)
		}
	}
}
