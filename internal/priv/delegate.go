package priv

import (
	"context"
	"jailops.net/jailops/sdk/api"
	"strings"
)

// delegationKept marks a context whose jail.conf has the same delegation lines as the file it replaces.
type delegationKept struct{}

// delegationAllowed reports whether the delegation parameters of a jail.conf are acceptable: the operator allowed it in
// priv.conf, and an administrator asked for them or the file already had them.
func (c Config) delegationAllowed(ctx context.Context, admin bool) bool {
	kept, _ := ctx.Value(delegationKept{}).(bool)
	return c.Admin.ZFSDelegation && (admin || kept)
}

// delegationLines are the lines of a jail.conf that hand a jail a dataset, in order.
func delegationLines(conf string) string {
	var out []string
	for _, l := range strings.Split(conf, "\n") {
		k, _, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch strings.TrimRight(strings.TrimSuffix(strings.TrimSpace(k), ";"), " ") {
		case "zfs.dataset", "allow.mount", "allow.mount.zfs", "enforce_statfs":
			out = append(out, strings.TrimSpace(l))
		}
	}
	return strings.Join(out, "\n")
}

// delegatedLeaf is the name of the dataset a jail may be handed: the child `delegated` of its container.
const delegatedLeaf = "delegated"

// delegatedDatasetNames are the names the delegated dataset of the jail with this key (`<project>_<name>`) can have:
// one per storage root, because the helper does not know which storage the jail lives on.
func (c Config) delegatedDatasetNames(key string) []string {
	project, name, ok := strings.Cut(key, "_")
	if !ok || !api.IsName(project, api.MaxName) || !api.IsName(name, api.MaxName) {
		return nil
	}
	var out []string
	for _, r := range c.Roots() {
		out = append(out, r+"/projects/"+project+"/jails/"+name+"/"+delegatedLeaf)
	}
	return out
}

// isDelegatedDataset reports whether a dataset name is the delegated dataset of some jail below a storage root.
func (c Config) isDelegatedDataset(name string) bool {
	for _, r := range c.Roots() {
		rel, ok := strings.CutPrefix(name, r+"/")
		if !ok {
			continue
		}
		p := strings.Split(rel, "/")
		if len(p) == 5 && p[0] == "projects" && p[2] == "jails" && p[4] == delegatedLeaf &&
			api.IsName(p[1], api.MaxName) && api.IsName(p[3], api.MaxName) {
			return true
		}
	}
	return false
}

// setJailed sets `jailed` on the delegated dataset of a managed jail and on nothing else. It needs the admin assertion
// and the operator's consent in priv.conf (admin-zfs-delegation): the jail's root manages the dataset from then on,
// outside the rules the helper applies to everything it mounts itself.
func (g zfsGuard) setJailed(ctx context.Context, name string, props map[string]string) error {
	if len(props) != 1 {
		return forbidden("jailed is set alone")
	}
	if v := props["jailed"]; v != "on" && v != "off" {
		return invalid("jailed is on or off")
	}
	if !isAdmin(ctx) || !g.l.cfg.Admin.ZFSDelegation {
		return forbidden("handing a dataset to a jail needs the admin assertion and admin-zfs-delegation in priv.conf")
	}
	if !g.l.cfg.isDelegatedDataset(dsPart(name)) {
		return forbidden("jailed can be set on the delegated dataset of a jail only, not on %s", name)
	}
	if err := g.managed(ctx, name); err != nil {
		return err
	}
	return g.l.d.ZFS.Set(ctx, name, props)
}
