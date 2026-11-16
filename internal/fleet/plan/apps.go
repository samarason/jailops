package plan

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"jailops.net/jailops/internal/fleet/config"
	"jailops.net/jailops/internal/fleet/model"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// AppChange is the Spec of an App or AppAccess item: one call of the
// application catalog's API. Exactly one of Install, Allow and Deny is set.
type AppChange struct {
	// Jail is the jail the app is (or is to be) installed as.
	Jail string
	// App and Install install the app (App is the catalog name).
	App     string
	Install *api.AppInstall
	// Allow and Deny change who may reach it.
	Allow *api.AppAllow
	Deny  *api.AppDeny
}

// planApps decides the App and AppAccess items of one host. An App is
// installed when its jail does not exist and is never changed or deleted
// afterwards (the API gives an installed jail no ownership marker, and a
// reinstall would lose its data). An AppAccess document is the whole list of
// sources of its app: missing grants are allowed, changed ports allowed again,
// and grants it does not list are denied with --prune only.
func planApps(ctx context.Context, s *Session, c *sdk.Client, host string, live map[config.Key]Live) (work, deletes []Item) {
	objs := s.Fleet.ObjectsFor(host)
	installing := map[config.Key]bool{}
	for _, o := range objs {
		if o.Kind != model.KindApp {
			continue
		}
		it := Item{Host: host, Kind: o.Kind, Project: o.Project, Name: o.Name, Desired: o}
		spec := o.Spec.(model.AppSpec)
		jk := config.Key{Kind: api.KindJail, Project: o.Project, Name: o.Name}
		l, found := live[jk]
		switch {
		case !c.Has("app_install"):
			it.Action, it.Details = ActionError, []string{`the server does not advertise "app_install"`}
		case !found:
			it.Action = ActionCreate
			it.Spec = AppChange{Jail: o.Name, App: spec.App, Install: &api.AppInstall{Jail: o.Name, Network: spec.Network,
				Storage: spec.Storage, Image: spec.Image, Limits: spec.Limits}}
			it.Details = []string{fmt.Sprintf("install app %s as jail %s", spec.App, o.Name)}
			installing[jk] = true
		case l.Meta.Labels[api.LabelApp] == spec.App:
			it.Action = ActionMatch
		case l.Meta.Labels[api.LabelApp] == "":
			it.Action, it.Owner = ActionRefuse, l.Meta.ManagedBy
			it.Details = []string{fmt.Sprintf("jail %s exists and was not installed from the catalog; sync never installs over a jail", o.Name)}
		default:
			it.Action, it.Owner = ActionRefuse, l.Meta.ManagedBy
			it.Details = []string{fmt.Sprintf("jail %s runs app %s, not %s; sync never reinstalls: delete the jail by hand to change it", o.Name, l.Meta.Labels[api.LabelApp], spec.App)}
		}
		work = append(work, it)
	}
	for _, o := range objs {
		if o.Kind != api.KindAppAccess {
			continue
		}
		spec := o.Spec.(model.AppAccessSpec)
		fail := func(msg string) {
			work = append(work, Item{Host: host, Kind: o.Kind, Project: o.Project, Name: o.Name, Desired: o, Action: ActionError, Details: []string{msg}})
		}
		if !c.Has("app_access") {
			fail(`the server does not advertise "app_access"`)
			continue
		}
		jk := config.Key{Kind: api.KindJail, Project: o.Project, Name: o.Name}
		var grants []api.AppAccessGrant
		if _, ok := live[jk]; ok {
			acc, err := c.Project(o.Project).Apps().Access(ctx, o.Name)
			if err != nil {
				fail("read the grants: " + err.Error())
				continue
			}
			grants = acc.Grants
		} else if !installing[jk] {
			fail(fmt.Sprintf("jail %s does not exist on host %s and no App of the repository installs it", o.Name, host))
			continue
		}
		have := map[string]api.AppAccessGrant{}
		for _, g := range grants {
			have[g.Source] = g
		}
		declared := map[string]bool{}
		for _, g := range spec.Grants {
			src, _ := model.CanonicalSource(g.Source)
			ports, _ := model.NormalizePorts(g.Ports)
			declared[src] = true
			it := Item{Host: host, Kind: o.Kind, Project: o.Project, Name: o.Name + " from " + src, Desired: o,
				Spec: AppChange{Jail: o.Name, Allow: &api.AppAllow{Source: src, Ports: ports, Database: g.Database}}}
			lg, ok := have[src]
			var why []string
			switch {
			case !ok:
				it.Action = ActionCreate
				what := "allow " + src
				if len(ports) > 0 {
					what += " on " + strings.Join(ports, ", ")
				}
				if g.Database != "" {
					what += ", database " + g.Database
				}
				it.Details = []string{what}
				work = append(work, it)
				continue
			case g.Database != "" && lg.Database != "" && g.Database != lg.Database:
				it.Action = ActionError
				it.Details = []string{fmt.Sprintf("%s has access to database %s on the host, %s is declared; the database of a grant does not change: deny it first (jailops app deny %s --from %s)", src, lg.Database, g.Database, o.Name, src)}
				work = append(work, it)
				continue
			}
			live := slices.Clone(lg.Ports)
			slices.Sort(live)
			if len(ports) > 0 && !slices.Equal(ports, live) {
				why = append(why, fmt.Sprintf("ports %s, declared %s", strings.Join(live, ","), strings.Join(ports, ",")))
			}
			for _, p := range lg.Problems {
				why = append(why, "drift: "+p)
			}
			if len(why) == 0 {
				it.Action = ActionMatch
			} else {
				it.Action, it.Details = ActionUpdate, why
			}
			work = append(work, it)
		}
		for _, g := range grants {
			if declared[g.Source] {
				continue
			}
			deletes = append(deletes, Item{Host: host, Kind: o.Kind, Project: o.Project, Name: o.Name + " from " + g.Source, Action: ActionDelete,
				Spec:    AppChange{Jail: o.Name, Deny: &api.AppDeny{Source: g.Source}},
				Details: []string{"allowed on the host, not listed in " + o.Origin + "; sync --apply --prune denies it (a role keeps its database)"}})
		}
	}
	return work, deletes
}

// appJails are the jails the repository declares as Apps on a host: they are
// installed, not stored objects, so the jail list does not report them as undeclared.
func appJails(f *config.Fleet, host string) map[config.Key]bool {
	out := map[config.Key]bool{}
	for _, o := range f.ObjectsFor(host) {
		if o.Kind == model.KindApp {
			out[config.Key{Kind: api.KindJail, Project: o.Project, Name: o.Name}] = true
		}
	}
	return out
}
