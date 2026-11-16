package service

import (
	"context"
	"slices"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// BootPlan returns what the boot pass would do after a boot of the host, for the jails of the projects the caller
// may use (every project of a global identity, or the project the request names): the jails it starts in order, and
// the jails with autostart that it does not start, each with why. The order is that of the whole host (dependencies
// first, then boot.priority, then the key of the jail); a caller sees it without the jails of other projects, in the
// same order.
func (s *Service) BootPlan(ctx context.Context) (api.BootPlan, error) {
	all, projects, err := s.visibleProjects(ctx)
	if err != nil {
		return api.BootPlan{}, err
	}
	running := s.runningJails(ctx)
	s.mu.RLock()
	keys := sortedKeys(s.jails)
	entries := make([]api.Jail, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, s.jails[k].jail)
	}
	s.mu.RUnlock()
	jails := make([]api.BootJail, 0, len(entries))
	for _, j := range entries {
		spec := s.effective(j)
		key := jailKey(j)
		b := api.BootJail{Key: key, Project: j.Metadata.Project, Name: j.Metadata.Name, Boot: spec.Boot}
		b.Boot.Depends = nil
		for _, dep := range spec.Boot.Depends {
			if k, err := validate.QualifiedName(j.Metadata.Project, dep); err == nil {
				b.Boot.Depends = append(b.Boot.Depends, k)
			}
		}
		for _, v := range spec.Volumes {
			if o, err := s.volKind.p(j.Metadata.Project).get(v.Name); err == nil && o.Spec.Encrypted {
				b.Encrypted = true
			}
		}
		_, b.Running = running[key]
		jails = append(jails, b)
	}
	plan := api.PlanBoot(jails)
	return plan.Visible(func(p string) bool { return all || slices.Contains(projects, p) }), nil
}
