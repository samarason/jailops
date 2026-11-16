package fake

import (
	"net/http"
	"sort"

	"jailops.net/jailops/sdk/api"
)

// handleBoot answers GET /api/v1/boot like the daemon: the plan of a boot over every jail, shown for the projects
// the caller may use.
func (s *Server) handleBoot(w http.ResponseWriter, r *http.Request) {
	rc := s.info(r)
	project := rc.project
	if v := r.URL.Query().Get("all_projects"); v == "true" || v == "1" {
		project = ""
	}
	s.mu.Lock()
	var jails []api.BootJail
	for _, j := range s.jails.items {
		p, n := j.Metadata.Project, j.Metadata.Name
		b := api.BootJail{Key: p + "_" + n, Project: p, Name: n, Boot: j.Spec.Boot, Running: j.Status.Power == api.PowerRunning}
		b.Boot.Depends = nil
		for _, d := range j.Spec.Boot.Depends {
			b.Boot.Depends = append(b.Boot.Depends, p+"_"+d)
		}
		for _, a := range j.Spec.Volumes {
			if v := s.volumes.items[p+"/"+a.Name]; v != nil && v.Spec.Encrypted {
				b.Encrypted = true
			}
		}
		jails = append(jails, b)
	}
	s.mu.Unlock()
	sort.Slice(jails, func(a, b int) bool { return jails[a].Key < jails[b].Key })
	plan := api.PlanBoot(jails).Visible(func(p string) bool { return (project == "" || p == project) && rc.canProject(p) })
	writeSync(w, 200, plan)
}
