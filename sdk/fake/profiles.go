package fake

import (
	"net/http"
	"sort"

	"jailops.net/jailops/sdk/api"
)

// profilesFor resolves the profiles a jail names: its project's, then the
// host-level ones. s.mu is held.
func (s *Server) profilesFor(project string, names []string) []api.Profile {
	var out []api.Profile
	for _, n := range names {
		if p := s.profiles.items[project+"/"+n]; p != nil {
			out = append(out, *p)
		} else if p := s.profiles.items[api.HostProfileProject+"/"+n]; p != nil {
			out = append(out, *p)
		}
	}
	return out
}

func (s *Server) setupProfiles() {
	k := s.profiles
	k.validate = func(p, _ *api.Profile) *api.Error {
		if err := api.ValidateProfile(p.Spec); err != nil {
			if ae, ok := err.(*api.Error); ok {
				return ae
			}
			return api.Errorf(api.CodeInvalid, "%v", err)
		}
		return nil
	}
	k.beforeDelete = func(p *api.Profile) *api.Error {
		for _, j := range s.jails.items {
			for _, n := range j.Spec.Profiles {
				if n == p.Metadata.Name && (p.Metadata.Project == api.HostProfileProject || j.Metadata.Project == p.Metadata.Project) {
					return api.Errorf(api.CodeBusy, "profile %q is used by jail %q", n, j.Metadata.Name)
				}
			}
		}
		return nil
	}
}

func (s *Server) handleConfigKeys(w http.ResponseWriter, r *http.Request) {
	writeSync(w, 200, api.ConfigKeys())
}

// jailExpanded is what GET /api/v1/jails/<n>?expanded=true answers. s.mu is held.
func (s *Server) jailExpanded(j *api.Jail) any {
	eff, src := api.ExpandedConfig(j.Spec, s.profilesFor(j.Metadata.Project, j.Spec.Profiles))
	out := *j
	out.Spec = eff
	return api.JailExpanded{Jail: out, Sources: src}
}

type configResult struct {
	api.Jail
	RestartRequired []string `json:"restart_required"`
	Restarted       bool     `json:"restarted,omitempty"`
}

// jailConfig implements POST /api/v1/jails/<n>/config. Like the daemon, it never
// restarts a jail unless the request says restart=true.
func (s *Server) jailConfig(w http.ResponseWriter, r *http.Request) {
	ch, e := decode[api.ConfigChange](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	restart := r.URL.Query().Get("restart") == "true"
	name := r.PathValue("name")
	rc := s.info(r)
	s.mu.Lock()
	rp := func() reply {
		key, j := s.jails.find(r, name)
		if j == nil {
			return reply{err: notFound("jail", name)}
		}
		for k := range ch.Set {
			if ck, _, ok := api.ConfigKeyFor(k); ok && ck.Admin && !rc.id.AllRoles && !rc.id.Permission.Satisfies(api.PermAdmin) {
				return reply{err: api.Errorf(api.CodeForbidden, "%s needs the admin role", k)}
			}
		}
		spec := j.Spec
		if _, err := api.ApplyConfig(&spec, ch.Set, ch.Unset); err != nil {
			return reply{err: err.(*api.Error)}
		}
		op := s.startOp(rc.project, "jails.config", "Configure jail "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			cur := s.jails.items[key]
			if cur == nil {
				return nil, notFound("jail", name)
			}
			spec := cur.Spec
			keys, err := api.ApplyConfig(&spec, ch.Set, ch.Unset)
			if err != nil {
				return nil, err.(*api.Error)
			}
			if !jsonSame(spec, cur.Spec) {
				cur.Spec = spec
				cur.Metadata.Generation++
				cur.Metadata.UpdatedAt = s.now()
				s.emit("jail-updated", "/api/v1/jails/"+name)
			}
			res := configResult{RestartRequired: keys}
			if res.RestartRequired == nil {
				res.RestartRequired = []string{}
			}
			if restart && len(keys) > 0 && cur.Status.Power == api.PowerRunning {
				s.nextJID++
				cur.Status.JID, cur.Status.StartedAt = s.nextJID, s.now()
				res.Restarted = true
			}
			res.Jail = clone(cur)
			return res, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func jsonSame(a, b any) bool {
	return string(mustJSON(a)) == string(mustJSON(b))
}

var _ = sort.Strings

func mustJSON(v any) []byte {
	b, _ := jsonMarshal(v)
	return b
}
