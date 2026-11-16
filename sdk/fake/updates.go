package fake

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// The fake's managed updates and provisioning. A test seeds the package
// updates a jail has (SeedPackageUpdates) and can make the next health check
// fail (SeedUpdateFailure); image generations come from SeedGeneration.

// SeedPackageUpdates sets the package updates a check of the jail finds.
func (s *Server) SeedPackageUpdates(project, jail string, pkgs []api.PackageUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updPkgs == nil {
		s.updPkgs = map[string][]api.PackageUpdate{}
	}
	s.updPkgs[project+"/"+jail] = pkgs
}

// SeedUpdateFailure makes applying updates to the jail fail its health check.
func (s *Server) SeedUpdateFailure(project, jail string, fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updFail == nil {
		s.updFail = map[string]bool{}
	}
	s.updFail[project+"/"+jail] = fail
}

func (s *Server) updKey(j *api.Jail) string { return j.Metadata.Project + "/" + j.Metadata.Name }

// updateTargets resolves the jails of a request in the request's project.
func (s *Server) updateTargets(rc *reqInfo, names []string, all bool) ([]*api.Jail, *api.Error) {
	var out []*api.Jail
	if all {
		var keys []string
		for k, j := range s.jails.items {
			if j.Metadata.Project == rc.project {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, s.jails.items[k])
		}
		return out, nil
	}
	if len(names) == 0 {
		return nil, api.Errorf(api.CodeInvalid, "name the jails, or ask for all of them")
	}
	for _, n := range names {
		j := s.jails.items[s.jails.keyIn(rc.project, n)]
		if j == nil {
			return nil, notFound("jail", n)
		}
		out = append(out, j)
	}
	return out, nil
}

func (s *Server) osUpdateFor(j *api.Jail) *api.OSUpdate {
	gens := s.gens[imageName(j.Spec.Image)]
	if len(gens) == 0 || j.Spec.Layout == api.LayoutThick {
		return nil
	}
	cur := genNumber(j.Status.Generation)
	last := gens[len(gens)-1].Number
	if last <= cur {
		return nil
	}
	img := imageName(j.Spec.Image)
	return &api.OSUpdate{From: img + "#g" + strconv.Itoa(cur), To: img + "#g" + strconv.Itoa(last)}
}

func (s *Server) checkReport(j *api.Jail) api.UpdateReport {
	rep := api.UpdateReport{Jail: j.Metadata.Name, Project: j.Metadata.Project, Mode: j.Spec.Update.Mode, CheckedAt: s.now()}
	if j.Status.Power == api.PowerRunning {
		rep.Packages = append(rep.Packages, s.updPkgs[s.updKey(j)]...)
	} else {
		rep.Error = "the jail is stopped; its packages cannot be checked"
	}
	rep.OS = s.osUpdateFor(j)
	rep.Available = len(rep.Packages) > 0 || rep.OS != nil
	return rep
}

func (s *Server) handleUpdatesList(w http.ResponseWriter, r *http.Request) {
	rc := s.info(r)
	s.mu.Lock()
	var keys []string
	for k, rep := range s.updReports {
		if rc.id.Global || containsString(rc.id.Projects, rep.Project) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := []api.UpdateReport{}
	for _, k := range keys {
		out = append(out, s.updReports[k])
	}
	s.mu.Unlock()
	writeSync(w, 200, out)
}

func (s *Server) handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	req, e := decodeOptional[api.UpdateCheckRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	rc := s.info(r)
	s.mu.Lock()
	rp := func() reply {
		targets, e := s.updateTargets(rc, req.Jails, req.All)
		if e != nil {
			return reply{err: e}
		}
		op := s.startOp(rc.project, "updates.check", "Check for updates in project "+rc.project, nil, func() (any, *api.Error) {
			out := []api.UpdateReport{}
			if s.updReports == nil {
				s.updReports = map[string]api.UpdateReport{}
			}
			for _, j := range targets {
				rep := s.checkReport(j)
				s.updReports[s.updKey(j)] = rep
				out = append(out, rep)
			}
			return out, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func (s *Server) handleUpdatesApply(w http.ResponseWriter, r *http.Request) {
	req, e := decodeOptional[api.UpdateApplyRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	rc := s.info(r)
	s.mu.Lock()
	rp := func() reply {
		targets, e := s.updateTargets(rc, req.Jails, req.All)
		if e != nil {
			return reply{err: e}
		}
		op := s.startOp(rc.project, "updates.apply", "Apply updates in project "+rc.project, nil, func() (any, *api.Error) {
			out := []api.UpdateRecord{}
			for _, j := range targets {
				out = append(out, s.applyTo(j, req)...)
			}
			return out, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// applyTo is the pipeline of one jail: OS first, then packages; a failed
// health check records the failure (an OS update is swapped back).
func (s *Server) applyTo(j *api.Jail, req api.UpdateApplyRequest) []api.UpdateRecord {
	var recs []api.UpdateRecord
	add := func(r api.UpdateRecord) {
		r.ID = "upd-" + randHex(4)
		r.Jail, r.Project, r.Started, r.Finished = j.Metadata.Name, j.Metadata.Project, s.now(), s.now()
		if s.updHistory == nil {
			s.updHistory = map[string][]api.UpdateRecord{}
		}
		s.updHistory[s.updKey(j)] = append(s.updHistory[s.updKey(j)], r)
		recs = append(recs, r)
		if r.Result == api.UpdateOK {
			s.emitIn(j.Metadata.Project, "update.applied", "/api/v1/jails/"+j.Metadata.Name+"/updates")
		} else {
			s.emitIn(j.Metadata.Project, "update.failed", "/api/v1/jails/"+j.Metadata.Name+"/updates")
		}
	}
	both := !req.Packages && !req.OS
	failing := s.updFail[s.updKey(j)]
	if req.OS || both {
		if os := s.osUpdateFor(j); os != nil {
			rec := api.UpdateRecord{Kind: api.UpdateKindOS, From: os.From, To: os.To, Snapshot: "jo-pre-upgrade-" + randHex(3)}
			if failing {
				rec.Result, rec.Error, rec.RootRolledBack = api.UpdateRolledBack, "health check failed", true
				rec.Note = "the jail was swapped back to " + os.From + "; application data was not touched"
				add(rec)
				return recs
			}
			j.Status.Generation = "g" + strconv.Itoa(genNumber(os.To[strings.IndexByte(os.To, '#')+2:]))
			rec.Result = api.UpdateOK
			add(rec)
		}
	}
	if (req.Packages || both) && len(s.updPkgs[s.updKey(j)]) > 0 && j.Status.Power == api.PowerRunning {
		rec := api.UpdateRecord{Kind: api.UpdateKindPackages, Packages: s.updPkgs[s.updKey(j)], Snapshot: "update-" + randHex(3)}
		if failing {
			rec.Result, rec.Error = api.UpdateFailed, "health check failed"
		} else {
			rec.Result = api.UpdateOK
			delete(s.updPkgs, s.updKey(j))
		}
		add(rec)
	}
	return recs
}

func (s *Server) handleUpdateHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	_, j := s.jails.find(r, r.PathValue("name"))
	var out []api.UpdateRecord
	if j != nil {
		h := s.updHistory[s.updKey(j)]
		for i := len(h) - 1; i >= 0; i-- {
			out = append(out, h[i])
		}
	}
	s.mu.Unlock()
	if j == nil {
		writeErr(w, notFound("jail", r.PathValue("name")))
		return
	}
	if out == nil {
		out = []api.UpdateRecord{}
	}
	writeSync(w, 200, out)
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	req, e := decodeOptional[api.ProvisionRequest](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	rc := s.info(r)
	jk := s.jails.key(r, name)
	s.mu.Lock()
	rp := func() reply {
		j := s.jails.items[jk]
		if j == nil {
			return reply{err: notFound("jail", name)}
		}
		if j.Spec.Provision == nil {
			return reply{err: api.Errorf(api.CodeInvalid, "jail %q declares no provisioning", name)}
		}
		if !j.Status.ProvisionedAt.IsZero() && !req.Again {
			return reply{err: api.Errorf(api.CodeAlreadyExists, "jail %q was provisioned at %s", name, j.Status.ProvisionedAt.Format(time.RFC3339)).
				WithHint("changing the declaration does nothing until you ask: provision --again")}
		}
		op := s.startOp(rc.project, "jails.provision", "Provision jail "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			j := s.jails.items[jk]
			if j == nil {
				return nil, notFound("jail", name)
			}
			if j.Status.Power != api.PowerRunning {
				return nil, api.Errorf(api.CodeBusy, "jail %q is not running; provisioning runs inside it", name).WithHint("start it first")
			}
			p := j.Spec.Provision
			steps := []string{}
			if len(p.Packages) > 0 {
				steps = append(steps, "packages")
			}
			for _, f := range p.Files {
				steps = append(steps, "file "+f.Destination)
			}
			for _, x := range p.Services.Enable {
				steps = append(steps, "enable "+x)
			}
			for _, x := range p.Services.Start {
				steps = append(steps, "start "+x)
			}
			for _, c := range p.Commands {
				steps = append(steps, "run "+strings.Join(c, " "))
			}
			j.Status.ProvisionedAt = s.now()
			s.emitIn(rc.project, "jail-provisioned", "/api/v1/jails/"+name)
			return api.ProvisionResult{Jail: name, ProvisionedAt: j.Status.ProvisionedAt, Steps: steps}, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

// handleShellSetup answers like the daemon: a running FreeBSD jail gets bash as its shell and the default prompt
// where its keys are empty, and the steps say what a host would do.
func (s *Server) handleShellSetup(w http.ResponseWriter, r *http.Request) {
	if _, e := decodeOptional[api.ShellSetupRequest](r); e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	rc := s.info(r)
	jk := s.jails.key(r, name)
	s.mu.Lock()
	rp := func() reply {
		j := s.jails.items[jk]
		if j == nil {
			return reply{err: notFound("jail", name)}
		}
		if j.Spec.OS == api.OSLinux {
			return reply{err: api.Errorf(api.CodeInvalid, "jail %q is a linux jail: the shell setup is for FreeBSD jails", name)}
		}
		if j.Status.Power != api.PowerRunning {
			return reply{err: api.Errorf(api.CodeBusy, "jail %q is not running; the shell is set up inside it", name).WithHint("start it first")}
		}
		op := s.startOp(rc.project, "jails.shell-setup", "Set up the shell of jail "+name, map[string][]string{"jails": {"/api/v1/jails/" + name}}, func() (any, *api.Error) {
			j := s.jails.items[jk]
			if j == nil {
				return nil, notFound("jail", name)
			}
			if j.Spec.Shell == "" {
				j.Spec.Shell = api.BashPath
			}
			if j.Spec.Prompt == "" && j.Spec.Shell == api.BashPath {
				j.Spec.Prompt = api.PromptDefault
			}
			steps := []string{}
			if j.Spec.Shell == api.BashPath {
				steps = append(steps, "pkg -r ROOT install -y bash")
			}
			ps1 := api.EffectivePS1(j.Spec.Prompt, api.DefaultPromptColor)
			if ps1 != "" {
				steps = append(steps, "wrote "+api.PromptFile)
			}
			s.emitIn(rc.project, "jail-shell-set-up", "/api/v1/jails/"+name)
			return api.ShellSetupResult{Jail: name, Shell: j.Spec.Shell, Prompt: j.Spec.Prompt, PS1: ps1, Steps: steps}, nil
		})
		return reply{op: &op}
	}()
	s.mu.Unlock()
	s.respond(w, rp)
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
