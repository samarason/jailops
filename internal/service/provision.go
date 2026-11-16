package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Provisioning (design 8.5): a short, repeatable creation step. JailOps knows
// how to do each step on FreeBSD (pkg, files with owner and mode, sysrc,
// service) and on Alpine (apk, the init of the jail), so the user does not
// write those commands. Steps run in order, once per jail; the completion is
// recorded and the declaration is not applied again until the user asks
// (`provision --again`). There is no agent in the jail and no convergence.
// UNVERIFIED on FreeBSD: every command below as run through jexec.

type provMarks struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (s *Service) provPath(key string) string {
	return filepath.Join(s.d.StateDir, "provisioned", key+".json")
}

// provisionedAt returns when the jail's provisioning completed (zero: never).
func (s *Service) provisionedAt(key string) time.Time {
	s.prov.mu.Lock()
	defer s.prov.mu.Unlock()
	if t, ok := s.prov.m[key]; ok {
		return t
	}
	var t time.Time
	if s.d.StateDir != "" {
		if b, err := os.ReadFile(s.provPath(key)); err == nil {
			var v struct {
				At time.Time `json:"at"`
			}
			if json.Unmarshal(b, &v) == nil {
				t = v.At
			}
		}
	}
	if s.prov.m == nil {
		s.prov.m = map[string]time.Time{}
	}
	s.prov.m[key] = t
	return t
}

func (s *Service) markProvisioned(key string, at time.Time) {
	s.prov.mu.Lock()
	if s.prov.m == nil {
		s.prov.m = map[string]time.Time{}
	}
	s.prov.m[key] = at
	s.prov.mu.Unlock()
	if s.d.StateDir == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.provPath(key)), 0o750)
	b, _ := json.Marshal(map[string]time.Time{"at": at})
	tmp := s.provPath(key) + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, s.provPath(key))
	}
}

// forgetProvisioned drops the marker of a deleted jail.
func (s *Service) forgetProvisioned(key string) {
	s.prov.mu.Lock()
	delete(s.prov.m, key)
	s.prov.mu.Unlock()
	if s.d.StateDir != "" {
		_ = os.Remove(s.provPath(key))
	}
	s.forgetShell(key)
	s.upd.forget(key)
}

// projectFilesDir is where a project's provisioning files live.
func (s *Service) projectFilesDir(project string) string {
	base := s.d.ProjectFilesDir
	if base == "" {
		base = filepath.Join(s.d.StateDir, "project-files")
	}
	return filepath.Join(base, project)
}

// readProjectFile reads a file of the project's files directory. The source
// is a clean relative path; a symbolic link that leaves the directory is
// refused, so provisioning can never read an arbitrary host path.
func (s *Service) readProjectFile(project, source string) ([]byte, error) {
	if source == "" || path.IsAbs(source) || path.Clean(source) != source || strings.HasPrefix(source, "../") {
		return nil, invalid("source %q is not a path below the project's files", source)
	}
	root := s.projectFilesDir(project)
	full := filepath.Join(root, filepath.FromSlash(source))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, api.Errorf(api.CodeNotFound, "the project %q has no file %q", project, source).
			WithHint("put it in " + root)
	}
	rr, err := filepath.EvalSymlinks(root)
	if err != nil || (real != rr && !strings.HasPrefix(real, rr+string(filepath.Separator))) {
		return nil, api.Errorf(api.CodeForbidden, "file %q leaves the project's files directory", source)
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, invalid("%q is not a regular file", source)
	}
	if fi.Size() > 16<<20 {
		return nil, invalid("%q is larger than 16 MiB", source)
	}
	return os.ReadFile(real)
}

var svcVarRE = regexp.MustCompile(`[^A-Za-z0-9_]`)

// provisionSteps lists the commands a declaration means, in order, for the
// jail's OS. Files are handled separately (they are copied, not run).
type provStep struct {
	name string
	argv []string
	file *api.ProvisionFile
}

func provisionSteps(p api.Provision, linux bool) []provStep {
	var out []provStep
	if len(p.Packages) > 0 {
		if linux {
			out = append(out, provStep{name: "packages", argv: append([]string{"apk", "add", "--no-interactive"}, p.Packages...)})
		} else {
			out = append(out, provStep{name: "packages", argv: append([]string{"pkg", "install", "-y"}, p.Packages...)})
		}
	}
	for i := range p.Files {
		f := p.Files[i]
		out = append(out, provStep{name: "file " + f.Destination, file: &f})
	}
	for _, svc := range p.Services.Enable {
		if linux {
			out = append(out, provStep{name: "enable " + svc, argv: []string{"rc-update", "add", svc, "default"}})
		} else {
			out = append(out, provStep{name: "enable " + svc, argv: []string{"sysrc", svcVarRE.ReplaceAllString(svc, "_") + "_enable=YES"}})
		}
	}
	for _, svc := range p.Services.Start {
		if linux {
			out = append(out, provStep{name: "start " + svc, argv: []string{"rc-service", svc, "start"}})
		} else {
			// through the fixed wrapper that keeps a daemon the rc script starts off the exec's pipes; the name was
			// validated with the declaration
			argv, err := apps.ServiceStartArgv(svc)
			if err != nil {
				argv = []string{"service", svc, "start"}
			}
			out = append(out, provStep{name: "start " + svc, argv: argv})
		}
	}
	for _, c := range p.Commands {
		out = append(out, provStep{name: "run " + strings.Join(c, " "), argv: c})
	}
	return out
}

// runProvision runs the steps in order and stops at the first failure.
func (s *Service) runProvision(ctx context.Context, key string, j api.Jail) (api.ProvisionResult, error) {
	res := api.ProvisionResult{Jail: j.Metadata.Name, Steps: []string{}}
	p := j.Spec.Provision
	if p == nil {
		return res, invalid("jail %q declares no provisioning", j.Metadata.Name)
	}
	if !s.jailRunning(ctx, key) {
		return res, api.Errorf(api.CodeBusy, "jail %q is not running; provisioning runs inside it", j.Metadata.Name).WithHint("start it first")
	}
	linux := s.jailIsLinux(j)
	for _, st := range provisionSteps(*p, linux) {
		if st.file != nil {
			if err := s.provisionFile(ctx, key, j, *st.file); err != nil {
				return res, fmt.Errorf("provisioning step %q: %w", st.name, err)
			}
		} else if _, err := s.runInJail(ctx, key, 30*time.Minute, st.argv...); err != nil {
			return res, fmt.Errorf("provisioning step %q: %w", st.name, err)
		}
		res.Steps = append(res.Steps, st.name)
	}
	res.ProvisionedAt = s.now().UTC()
	s.markProvisioned(key, res.ProvisionedAt)
	return res, nil
}

func (s *Service) provisionFile(ctx context.Context, key string, j api.Jail, f api.ProvisionFile) error {
	data, err := s.readProjectFile(j.Metadata.Project, f.Source)
	if err != nil {
		return err
	}
	dest := path.Clean(f.Destination)
	if !path.IsAbs(dest) || dest == "/" || strings.Contains(dest, "..") {
		return invalid("destination %q is not usable", f.Destination)
	}
	full := s.rootMount(key) + dest
	if err := s.d.Files.MkdirAll(ctx, path.Dir(full)); err != nil {
		return err
	}
	if err := s.d.Files.WriteAtomic(ctx, full, data); err != nil {
		return err
	}
	if f.Owner != "" || f.Group != "" {
		spec := f.Owner
		if f.Group != "" {
			spec += ":" + f.Group
		}
		if _, err := s.runInJail(ctx, key, time.Minute, "chown", spec, dest); err != nil {
			return err
		}
	}
	if f.Mode != "" {
		if _, err := s.runInJail(ctx, key, time.Minute, "chmod", f.Mode, dest); err != nil {
			return err
		}
	}
	return nil
}

// ProvisionJail runs a jail's provisioning as an operation. It refuses when
// provisioning completed before unless Again is set.
func (s *Service) ProvisionJail(ctx context.Context, name string, req api.ProvisionRequest) (api.Operation, error) {
	if err := s.requireHost("provisioning"); err != nil {
		return api.Operation{}, err
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.Operation{}, err
	}
	j, err := s.jailSnapshot(key)
	if err != nil {
		return api.Operation{}, err
	}
	if j.Spec.Provision == nil {
		return api.Operation{}, invalid("jail %q declares no provisioning", name)
	}
	if at := s.provisionedAt(key); !at.IsZero() && !req.Again {
		return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "jail %q was provisioned at %s", name, at.Format(time.RFC3339)).
			WithHint("changing the declaration does nothing until you ask: provision --again")
	}
	return s.Submit(ctx, OpSpec{Description: "Provision jail " + name, Locks: []string{jailLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			res, err := s.runProvision(ctx, key, j)
			if err != nil {
				return nil, err
			}
			s.emitIn(ctx, p.Meta.Name, "jail-provisioned", "/api/v1/jails/"+name)
			return res, nil
		}})
}

// provisionPending runs the declaration of a jail that has one and has not
// been provisioned yet. The first start of a jail calls it.
func (s *Service) provisionPending(ctx context.Context, key string) error {
	j, err := s.jailSnapshot(key)
	if err != nil || j.Spec.Provision == nil || !s.provisionedAt(key).IsZero() {
		return nil
	}
	_, err = s.runProvision(ctx, key, j)
	if err != nil {
		return fmt.Errorf("the jail started, but provisioning failed: %w", err)
	}
	return nil
}

var _ = validate.JailName
