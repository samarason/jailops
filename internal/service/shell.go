package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"jailops.net/jailops/internal/supervise"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// The shell of a FreeBSD jail and its bash prompt (docs/shell.md).
//
// A new FreeBSD jail gets the defaults of jailopsd.yaml (jails.shell, jails.prompt) in its spec when its request
// and its profiles leave the keys empty, so `jailops config show` shows what it got. At its first start JailOps
// installs bash into the jail's /usr/local from the host (pkg -r ROOT, as an app installation does) and writes the
// prompt: api.PromptFile, and a marked block that sources it at the top of api.ProfilePath and api.BashrcPath.
// /usr/local is a persistent dataset of a thin jail, so all of it survives an OS update (root swap). A failure does
// not fail the start: it is a ShellSetup condition of the jail, and `jailops jail shell-setup` tries again.
//
// Existing jails are never changed on their own: their keys are empty, and empty means "leave the files alone".
// `jailops jail shell-setup NAME` gives such a jail what a new one gets. A changed prompt key is written at once
// into a running jail (under the jail's lock, by the update), or at the next start of a stopped one.
// Linux jails are left alone: the prompt key is refused for them and nothing is installed.

// shellMark is the per-jail record of the setup, in <StateDir>/shell/<key>.json.
type shellMark struct {
	// Pending: the jail was created with a shell or prompt to set up at its first start.
	Pending bool `json:"pending,omitempty"`
	// Started: the jail has started at least once. The host fetches bash for a jail only before its first start; a
	// later start never waits for a package server, and what is still missing is tried again in the background.
	Started bool `json:"started,omitempty"`
	// Applied is what the prompt file last said (promptState): the PS1 text, or "none".
	Applied string `json:"applied,omitempty"`
	// Error is the latest failure of the setup (empty after a success), At its time.
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at,omitzero"`
}

type shellMarks struct {
	mu sync.Mutex
	m  map[string]shellMark
}

func (s *Service) shellPath(key string) string {
	return filepath.Join(s.d.StateDir, "shell", key+".json")
}

func (s *Service) shellMark(key string) shellMark {
	s.shellM.mu.Lock()
	defer s.shellM.mu.Unlock()
	if m, ok := s.shellM.m[key]; ok {
		return m
	}
	var m shellMark
	if s.d.StateDir != "" {
		if b, err := os.ReadFile(s.shellPath(key)); err == nil {
			_ = json.Unmarshal(b, &m)
		}
	}
	if s.shellM.m == nil {
		s.shellM.m = map[string]shellMark{}
	}
	s.shellM.m[key] = m
	return m
}

func (s *Service) setShellMark(key string, m shellMark) {
	s.shellM.mu.Lock()
	if s.shellM.m == nil {
		s.shellM.m = map[string]shellMark{}
	}
	s.shellM.m[key] = m
	s.shellM.mu.Unlock()
	if s.d.StateDir == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.shellPath(key)), 0o750)
	b, _ := json.Marshal(m)
	tmp := s.shellPath(key) + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, s.shellPath(key))
	}
}

func (s *Service) forgetShell(key string) {
	s.shellM.mu.Lock()
	delete(s.shellM.m, key)
	s.shellM.mu.Unlock()
	if s.d.StateDir != "" {
		_ = os.Remove(s.shellPath(key))
	}
}

// shellCondition is the jail's ShellSetup condition: present only while the latest setup failed.
func (s *Service) shellCondition(key string) []api.Condition {
	m := s.shellMark(key)
	if m.Error == "" {
		return nil
	}
	_, name := validate.SplitQualified(key)
	return []api.Condition{{Type: "ShellSetup", Status: api.ConditionFalse, Reason: "Failed", Since: m.At,
		Message: m.Error + "; try again with `jailops jail shell-setup " + name + "`, or choose FreeBSD's own shell with `jailops set " + name + " shell sh`"}}
}

// promptContext is where the jail key is: the jail, its project and the short name of the host. The jail.conf that is
// rendered for every start carries it as the parameters env.jailops_jail, env.jailops_project and env.jailops_host, so it is the host the
// jail is started on that is named, whichever host that is.
func (s *Service) promptContext(key string) api.PromptContext {
	project, name := validate.SplitQualified(key)
	return api.PromptContext{Jail: name, Project: project, Host: api.ShortHost(s.d.Hostname)}
}

func (s *Service) promptColor() int {
	if c := s.d.JailPromptColor; c > 0 && c < 256 {
		return c
	}
	return api.DefaultPromptColor
}

// shellDefaults fills the shell and prompt keys of a new FreeBSD jail from jailopsd.yaml where neither the spec nor
// its profiles set them, and reports whether there is anything to set up at the first start.
func (s *Service) shellDefaults(spec *api.JailSpec, profs []api.Profile) bool {
	if spec.OS != api.OSFreeBSD {
		return false
	}
	spec.Shell = api.ShellPath(spec.Shell)
	eff, _ := api.ExpandedConfig(*spec, profs)
	shell := eff.Shell
	if shell == "" && s.d.JailShell == api.ShellBash {
		spec.Shell, shell = api.BashPath, api.BashPath
	}
	prompt := eff.Prompt
	if prompt == "" && shell == api.BashPath && s.d.JailPrompt != "" {
		spec.Prompt, prompt = s.d.JailPrompt, s.d.JailPrompt
	}
	return shell == api.BashPath || (prompt != "" && prompt != api.PromptNone)
}

// promptState is what the prompt key means for the files: the PS1 text, "none", or "" (leave them alone).
func (s *Service) promptState(key string, eff api.JailSpec) string {
	switch eff.Prompt {
	case "":
		return ""
	case api.PromptNone:
		return api.PromptNone
	}
	return api.EffectivePS1(eff.Prompt, s.promptColor())
}

func notExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || api.IsCode(err, api.CodeNotFound)
}

// applyPrompt writes what the files of the jail key stand for into the jail root: the variables script (the same text
// in every jail), the prompt file (unless the prompt is none, which removes it and keeps the variables) and the block
// at the top of the two start-up files that sources them. ps1 is promptState. It returns what it did.
func (s *Service) applyPrompt(ctx context.Context, key, ps1 string) ([]string, error) {
	root := s.rootMount(key)
	f := s.d.Files
	var steps []string
	write := func(path, body string) error {
		if cur, err := f.ReadFile(ctx, root+path); err == nil && string(cur) == body {
			return nil
		}
		if err := f.WriteAtomic(ctx, root+path, []byte(body)); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		steps = append(steps, "wrote "+path)
		return nil
	}
	if err := write(api.EnvFile, render.EnvScript()); err != nil {
		return steps, err
	}
	withPrompt := ps1 != api.PromptNone
	if withPrompt {
		body, err := render.PromptFile(ps1)
		if err != nil {
			return steps, err
		}
		if err := write(api.PromptFile, body); err != nil {
			return steps, err
		}
	} else if ok, _ := f.Exists(ctx, root+api.PromptFile); ok {
		if err := f.RemoveAll(ctx, root+api.PromptFile); err != nil {
			return steps, fmt.Errorf("remove %s: %w", api.PromptFile, err)
		}
		steps = append(steps, "removed "+api.PromptFile)
	}
	for _, p := range []string{api.ProfilePath, api.BashrcPath} {
		cur, err := f.ReadFile(ctx, root+p)
		if err != nil && !notExist(err) {
			return steps, fmt.Errorf("read %s: %w", p, err)
		}
		next, err := render.PromptHookSet(string(cur), withPrompt)
		if err != nil {
			return steps, fmt.Errorf("%s: %w", p, err)
		}
		if next == string(cur) {
			continue
		}
		if err := f.WriteAtomic(ctx, root+p, []byte(next)); err != nil {
			return steps, fmt.Errorf("write %s: %w", p, err)
		}
		steps = append(steps, "put the jailops block at the top of "+p)
	}
	if len(steps) == 0 {
		steps = append(steps, "the shell files are in place: "+api.EnvFile+" and "+api.PromptFile+", sourced from "+api.ProfilePath+" and "+api.BashrcPath)
	}
	return steps, nil
}

// holdJailForPackages keeps exec, shell and console sessions out of a jail, and a second package operation away,
// while pkg works in it (an operator's session must not change the packages meanwhile). It refuses with `busy` when
// another package operation already holds the jail. The caller calls release when the package work is done.
func (s *Service) holdJailForPackages(key string) (release func(), err error) {
	s.execMu.Lock()
	if s.installing[key] {
		s.execMu.Unlock()
		return nil, api.Errorf(api.CodeBusy, "a package operation is working on this jail").WithHint("wait for it to end")
	}
	s.installing[key] = true
	s.execMu.Unlock()
	return func() {
		s.execMu.Lock()
		delete(s.installing, key)
		s.execMu.Unlock()
	}, nil
}

// installBash installs the bash package into a running FreeBSD jail with pkg -j (pkg enters the jail, so the host's
// root never writes into a root that runs), unless it is there. Exec sessions are kept out while pkg works, and the
// jail's library cache is refreshed afterwards; an app installation (inApp) does both itself.
func (s *Service) installBash(ctx context.Context, key string, inApp bool) ([]string, error) {
	guard := !inApp
	root := s.rootMount(key)
	if ok, _ := s.d.Files.Exists(ctx, root+api.BashPath); ok {
		return []string{api.BashPath + " is installed"}, nil
	}
	if s.d.Run == nil {
		return nil, api.Errorf(api.CodeUnsupported, "this daemon cannot run pkg on the host")
	}
	if guard {
		release, err := s.holdJailForPackages(key)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	// inside the running jail: over the jail's own network, which its firewall may close, so it does not wait long
	argv := apps.PkgInstallInJailArgv(key, []string{api.BashPackage})
	if err := s.runHost(ctx, 5*time.Minute, argv); err != nil {
		return nil, err
	}
	steps := []string{strings.Join(argv, " ")}
	if inApp {
		return steps, nil
	}
	// the library cache of the running jail must learn about the libraries bash brought into /usr/local/lib.
	if _, err := s.runInJail(ctx, key, 5*time.Minute, "/sbin/ldconfig", "-m", "/usr/local/lib"); err != nil {
		return steps, err
	}
	return append(steps, "in the jail: /sbin/ldconfig -m /usr/local/lib"), nil
}

// setUpShell installs bash when the effective shell is bash and writes the prompt the spec names. It records the
// outcome in the jail's mark. inApp: an app installation runs it (installBash).
func (s *Service) setUpShell(ctx context.Context, key string, eff api.JailSpec, inApp bool) ([]string, error) {
	var steps []string
	var err error
	bashFailed := false
	if eff.Shell == api.BashPath {
		steps, err = s.installBash(ctx, key, inApp)
		bashFailed = err != nil
	}
	m := s.shellMark(key)
	// bash that could not be fetched stays due: the next start of the jail tries again from the host, whose network
	// and cache do not depend on the firewall of the jail
	m.Pending = bashFailed
	if err == nil {
		if ps1 := s.promptState(key, eff); ps1 != "" {
			var more []string
			more, err = s.applyPrompt(ctx, key, ps1)
			steps = append(steps, more...)
			if err == nil {
				m.Applied = s.promptState(key, eff)
			}
		}
	}
	m.At = s.now().UTC()
	m.Error = ""
	if err != nil {
		m.Error = "setting up the shell failed: " + tailOf([]byte(err.Error()))
	}
	s.setShellMark(key, m)
	return steps, err
}

// shellSetupDeadline is how long the setup after a start may take.
var shellSetupDeadline = 60 * time.Second

// shellRetryAfter is how long a failed setup of bash waits before a start tries it again in the background.
var shellRetryAfter = 30 * time.Minute

// shellAtStart runs after a jail started: the setup of a new jail, or a prompt that changed while it was stopped.
// It never fails the start; a failure is the jail's ShellSetup condition and an event.
func (s *Service) shellAtStart(ctx context.Context, key string) {
	// A start never waits on the shell: what takes longer than this (a package server the jail cannot reach) is a
	// failed setup with its event, and the jail keeps the shell it has.
	ctx, cancel := context.WithTimeout(ctx, shellSetupDeadline)
	defer cancel()
	j, err := s.jailSnapshot(key)
	if err != nil || j.Spec.OS != api.OSFreeBSD {
		return
	}
	eff := s.effective(j)
	m := s.shellMark(key)
	if !m.Started {
		m.Started = true
		s.setShellMark(key, m)
	}
	switch {
	case m.Pending && eff.Shell == api.BashPath && !s.bashInRoot(ctx, key):
		// a failed attempt is not repeated at every start: `jailops jail shell-setup` asks for one at once
		if m.Error != "" && s.now().Sub(m.At) < shellRetryAfter {
			return
		}
		// bash did not get in before the start (no network on the host in time): the jail is up with the shell it has,
		// and the attempt from inside the running jail goes on in the background, so the start never waits for it.
		s.setUpShellInBackground(key, j.Metadata.Project, j.Metadata.Name)
		return
	case m.Pending:
		_, err = s.setUpShell(ctx, key, eff, false)
	case s.promptState(key, eff) != "" && s.promptState(key, eff) != m.Applied:
		err = s.writePromptMark(ctx, key, eff)
	default:
		return
	}
	if err != nil {
		s.log.Warn("shell setup", "jail", key, "err", err)
		s.emitIn(ctx, j.Metadata.Project, "jail-shell-setup-failed", "/api/v1/jails/"+j.Metadata.Name)
	}
}

// bashInRoot says whether the jail's root has bash.
func (s *Service) bashInRoot(ctx context.Context, key string) bool {
	ok, _ := s.d.Files.Exists(ctx, s.rootMount(key)+api.BashPath)
	return ok
}

// setUpShellInBackground runs the setup of the shell of a running jail without holding the operation that started
// it. A failure is the jail's ShellSetup condition and an event, as when the setup runs inside the start.
func (s *Service) setUpShellInBackground(key, project, name string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { supervise.Report(s.log, "shell-setup", recover()) }()
		base := s.baseCtx
		if base == nil {
			base = context.Background()
		}
		ctx, cancel := context.WithTimeout(base, shellSetupDeadline)
		defer cancel()
		j, err := s.jailSnapshot(key)
		if err != nil {
			return
		}
		if _, err := s.setUpShell(ctx, key, s.effective(j), false); err != nil {
			s.log.Warn("shell setup", "jail", key, "err", err)
			s.emitIn(ctx, project, "jail-shell-setup-failed", "/api/v1/jails/"+name)
		}
	}()
}

// writePromptMark applies the prompt of eff and records it.
func (s *Service) writePromptMark(ctx context.Context, key string, eff api.JailSpec) error {
	_, err := s.applyPrompt(ctx, key, s.promptState(key, eff))
	m := s.shellMark(key)
	m.At, m.Error = s.now().UTC(), ""
	if err != nil {
		m.Error = "writing the prompt failed: " + tailOf([]byte(err.Error()))
	} else {
		m.Applied = s.promptState(key, eff)
	}
	s.setShellMark(key, m)
	return err
}

// promptChanged writes a changed prompt into a running jail; a stopped one gets it at its next start. The caller
// holds the jail's lock. A failure is logged and kept as the ShellSetup condition: the change itself is stored.
func (s *Service) promptChanged(ctx context.Context, key string, old, nj api.Jail) {
	if nj.Spec.OS != api.OSFreeBSD {
		return
	}
	eff := s.effective(nj)
	st := s.promptState(key, eff)
	if st == "" || st == s.promptState(key, s.effective(old)) {
		return
	}
	if !s.jailRunning(ctx, key) {
		return
	}
	if err := s.writePromptMark(ctx, key, eff); err != nil {
		s.log.Warn("prompt", "jail", key, "err", err)
	}
}

// ShellSetupJail gives a FreeBSD jail the shell and prompt a new jail gets (docs/shell.md): the keys the jail and
// its profiles leave empty are filled from jailopsd.yaml and stored, bash is installed into the jail's /usr/local
// from the host when the shell is bash and it is missing, and the prompt is written. The jail must run.
func (s *Service) ShellSetupJail(ctx context.Context, name string, _ api.ShellSetupRequest) (api.Operation, error) {
	if err := s.requireHost("jails"); err != nil {
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
	if j.Spec.OS != api.OSFreeBSD {
		return api.Operation{}, invalid("jail %q is a %s jail: the shell setup is for FreeBSD jails", name, j.Spec.OS).
			WithHint("a Linux jail keeps the shell and prompt of its distribution")
	}
	if !s.jailRunning(ctx, key) {
		return api.Operation{}, api.Errorf(api.CodeBusy, "jail %q is not running; the shell is set up inside it", name).WithHint("start it first")
	}
	return s.Submit(ctx, OpSpec{Description: "Set up the shell of jail " + name, Locks: []string{jailLock(key)}, Project: p.Meta.Name,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + name}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			cur, err := s.jailSnapshot(key)
			if err != nil {
				return nil, err
			}
			profs, _ := s.resolveProfiles(p.Meta.Name, cur.Spec.Profiles)
			spec := cur.Spec
			s.shellDefaults(&spec, profs)
			if spec.Shell != cur.Spec.Shell || spec.Prompt != cur.Spec.Prompt {
				in := cur
				in.Spec = spec
				if _, err := s.updateJail(ctx, p, key, name, in, AnyGeneration, true); err != nil {
					return nil, err
				}
				if cur, err = s.jailSnapshot(key); err != nil {
					return nil, err
				}
			}
			eff := s.effective(cur)
			if eff.Shell == "" {
				eff.Shell = DefaultShell
			}
			steps, err := s.setUpShell(ctx, key, eff, false)
			if err != nil {
				return nil, err
			}
			s.emitIn(ctx, p.Meta.Name, "jail-shell-set-up", "/api/v1/jails/"+name)
			if len(steps) == 0 {
				steps = []string{"nothing to do"}
			}
			return api.ShellSetupResult{Jail: name, Shell: eff.Shell, Prompt: eff.Prompt, PS1: api.EffectivePS1(eff.Prompt, s.promptColor()), Steps: steps}, nil
		}})
}

// shellStepDescribe says what setUpShell does for a spec, for the steps of an app installation; empty when it does
// nothing.
func (s *Service) shellStepDescribe(key string, spec api.JailSpec) string {
	var parts []string
	if spec.OS == api.OSFreeBSD && spec.Shell == api.BashPath {
		parts = append(parts, "install bash unless it is there ("+strings.Join(apps.PkgInstallInJailArgv(key, []string{api.BashPackage}), " ")+")")
	}
	switch st := s.promptState(key, spec); {
	case spec.OS != api.OSFreeBSD || st == "":
	case st == api.PromptNone:
		parts = append(parts, "write "+api.EnvFile+" (where the jail is), no prompt")
	default:
		parts = append(parts, "write "+api.EnvFile+" (where the jail is) and the bash prompt "+api.PromptFile+", sourced from "+api.ProfilePath+" and "+api.BashrcPath)
	}
	return strings.Join(parts, "; ")
}

// isShellFile reports whether a line names one of the files the shell setup writes.
func isShellFile(l string) bool {
	switch strings.TrimSpace(l) {
	case api.PromptFile, api.EnvFile, api.ProfilePath, api.BashrcPath:
		return true
	}
	return false
}

// dropLines returns out without the lines drop matches.
func dropLines(out []byte, drop func(string) bool) []byte {
	var b strings.Builder
	for _, l := range strings.SplitAfter(string(out), "\n") {
		if l != "" && !drop(strings.TrimRight(l, "\n")) {
			b.WriteString(l)
		}
	}
	return []byte(b.String())
}

// installBashBeforeFirstStart puts the bash package into the root of a FreeBSD jail that has never run, with pkg -r
// from the host: nothing runs in the root yet, and the host's network fetches the package, whatever the jail's own
// firewall policy says. The setup after the start finds bash there. It does nothing for a jail that is not new or
// does not use bash; a failure is logged and the setup after the start tries again from inside the jail.
func (s *Service) installBashBeforeFirstStart(ctx context.Context, key string) {
	j, err := s.jailSnapshot(key)
	if err != nil || j.Spec.OS != api.OSFreeBSD || s.d.Run == nil {
		return
	}
	// Only the very first start: a jail that has run (the mark says so) or that has no shell to set up costs a
	// restart nothing here, whatever its root holds.
	if m := s.shellMark(key); m.Started || !m.At.IsZero() || !m.Pending { // a recorded attempt means it has run
		return
	}
	if eff := s.effective(j); eff.Shell != api.BashPath {
		return
	}
	if err := s.life.MountTree(ctx, key); err != nil {
		s.log.Warn("bash before the first start", "jail", key, "err", err)
		return
	}
	root := s.rootMount(key)
	if ok, _ := s.d.Files.Exists(ctx, root+api.BashPath); ok {
		return
	}
	// The first start of a jail never waits long for a package mirror: what is not fetched in time is tried again
	// from inside the running jail (shellAtStart), and the jail starts with the shell it has.
	ctx, cancel := context.WithTimeout(ctx, bashBeforeStartDeadline)
	defer cancel()
	if err := s.runHost(ctx, bashBeforeStartDeadline, apps.PkgInstallCachedArgv(root, "ports", s.pkgCache(), []string{api.BashPackage})); err != nil {
		s.log.Warn("bash before the first start", "jail", key, "err", err)
	}
}

// bashBeforeStartDeadline is how long the first start of a jail waits for the host to fetch bash.
var bashBeforeStartDeadline = 20 * time.Second

// pkgCache is the directory in which the host keeps the packages it downloaded for jail roots: the cache of the
// image builds, so that the second jail, and the next one after a first image build, need no download.
func (s *Service) pkgCache() string {
	if s.lcfg.MountBase == "" {
		return ""
	}
	return path.Join(s.lcfg.MountBase, "cache", "pkg")
}
