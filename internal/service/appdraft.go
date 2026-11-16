package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// draftTimeout bounds each command an app draft runs.
const draftTimeout = time.Minute

// AppDraft answers GET /api/v1/jails/<name>/app-draft: a definition drafted
// from a running FreeBSD jail of the project, for a person to complete
// (docs/apps.md, "Write your own app"). It reads, and changes nothing: the
// packages installed on purpose (pkg -r <root> query on the host, through the
// helper's allow-list), /etc/rc.conf of the jail, and in the jail the
// listening sockets, the names of the files below /usr/local/etc and
// /var/log changed after the last package operation and the owners of the
// directories the app writes to. The content of a configuration file is
// never read. Operator: it runs commands in the jail, like exec. Audited.
// UNVERIFIED on FreeBSD: the output of sockstat, find and stat in a jail.
func (s *Service) AppDraft(ctx context.Context, name string) (api.AppDraft, error) {
	if err := s.requireHost("app drafts"); err != nil {
		return api.AppDraft{}, err
	}
	if s.d.Run == nil || s.d.Jails == nil || s.d.Files == nil {
		return api.AppDraft{}, api.Errorf(api.CodeUnsupported, "this daemon cannot read inside jails")
	}
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.AppDraft{}, err
	}
	j, err := s.getByKey(ctx, key)
	if err != nil {
		return api.AppDraft{}, err
	}
	if s.jailIsLinux(j) {
		return api.AppDraft{}, invalid("jail %q is a Linux jail; an app definition describes a FreeBSD jail", name)
	}
	if j.Status.Power != api.PowerRunning {
		return api.AppDraft{}, api.Errorf(api.CodeBusy, "jail %q is not running", name).
			WithHint("start it first: jailops start " + name + "; the draft reads the sockets the app listens on")
	}
	s.execMu.Lock()
	installing := s.installing[key]
	s.execMu.Unlock()
	if installing {
		return api.AppDraft{}, api.Errorf(api.CodeBusy, "jail %q is busy: packages are being installed or updated", name).
			WithHint("wait for the installation to end; `jailops op list` shows it")
	}
	root := s.rootMount(key)
	f := apps.DraftFacts{Jail: name, SysVIPC: j.Spec.SysVIPC, Resources: j.Spec.Resources, Errs: map[string]string{}}
	for _, v := range j.Spec.Volumes {
		f.Volumes = append(f.Volumes, v.Mount)
	}

	argv := apps.PkgLeavesArgv(key)
	res, err := s.d.Run.Run(ctx, run.Cmd{Name: argv[0], Args: argv[1:], Timeout: draftTimeout})
	if err != nil {
		return api.AppDraft{}, fmt.Errorf("list the packages of jail %s: %w: %s", name, err, tailOf(res.Stderr))
	}
	f.Packages = res.Stdout
	if j.Spec.Shell == api.BashPath {
		f.Packages = dropLines(f.Packages, func(l string) bool { return strings.HasPrefix(l, api.BashPackage+" ") })
	}
	if b, err := s.d.Files.ReadFile(ctx, apps.RcConfPath(root)); err == nil {
		f.RcConf = b
	} else if !errors.Is(err, os.ErrNotExist) && !api.IsCode(err, api.CodeNotFound) {
		f.Errs["rc.conf"] = err.Error()
	}
	inJail := func(step string, argv []string) []byte {
		res, err := s.d.Jails.Exec(ctx, key, jailos.ExecOpts{Argv: argv, Timeout: draftTimeout})
		if err != nil {
			f.Errs[step] = strings.Join(argv, " ") + ": " + err.Error() + ": " + tailOf(res.Stderr)
		}
		return res.Stdout
	}
	f.Sockets = inJail("sockets", apps.SockstatArgv())
	// the shell's prompt files belong to JailOps, not to the app
	f.Configs = dropLines(inJail("config", apps.FindNewerArgv("/usr/local/etc")), isShellFile)
	f.Logs = inJail("logs", apps.FindNewerArgv("/var/log"))
	services := apps.DraftServices(apps.ParseRcConf(f.RcConf))
	// rc.conf spells web-worker as web_worker: name the rc.d script as it is
	f.Scripts = map[string]string{}
	for _, sv := range services {
		if dashed := strings.ReplaceAll(sv, "_", "-"); dashed != sv {
			if ok, _ := s.d.Files.Exists(ctx, root+"/usr/local/etc/rc.d/"+dashed); ok {
				f.Scripts[sv] = dashed
			}
		}
	}
	scripts := make([]string, len(services))
	for i, sv := range services {
		scripts[i] = sv
		if sc := f.Scripts[sv]; sc != "" {
			scripts[i] = sc
		}
	}
	if paths := apps.OwnerPaths(f.Volumes, apps.DraftLogs(f.Logs), scripts); len(paths) > 0 {
		// stat exits 1 when a path is missing (/var/run/<service> often is); what it printed for the others counts
		res, _ := s.d.Jails.Exec(ctx, key, jailos.ExecOpts{Argv: apps.StatOwnerArgv(paths), Timeout: draftTimeout})
		f.Owners = res.Stdout
	}
	d := apps.BuildDraft(f)
	a := ActorFrom(ctx)
	s.Audit(ctx, store.AuditEntry{Actor: a.Name, ActorKind: a.Kind, Method: "GET", Route: "/api/v1/jails/{name}/app-draft",
		Object: "/api/v1/jails/" + name, Project: p.Meta.Name, Result: "ok", Remote: a.Remote,
		Detail: fmt.Sprintf("app draft: %d package(s), %d service(s), %d port(s)", len(d.Definition.Packages), len(d.Definition.Services), len(d.Definition.Ports))})
	return d, nil
}
