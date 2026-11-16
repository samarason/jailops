package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Installing an app (docs/apps.md, "How the installation works") is one
// operation: a thin jail with the data paths as volumes, the packages installed
// from the host into its root with pkg -r while it has never run, then started,
// rc.conf written, the setup commands and the services run in the jail, the
// health check, the snapshot. Every step is a plan step. A failure before the
// packages go in undoes the creation; from there on the jail is stopped and
// kept, so what went wrong can be looked at.

// installState is what the steps of one installation share.
type installState struct {
	started  bool
	kept     bool // the root was mounted and the packages are going in: a failure leaves the jail, stopped, to look at
	version  string
	snapshot string
}

// defaultAppImage is the image an app is installed from when the request names
// none, by its bare name (its newest generation): of the FreeBSD images the
// caller may use, the one of the highest release the host's kernel can run,
// the first by name when two have that release. No FreeBSD image, or only
// images of a newer release than the host's, is refused with the images there are.
func (s *Service) defaultAppImage(ctx context.Context) (string, error) {
	objs, err := s.imgKind.list()
	if err != nil {
		return "", err
	}
	host := s.hostBaseRelease()
	var all []string
	best, bestRel, freebsd := "", "", 0
	for _, o := range objs {
		if !s.imageVisible(ctx, o.Meta.Name) {
			continue
		}
		all = append(all, o.Meta.Name)
		if o.Spec.OS != api.OSFreeBSD {
			continue
		}
		freebsd++
		if _, err := apps.ReleaseAtLeast(o.Spec.Release, "15.1"); err != nil {
			continue // a release that cannot be compared is never a default
		}
		if host != "" {
			if ok, err := apps.ReleaseAtLeast(host, o.Spec.Release); err == nil && !ok {
				continue // newer than the running kernel
			}
		}
		if best == "" || newerRelease(o.Spec.Release, bestRel) || sameRelease(o.Spec.Release, bestRel) && o.Meta.Name < best {
			best, bestRel = o.Meta.Name, o.Spec.Release
		}
	}
	if best != "" {
		return best, nil
	}
	sort.Strings(all)
	yours := "you have no images"
	if len(all) > 0 {
		yours = "your images: " + strings.Join(all, ", ")
	}
	if freebsd == 0 {
		// nothing to name: the base image is missing, and the hint says how to make it
		hint := api.ImageCreateHint("the base image", "", "", host)
		if len(all) > 0 {
			hint += "; " + yours
		}
		return "", invalid("no image named, and there is no FreeBSD image yet").WithHint(hint)
	}
	msg := "no image named, and no FreeBSD image has a release this host can run"
	if host != "" {
		msg = fmt.Sprintf("no image named, and every FreeBSD image is of a newer release than this host (%s)", host)
	}
	return "", invalid("%s", msg).WithHint("name an image with --image; " + yours)
}

// newerRelease reports whether release a is newer than release b; both compare.
func newerRelease(a, b string) bool {
	ok, err := apps.ReleaseAtLeast(b, a)
	return err == nil && !ok
}

func sameRelease(a, b string) bool {
	x, err1 := apps.ReleaseAtLeast(a, b)
	y, err2 := apps.ReleaseAtLeast(b, a)
	return err1 == nil && err2 == nil && x && y
}

// InstallApp answers POST /api/v1/apps/<name>/install. Everything that can
// be refused is refused before the operation starts: an unknown or invalid
// definition, a jail that exists, an image that is not present, a network or
// storage the project is not granted.
func (s *Service) InstallApp(ctx context.Context, name string, req api.AppInstall) (api.Operation, error) {
	if err := s.requireHost("apps"); err != nil {
		return api.Operation{}, err
	}
	if s.d.Run == nil {
		return api.Operation{}, api.Errorf(api.CodeUnsupported, "this daemon cannot run pkg on the host")
	}
	p, err := s.access(ctx)
	if err != nil {
		return api.Operation{}, err
	}
	proj := p.Meta.Name
	if err := bodyProject(proj, req.Project); err != nil {
		return api.Operation{}, err
	}
	e, ok, err := s.findApp(name)
	if err != nil {
		return api.Operation{}, err
	}
	if !ok {
		return api.Operation{}, api.Errorf(api.CodeNotFound, "app %q is not in the catalog", name).
			WithHint("jailops app list shows the catalog")
	}
	if e.Err == nil {
		// the persistent datasets this host configures, besides the default ones the validator knows
		var persistent []string
		for _, pp := range s.lcfg.Persistent {
			persistent = append(persistent, pp.Path)
		}
		e.Err = apps.CheckPersistent(e.App, persistent)
	}
	if e.Err != nil {
		return api.Operation{}, api.Errorf(api.CodeInvalid, "app %q: the definition %s is invalid and cannot be installed: %v", name, e.File, e.Err).
			WithHint(s.invalidHint(e)).WithDetail("file", e.File)
	}
	app := e.App
	jail := req.Jail
	if jail == "" {
		jail = name
	}
	if err := validate.JailName(jail); err != nil {
		return api.Operation{}, err
	}
	key, err := validate.QualifiedName(proj, jail)
	if err != nil {
		return api.Operation{}, err
	}
	s.mu.RLock()
	_, exists := s.jails[key]
	s.mu.RUnlock()
	if exists {
		return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "jail %q already exists", jail).
			WithHint("name the jail with --name, or delete the jail first")
	}
	if _, _, err := s.accessPolicy(proj, jail); err != nil {
		return api.Operation{}, err
	}
	for _, v := range apps.Volumes(jail, app.Data) {
		if s.volKind.p(proj).exists(v.Name) {
			return api.Operation{}, api.Errorf(api.CodeAlreadyExists, "volume %q already exists", v.Name).
				WithHint("an earlier jail of this name left it: keep its files by attaching it to a jail made by hand, or delete it with jailops volume delete " + v.Name)
		}
	}
	if err := validate.Name("policy", apps.AccessPolicyName(jail)); err != nil {
		return api.Operation{}, invalid("jail name %q is too long: its firewall policy %s must be a name too", jail, apps.AccessPolicyName(jail))
	}
	network, storage := req.Network, req.Storage
	if network == "" {
		network = p.Spec.SoleNetwork()
	}
	if storage == "" {
		storage = p.Spec.SoleStorage()
	}
	if network == "" {
		return api.Operation{}, invalid("name the network the jail is attached to (--network NAME); project %q is granted %s", proj, grantedNames(p.Spec)).
			WithHint("jailops project show " + proj + " lists the grants")
	}
	if storage == "" {
		return api.Operation{}, invalid("name the storage the jail is created on (--storage NAME)").
			WithHint("jailops project show " + proj + " lists the grants")
	}
	image := req.Image
	if image == "" {
		if image, err = s.defaultAppImage(ctx); err != nil {
			return api.Operation{}, err
		}
	}
	limits := apps.Limits(app.Resources)
	if req.Limits != nil {
		limits = *req.Limits
	}
	spec := api.JailSpec{
		Image: image, Storage: storage, Hostname: jail, Layout: api.LayoutThin,
		Network:   []api.NetworkAttach{{Network: network}},
		Volumes:   apps.Volumes(jail, app.Data),
		Resources: limits,
		SysVIPC:   app.SysVIPC,
		Boot:      api.BootPolicy{StopTimeout: app.StopTimeout},
	}
	im, ref, err := s.imageFor(spec)
	if err != nil {
		return api.Operation{}, err
	}
	if im.Spec.OS != api.OSFreeBSD {
		return api.Operation{}, invalid("image %q is a %s image; app %s runs on FreeBSD", ref.Name, im.Spec.OS, name)
	}
	if ok, err := apps.ReleaseAtLeast(im.Spec.Release, app.Image.ReleaseMin); err != nil {
		return api.Operation{}, invalid("image %q has release %q, which cannot be compared with %q", ref.Name, im.Spec.Release, app.Image.ReleaseMin)
	} else if !ok {
		return api.Operation{}, invalid("image %q is release %s; app %s needs %s or later", ref.Name, im.Spec.Release, name, app.Image.ReleaseMin).
			WithHint("create an image of a newer release and name it with --image")
	}
	release, err := s.admit(ctx, p, key, &spec, nil)
	if err != nil {
		return api.Operation{}, err
	}
	submitted := false
	defer func() {
		if !submitted {
			release()
		}
	}()
	if err := s.validateJail(proj, jail, spec); err != nil {
		return api.Operation{}, err
	}
	if err := canonicalJailSizes(&spec); err != nil {
		return api.Operation{}, err
	}
	if err := s.checkNewJail(proj, jail, spec); err != nil {
		return api.Operation{}, err
	}
	spec.OS = im.Spec.OS
	s.shellDefaults(&spec, nil)
	now := s.now().UTC()
	meta := api.ObjectMeta{Name: jail, Project: proj, UUID: state_uuid(), Scope: api.ScopeHost, Host: s.d.HostUUID, Generation: 1,
		Labels: map[string]string{api.LabelApp: name, api.LabelAppHash: e.Hash}, CreatedAt: now, UpdatedAt: now}
	nj := api.Jail{Metadata: meta, Spec: spec}
	// The network locks are taken for the creation only: the start renders
	// the network under them itself.
	locks := append([]string{jailLock(key), anchorLock(key)}, s.imageLocks(ctx, ref, spec.Storage)...)
	desc := "Install app " + name + " as jail " + jail
	if req.DryRun {
		desc += " (dry run)"
	}
	op, err := s.Submit(ctx, OpSpec{
		Description: desc, Locks: locks, Project: proj,
		Resources: map[string][]string{"jails": {"/api/v1/jails/" + jail}},
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			defer release()
			return s.appInstallRun(ctx, h, p, e, nj, req.DryRun)
		},
	})
	if err == nil {
		submitted = true
	}
	return op, err
}

func grantedNames(sp api.ProjectSpec) string {
	var l []string
	for _, n := range sp.Networks {
		l = append(l, n.Network)
	}
	if len(l) == 0 {
		return "no network"
	}
	return "network " + strings.Join(l, ", ")
}

// appInstallRun is the body of the install operation; the caller holds the
// locks of the jail, its network and its image.
func (s *Service) appInstallRun(ctx context.Context, h *OpHandle, p project, e apps.Entry, nj api.Jail, dry bool) (any, error) {
	app := e.App
	key := jailKey(nj)
	proj, jail := nj.Metadata.Project, nj.Metadata.Name
	s.place(key, nj.Spec.Storage)
	kept := false
	defer func() {
		if !kept {
			s.unplace(key)
		}
	}()
	res := api.AppInstallResult{App: app.Name, Hash: e.Hash, Data: app.Data, Config: app.Config, Logs: app.Logs, Notes: app.Notes, DryRun: dry}
	if dry {
		// the steps only: no dataset, no address
		res.Steps = s.appInstallPlan(h, nj, app, &installState{}, func() {}).Describe()
		return res, nil
	}
	// No exec session may enter the jail while pkg works on its root from the host.
	s.execMu.Lock()
	s.installing[key] = true
	s.execMu.Unlock()
	defer func() {
		s.execMu.Lock()
		delete(s.installing, key)
		s.execMu.Unlock()
	}()
	si, _ := s.storage(nj.Spec.Storage)
	g, _ := specStorageGrant(p.Spec, nj.Spec.Storage)
	if err := s.ensureProjectDatasets(ctx, proj, si, g); err != nil {
		return nil, err
	}
	// The addresses are allocated and the jail created under the locks of
	// its networks; the start takes them itself, so they go after the create.
	unlockNets, err := s.locks.lockPatient(ctx, "install app "+app.Name+" as jail "+jail, s.netLocksEff(proj, nj.Spec)...)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	created := func() { once.Do(unlockNets) }
	defer created()
	if err := s.assignOwn(proj, key, &nj.Spec); err != nil {
		return nil, err
	}
	st := &installState{}
	pl := s.appInstallPlan(h, nj, app, st, created)
	res.Steps = pl.Describe()
	if err := h.Bind("app-install/"+key, &opRequest{Kind: "app-install", Jail: key, Create: &nj}); err != nil {
		return nil, err
	}
	err = s.life.Executor.Run(ctx, "app-install/"+key, pl)
	kept = st.started || st.kept
	if err != nil {
		s.emitIn(ctx, proj, "app.install.failed", "/api/v1/jails/"+jail)
		s.kick()
		return nil, installError(err, app.Name, jail, st.started || st.kept)
	}
	s.emitIn(ctx, proj, "app.installed", "/api/v1/jails/"+jail)
	s.kick()
	j, err := s.getByKey(ctx, key)
	if err != nil {
		return nil, err
	}
	res.Jail, res.Version, res.Snapshot, res.Addresses = j, st.version, st.snapshot, j.Status.Addresses
	first := ""
	if a := jailAddrs(j.Spec); len(a) > 0 {
		first = a[0].String()
	}
	for _, pt := range app.Ports {
		ip := api.AppInstalledPort{Name: pt.Name, Port: pt.Port, Proto: pt.Proto, Expose: pt.Expose, Description: pt.Description}
		if first != "" {
			ip.Endpoint = net.JoinHostPort(first, strconv.Itoa(pt.Port))
		}
		res.Ports = append(res.Ports, ip)
	}
	return res, nil
}

// installError turns the plan error of an installation into the error the
// operation reports: the step that failed, and whether the jail was kept.
func installError(err error, app, jail string, kept bool) error {
	ae := toAPIError(err)
	step := ""
	var pe *plan.Error
	if errors.As(err, &pe) {
		step = pe.Step
	}
	msg := fmt.Sprintf("installing app %s as jail %s failed", app, jail)
	if step != "" {
		msg += " at step " + step
	}
	out := api.Errorf(ae.Code, "%s: %s", msg, ae.Message).WithDetail("jail", jail).WithDetail("step", step)
	hint := "nothing was left behind; the jail was deleted again"
	if kept {
		hint = "the jail was left stopped for inspection: look inside it with `jailops shell " + jail + "` after `jailops start " + jail +
			"`, and delete it with `jailops delete " + jail + "` before trying again"
		out = out.WithDetail("jail_kept", "true")
	}
	if pe != nil && len(pe.UndoErrs) > 0 {
		hint += ". The rollback of this operation was incomplete; run `jailops doctor`"
	}
	return out.WithHint(hint)
}

// appInstallPlan builds the steps of docs/apps.md as plan steps. The create step
// undoes itself (the jail is deleted) only until the root is mounted for the
// packages; from there on, a failure stops the jail if it runs and keeps it.
func (s *Service) appInstallPlan(h *OpHandle, nj api.Jail, app api.App, st *installState, created func()) *plan.Plan {
	key := jailKey(nj)
	proj, jail := nj.Metadata.Project, nj.Metadata.Name
	root := s.rootMount(key)
	pl := plan.New("install-app " + app.Name + " " + key)
	// The data of the app are volumes of the project, <jail>-<name>, made before the jail that attaches them. They
	// are never deleted with the jail; a failed installation removes the ones it made.
	for _, v := range nj.Spec.Volumes {
		v := v
		pl.Add(plan.Step{Name: "create-volume-" + v.Name, Describe: fmt.Sprintf("create volume %s for %s", v.Name, v.Mount),
			Do: func(ctx context.Context) error {
				p, err := s.projKind.get(proj)
				if err != nil {
					return err
				}
				si, ok := s.storage(nj.Spec.Storage)
				if !ok {
					return notFound("storage", nj.Spec.Storage)
				}
				spec := api.VolumeSpec{Storage: si.Name, Mode: "0755", Comment: "data of " + jail + " (" + app.Name + "): " + v.Mount}
				meta := api.ObjectMeta{Name: v.Name, Project: proj, Labels: map[string]string{api.LabelApp: app.Name}}
				_, err = s.makeVolume(ctx, project{Meta: p.Meta, Spec: p.Spec}, si, meta, spec, 0o755, nil, false)
				return err
			},
			Undo: func(ctx context.Context) error {
				if st.started || st.kept {
					return nil // kept with the jail for inspection
				}
				return s.dropVolume(ctx, proj, v.Name)
			}, UndoOnFail: true})
	}
	pl.Add(plan.Step{Name: "create-jail", Describe: fmt.Sprintf("create thin jail %s from %s attaching %d volume(s), with the labels %s, %s", jail, nj.Spec.Image, len(nj.Spec.Volumes), api.LabelApp, api.LabelAppHash),
		Do: func(ctx context.Context) error {
			defer created()
			if err := h.Bind("create/"+key, &opRequest{Kind: "create", Jail: key, Create: &nj}); err != nil {
				return err
			}
			if _, err := s.life.CreateJail(ctx, nj, false); err != nil {
				return err
			}
			if err := s.refreshJail(ctx, key); err != nil {
				return err
			}
			s.emitIn(ctx, proj, "jail-created", "/api/v1/jails/"+jail)
			return nil
		},
		Undo: func(ctx context.Context) error {
			if st.started || st.kept {
				return nil // kept for inspection
			}
			return s.dropCreatedJail(ctx, proj, key)
		}, UndoOnFail: true})
	// The packages go in while the jail has never run: the host writes into its root as root, and the root of a
	// jail that runs belongs to whatever runs in it. The datasets are mounted for that and the start mounts them anyway.
	pl.Add(plan.Step{Name: "mount-jail", Describe: "mount the datasets of " + jail + " on the host, so the packages can be installed before it first runs",
		Do: func(ctx context.Context) error {
			if err := s.life.MountTree(ctx, key); err != nil {
				return err
			}
			st.kept = true
			return nil
		},
		Undo: func(ctx context.Context) error { return s.life.UnmountTree(ctx, key) }, UndoOnFail: true})
	if len(nj.Spec.Volumes) > 0 {
		// The volumes of the app cover directories of the packages (/usr/local/www, /var/db/postgres): bound into the
		// root as they are when the jail runs, the files of the packages land in them.
		pl.Add(plan.Step{Name: "bind-volumes", Describe: "mount the volumes of " + jail + " into its root, as its start does, so the files of the packages go into them",
			Do:   func(ctx context.Context) error { return s.life.BindVolumes(ctx, key) },
			Undo: func(ctx context.Context) error { return s.life.UnbindVolumes(ctx, key) }, UndoOnFail: true})
	}
	ports, jailops := apps.PackageGroups(app.Packages)
	for _, grp := range []struct {
		repo  string
		names []string
	}{{"ports", ports}, {apps.JailopsRepo, jailops}} {
		if len(grp.names) == 0 {
			continue
		}
		argv := apps.PkgInstallCachedArgv(root, grp.repo, s.pkgCache(), grp.names)
		pl.Add(plan.Step{Name: "install-packages-" + grp.repo, Describe: strings.Join(argv, " "),
			Do: func(ctx context.Context) error { return s.runHost(ctx, 60*time.Minute, argv) }})
		if grp.repo == apps.JailopsRepo {
			pl.Add(plan.Step{Name: "seed-jailops-repo", Describe: "copy the configuration and the key of the " + apps.JailopsRepo + " repository into the jail, so that its packages are updated from it",
				Do: func(ctx context.Context) error { return s.seedJailopsRepo(ctx, root) }})
		}
	}
	if nj.Spec.OS == api.OSFreeBSD && nj.Spec.Shell == api.BashPath {
		// the jail's shell goes in with the packages, while nothing runs in the root (docs/shell.md)
		argv := apps.PkgInstallCachedArgv(root, "ports", s.pkgCache(), []string{api.BashPackage})
		pl.Add(plan.Step{Name: "install-bash", Describe: strings.Join(argv, " ") + ", the shell of the jail",
			Do: func(ctx context.Context) error {
				if ok, _ := s.d.Files.Exists(ctx, root+api.BashPath); ok {
					return nil
				}
				return s.runHost(ctx, 30*time.Minute, argv)
			}})
	}
	first := app.Packages[0].Name
	pl.Add(plan.Step{Name: "record-version", Describe: strings.Join(apps.PkgVersionArgv(root, first), " ") + ", then label " + api.LabelAppVersion,
		Do: func(ctx context.Context) error {
			out, err := s.d.Run.Run(ctx, run.Cmd{Name: "pkg", Args: apps.PkgVersionArgv(root, first)[1:], Timeout: 5 * time.Minute})
			if err != nil {
				return fmt.Errorf("pkg query %s: %w: %s", first, err, tailOf(append(out.Stdout, out.Stderr...)))
			}
			v, ok := packageVersion(out.Stdout)
			if !ok {
				return fmt.Errorf("pkg query %s answered %q, not a version", first, tailOf(out.Stdout))
			}
			st.version = v
			return s.setJailLabels(ctx, key, map[string]string{api.LabelAppVersion: v})
		}})
	if len(nj.Spec.Volumes) > 0 {
		pl.Add(plan.Step{Name: "unbind-volumes", Describe: "unmount them again: the start mounts them",
			Do: func(ctx context.Context) error { return s.life.UnbindVolumes(ctx, key) }})
	}
	pl.Add(plan.Step{Name: "start-jail", Describe: "start " + jail,
		Do: func(ctx context.Context) error {
			if err := s.life.StartJail(ctx, key); err != nil {
				return err
			}
			st.started = true
			s.markStarted(key)
			s.emitIn(ctx, proj, "jail-started", "/api/v1/jails/"+jail)
			return nil
		},
		Undo: func(ctx context.Context) error {
			if err := s.life.StopJail(ctx, key); err != nil {
				return err
			}
			s.markStopped(key)
			s.emitIn(ctx, proj, "jail-stopped", "/api/v1/jails/"+jail)
			return nil
		}, UndoOnFail: true})
	if desc := s.shellStepDescribe(key, nj.Spec); desc != "" {
		// like a jail created by hand: bash and the prompt (docs/shell.md). A failure does not stop the
		// installation; it is the jail's ShellSetup condition and `jailops jail shell-setup` tries again.
		pl.Add(plan.Step{Name: "set-up-shell", Describe: desc,
			Do: func(ctx context.Context) error {
				if _, err := s.setUpShell(ctx, key, nj.Spec, true); err != nil {
					s.log.Warn("shell setup", "jail", key, "err", err)
				}
				return nil
			}})
	}
	// The library cache of a running jail was built before the packages put their libraries in /usr/local/lib; pkg
	// -r does not run the ldconfig trigger of the jail, so a program would not find them.
	pl.Add(plan.Step{Name: "refresh-library-cache", Describe: "in the jail: /sbin/ldconfig -m /usr/local/lib",
		Do: func(ctx context.Context) error {
			_, err := s.runInJail(ctx, key, 5*time.Minute, "/sbin/ldconfig", "-m", "/usr/local/lib")
			return err
		}})
	if vars := apps.RcVars(app.Services); len(vars) > 0 {
		var names []string
		for _, v := range vars {
			names = append(names, v.Name)
		}
		pl.Add(plan.Step{Name: "write-rc-conf", Describe: "set " + strings.Join(names, ", ") + " in " + apps.RcConfPath(root),
			Do: func(ctx context.Context) error {
				path := apps.RcConfPath(root)
				cur, err := s.d.Files.ReadFile(ctx, path)
				if err != nil && !errors.Is(err, os.ErrNotExist) && !api.IsCode(err, api.CodeNotFound) {
					return fmt.Errorf("read %s: %w", path, err)
				}
				rv := make([]render.RcVar, len(vars))
				for i, v := range vars {
					rv[i] = render.RcVar(v)
				}
				next, err := render.RcConfSet(string(cur), rv)
				if err != nil {
					return err
				}
				return s.d.Files.WriteAtomic(ctx, path, []byte(next))
			}})
	}
	for i, argv := range app.Setup {
		argv := argv
		pl.Add(plan.Step{Name: "setup-" + strconv.Itoa(i+1), Describe: "in the jail: " + strings.Join(argv, " "),
			Do: func(ctx context.Context) error {
				_, err := s.runInJail(ctx, key, 30*time.Minute, argv...)
				return err
			}})
	}
	for _, svc := range app.Services {
		if svc.Start != nil && !*svc.Start {
			continue
		}
		// the description says what is started; the step runs it through the fixed wrapper that keeps a daemon
		// the rc script starts off the exec's pipes
		desc := strings.Join(apps.ServiceArgv(svc.Name, "start"), " ")
		pl.Add(plan.Step{Name: "start-service-" + svc.Name, Describe: "in the jail: " + desc,
			Do: func(ctx context.Context) error {
				argv, err := apps.ServiceStartArgv(svc.Name)
				if err != nil {
					return err
				}
				if out, err := s.runInJail(ctx, key, 10*time.Minute, argv...); err != nil {
					// the wrapper's script is noise in the message: name the command it stands for
					return fmt.Errorf("%s: %w: %s", desc, errors.Unwrap(err), tailOf(out))
				}
				return nil
			}})
	}
	if app.Health != nil {
		pl.Add(plan.Step{Name: "health-check", Describe: healthDescribe(app.Health),
			Do: func(ctx context.Context) error { return s.appHealth(ctx, key, app.Health) }})
	}
	// Default closed: from here on nothing reaches the jail until a source is allowed (docs/apps.md, "Who may
	// connect"). It comes after the health check, which connects from the host.
	pl.Add(plan.Step{Name: "close-firewall", Describe: "firewall policy " + apps.AccessPolicyName(jail) + " (managed by app access): deny every inbound connection until jailops app allow " + jail + " --from SOURCE",
		Do: func(ctx context.Context) error { return s.closeApp(ctx, proj, jail) }})
	pl.Add(plan.Step{Name: "snapshot", Describe: "snapshot every dataset of " + jail + " as " + apps.SnapshotName,
		Do: func(ctx context.Context) error {
			r, err := s.life.SnapshotJail(ctx, key, apps.SnapshotName, "app "+app.Name+" as installed")
			if err != nil {
				return err
			}
			st.snapshot = r.Name
			s.emitIn(ctx, proj, "jail-snapshot-created", "/api/v1/jails/"+jail+"/snapshots/"+r.Name)
			return nil
		}})
	// An installed service is meant to run: it comes back when the host boots. The last step, so that an interrupted
	// or failed installation, which is kept stopped for inspection, never starts again by itself.
	pl.Add(plan.Step{Name: "enable-autostart", Describe: "boot.autostart of " + jail + ": start with the host",
		Do: func(ctx context.Context) error { return s.setJailAutostart(ctx, key, true) }})
	return pl
}

// dropCreatedJail deletes a jail an installation created and never started;
// it does nothing for a jail that was not made.
func (s *Service) dropCreatedJail(ctx context.Context, proj, key string) error {
	_, jail := validate.SplitQualified(key)
	if ok, err := s.d.ZFS.Exists(ctx, s.lcfg.ContainerDS(key)); err != nil {
		return err
	} else if ok {
		if _, err := s.life.DestroyJail(ctx, key, true, false); err != nil {
			return err
		}
	}
	s.mu.Lock()
	_, had := s.jails[key]
	delete(s.jails, key)
	s.forgetProvisioned(key)
	delete(s.status, key)
	s.mu.Unlock()
	if had {
		s.emitIn(ctx, proj, "jail-deleted", "/api/v1/jails/"+jail)
	}
	return nil
}

// runHost runs a host command through the runner (the privileged helper in
// production, which checks it against its allow-list).
func (s *Service) runHost(ctx context.Context, timeout time.Duration, argv []string) error {
	res, err := s.d.Run.Run(ctx, run.Cmd{Name: argv[0], Args: argv[1:], Timeout: timeout})
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, tailOf(append(res.Stdout, res.Stderr...)))
	}
	return nil
}

func tailOf(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 1000 {
		s = "..." + s[len(s)-1000:]
	}
	return s
}

// packageVersion reads the answer of `pkg query %v`: one line, a version.
func packageVersion(out []byte) (string, bool) {
	v := strings.TrimSpace(string(out))
	if v == "" || len(v) > 64 || strings.ContainsAny(v, " \t\n") {
		return "", false
	}
	for _, r := range v {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return v, true
}

// setJailLabels adds labels to a jail record; the caller holds the jail lock.
func (s *Service) setJailLabels(ctx context.Context, key string, set map[string]string) error {
	nj, err := s.jailSnapshot(key)
	if err != nil {
		return err
	}
	if nj.Metadata.Labels == nil {
		nj.Metadata.Labels = map[string]string{}
	}
	for k, v := range set {
		nj.Metadata.Labels[k] = v
	}
	nj.Metadata.Generation++
	nj.Metadata.UpdatedAt = s.now().UTC()
	if err := s.writeJailRecord(ctx, nj); err != nil {
		return internal(err)
	}
	s.mu.Lock()
	if e := s.jails[key]; e != nil {
		nj.Status.Generation = e.jail.Status.Generation
		e.jail = nj
	}
	s.mu.Unlock()
	return nil
}

// setJailAutostart writes boot.autostart of a jail without touching anything else of it.
func (s *Service) setJailAutostart(ctx context.Context, key string, on bool) error {
	nj, err := s.jailSnapshot(key)
	if err != nil {
		return err
	}
	nj.Spec.Boot.Autostart = on
	nj.Metadata.Generation++
	nj.Metadata.UpdatedAt = s.now().UTC()
	if err := s.writeJailRecord(ctx, nj); err != nil {
		return internal(err)
	}
	s.mu.Lock()
	if e := s.jails[key]; e != nil {
		nj.Status.Generation = e.jail.Status.Generation
		e.jail = nj
	}
	s.mu.Unlock()
	return nil
}

// ---- health ----

func healthDescribe(h *api.AppHealth) string {
	switch {
	case h.TCP != 0:
		return fmt.Sprintf("connect to tcp port %d of the jail's first address, retried for %ds", h.TCP, h.WaitSeconds)
	case h.HTTP != nil:
		return fmt.Sprintf("GET http://<first address>:%d%s must answer %d, retried for %ds", h.HTTP.Port, h.HTTP.Path, h.HTTP.Status, h.WaitSeconds)
	default:
		return fmt.Sprintf("in the jail: %s must exit 0, retried for %ds", strings.Join(h.Exec, " "), h.WaitSeconds)
	}
}

// appHealth runs the check until it passes or wait_seconds have passed.
func (s *Service) appHealth(ctx context.Context, key string, h *api.AppHealth) error {
	j, err := s.jailSnapshot(key)
	if err != nil {
		return err
	}
	var addr netip.Addr
	if h.TCP != 0 || h.HTTP != nil {
		a := jailAddrs(s.effective(j))
		if len(a) == 0 {
			return errors.New("the jail has no address to check")
		}
		addr = a[0]
	}
	return healthLoop(ctx, s.now, s.sleep, time.Duration(max(h.WaitSeconds, 1))*time.Second, func(timeout time.Duration) error {
		return s.appHealthOnce(ctx, key, addr, h, timeout)
	})
}

// healthAttempt is the longest one attempt of a health check may take.
const healthAttempt = 5 * time.Second

// healthLoop runs check once a second until it passes or wait has passed.
// Each attempt is given min(healthAttempt, the time left), so the loop ends
// within wait and one attempt.
func healthLoop(ctx context.Context, now func() time.Time, sleep func(context.Context, time.Duration) error, wait time.Duration, check func(timeout time.Duration) error) error {
	deadline := now().Add(wait)
	for {
		left := deadline.Sub(now())
		err := check(max(min(healthAttempt, left), time.Second))
		if err == nil {
			return nil
		}
		if !now().Add(time.Second).Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("the health check did not pass within %ds: %w", int(wait/time.Second), err)
		}
		if err := sleep(ctx, time.Second); err != nil {
			return err
		}
	}
}

func (s *Service) appHealthOnce(ctx context.Context, key string, addr netip.Addr, h *api.AppHealth, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch {
	case h.TCP != 0:
		c, err := s.dial(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(h.TCP)))
		if err != nil {
			return err
		}
		return c.Close()
	case h.HTTP != nil:
		client := &http.Client{Transport: &http.Transport{DialContext: s.dial, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(addr.String(), strconv.Itoa(h.HTTP.Port))+h.HTTP.Path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != h.HTTP.Status {
			return fmt.Errorf("GET %s answered %d, not %d", h.HTTP.Path, resp.StatusCode, h.HTTP.Status)
		}
		return nil
	default:
		_, err := s.runInJail(ctx, key, timeout, h.Exec...)
		return err
	}
}

// dial connects from the host to an address of a jail.
func (s *Service) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if s.d.DialJail != nil {
		return s.d.DialJail(ctx, network, address)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, address)
}

// sleep waits, through the lifecycle's clock when a test set one.
func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.lcfg.Sleep != nil {
		return s.lcfg.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
