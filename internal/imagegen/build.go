package imagegen

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

// BuildResult is the outcome of Build.
type BuildResult struct {
	// Plan lists the exact steps (always set; for a dry run it is all there is).
	Plan       []string
	DryRun     bool
	Generation api.ImageGeneration
	// Status is the image status recorded after the build.
	Status api.ImageStatus
	// Unchanged is set by Upgrade when the package set equals the parent's:
	// the staging dataset was destroyed and no generation was kept.
	Unchanged bool
}

type buildState struct {
	pkgs      []Package
	manifest  string
	createdAt string
	imageMade bool
	oldAlias  string
	hadAlias  bool
	// requireChange stops the plan, keeping nothing, when the package set
	// equals the parent's.
	requireChange bool
}

// errUnchanged stops an upgrade whose package set equals the parent's. The
// plan rolls back as for any failure, so nothing is left behind.
var errUnchanged = errors.New("the package set did not change")

// Build builds the next generation of an image: a staging clone of the parent
// (or an empty dataset for the first one), install or upgrade through the
// source, validation, @ro, jailops:* properties, and a rename into place. The
// rename is the commit point; a failure before it leaves no generation and no
// leaked dataset. DryRun returns the exact plan without touching anything.
func (m *Manager) Build(ctx context.Context, image string, req api.ImageBuild) (BuildResult, error) {
	return m.build(ctx, image, req, false)
}

// Upgrade is Build from an earlier generation (req.FromGeneration, required)
// that keeps the result only when the package set changed: the package
// manager exits cleanly when there is nothing to upgrade, which would leave a
// generation identical to its parent. The result then says Unchanged and
// holds no generation.
func (m *Manager) Upgrade(ctx context.Context, image string, req api.ImageBuild) (BuildResult, error) {
	if req.FromGeneration <= 0 {
		return BuildResult{}, api.Errorf(api.CodeInvalid, "an upgrade needs the generation to build from")
	}
	return m.build(ctx, image, req, true)
}

func (m *Manager) build(ctx context.Context, image string, req api.ImageBuild, requireChange bool) (BuildResult, error) {
	var res BuildResult
	if m.Specs == nil {
		return res, api.Errorf(api.CodeInternal, "image manager has no spec provider")
	}
	spec, err := m.Specs(ctx, image)
	if err != nil {
		return res, err
	}
	src, err := m.source(spec.Source.Type)
	if err != nil {
		return res, err
	}
	if err := src.CheckSpec(spec); err != nil {
		return res, err
	}
	obs, err := m.Observe(ctx, image)
	if err != nil {
		return res, err
	}
	if len(obs.Staging) > 0 {
		return res, api.Errorf(api.CodeBusy, "image %s has leftover staging datasets %v from an interrupted build", image, obs.Staging).
			WithHint("run recovery for the image build or destroy the staging datasets")
	}
	max, err := m.MaxNumber(ctx, image)
	if err != nil {
		return res, err
	}
	n := max + 1
	b := &Build{M: m, Image: image, Spec: spec, Number: n, Root: m.Layout.StagingMount(image, n),
		Work: path.Join(m.Work, fmt.Sprintf("%s-g%d", image, n))}
	if req.FromGeneration > 0 {
		if _, ok := obs.gen(req.FromGeneration); !ok {
			// The parent may exist on another pool only; a clone needs it here.
			if req.DryRun {
				if _, perr := m.findAcross(ctx, image, req.FromGeneration); perr != nil {
					return res, perr
				}
			} else if _, perr := m.Provide(ctx, GenerationName(image, req.FromGeneration)); perr != nil {
				return res, perr
			}
		}
		b.Parent = req.FromGeneration
	}
	var srcSteps []plan.Step
	if b.Parent > 0 {
		srcSteps, err = src.Upgrade(b)
	} else {
		srcSteps, err = src.Install(b)
	}
	if err != nil {
		return res, err
	}
	st := &buildState{requireChange: requireChange}
	p := m.buildPlan(b, src, srcSteps, st)
	res.Plan = p.Describe()
	if req.DryRun {
		res.DryRun = true
		return res, nil
	}
	if err := m.executor().Run(ctx, fmt.Sprintf("image-build/%s/g%d", image, n), p); err != nil {
		var pe *plan.Error
		if errors.Is(err, errUnchanged) && (!errors.As(err, &pe) || len(pe.UndoErrs) == 0) {
			res.Unchanged = true
			return res, nil
		}
		return res, err
	}
	after, err := m.Observe(ctx, image)
	if err != nil {
		return res, err
	}
	res.Status = after.Status
	g, ok := after.gen(n)
	if !ok {
		return res, api.Errorf(api.CodeInternal, "generation %s missing after build", GenerationName(image, n))
	}
	res.Generation = g
	return res, nil
}

func (m *Manager) buildPlan(b *Build, src Source, srcSteps []plan.Step, st *buildState) *plan.Plan {
	z := m.ZFS
	imageDS := m.Layout.ImageDS(b.Image)
	staging := m.Layout.StagingDS(b.Image, b.Number)
	final := m.Layout.GenDS(b.Image, b.Number)
	ro := final + "@" + ROSnap
	stagingRO := staging + "@" + ROSnap
	finalMount := m.Layout.GenMount(b.Image, b.Number)
	p := plan.New("image-build " + GenerationName(b.Image, b.Number))
	baseProps := map[string]string{PropManaged: "on", PropImage: b.Image}
	with := func(extra map[string]string) map[string]string {
		o := map[string]string{}
		for k, v := range baseProps {
			o[k] = v
		}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	destroyIfExists := func(ds string, recursive bool) func(context.Context) error {
		return func(ctx context.Context) error {
			ok, err := z.Exists(ctx, ds)
			if err != nil || !ok {
				return err
			}
			if recursive {
				return z.DestroyRecursive(ctx, ds)
			}
			return z.Destroy(ctx, ds)
		}
	}

	p.Add(plan.Step{
		Name: "ensure-image-dataset", Describe: "zfs create " + imageDS + " (if missing)",
		Do: func(ctx context.Context) error {
			ok, err := z.Exists(ctx, imageDS)
			if err != nil || ok {
				return err
			}
			st.imageMade = true
			return z.Create(ctx, imageDS, with(map[string]string{PropKind: KindImage, "canmount": "off", "mountpoint": "none"}))
		},
		Undo: func(ctx context.Context) error {
			if !st.imageMade {
				return nil
			}
			return destroyIfExists(imageDS, false)(ctx)
		},
		UndoOnFail: true,
	})
	props := with(map[string]string{PropKind: KindStaging, "mountpoint": b.Root, "canmount": "on", PropGen: strconv.Itoa(b.Number)})
	if b.Parent > 0 {
		parentSnap := m.Layout.GenDS(b.Image, b.Parent) + "@" + ROSnap
		p.Add(plan.Step{Name: "clone-parent", Describe: "zfs clone " + parentSnap + " " + staging,
			Do:   func(ctx context.Context) error { return z.Clone(ctx, parentSnap, staging, props) },
			Undo: destroyIfExists(staging, true)})
	} else {
		p.Add(plan.Step{Name: "create-staging", Describe: "zfs create " + staging,
			Do:   func(ctx context.Context) error { return z.Create(ctx, staging, props) },
			Undo: destroyIfExists(staging, true)})
	}
	p.Add(plan.Step{Name: "mount-staging", Describe: "zfs mount " + staging,
		Do: func(ctx context.Context) error { return z.Mount(ctx, staging) },
		Undo: func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, staging); !ok {
				return nil
			}
			return z.Unmount(ctx, staging)
		}})
	p.Add(srcSteps...)
	p.Add(plan.Step{
		Name: "read-packages", Describe: "read the installed package set and hash it",
		Do: func(ctx context.Context) error {
			pk, err := src.Packages(ctx, b)
			if err != nil {
				return err
			}
			if len(pk) == 0 {
				return fmt.Errorf("the installed package set is empty")
			}
			st.pkgs, st.manifest = pk, ManifestHash(pk)
			return nil
		}})
	if st.requireChange && b.Parent > 0 {
		parentDS := m.Layout.GenDS(b.Image, b.Parent)
		p.Add(plan.Step{
			Name: "require-change", Describe: "stop, keeping nothing, when the package set equals that of " + GenerationName(b.Image, b.Parent),
			Do: func(ctx context.Context) error {
				if v, _ := z.Get(ctx, parentDS, PropManifest); v == st.manifest {
					return errUnchanged
				}
				return nil
			}})
	}
	p.Add(src.Check(b)...)
	p.Add(plan.Step{
		Name: "validate-paths", Describe: fmt.Sprintf("require %v under %s", src.RequiredPaths(), b.Root),
		Do: func(ctx context.Context) error {
			for _, rp := range src.RequiredPaths() {
				ok, err := m.Files.Exists(ctx, path.Join(b.Root, rp))
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("generation is incomplete: %s is missing", rp)
				}
			}
			return nil
		}})
	p.Add(plan.Step{Name: "unmount-staging", Describe: "zfs unmount " + staging,
		Do: func(ctx context.Context) error { return z.Unmount(ctx, staging) }})
	p.Add(plan.Step{
		Name: "set-properties", Describe: "zfs set jailops:* canmount=noauto mountpoint=" + finalMount + " " + staging,
		Do: func(ctx context.Context) error {
			st.createdAt = m.now().Format("2006-01-02T15:04:05Z07:00")
			props := map[string]string{
				PropKind: KindGeneration, PropManifest: st.manifest, PropPackages: strconv.Itoa(len(st.pkgs)),
				PropParent: strconv.Itoa(b.Parent), PropOSRelease: b.Spec.Release, PropSource: b.Spec.Source.Type, PropOS: string(b.Spec.OS),
				PropCreated: st.createdAt, "canmount": "noauto", "mountpoint": finalMount,
			}
			if v := FreeBSDVersion(st.pkgs); v != "" {
				props[PropFreeBSD] = v
			}
			return z.Set(ctx, staging, props)
		}})
	p.Add(plan.Step{Name: "snapshot-ro", Describe: "zfs snapshot " + stagingRO,
		Do:   func(ctx context.Context) error { return z.Snapshot(ctx, nil, stagingRO) },
		Undo: destroyIfExists(stagingRO, false)})
	p.Add(plan.Step{Name: "hold-ro", Describe: "zfs hold " + HoldTag + " " + stagingRO,
		Do: func(ctx context.Context) error { return z.Hold(ctx, stagingRO, HoldTag) },
		Undo: func(ctx context.Context) error {
			for _, snap := range []string{stagingRO, ro} {
				if ok, _ := z.Exists(ctx, snap); ok {
					hs, err := z.Holds(ctx, snap)
					if err != nil {
						return err
					}
					for _, h := range hs {
						if h == HoldTag {
							return z.Release(ctx, snap, HoldTag)
						}
					}
				}
			}
			return nil
		}})
	p.Add(plan.Step{Name: "rename-into-place", Describe: "zfs rename " + staging + " " + final + "  (commit point)",
		Do: func(ctx context.Context) error { return z.Rename(ctx, staging, final) },
		Undo: func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, final); !ok {
				return nil
			}
			if ok, _ := z.Exists(ctx, staging); ok {
				return nil
			}
			return z.Rename(ctx, final, staging)
		}})
	p.Add(plan.Step{
		Name: "move-aliases", Describe: "alias latest and unset aliases of the spec point at " + GenerationName(b.Image, b.Number),
		Do: func(ctx context.Context) error {
			old, err := z.Get(ctx, imageDS, PropAliases)
			if err != nil {
				return err
			}
			st.oldAlias, st.hadAlias = old, old != ""
			al := parseAliases(old)
			for _, a := range b.Spec.Aliases {
				if _, set := al[a]; !set || a == "latest" {
					al[a] = b.Number
				}
			}
			if v := formatAliases(al); v != old && v != "" {
				return z.Set(ctx, imageDS, map[string]string{PropAliases: v})
			}
			return nil
		},
		Undo: func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, imageDS); !ok {
				return nil
			}
			cur, _ := z.Get(ctx, imageDS, PropAliases)
			if cur == st.oldAlias {
				return nil
			}
			if st.hadAlias {
				return z.Set(ctx, imageDS, map[string]string{PropAliases: st.oldAlias})
			}
			return z.Inherit(ctx, imageDS, PropAliases)
		},
		UndoOnFail: true,
	})
	var oldLast string
	p.Add(plan.Step{
		Name: "record-last-generation", Describe: fmt.Sprintf("zfs set %s=%d %s", PropLastGen, b.Number, imageDS),
		Do: func(ctx context.Context) error {
			oldLast, _ = z.Get(ctx, imageDS, PropLastGen)
			return z.Set(ctx, imageDS, map[string]string{PropLastGen: strconv.Itoa(b.Number)})
		},
		Undo: func(ctx context.Context) error {
			if ok, _ := z.Exists(ctx, imageDS); !ok {
				return nil
			}
			cur, _ := z.Get(ctx, imageDS, PropLastGen)
			if cur == oldLast {
				return nil
			}
			if oldLast == "" {
				return z.Inherit(ctx, imageDS, PropLastGen)
			}
			return z.Set(ctx, imageDS, map[string]string{PropLastGen: oldLast})
		},
		UndoOnFail: true,
	})
	p.Add(m.cleanWork(b.Work))
	return p
}

// SetAlias moves an alias to an existing generation (for example "stable").
func (m *Manager) SetAlias(ctx context.Context, image, alias string, n int) error {
	if !validAlias(alias) {
		return api.Errorf(api.CodeInvalid, "bad alias %q", alias)
	}
	o, err := m.Observe(ctx, image)
	if err != nil {
		return err
	}
	if _, ok := o.gen(n); !ok {
		return api.Errorf(api.CodeNotFound, "generation %s does not exist", GenerationName(image, n))
	}
	al := o.Status.Aliases
	if al == nil {
		al = map[string]int{}
	}
	al[alias] = n
	return m.ZFS.Set(ctx, m.Layout.ImageDS(image), map[string]string{PropAliases: formatAliases(al)})
}
