package imagegen

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

// Manager builds, observes and deletes image generations. It holds no state of
// its own: ZFS properties are authoritative. Callers serialise operations on
// one image with a per-image lock.
type Manager struct {
	Layout   Layout
	Work     string // scratch directory for repository configuration
	ZFS      ZFS
	Exec     Exec
	Files    Files
	Executor *plan.Executor
	// Specs returns the desired spec of an image.
	Specs func(ctx context.Context, image string) (api.ImageSpec, error)
	Now   func() time.Time
	// Sources overrides the source registry (DefaultSources when nil).
	Sources map[string]Source
	// Peers returns the managers of every pool, this one included. Clones
	// need a generation on their own pool, so each pool holds its own copy of
	// the generations its jails use; a pool that lacks one receives it from a
	// peer (Provide), and generation numbers are unique across all pools.
	Peers func() []*Manager
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) executor() *plan.Executor {
	if m.Executor != nil {
		return m.Executor
	}
	return &plan.Executor{}
}

func (m *Manager) source(typ string) (Source, error) {
	srcs := m.Sources
	if srcs == nil {
		srcs = DefaultSources()
	}
	s, ok := srcs[typ]
	if !ok {
		return nil, api.Errorf(api.CodeUnsupported, "image source type %q is not implemented", typ)
	}
	return s, nil
}

// Observed is what the datasets say about one image.
type Observed struct {
	Status api.ImageStatus
	// Deleted lists generation numbers parked in deleted/ (still referenced by clones).
	Deleted []int
	// Staging lists leftover staging datasets from interrupted builds.
	Staging []string
	// Problems lists generation datasets that are not valid (no @ro, not managed).
	Problems  []string
	MaxNumber int
}

func (o Observed) gen(n int) (api.ImageGeneration, bool) {
	for _, g := range o.Status.Generations {
		if g.Number == n {
			return g, true
		}
	}
	return api.ImageGeneration{}, false
}

func formatAliases(a map[string]int) string {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + strconv.Itoa(a[k])
	}
	return strings.Join(parts, ",")
}

func parseAliases(s string) map[string]int {
	out := map[string]int{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(v); err == nil && validAlias(k) {
			out[k] = n
		}
	}
	return out
}

func directChildren(parent string, all []string) []string {
	var out []string
	for _, n := range all {
		rest := strings.TrimPrefix(n, parent+"/")
		if rest != n && !strings.Contains(rest, "/") {
			out = append(out, rest)
		}
	}
	return out
}

// Observe reads the generations of an image from ZFS.
func (m *Manager) Observe(ctx context.Context, image string) (Observed, error) {
	var o Observed
	if !validImage(image) {
		return o, api.Errorf(api.CodeInvalid, "bad image name %q", image)
	}
	ids := m.Layout.ImageDS(image)
	ok, err := m.ZFS.Exists(ctx, ids)
	if err != nil {
		return o, err
	}
	if ok {
		all, err := m.ZFS.Descendants(ctx, ids)
		if err != nil {
			return o, err
		}
		for _, c := range directChildren(ids, all) {
			ds := ids + "/" + c
			if strings.HasPrefix(c, "staging-") {
				o.Staging = append(o.Staging, ds)
				continue
			}
			mm := genRe.FindStringSubmatch(c)
			if mm == nil {
				continue
			}
			n, _ := strconv.Atoi(mm[1])
			if n > o.MaxNumber {
				o.MaxNumber = n
			}
			g, err := m.readGen(ctx, image, n, ds)
			if err != nil {
				o.Problems = append(o.Problems, fmt.Sprintf("%s: %v", ds, err))
				continue
			}
			o.Status.Generations = append(o.Status.Generations, g)
		}
		if lg, _ := m.ZFS.Get(ctx, ids, PropLastGen); lg != "" {
			if n, err := strconv.Atoi(lg); err == nil && n > o.MaxNumber {
				o.MaxNumber = n
			}
		}
		al, err := m.ZFS.Get(ctx, ids, PropAliases)
		if err != nil {
			return o, err
		}
		if al != "" {
			o.Status.Aliases = parseAliases(al)
		}
	}
	dp := m.Layout.DeletedParent()
	if ok, _ := m.ZFS.Exists(ctx, dp); ok {
		all, err := m.ZFS.Descendants(ctx, dp)
		if err != nil {
			return o, err
		}
		for _, c := range directChildren(dp, all) {
			ds := dp + "/" + c
			if img, _ := m.ZFS.Get(ctx, ds, PropImage); img != image {
				continue
			}
			gs, _ := m.ZFS.Get(ctx, ds, PropGen)
			if n, err := strconv.Atoi(gs); err == nil {
				o.Deleted = append(o.Deleted, n)
				if n > o.MaxNumber {
					o.MaxNumber = n
				}
			}
		}
		sort.Ints(o.Deleted)
	}
	sort.Slice(o.Status.Generations, func(i, j int) bool { return o.Status.Generations[i].Number < o.Status.Generations[j].Number })
	return o, nil
}

func (m *Manager) readGen(ctx context.Context, image string, n int, ds string) (api.ImageGeneration, error) {
	g := api.ImageGeneration{Number: n, Name: GenerationName(image, n), Dataset: ds}
	if ok, err := m.ZFS.Exists(ctx, ds+"@"+ROSnap); err != nil {
		return g, err
	} else if !ok {
		return g, fmt.Errorf("no @%s snapshot", ROSnap)
	}
	if v, _ := m.ZFS.Get(ctx, ds, PropManaged); v != "on" {
		return g, fmt.Errorf("not managed by JailOps")
	}
	get := func(p string) string { v, _ := m.ZFS.Get(ctx, ds, p); return v }
	g.Manifest = get(PropManifest)
	g.Packages, _ = strconv.Atoi(get(PropPackages))
	g.FreeBSDVersion = get(PropFreeBSD)
	g.Parent, _ = strconv.Atoi(get(PropParent))
	if t, err := time.Parse(time.RFC3339, get(PropCreated)); err == nil {
		g.CreatedAt = t
	}
	return g, nil
}

// FreeBSDVersion reads the FreeBSD version recorded on generation n of an image on this pool: "" when the generation
// is not here or was built before JailOps recorded it.
func (m *Manager) FreeBSDVersion(ctx context.Context, image string, n int) string {
	v, _ := m.ZFS.Get(ctx, m.Layout.GenDS(image, n), PropFreeBSD)
	return v
}

// Resolve turns an image reference into a generation.
func (m *Manager) Resolve(ctx context.Context, ref string) (api.ImageGeneration, error) {
	r, err := ParseRef(ref)
	if err != nil {
		return api.ImageGeneration{}, err
	}
	o, err := m.Observe(ctx, r.Image)
	if err != nil {
		return api.ImageGeneration{}, err
	}
	n, err := resolveNumber(r, o.Status)
	if err != nil {
		return api.ImageGeneration{}, err
	}
	g, ok := o.gen(n)
	if !ok {
		return g, api.Errorf(api.CodeNotFound, "generation %s does not exist", GenerationName(r.Image, n))
	}
	return g, nil
}

func resolveNumber(r Ref, st api.ImageStatus) (int, error) {
	switch {
	case r.Gen > 0:
		return r.Gen, nil
	case r.Alias != "":
		n, ok := st.Aliases[r.Alias]
		if !ok {
			return 0, api.Errorf(api.CodeNotFound, "image %s has no alias %q", r.Image, r.Alias)
		}
		return n, nil
	}
	max := 0
	for _, g := range st.Generations {
		if g.Number > max {
			max = g.Number
		}
	}
	if max == 0 {
		return 0, api.Errorf(api.CodeNotFound, "image %s has no generations", r.Image)
	}
	return max, nil
}

// Ensure resolves a reference, building the first generation from the source
// when the image has none yet. It never invents a pinned generation number.
func (m *Manager) Ensure(ctx context.Context, ref string) (api.ImageGeneration, error) {
	g, err := m.Resolve(ctx, ref)
	if err == nil || !api.IsCode(err, api.CodeNotFound) {
		return g, err
	}
	r, _ := ParseRef(ref)
	o, oerr := m.Observe(ctx, r.Image)
	if oerr != nil {
		return g, oerr
	}
	if r.Gen > 0 || len(o.Status.Generations) > 0 {
		return g, err
	}
	res, berr := m.Build(ctx, r.Image, api.ImageBuild{})
	if berr != nil {
		return g, berr
	}
	return res.Generation, nil
}
