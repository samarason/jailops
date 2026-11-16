package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/hostdir"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

// ZFS user properties on jail datasets.
const (
	PropManaged      = "jailops:managed"
	PropID           = "jailops:id"
	PropKind         = "jailops:kind"
	PropName         = "jailops:name"
	PropProject      = "jailops:project"
	PropImage        = "jailops:image"
	PropGen          = "jailops:gen"
	PropPrevGen      = "jailops:prev_gen"
	PropManifest     = "jailops:manifest"
	PropLayout       = "jailops:layout"
	PropComplete     = "jailops:complete"
	PropClass        = "jailops:class"
	PropMerge        = "jailops:merge"
	PropPath         = "jailops:path"
	PropCleanupAfter = "jailops:cleanup_after"
	PropComment      = "jailops:comment"
	// PropEncrypted marks a volume JailOps created as an encryption root with a passphrase.
	PropEncrypted = "jailops:encrypted"
	// Properties of image generation datasets that the lifecycle reads. The
	// strings are the same as in internal/imagegen.
	PropOSRelease = "jailops:osrelease"
	PropOS        = "jailops:os"

	KindContainer  = "container"
	KindRoot       = "root"
	KindPersistent = "persistent"
	KindVolume     = "volume"
	KindVolumes    = "volumes"
	// KindDelegated is the dataset a jail manages itself (zfs_delegation): <container>/delegated.
	KindDelegated = "delegated"

	roSnap = "ro"
)

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	sizeRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[KMGTP]?$`)
)

// Service runs jail lifecycle operations. Callers hold a per-jail lock around
// every method; the Service itself keeps no state.
type Service struct {
	Cfg      Config
	ZFS      ZFS
	Exec     Exec
	Jails    Jails
	Files    Files
	Hooks    Hooks
	Images   Images
	Executor *plan.Executor
	// Keys encrypts volumes; nil refuses encrypted volumes (unsupported).
	Keys Keys
	// Warn, when set, is told of something a stop could not finish or had to force: the jail, the event's action, what.
	Warn func(ctx context.Context, jail, action, what string)
}

func (s *Service) executor() *plan.Executor {
	if s.Executor != nil {
		return s.Executor
	}
	return &plan.Executor{}
}

// run executes a plan under a journal id of the form "<op>/<jail>".
func (s *Service) run(ctx context.Context, op, jail string, p *plan.Plan) error {
	return s.executor().Run(ctx, op+"/"+jail, p)
}

// RecoverRun rolls back an interrupted run of op on jail; p must be rebuilt with
// the same inputs (including the Stamp) as the interrupted run.
func (s *Service) RecoverRun(ctx context.Context, op, jail string, p *plan.Plan) (bool, error) {
	return s.executor().Recover(ctx, op+"/"+jail, p)
}

func validName(kind, n string) error {
	if !nameRe.MatchString(n) {
		return api.Errorf(api.CodeInvalid, "%s name %q must match %s", kind, n, nameRe)
	}
	return nil
}

// dsInfo describes one dataset of a jail.
type dsInfo struct {
	DS    string
	Kind  string
	Class Class
	Path  string // mount path inside the jail
	Merge bool
	MP    string // absolute mountpoint
	// Encrypted is set on a volume that is its own encryption root (jailops:encrypted=on).
	Encrypted bool
}

// jailState is what the datasets say about a jail.
type jailState struct {
	Name      string
	Container string
	ID        string
	Layout    api.Layout
	Image     string // image name
	Gen       int
	Prev      int
	Manifest  string
	Complete  bool
	Root      string
	Persist   []dsInfo // persistent datasets, mount order
	Volumes   []dsInfo // the volumes attached to the jail
	// HostDirs are the attached volumes that are directories of the host: they have no dataset.
	HostDirs []Attached
	// VolumeErr is why an attached volume could not be found: the jail does not start, everything else still works.
	VolumeErr error
	Delegated string   // the dataset handed to the jail (zfs_delegation), empty when there is none
	Extra     []string // root.new, root.old if present
}

func (st *jailState) hasRootOld() bool   { return st.has("/root.old") }
func (st *jailState) hasRootNew() bool   { return st.has("/root.new") }
func (st *jailState) hasRootStale() bool { return st.has("/root.stale") }
func (st *jailState) has(suffix string) bool {
	for _, e := range st.Extra {
		if strings.HasSuffix(e, suffix) {
			return true
		}
	}
	return false
}

// all returns every dataset of the snapshot set: container, root, persistent and the delegated dataset (not
// root.new/root.old, and not the volumes attached to the jail: they belong to the project and are never snapshotted,
// rolled back or copied with a jail).
func (st *jailState) all() []string {
	out := []string{st.Container, st.Root}
	for _, d := range st.Persist {
		out = append(out, d.DS)
	}
	if st.Delegated != "" {
		out = append(out, st.Delegated)
	}
	return out
}

// mountOrder is root first, then persistent datasets by path depth. The volumes attached to the jail are mounted on
// the host where their own mountpoint is (the jail reaches them through nullfs) and stay mounted when the jail stops.
func (st *jailState) mountOrder() []string {
	out := []string{st.Root}
	for _, d := range st.Persist {
		out = append(out, d.DS)
	}
	return out
}

func depth(p string) int { return strings.Count(strings.Trim(p, "/"), "/") }

func (s *Service) prop(ctx context.Context, ds, p string) string {
	v, _ := s.ZFS.Get(ctx, ds, p)
	return v
}

// observe reads a jail from its datasets. Objects without jailops:managed=on
// are never touched.
func (s *Service) observe(ctx context.Context, name string) (*jailState, error) {
	if err := validName("jail", name); err != nil {
		return nil, err
	}
	c := s.Cfg.at(name).containerDS()
	ok, err := s.ZFS.Exists(ctx, c)
	if err != nil {
		return nil, err
	}
	if !ok || s.prop(ctx, c, PropManaged) != "on" || s.prop(ctx, c, PropKind) != KindContainer {
		return nil, api.Errorf(api.CodeNotFound, "jail %q does not exist", name)
	}
	st := &jailState{Name: name, Container: c, ID: s.prop(ctx, c, PropID), Root: s.Cfg.at(name).rootDS(),
		Layout: api.Layout(s.prop(ctx, c, PropLayout)), Complete: s.prop(ctx, c, PropComplete) == "on"}
	// the container carries the image name, so it is known even in the middle
	// of a root swap when no dataset is named root
	st.Image = s.prop(ctx, c, PropImage)
	st.Gen, _ = strconv.Atoi(s.prop(ctx, st.Root, PropGen))
	st.Prev, _ = strconv.Atoi(s.prop(ctx, st.Root, PropPrevGen))
	st.Manifest = s.prop(ctx, st.Root, PropManifest)
	desc, err := s.ZFS.Descendants(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, d := range desc {
		rel := strings.TrimPrefix(d, c+"/")
		switch {
		case rel == "root":
		case rel == "root.new" || rel == "root.old" || rel == "root.stale":
			st.Extra = append(st.Extra, d)
		case rel == "data":
		case rel == "delegated":
			st.Delegated = d
		case !strings.Contains(rel, "/") && s.prop(ctx, d, PropKind) == KindPersistent:
			st.Persist = append(st.Persist, s.info(ctx, d, KindPersistent))
		}
	}
	sortByDepth := func(l []dsInfo) {
		sort.SliceStable(l, func(i, j int) bool {
			if di, dj := depth(l[i].Path), depth(l[j].Path); di != dj {
				return di < dj
			}
			return l[i].DS < l[j].DS
		})
	}
	sortByDepth(st.Persist)
	att, verr := s.Cfg.attached(name)
	st.VolumeErr = verr
	for _, a := range att {
		if a.HostDir {
			st.HostDirs = append(st.HostDirs, a)
			continue
		}
		st.Volumes = append(st.Volumes, dsInfo{DS: a.Dataset, Kind: KindVolume, Class: ClassData, Path: a.Path, MP: a.Mountpoint, Encrypted: a.Encrypted})
	}
	sortByDepth(st.Volumes)
	return st, nil
}

func (s *Service) info(ctx context.Context, ds, kind string) dsInfo {
	return dsInfo{DS: ds, Kind: kind, Class: Class(s.prop(ctx, ds, PropClass)), Path: s.prop(ctx, ds, PropPath),
		Merge: s.prop(ctx, ds, PropMerge) == "on", MP: s.prop(ctx, ds, "mountpoint"), Encrypted: kind == KindVolume && s.prop(ctx, ds, PropEncrypted) == "on"}
}

func (s *Service) mergeDatasets(st *jailState) []string {
	var out []string
	for _, d := range st.Persist {
		if d.Merge {
			out = append(out, d.DS)
		}
	}
	return out
}

// dataDatasets are the datasets a "data" rollback restores.
func dataDatasets(st *jailState) []string {
	var out []string
	for _, d := range st.Persist {
		if d.Class != ClassSystem {
			out = append(out, d.DS)
		}
	}
	if st.Delegated != "" {
		out = append(out, st.Delegated)
	}
	return out
}

func (s *Service) systemDatasets(st *jailState) []string {
	var out []string
	for _, d := range st.Persist {
		if d.Class == ClassSystem {
			out = append(out, d.DS)
		}
	}
	return out
}

// mountTree mounts the root, the persistent datasets and the volumes, creating
// volume mount directories inside the root first. Mount is idempotent.
func (s *Service) mountTree(ctx context.Context, name string) error {
	st, err := s.observe(ctx, name)
	if err != nil {
		return err
	}
	if st.VolumeErr != nil {
		return st.VolumeErr
	}
	if err := s.refuseLocked(ctx, st); err != nil {
		return err
	}
	if err := s.ZFS.Mount(ctx, st.Root); err != nil {
		return err
	}
	for _, d := range st.Persist {
		if err := s.ZFS.Mount(ctx, d.DS); err != nil {
			return err
		}
	}
	for _, v := range st.Volumes {
		// The volume is mounted on the host at its own mountpoint (idempotent); the jail's fstab binds it into the
		// jail with nullfs. The mount point directory must exist in the root: creating it here keeps it correct after
		// an upgrade replaced the root.
		if err := s.ZFS.Mount(ctx, v.DS); err != nil {
			return fmt.Errorf("volume %s: %w", volumeName(v.DS), err)
		}
		if err := s.Files.MkdirAll(ctx, s.Cfg.at(name).rootMP()+v.Path); err != nil {
			return err
		}
	}
	for _, h := range st.HostDirs {
		// A host directory that is not on a mount is the empty directory a lost mount leaves behind: the jail would
		// take it for its data. It does not start.
		if err := s.checkHostDir(ctx, h); err != nil {
			return err
		}
		if err := s.Files.MkdirAll(ctx, s.Cfg.at(name).rootMP()+h.Path); err != nil {
			return err
		}
	}
	return nil
}

// checkHostDir refuses to give a jail a host directory that is not on a mount now.
func (s *Service) checkHostDir(ctx context.Context, h Attached) error {
	p, err := hostdir.Within(ctx, hostdir.Timeout, func(ctx context.Context) (hostdir.Probe, error) {
		return s.Files.ProbeSource(ctx, h.Mountpoint, h.WriteProbe)
	})
	if err != nil {
		return fmt.Errorf("volume %s: %w", h.Name, err)
	}
	if !p.Usable(h.WriteProbe) {
		return api.Errorf(api.CodeBusy, "volume %q is lost: %s (%s)", h.Name, p.Lost(h.WriteProbe), h.Mountpoint).
			WithHint("mount it again; the jail starts when it is there")
	}
	return nil
}

// MountTree mounts the datasets of a stopped jail on the host (see mountTree): the host can write into its root before
// it first runs, as the installation of an app's packages does.
func (s *Service) MountTree(ctx context.Context, name string) error { return s.mountTree(ctx, name) }

// UnmountTree undoes MountTree.
func (s *Service) UnmountTree(ctx context.Context, name string) error {
	return s.unmountTree(ctx, name)
}

// unmountTree unmounts in reverse mount order, continuing after errors.
func (s *Service) unmountTree(ctx context.Context, name string) error {
	st, err := s.observe(ctx, name)
	if err != nil {
		return err
	}
	order := st.mountOrder()
	var errs []error
	for i := len(order) - 1; i >= 0; i-- {
		if err := s.ZFS.Unmount(ctx, order[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// waitReady polls the jail until it runs or ReadyTimeout passes.
func (s *Service) waitReady(ctx context.Context, name string) error {
	deadline := s.Cfg.now().Add(s.Cfg.ReadyTimeout)
	for {
		up, err := s.Jails.Running(ctx, name)
		if err != nil {
			return err
		}
		if up {
			return nil
		}
		if !s.Cfg.now().Before(deadline) {
			return api.Errorf(api.CodeInternal, "jail %s is not running after %s", name, s.Cfg.ReadyTimeout)
		}
		if err := s.Cfg.sleep(ctx, s.Cfg.PollInterval); err != nil {
			return err
		}
	}
}

// doStart: mount, render, jail(8), readiness.
func (s *Service) doStart(ctx context.Context, name string) error {
	if err := s.mountTree(ctx, name); err != nil {
		return err
	}
	if err := s.Hooks.PreStart(ctx, name); err != nil {
		return err
	}
	if up, err := s.Jails.Running(ctx, name); err != nil {
		return err
	} else if !up {
		if err := s.Jails.Start(ctx, name); err != nil {
			return err
		}
		// jail(8) makes the nullfs mounts of the fstab a moment after the check of mountTree: a box that went away in
		// between leaves the jail on the empty directory of the host's mount point. A second look ends that.
		if atts, err := s.Cfg.attached(name); err == nil {
			for _, a := range atts {
				if !a.HostDir {
					continue
				}
				if err := s.checkHostDir(ctx, a); err != nil {
					_ = s.doStop(ctx, name)
					return err
				}
			}
		}
	}
	return s.waitReady(ctx, name)
}

// doStop: stop the jail if running, tear down its rendered state, unmount.
func (s *Service) doStop(ctx context.Context, name string) error {
	if up, err := s.Jails.Running(ctx, name); err != nil {
		return err
	} else if up {
		if err := s.stopJail(ctx, name); err != nil {
			s.cleanAfterFailedStop(ctx, name, err)
			return err
		}
	}
	if err := s.Hooks.PostStop(ctx, name); err != nil {
		return err
	}
	return s.unmountTree(ctx, name)
}

// ---- records on disk ----

// Record is spec.json: the jail's identity and desired state.
type Record struct {
	Version  int            `json:"version"`
	Metadata api.ObjectMeta `json:"metadata"`
	Spec     api.JailSpec   `json:"spec"`
}

// Bundle is bundle.json, the restore closure this package knows about: the
// spec and the image generation. Networks, policies and sealed secret
// references are added by their owners (design section 9).
type Bundle struct {
	Version  int                `json:"version"`
	Metadata api.ObjectMeta     `json:"metadata"`
	Spec     api.JailSpec       `json:"spec"`
	Image    BundleImage        `json:"image"`
	Volumes  []api.VolumeAttach `json:"volumes,omitempty"`
	Written  time.Time          `json:"written_at"`
}

// BundleImage names the generation the root was built from.
type BundleImage struct {
	Ref        string `json:"ref"`
	Name       string `json:"name"`
	Generation int    `json:"generation"`
	Manifest   string `json:"manifest"`
	Dataset    string `json:"dataset"`
}

func marshal(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err) // types are plain data
	}
	return append(b, '\n')
}

func (s *Service) readRecord(ctx context.Context, name string) (Record, error) {
	var r Record
	b, err := s.Files.ReadFile(ctx, s.Cfg.at(name).specPath())
	if err != nil {
		if b, err = s.Files.ReadFile(ctx, s.Cfg.at(name).specPath()+".previous"); err != nil {
			return r, err
		}
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("spec.json: %w", err)
	}
	return r, nil
}

func (s *Service) bundleBytes(rec Record, ref, imageName string, gen int, manifest, dataset string, stamp time.Time) []byte {
	return marshal(Bundle{Version: 1, Metadata: rec.Metadata, Spec: rec.Spec, Volumes: rec.Spec.Volumes, Written: stamp,
		Image: BundleImage{Ref: ref, Name: fmt.Sprintf("%s#g%d", imageName, gen), Generation: gen, Manifest: manifest, Dataset: dataset}})
}

// destroyIfExists is the shared idempotent undo for datasets a plan created.
func (s *Service) destroyIfExists(ds string) func(context.Context) error {
	return func(ctx context.Context) error {
		ok, err := s.ZFS.Exists(ctx, ds)
		if err != nil || !ok {
			return err
		}
		return s.ZFS.DestroyRecursive(ctx, ds)
	}
}
