package service

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// canonicalProjectSizes stores the storage quotas and the memory quota of a project as decimal bytes: the quota is
// written to ZFS as it is stored, and the helper accepts no other spelling than digits with an upper case unit.
func canonicalProjectSizes(spec *api.ProjectSpec) error {
	spec.Storage = slices.Clone(spec.Storage)
	for i, g := range spec.Storage {
		if g.Quota == "" {
			continue
		}
		v, err := validate.CanonicalSize(fmt.Sprintf("storage[%d].quota", i), g.Quota)
		if err != nil {
			return err
		}
		spec.Storage[i].Quota = v
	}
	if spec.Quotas.Memory != "" {
		v, err := validate.CanonicalSize("quotas.memory", spec.Quotas.Memory)
		if err != nil {
			return err
		}
		spec.Quotas.Memory = v
	}
	return nil
}

// canonicalJailSizes stores the ZFS sizes of a jail (its disk quota and reservation) as decimal bytes, so the
// lifecycle and the helper accept them.
func canonicalJailSizes(spec *api.JailSpec) error {
	for _, r := range []struct {
		field string
		v     *string
	}{{"resources.disk", &spec.Resources.Disk}, {"resources.disk_reservation", &spec.Resources.DiskReservation}} {
		if *r.v == "" {
			continue
		}
		c, err := validate.CanonicalSize(r.field, *r.v)
		if err != nil {
			return err
		}
		*r.v = c
	}
	return nil
}

// quotaDiffers compares the quota ZFS reports (bytes, "-" or "none" when unset) with the wanted one by value.
func quotaDiffers(have, want string) bool {
	w, err := validate.ParseSize(want)
	if err != nil {
		return true
	}
	h, err := strconv.ParseUint(have, 10, 64)
	return err != nil || h != w
}

// checkNewJail applies the limits of a new jail (create and copy): the length of its name and the length of the
// deepest dataset name it would get on its storage. Admission has resolved the storage.
func (s *Service) checkNewJail(project, name string, spec api.JailSpec) error {
	if err := validate.NameLength("jail", "name", name, validate.MaxJailName); err != nil {
		return err
	}
	if err := validate.AnchorPath("name", render.JailAnchorFor(project, name)); err != nil {
		return err
	}
	si, ok := s.storage(spec.Storage)
	if !ok {
		return nil
	}
	ds := lifecycle.ProjectJailsDS(si.lifecycle(), project) + "/" + name + "/root.stale"
	return validate.DatasetBudget("name", "jail "+name, ds, validate.SnapshotReserve)
}

// checkSnapshotBudget refuses a snapshot name that makes the snapshot of a jail's deepest dataset longer than ZFS
// allows (a jail on a storage with a long dataset, created before the limits).
func (s *Service) checkSnapshotBudget(key, snap string) error {
	s.mu.RLock()
	e, ok := s.jails[key]
	var spec api.JailSpec
	if ok {
		spec = e.jail.Spec
	}
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	si, ok := s.storage(spec.Storage)
	if !ok {
		return nil
	}
	project, name := validate.SplitQualified(key)
	ds := lifecycle.ProjectJailsDS(si.lifecycle(), project) + "/" + name + "/root.stale"
	return validate.DatasetBudget("name", "snapshot "+snap, ds, 1+len(snap))
}

// doctorNameLengths is the check names.length: objects created before the name limits of design section 3.1 keep
// working, and this lists them (and is absent when there is none) so an operator knows which names a copy or a new object could not reuse.
func (s *Service) doctorNameLengths(_ context.Context, c *checkSet) {
	var long []string
	add := func(kind, name string, max int) {
		if len(name) > max {
			long = append(long, fmt.Sprintf("%s %s (%d > %d)", kind, name, len(name), max))
		}
	}
	if l, err := s.projKind.list(); err == nil {
		for _, o := range l {
			add("project", o.Meta.Name, validate.MaxProjectName)
		}
	}
	if l, err := s.imgKind.list(); err == nil {
		for _, o := range l {
			add("image", o.Meta.Name, validate.MaxImageName)
		}
	}
	if l, err := s.stoKind.list(); err == nil {
		for _, o := range l {
			add("storage dataset", o.Spec.Dataset, validate.MaxStorageDataset)
		}
	}
	s.mu.RLock()
	for _, e := range s.jails {
		jn := jailDisplay(e.jail.Metadata.Project, e.jail.Metadata.Name)
		add("jail", e.jail.Metadata.Name, validate.MaxJailName)
		for _, v := range e.jail.Spec.Volumes {
			add("volume "+jn+":", v.Name, validate.MaxVolumeName)
		}
	}
	s.mu.RUnlock()
	if len(long) == 0 {
		return
	}
	slices.Sort(long)
	c.add("names.length", api.DoctorInfo, "names longer than a new object may have (they keep working): "+strings.Join(long, ", "),
		"nothing to do; a copy or a new object needs a shorter name (design section 3.1)")
}

// checkWireGuardName refuses the name of a new tunnel that is too long to name its interface (wg-<name>, 15
// characters at most) when no interface is given; the error says so instead of naming a field the caller never set.
func checkWireGuardName(name, iface string) error {
	if iface == "" && len(name) > validate.MaxWireGuardName {
		return validate.Invalid("name", "name %q is longer than %d characters: give --interface (the default interface wg-%s would have more than 15)", name, validate.MaxWireGuardName, name).
			WithHint("name the interface with --interface wgNAME (at most 15 characters), or choose a name of at most 12")
	}
	return validate.AnchorPath("name", wireguard.Anchor(name))
}
