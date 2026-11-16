package service

import (
	"context"

	"jailops.net/jailops/sdk/api"
)

// applyDiskLimits writes a changed disk limit or reservation of a jail to its container dataset, the one that carries
// the quota of every dataset below it (root, persistent datasets) and of their snapshots. A volume is not below it: it
// belongs to the project. An unset limit is
// "none". It is done before the change is stored, so a quota ZFS refuses (below what the jail uses) refuses the
// change.
func (s *Service) applyDiskLimits(ctx context.Context, key string, old, nw api.JailSpec) error {
	props := map[string]string{}
	if old.Resources.Disk != nw.Resources.Disk {
		props["quota"] = sizeOrNone(nw.Resources.Disk)
	}
	if old.Resources.DiskReservation != nw.Resources.DiskReservation {
		props["reservation"] = sizeOrNone(nw.Resources.DiskReservation)
	}
	if len(props) == 0 || s.d.ZFS == nil {
		return nil
	}
	if err := s.d.ZFS.Set(ctx, s.lcfg.ContainerDS(key), props); err != nil {
		return err
	}
	return nil
}

func sizeOrNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

// statesLimit is the number of pf states each pass rule of a jail's anchor may create: its limits.states, else the
// host's jails.max_states; 0 sets no limit.
func (s *Service) statesLimit(j api.Jail) int {
	if n := s.effective(j).Resources.States; n > 0 {
		return n
	}
	return s.d.JailMaxStates
}
