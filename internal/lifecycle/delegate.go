package lifecycle

import (
	"context"

	"jailops.net/jailops/sdk/api"
)

// SetDelegation turns zfs_delegation on or off for an existing jail. On: the dataset <container>/delegated is made when
// it is not there and gets jailed=on, so the next start of the jail attaches it. Off: jailed is cleared and the data
// stays, so turning it on again finds it; a running jail keeps the dataset until it stops, so the jail must be stopped.
func (s *Service) SetDelegation(ctx context.Context, name string, on bool) error {
	st, err := s.observe(ctx, name)
	if err != nil {
		return err
	}
	ds := s.Cfg.at(name).delegatedDS()
	exists, err := s.ZFS.Exists(ctx, ds)
	if err != nil {
		return err
	}
	if !on {
		if !exists {
			return nil
		}
		if up, err := s.Jails.Running(ctx, name); err != nil {
			return err
		} else if up {
			return api.Errorf(api.CodeConflict, "jail %q is running with its delegated dataset: stop it before turning zfs_delegation off", name)
		}
		return s.ZFS.Set(ctx, ds, map[string]string{"jailed": "off"})
	}
	if !exists {
		project, jail := splitKey(name)
		if err := s.ZFS.Create(ctx, ds, map[string]string{PropManaged: "on", PropID: st.ID, PropKind: KindDelegated,
			PropName: jail, PropProject: project, "mountpoint": "none", "canmount": "noauto"}); err != nil {
			return err
		}
	}
	return s.ZFS.Set(ctx, ds, map[string]string{"jailed": "on"})
}
