package service

import (
	"context"
	"strconv"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// JailUsage measures one jail of the request's project when asked: the
// kernel's resource accounting (rctl -u through the helper) while it runs,
// and the space of its datasets always. Nothing is stored or cached, and a
// part that cannot be measured says why instead of reporting zeros.
func (s *Service) JailUsage(ctx context.Context, name string) (api.JailUsage, error) {
	_, key, err := s.jailRef(ctx, name)
	if err != nil {
		return api.JailUsage{}, err
	}
	j, err := s.getByKey(ctx, key)
	if err != nil {
		return api.JailUsage{}, err
	}
	u := api.JailUsage{Jail: name, Power: j.Status.Power, MeasuredAt: s.now().UTC()}
	if j.Status.Power == api.PowerRunning {
		u.Accounting = s.accounting(ctx, key)
	}
	u.Disk = s.diskUsage(ctx, key)
	return u, nil
}

// accounting reads racct for a running jail. racct is off by default on
// FreeBSD; doctor asks for it the same way.
func (s *Service) accounting(ctx context.Context, key string) *api.JailAccounting {
	a := &api.JailAccounting{}
	switch v, err := s.sysctl(ctx, "kern.racct.enable"); {
	case err != nil:
		a.Error = "kern.racct.enable cannot be read: " + err.Error()
	case v != "1":
		a.Error = "racct is off: set kern.racct.enable=1 in /boot/loader.conf and reboot"
	case s.d.Run == nil:
		a.Error = "no command runner"
	default:
		r, err := jailos.ReadUsage(ctx, s.d.Run, key)
		if err != nil {
			a.Error = err.Error()
			break
		}
		a.Processes, a.CPUSeconds, a.MemoryBytes = r.Processes, r.CPUSeconds, r.MemoryBytes
	}
	return a
}

// diskUsage lists the container with used and referenced in one call: the
// root is the root dataset and the data are the persistent datasets; the
// volumes a jail attaches belong to the project and are not counted.
func (s *Service) diskUsage(ctx context.Context, key string) api.JailDiskUsage {
	if s.d.ZClient == nil {
		return api.JailDiskUsage{Error: "no ZFS client"}
	}
	container, root := s.lcfg.ContainerDS(key), s.lcfg.RootDS(key)
	rows, err := s.d.ZClient.List(ctx, zfs.ListOpts{Root: container, Recursive: true, Props: []string{"used", "referenced", lifecycle.PropKind}})
	if err != nil {
		return api.JailDiskUsage{Error: err.Error()}
	}
	var d api.JailDiskUsage
	seenRoot := false
	for _, r := range rows {
		used, uok := bytesProp(r.Props["used"])
		ref, rok := bytesProp(r.Props["referenced"])
		switch {
		case r.Name == root:
			if !uok || !rok {
				return api.JailDiskUsage{Error: "zfs reports no used or referenced for " + r.Name}
			}
			d.RootBytes, d.RootReferencedBytes, seenRoot = used, ref, true
		case r.Props[lifecycle.PropKind] == lifecycle.KindPersistent:
			if !uok {
				return api.JailDiskUsage{Error: "zfs reports no used for " + r.Name}
			}
			d.DataBytes += used
		}
	}
	if !seenRoot {
		return api.JailDiskUsage{Error: "the root dataset " + root + " is missing"}
	}
	return d
}

// bytesProp reads a -p property value; absent or "-" is not a number.
func bytesProp(v string) (int64, bool) {
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}
