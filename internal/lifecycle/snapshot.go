package lifecycle

import (
	"context"
	"fmt"
	"time"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// SnapshotResult describes a jail snapshot.
type SnapshotResult struct {
	Name     string
	Datasets []string
	// Created is when the snapshot was taken (the creation property); zero when the ZFS layer does not say.
	Created time.Time
	// Written is what a data rollback to this snapshot would discard, per
	// dataset and in total (bytes written since the snapshot).
	Written      map[string]int64
	TotalWritten int64
}

// SnapshotJail takes ONE atomic zfs snapshot over every dataset of the jail
// (container, root, persistent datasets, volumes), so the set is consistent.
// An empty name generates "snap-<timestamp>".
func (s *Service) SnapshotJail(ctx context.Context, name, snapName, comment string) (SnapshotResult, error) {
	var res SnapshotResult
	st, err := s.ready(ctx, name)
	if err != nil {
		return res, err
	}
	if snapName == "" {
		snapName = "snap-" + s.Cfg.now().Format("20060102T150405Z")
	} else if err := validate.SnapshotName("name", snapName); err != nil {
		return res, err
	}
	if len(comment) > 1024 {
		return res, api.Errorf(api.CodeInvalid, "comment is too long")
	}
	return s.snapshotSet(ctx, st, snapName, comment)
}

func (s *Service) snapshotSet(ctx context.Context, st *jailState, snapName, comment string) (SnapshotResult, error) {
	res := SnapshotResult{Name: snapName}
	if ok, err := s.ZFS.Exists(ctx, st.Container+"@"+snapName); err != nil {
		return res, err
	} else if ok {
		return res, api.Errorf(api.CodeAlreadyExists, "snapshot %q already exists", snapName)
	}
	ds := st.all()
	names := make([]string, len(ds))
	for i, d := range ds {
		names[i] = d + "@" + snapName
	}
	props := map[string]string{PropGen: fmt.Sprint(st.Gen), PropImage: st.Image}
	if comment != "" {
		props[PropComment] = comment
	}
	if err := s.ZFS.Snapshot(ctx, props, names...); err != nil {
		return res, err
	}
	res.Datasets = ds
	return s.fillWritten(ctx, st, res)
}

func (s *Service) fillWritten(ctx context.Context, st *jailState, res SnapshotResult) (SnapshotResult, error) {
	res.Written = map[string]int64{}
	for _, d := range dataDatasets(st) {
		if ok, _ := s.ZFS.Exists(ctx, d+"@"+res.Name); !ok {
			continue // dataset created after the snapshot
		}
		w, err := s.ZFS.Written(ctx, d+"@"+res.Name)
		if err != nil {
			return res, err
		}
		res.Written[d] = w
		res.TotalWritten += w
	}
	return res, nil
}

// ListSnapshots lists the user snapshots of a jail with their written totals.
func (s *Service) ListSnapshots(ctx context.Context, name string) ([]SnapshotResult, error) {
	st, err := s.observe(ctx, name)
	if err != nil {
		return nil, err
	}
	names, err := s.ZFS.Snapshots(ctx, st.Container)
	if err != nil {
		return nil, err
	}
	var times map[string]time.Time
	if t, ok := s.ZFS.(interface {
		SnapshotTimes(ctx context.Context, dataset string) (map[string]time.Time, error)
	}); ok {
		times, _ = t.SnapshotTimes(ctx, st.Container)
	}
	var out []SnapshotResult
	for _, n := range names {
		r, err := s.fillWritten(ctx, st, SnapshotResult{Name: n, Datasets: st.all(), Created: times[n]})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
