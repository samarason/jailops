package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Recovered is a registry entry rebuilt from a jail's own datasets.
type Recovered struct {
	Jail api.Jail
	// Problems lists what is wrong with the jail's datasets or records.
	Problems []string
	// Notes lists things that are fine but worth knowing (root.old present).
	Notes []string
	// FromBundle is true when spec.json was unusable and bundle.json supplied the spec.
	FromBundle bool
	// Locked names the encrypted volumes whose key is not loaded.
	Locked []string
}

// Rebuild reconstructs the registry entry of one jail from its datasets and
// spec.json. ZFS is authoritative for host-scope jails (design section 7), so
// the SQLite registry can always be rebuilt this way. It changes nothing.
func (s *Service) Rebuild(ctx context.Context, name string) (Recovered, error) {
	var out Recovered
	st, err := s.observe(ctx, name)
	if err != nil {
		return out, err
	}
	// the container must be mounted to read its files
	if err := s.ZFS.Mount(ctx, st.Container); err != nil {
		out.Problems = append(out.Problems, "mount container: "+err.Error())
	}
	rec, rerr := s.readRecord(ctx, name)
	if rerr != nil {
		out.Problems = append(out.Problems, "spec.json: "+rerr.Error())
		b, berr := s.Files.ReadFile(ctx, s.Cfg.at(name).bundlePath())
		var bd Bundle
		if berr == nil {
			berr = json.Unmarshal(b, &bd)
		}
		if berr != nil {
			return out, api.Errorf(api.CodeInternal, "jail %s: spec.json and bundle.json are both unusable: %v; %v", name, rerr, berr)
		}
		rec = Record{Version: bd.Version, Metadata: bd.Metadata, Spec: bd.Spec}
		out.FromBundle = true
	}
	project, plain := splitKey(name)
	if rec.Metadata.Name != plain {
		out.Problems = append(out.Problems, fmt.Sprintf("spec.json names jail %q", rec.Metadata.Name))
	}
	if rec.Metadata.Project == "" {
		rec.Metadata.Project = project
	} else if rec.Metadata.Project != project {
		out.Problems = append(out.Problems, fmt.Sprintf("spec.json names project %q, the dataset is in project %q", rec.Metadata.Project, project))
	}
	if st.ID != "" && rec.Metadata.UUID != st.ID {
		out.Problems = append(out.Problems, fmt.Sprintf("uuid mismatch: dataset %s, spec.json %s", st.ID, rec.Metadata.UUID))
	}
	if !st.Complete {
		out.Problems = append(out.Problems, "creation did not complete")
	}
	if ok, _ := s.ZFS.Exists(ctx, st.Root); !ok {
		out.Problems = append(out.Problems, "root dataset is missing")
	}
	if st.Layout == api.LayoutThin {
		have := map[string]bool{}
		for _, d := range st.Persist {
			have[d.DS] = true
		}
		for _, pp := range s.Cfg.persistent() {
			if ds := st.Container + "/" + pp.Dataset; !have[ds] {
				out.Problems = append(out.Problems, "persistent dataset is missing: "+ds)
			}
		}
	}
	for _, v := range st.Volumes {
		if ok, _ := s.ZFS.Exists(ctx, v.DS); !ok {
			out.Problems = append(out.Problems, "volume dataset is missing: "+volumeName(v.DS))
		}
	}
	for _, e := range st.Extra {
		out.Notes = append(out.Notes, "leftover "+e[strings.LastIndex(e, "/")+1:])
	}
	if l, err := s.lockedVolumes(ctx, st); err != nil {
		out.Problems = append(out.Problems, "key status: "+err.Error())
	} else {
		out.Locked = names(l)
	}
	up, _ := s.Jails.Running(ctx, name)
	power := api.PowerStopped
	if up {
		power = api.PowerRunning
	}
	rec.Metadata.Scope = api.ScopeHost
	out.Jail = api.Jail{Metadata: rec.Metadata, Spec: rec.Spec, Status: api.JailStatus{Power: power}}
	if st.Gen > 0 {
		out.Jail.Status.Generation = genName(st.Image, st.Gen)
	}
	if layout := st.Layout; layout != "" && out.Jail.Spec.Layout == "" {
		out.Jail.Spec.Layout = layout
	}
	return out, nil
}

// Found is a jail container dataset discovered on a storage.
type Found struct {
	// Key is the project-qualified jail key.
	Key     string
	Storage Storage
}

// Discover lists the jail container datasets below every storage
// (<root>/projects/<project>/jails/<name>). Datasets without
// jailops:managed=on and jailops:kind=container are ignored.
func (s *Service) Discover(ctx context.Context) ([]Found, error) {
	sts := []Storage{{Root: s.Cfg.Root, MountBase: s.Cfg.MountBase}}
	if s.Cfg.Storages != nil {
		sts = s.Cfg.Storages()
	}
	var out []Found
	for _, st := range sts {
		base := path.Join(st.Root, "projects")
		if ok, e := s.ZFS.Exists(ctx, base); e != nil {
			return out, e
		} else if !ok {
			continue
		}
		all, err := s.ZFS.Descendants(ctx, base)
		if err != nil {
			return out, err
		}
		for _, d := range all {
			parts := strings.Split(strings.TrimPrefix(d, base+"/"), "/")
			// <project>/jails/<name>
			if len(parts) != 3 || parts[1] != "jails" {
				continue
			}
			if s.prop(ctx, d, PropManaged) != "on" || s.prop(ctx, d, PropKind) != KindContainer {
				continue
			}
			key, err := qualify(parts[0], parts[2])
			if err != nil {
				continue
			}
			out = append(out, Found{Key: key, Storage: st})
		}
	}
	return out, nil
}

// RebuildOn rebuilds one discovered jail. The jail's datasets are read from
// the storage it was found on, whatever Config.Locate says.
func (s *Service) RebuildOn(ctx context.Context, f Found) (Recovered, error) {
	c := *s
	prev := s.Cfg.Locate
	c.Cfg.Locate = func(key string) (Storage, bool) {
		if key == f.Key {
			return f.Storage, true
		}
		if prev != nil {
			return prev(key)
		}
		return Storage{}, false
	}
	return c.Rebuild(ctx, f.Key)
}

// RebuildAll rebuilds every jail below every storage. Datasets without
// jailops:managed=on are ignored. Per-jail failures are returned in errs.
func (s *Service) RebuildAll(ctx context.Context) (jails []Recovered, errs map[string]error, err error) {
	errs = map[string]error{}
	found, err := s.Discover(ctx)
	if err != nil {
		return nil, errs, err
	}
	for _, f := range found {
		r, e := s.RebuildOn(ctx, f)
		if e != nil {
			errs[f.Key] = e
			continue
		}
		jails = append(jails, r)
	}
	return jails, errs, nil
}
