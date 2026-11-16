package lifecycle

import (
	"context"
	"fmt"
	"path"
	"strconv"

	"jailops.net/jailops/sdk/api"
)

// Dataset kinds as the datasets' jailops:kind property names them.
const (
	// KindBackupRoot is how a layout names the root dataset (the thin root is
	// listed but not captured).
	KindBackupRoot = "root"
)

// JailDataset is one dataset of a jail, for backup capture.
type JailDataset struct {
	Name       string
	Kind       string
	Mountpoint string
	// Props are the user and native properties set locally and restored with
	// the dataset (jailops:path, jailops:class, quota, readonly, ...).
	Props map[string]string
	// Delegated marks the dataset handed to the jail: it is not mounted on the host, so a backup leaves it out.
	Delegated bool
}

// JailLayout is what the datasets say about a jail, in the shape backup
// capture needs.
type JailLayout struct {
	Key        string
	UUID       string
	Container  string
	Layout     api.Layout
	Image      string // image name
	Generation int
	Manifest   string
	Datasets   []JailDataset
}

var restoreProps = []string{PropPath, PropClass, PropMerge, "quota", "refquota", "reservation", "readonly", "compression", "recordsize", "atime"}

func (s *Service) layoutProps(ctx context.Context, ds string) map[string]string {
	out := map[string]string{}
	for _, p := range restoreProps {
		if v := s.prop(ctx, ds, p); v != "" {
			out[p] = v
		}
	}
	return out
}

// Layout reads the datasets of a jail: the container, the root, the
// persistent datasets, the volumes parent and the volumes. It changes nothing.
func (s *Service) Layout(ctx context.Context, key string) (JailLayout, error) {
	st, err := s.observe(ctx, key)
	if err != nil {
		return JailLayout{}, err
	}
	p := s.Cfg.at(key)
	out := JailLayout{Key: key, UUID: st.ID, Container: st.Container, Layout: st.Layout, Image: st.Image, Generation: st.Gen, Manifest: st.Manifest}
	// The container carries what the lifecycle needs to observe a restored jail again: its layout and the image.
	cprops := map[string]string{}
	if st.Layout != "" {
		cprops[PropLayout] = string(st.Layout)
	}
	if st.Image != "" {
		cprops[PropImage] = st.Image
	}
	out.Datasets = append(out.Datasets,
		JailDataset{Name: st.Container, Kind: KindContainer, Mountpoint: p.containerMP(), Props: cprops},
		JailDataset{Name: st.Root, Kind: KindBackupRoot, Mountpoint: p.rootMP(), Props: s.layoutProps(ctx, st.Root)})
	for _, d := range st.Persist {
		out.Datasets = append(out.Datasets, JailDataset{Name: d.DS, Kind: KindPersistent, Mountpoint: d.MP, Props: s.layoutProps(ctx, d.DS)})
	}
	if st.Delegated != "" {
		out.Datasets = append(out.Datasets, JailDataset{Name: st.Delegated, Kind: KindDelegated, Props: map[string]string{}, Delegated: true})
	}
	return out, nil
}

// WriteRecords writes spec.json and bundle.json of a jail whose datasets
// exist (a restored jail), into its mounted container. gen is the image
// generation the root was built from; it may be zero for a thick jail.
func (s *Service) WriteRecords(ctx context.Context, key string, j api.Jail, gen api.ImageGeneration) error {
	if err := validName("jail", key); err != nil {
		return err
	}
	p := s.Cfg.at(key)
	if err := s.ZFS.Mount(ctx, p.containerDS()); err != nil {
		return fmt.Errorf("mount %s: %w", p.containerDS(), err)
	}
	meta := j.Metadata
	meta.Scope = api.ScopeHost
	rec := Record{Version: 1, Metadata: meta, Spec: j.Spec}
	imageName, _, _ := cutGen(gen.Name)
	if imageName == "" {
		imageName = s.prop(ctx, p.containerDS(), PropImage)
	}
	num := gen.Number
	if num == 0 {
		num, _ = strconv.Atoi(s.prop(ctx, p.rootDS(), PropGen))
	}
	if err := s.Files.MkdirAll(ctx, p.containerMP()); err != nil {
		return err
	}
	if err := s.Files.WriteAtomic(ctx, p.specPath(), marshal(rec)); err != nil {
		return err
	}
	return s.Files.WriteAtomic(ctx, p.bundlePath(), s.bundleBytes(rec, j.Spec.Image, imageName, num, gen.Manifest, gen.Dataset, s.Cfg.now()))
}

func cutGen(name string) (image string, n int, ok bool) {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '#' {
			g := path.Base(name[i+1:])
			if len(g) > 1 && g[0] == 'g' {
				n, _ = strconv.Atoi(g[1:])
			}
			return name[:i], n, true
		}
	}
	return name, 0, false
}
