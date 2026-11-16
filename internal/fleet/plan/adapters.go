package plan

import (
	"context"
	"fmt"
	"iter"

	"jailops.net/jailops/internal/fleet/model"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// Live is one object as the host reports it.
type Live struct {
	Meta api.ObjectMeta
	Spec any
	// Built is set for an image: the host holds at least one generation of it.
	Built bool
}

// Adapter gives uniform access to one API kind through the SDK. It is the only
// place that knows which SDK client serves which kind.
type Adapter struct {
	Info model.KindInfo
	// List returns every object of the kind.
	List func(ctx context.Context, c *sdk.Client) ([]Live, error)
	// Get returns one object with its ETag.
	Get func(ctx context.Context, c *sdk.Client, name string) (Live, string, error)
	// Create stores a new object and waits for any operation it starts.
	Create func(ctx context.Context, c *sdk.Client, meta api.ObjectMeta, spec any) error
	// Update replaces an object, guarded by the ETag.
	Update func(ctx context.Context, c *sdk.Client, meta api.ObjectMeta, spec any, etag string) error
	// Patch merges a JSON merge patch (used to claim an object).
	Patch func(ctx context.Context, c *sdk.Client, name string, patch any, etag string) error
	// Delete removes an object and waits for any operation it starts.
	Delete func(ctx context.Context, c *sdk.Client, name string) error
}

type resource[T any] interface {
	List(ctx context.Context, opts ...sdk.ListOption) iter.Seq2[T, error]
	GetETag(ctx context.Context, name string) (T, string, error)
	Update(ctx context.Context, name string, v T, etag string) (T, error)
	Patch(ctx context.Context, name string, patch any, etag string) (T, error)
}

func build[T any](
	info model.KindInfo,
	res func(*sdk.Client) resource[T],
	meta func(*T) *api.ObjectMeta,
	spec func(*T) any,
	make_ func(api.ObjectMeta, any) T,
	create func(context.Context, *sdk.Client, T) error,
	del func(context.Context, *sdk.Client, string) error,
) *Adapter {
	live := func(v T) Live { return Live{Meta: *meta(&v), Spec: spec(&v)} }
	return &Adapter{
		Info: info,
		List: func(ctx context.Context, c *sdk.Client) ([]Live, error) {
			var out []Live
			for v, err := range res(c).List(ctx) {
				if err != nil {
					return nil, err
				}
				out = append(out, live(v))
			}
			return out, nil
		},
		Get: func(ctx context.Context, c *sdk.Client, name string) (Live, string, error) {
			v, etag, err := res(c).GetETag(ctx, name)
			if err != nil {
				return Live{}, "", err
			}
			return live(v), etag, nil
		},
		Create: func(ctx context.Context, c *sdk.Client, m api.ObjectMeta, s any) error {
			return create(ctx, c, make_(m, s))
		},
		Update: func(ctx context.Context, c *sdk.Client, m api.ObjectMeta, s any, etag string) error {
			_, err := res(c).Update(ctx, m.Name, make_(m, s), etag)
			return err
		},
		Patch: func(ctx context.Context, c *sdk.Client, name string, p any, etag string) error {
			_, err := res(c).Patch(ctx, name, p, etag)
			return err
		},
		Delete: del,
	}
}

func resCreate[T any](r func(*sdk.Client) *sdk.Resource[T]) func(context.Context, *sdk.Client, T) error {
	return func(ctx context.Context, c *sdk.Client, v T) error {
		_, err := r(c).Create(ctx, v)
		return err
	}
}

func resDelete[T any](r func(*sdk.Client) *sdk.Resource[T]) func(context.Context, *sdk.Client, string) error {
	return func(ctx context.Context, c *sdk.Client, name string) error { return r(c).Delete(ctx, name) }
}

func asRes[T any](r func(*sdk.Client) *sdk.Resource[T]) func(*sdk.Client) resource[T] {
	return func(c *sdk.Client) resource[T] { return r(c) }
}

var adapters = map[api.Kind]*Adapter{}

func init() {
	reg := func(a *Adapter) { adapters[a.Info.Kind] = a }
	info := func(k api.Kind) model.KindInfo { ki, _ := model.KindOf(k); return ki }

	images := func(c *sdk.Client) *sdk.Resource[api.Image] { return c.Images().Resource }
	reg(build(info(api.KindImage), asRes(images),
		func(v *api.Image) *api.ObjectMeta { return &v.Metadata }, func(v *api.Image) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.Image { return api.Image{Metadata: m, Spec: s.(api.ImageSpec)} },
		resCreate(images), resDelete(images)))
	// An image is declared by its definition, but a jail needs a built generation: list with the status.
	adapters[api.KindImage].List = func(ctx context.Context, c *sdk.Client) ([]Live, error) {
		var out []Live
		for v, err := range c.Images().Resource.List(ctx) {
			if err != nil {
				return nil, err
			}
			out = append(out, Live{Meta: v.Metadata, Spec: v.Spec, Built: len(v.Status.Generations) > 0})
		}
		return out, nil
	}

	networks := func(c *sdk.Client) *sdk.Resource[api.Network] { return c.Networks().Resource }
	reg(build(info(api.KindNetwork), asRes(networks),
		func(v *api.Network) *api.ObjectMeta { return &v.Metadata }, func(v *api.Network) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.Network { return api.Network{Metadata: m, Spec: s.(api.NetworkSpec)} },
		resCreate(networks), resDelete(networks)))

	// A tunnel's keys are made by the host when the object is created; files carry public parts only.
	wgs := func(c *sdk.Client) *sdk.Resource[api.WireGuard] { return c.WireGuard().Resource }
	reg(build(info(api.KindWireGuard), asRes(wgs),
		func(v *api.WireGuard) *api.ObjectMeta { return &v.Metadata }, func(v *api.WireGuard) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.WireGuard {
			return api.WireGuard{Metadata: m, Spec: s.(api.WireGuardSpec)}
		},
		resCreate(wgs), resDelete(wgs)))

	pols := func(c *sdk.Client) *sdk.Resource[api.FirewallPolicy] { return c.Firewall().Policies() }
	reg(build(info(api.KindFirewallPolicy), asRes(pols),
		func(v *api.FirewallPolicy) *api.ObjectMeta { return &v.Metadata }, func(v *api.FirewallPolicy) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.FirewallPolicy {
			return api.FirewallPolicy{Metadata: m, Spec: s.(api.FirewallPolicySpec)}
		},
		resCreate(pols), resDelete(pols)))

	sets := func(c *sdk.Client) *sdk.Resource[api.AddressSet] { return c.Firewall().AddressSets() }
	reg(build(info(api.KindAddressSet), asRes(sets),
		func(v *api.AddressSet) *api.ObjectMeta { return &v.Metadata }, func(v *api.AddressSet) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.AddressSet {
			return api.AddressSet{Metadata: m, Spec: s.(api.AddressSetSpec)}
		},
		resCreate(sets), resDelete(sets)))

	// A volume is made without a passphrase here: a file cannot carry one (check refuses encrypted volumes).
	reg(build(info(api.KindVolume),
		func(c *sdk.Client) resource[api.Volume] { return volRes{c.Volumes()} },
		func(v *api.Volume) *api.ObjectMeta { return &v.Metadata }, func(v *api.Volume) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.Volume { return api.Volume{Metadata: m, Spec: s.(api.VolumeSpec)} },
		func(ctx context.Context, c *sdk.Client, v api.Volume) error {
			op, err := c.Volumes().Create(ctx, v, "")
			if err != nil {
				return err
			}
			_, err = op.Wait(ctx)
			return err
		},
		func(ctx context.Context, c *sdk.Client, name string) error {
			op, err := c.Volumes().Delete(ctx, name)
			if err != nil {
				return err
			}
			_, err = op.Wait(ctx)
			return err
		}))

	targets := func(c *sdk.Client) *sdk.Resource[api.BackupTarget] { return c.Backups().Targets() }
	stor := func(c *sdk.Client) *sdk.Resource[api.Storage] { return c.Storage() }
	reg(build(info(api.KindStorage), asRes(stor),
		func(v *api.Storage) *api.ObjectMeta { return &v.Metadata }, func(v *api.Storage) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.Storage { return api.Storage{Metadata: m, Spec: s.(api.StorageSpec)} },
		resCreate(stor), resDelete(stor)))

	projs := func(c *sdk.Client) *sdk.Resource[api.Project] { return c.Projects().Resource }
	reg(build(info(api.KindProject), asRes(projs),
		func(v *api.Project) *api.ObjectMeta { return &v.Metadata }, func(v *api.Project) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.Project { return api.Project{Metadata: m, Spec: s.(api.ProjectSpec)} },
		resCreate(projs), resDelete(projs)))

	reg(build(info(api.KindBackupTarget), asRes(targets),
		func(v *api.BackupTarget) *api.ObjectMeta { return &v.Metadata }, func(v *api.BackupTarget) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.BackupTarget {
			return api.BackupTarget{Metadata: m, Spec: s.(api.BackupTargetSpec)}
		},
		resCreate(targets), resDelete(targets)))

	bpols := func(c *sdk.Client) *sdk.Resource[api.BackupPolicy] { return c.Backups().Policies() }
	reg(build(info(api.KindBackupPolicy), asRes(bpols),
		func(v *api.BackupPolicy) *api.ObjectMeta { return &v.Metadata }, func(v *api.BackupPolicy) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.BackupPolicy {
			return api.BackupPolicy{Metadata: m, Spec: s.(api.BackupPolicySpec)}
		},
		resCreate(bpols), resDelete(bpols)))

	reg(build(info(api.KindJail),
		func(c *sdk.Client) resource[api.Jail] { return jailRes{c.Jails()} },
		func(v *api.Jail) *api.ObjectMeta { return &v.Metadata }, func(v *api.Jail) any { return v.Spec },
		func(m api.ObjectMeta, s any) api.Jail { return api.Jail{Metadata: m, Spec: s.(api.JailSpec)} },
		func(ctx context.Context, c *sdk.Client, j api.Jail) error {
			op, err := c.Jails().Create(ctx, j)
			if err != nil {
				return err
			}
			_, err = op.Wait(ctx)
			return err
		},
		func(ctx context.Context, c *sdk.Client, name string) error {
			op, err := c.Jails().Delete(ctx, name)
			if err != nil {
				return err
			}
			_, err = op.Wait(ctx)
			return err
		}))
}

type volRes struct{ v *sdk.VolumeClient }

func (r volRes) List(ctx context.Context, opts ...sdk.ListOption) iter.Seq2[api.Volume, error] {
	return r.v.List(ctx, opts...)
}
func (r volRes) GetETag(ctx context.Context, n string) (api.Volume, string, error) {
	return r.v.GetETag(ctx, n)
}
func (r volRes) Update(ctx context.Context, n string, v api.Volume, etag string) (api.Volume, error) {
	return r.v.Update(ctx, n, v, etag)
}
func (r volRes) Patch(ctx context.Context, n string, p any, etag string) (api.Volume, error) {
	return r.v.Patch(ctx, n, p, etag)
}

type jailRes struct{ j *sdk.JailClient }

func (r jailRes) List(ctx context.Context, opts ...sdk.ListOption) iter.Seq2[api.Jail, error] {
	return r.j.List(ctx, opts...)
}
func (r jailRes) GetETag(ctx context.Context, n string) (api.Jail, string, error) {
	return r.j.GetETag(ctx, n)
}
func (r jailRes) Update(ctx context.Context, n string, v api.Jail, etag string) (api.Jail, error) {
	return r.j.Update(ctx, n, v, etag)
}
func (r jailRes) Patch(ctx context.Context, n string, p any, etag string) (api.Jail, error) {
	return r.j.Patch(ctx, n, p, etag)
}

// AdapterFor returns the adapter of a managed kind.
func AdapterFor(k api.Kind) (*Adapter, error) {
	a := adapters[k]
	if a == nil {
		return nil, fmt.Errorf("kind %q is not managed by jailops-sync", k)
	}
	return a, nil
}

// ScopeClient returns the client to use for objects of a kind in a project:
// project-level kinds carry ?project=<name>, host-level kinds do not.
func ScopeClient(c *sdk.Client, kind api.Kind, project string) *sdk.Client {
	if ki, ok := model.KindOf(kind); ok && ki.ProjectLevel {
		return c.Project(project) // a project-level kind always carries its project
	}
	return c
}
