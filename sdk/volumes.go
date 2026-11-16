package sdk

import (
	"context"
	"iter"
	"net/http"

	"jailops.net/jailops/sdk/api"
)

// NewVolume builds a Volume document from a name and a spec.
func NewVolume(name string, spec api.VolumeSpec) api.Volume {
	return api.Volume{Metadata: api.ObjectMeta{Name: name}, Spec: spec}
}

// VolumeClient accesses /api/v1/volumes (extension volumes): the volumes of a project, which jails attach by name.
type VolumeClient struct {
	c *Client
	r *Resource[api.Volume]
}

// Volumes returns the volumes client.
func (c *Client) Volumes() *VolumeClient {
	return &VolumeClient{c, newResource[api.Volume](c, "/api/v1/volumes")}
}

func (v *VolumeClient) fetch(name string) func(context.Context) (api.Volume, error) {
	return func(ctx context.Context) (api.Volume, error) { return v.Get(ctx, name) }
}

// List iterates the volumes of the project.
func (v *VolumeClient) List(ctx context.Context, opts ...ListOption) iter.Seq2[api.Volume, error] {
	if err := v.c.need("volumes"); err != nil {
		return func(y func(api.Volume, error) bool) { y(api.Volume{}, err) }
	}
	return v.r.List(ctx, opts...)
}

// Get fetches a volume.
func (v *VolumeClient) Get(ctx context.Context, name string) (api.Volume, error) {
	if err := v.c.need("volumes"); err != nil {
		return api.Volume{}, err
	}
	return v.r.Get(ctx, name)
}

// GetETag fetches a volume and its ETag.
func (v *VolumeClient) GetETag(ctx context.Context, name string) (api.Volume, string, error) {
	if err := v.c.need("volumes"); err != nil {
		return api.Volume{}, "", err
	}
	return v.r.GetETag(ctx, name)
}

// Update replaces the labels, the comment and the size of a volume, and the watch of a host directory (see Resource.Update).
func (v *VolumeClient) Update(ctx context.Context, name string, vol api.Volume, etag string) (api.Volume, error) {
	if err := v.c.need("volumes"); err != nil {
		return api.Volume{}, err
	}
	return v.r.Update(ctx, name, vol, etag)
}

// Patch merges a JSON merge patch into a volume.
func (v *VolumeClient) Patch(ctx context.Context, name string, patch any, etag string) (api.Volume, error) {
	if err := v.c.need("volumes"); err != nil {
		return api.Volume{}, err
	}
	return v.r.Patch(ctx, name, patch, etag)
}

// Create creates a volume; the operation's result is the created volume. The passphrase of an encrypted volume
// travels in this request only; the server never stores or returns it.
func (v *VolumeClient) Create(ctx context.Context, vol api.Volume, passphrase string) (*Operation[api.Volume], error) {
	if err := v.c.need("volumes"); err != nil {
		return nil, err
	}
	body := api.VolumeCreate{Metadata: vol.Metadata, Spec: vol.Spec, Passphrase: passphrase}
	op, _, err := sendOp(ctx, v.c, request{method: http.MethodPost, path: v.r.path, body: body}, v.fetch(vol.Metadata.Name))
	return op, err
}

// Delete deletes a volume that no jail attaches.
func (v *VolumeClient) Delete(ctx context.Context, name string) (*Operation[None], error) {
	if err := v.c.need("volumes"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[None](ctx, v.c, request{method: http.MethodDelete, path: v.r.item(name)}, nil)
	return op, err
}

// Unlock loads the key of an encrypted volume with its passphrase and, with start set, starts the jail that attaches
// it. A wrong passphrase fails the operation with bad_passphrase; after five in a row the volume answers rate_limited
// for 30 seconds.
func (v *VolumeClient) Unlock(ctx context.Context, name, passphrase string, start bool) (*Operation[api.Volume], error) {
	if err := v.c.need("volumes"); err != nil {
		return nil, err
	}
	op, _, err := sendOp(ctx, v.c, request{method: http.MethodPost, path: v.r.item(name) + "/unlock", body: api.VolumeUnlock{Passphrase: passphrase, Start: start}}, v.fetch(name))
	return op, err
}

// Lock stops the jail that attaches an encrypted volume, unmounts the volume and unloads its key.
func (v *VolumeClient) Lock(ctx context.Context, name string) (*Operation[api.Volume], error) {
	if err := v.c.need("volumes"); err != nil {
		return nil, err
	}
	op, _, err := sendOp(ctx, v.c, request{method: http.MethodPost, path: v.r.item(name) + "/lock"}, v.fetch(name))
	return op, err
}

// ChangePassphrase changes the passphrase of an unlocked encrypted volume.
func (v *VolumeClient) ChangePassphrase(ctx context.Context, name, oldPass, newPass string) (*Operation[api.Volume], error) {
	if err := v.c.need("volumes"); err != nil {
		return nil, err
	}
	op, _, err := sendOp(ctx, v.c, request{method: http.MethodPost, path: v.r.item(name) + "/passphrase", body: api.VolumePassphraseChange{Old: oldPass, New: newPass}}, v.fetch(name))
	return op, err
}

// Rollback returns a volume to a snapshot. Everything written since is discarded, so rb.ConfirmDataLoss must be
// true.
func (v *VolumeClient) Rollback(ctx context.Context, name string, rb api.VolumeRollback) (*Operation[api.Volume], error) {
	if err := v.c.need("volumes"); err != nil {
		return nil, err
	}
	op, _, err := sendOp(ctx, v.c, request{method: http.MethodPost, path: v.r.item(name) + "/rollback", body: rb}, v.fetch(name))
	return op, err
}

// VolumeSnapshotClient accesses the snapshots of one volume.
type VolumeSnapshotClient struct {
	c      *Client
	volume string
	r      *Resource[api.VolumeSnapshot]
}

// Snapshots returns the snapshot client of a volume.
func (v *VolumeClient) Snapshots(volume string) *VolumeSnapshotClient {
	return &VolumeSnapshotClient{v.c, volume, newResource[api.VolumeSnapshot](v.c, v.r.item(volume)+"/snapshots")}
}

// List iterates the snapshots of the volume.
func (s *VolumeSnapshotClient) List(ctx context.Context, opts ...ListOption) iter.Seq2[api.VolumeSnapshot, error] {
	if err := s.c.need("volumes"); err != nil {
		return func(y func(api.VolumeSnapshot, error) bool) { y(api.VolumeSnapshot{}, err) }
	}
	return s.r.List(ctx, opts...)
}

// Create takes a snapshot of the volume. An empty name lets the server choose one.
func (s *VolumeSnapshotClient) Create(ctx context.Context, name, comment string) (*Operation[api.VolumeSnapshot], error) {
	if err := s.c.need("volumes"); err != nil {
		return nil, err
	}
	body := api.VolumeSnapshot{Metadata: api.ObjectMeta{Name: name}, Spec: api.VolumeSnapshotSpec{Volume: s.volume, Comment: comment}}
	var fetch func(context.Context) (api.VolumeSnapshot, error)
	if name != "" {
		fetch = func(ctx context.Context) (api.VolumeSnapshot, error) { return s.r.Get(ctx, name) }
	}
	op, _, err := sendOp(ctx, s.c, request{method: http.MethodPost, path: s.r.path, body: body}, fetch)
	return op, err
}

// Delete deletes a snapshot of the volume.
func (s *VolumeSnapshotClient) Delete(ctx context.Context, name string) (*Operation[None], error) {
	if err := s.c.need("volumes"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[None](ctx, s.c, request{method: http.MethodDelete, path: s.r.item(name)}, nil)
	return op, err
}

// Rename gives a volume a new name and rewrites everything that refers to it (extension "rename"). See Resource.Rename.
func (v *VolumeClient) Rename(ctx context.Context, name string, req api.Rename, etag string) (*Operation[api.RenameResult], error) {
	return v.r.Rename(ctx, name, req, etag)
}
