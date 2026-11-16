package hostbackup

import (
	"context"

	"jailops.net/jailops/internal/imagegen"
	"jailops.net/jailops/sdk/api"
)

// Backups is the backup backend the daemon's service layer expects
// (service.Backups in internal/service). The two declarations must stay
// identical; *Service satisfies it without a wrapper.
type Backups interface {
	List(ctx context.Context) ([]api.Backup, error)
	Get(ctx context.Context, id string) (api.Backup, error)
	Delete(ctx context.Context, id string) error
	Preflight(ctx context.Context, req api.RestoreRequest) (api.RestorePreflight, error)
	Restore(ctx context.Context, req api.RestoreRequest) (api.Jail, error)
	// RestoreVolume restores a volume backup as a new volume of the project.
	RestoreVolume(ctx context.Context, req api.RestoreRequest) (api.Volume, error)
}

var _ Backups = (*Service)(nil)

// RestoreVolume implements Backups: it is RestoreVolumeBackup.
func (s *Service) RestoreVolume(ctx context.Context, req api.RestoreRequest) (api.Volume, error) {
	return s.RestoreVolumeBackup(ctx, req)
}

// List returns the backups this host knows about, newest first, from the
// catalog (Reindex rebuilds it from the repository).
func (s *Service) List(ctx context.Context) ([]api.Backup, error) {
	return s.deps.Catalog.Backups(ctx)
}

// Get returns one backup by its snapshot id.
func (s *Service) Get(ctx context.Context, id string) (api.Backup, error) {
	return s.findBackup(ctx, id)
}

// Delete answers api.CodeUnsupported: a host cannot delete backups. Deletion is
// retention, run only by the backup node, or an administrator's request there
// (design 9.5 and 9.6).
func (s *Service) Delete(ctx context.Context, id string) error {
	return api.Errorf(api.CodeUnsupported, "a host cannot delete backups").
		WithHint("retention runs on the backup node; request a deletion there (jailops-backupd admin)")
}

// ImagegenImages adapts internal/imagegen's managers to Images: one manager
// per storage, because a generation lives on the pool of the jail that clones it.
type ImagegenImages struct {
	// Manager returns the manager of a storage ("" is the default storage).
	Manager func(storage string) (*imagegen.Manager, error)
}

// Resolve implements Images.
func (i ImagegenImages) Resolve(ctx context.Context, storage, generation string) (api.ImageGeneration, error) {
	m, err := i.Manager(storage)
	if err != nil {
		return api.ImageGeneration{}, err
	}
	return m.Resolve(ctx, generation)
}
