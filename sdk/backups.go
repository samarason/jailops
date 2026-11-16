package sdk

import (
	"context"
	"iter"
	"net/http"

	"jailops.net/jailops/sdk/api"
)

// BackupClient accesses backups, targets and policies.
type BackupClient struct {
	c *Client
	r *Resource[api.Backup]
}

// Backups returns the backups client.
func (c *Client) Backups() *BackupClient {
	return &BackupClient{c, newResource[api.Backup](c, "/api/v1/backups")}
}

// Targets accesses /api/v1/backup-targets.
func (b *BackupClient) Targets() *Resource[api.BackupTarget] {
	return newResource[api.BackupTarget](b.c, "/api/v1/backup-targets")
}

// Policies accesses /api/v1/backup-policies.
func (b *BackupClient) Policies() *Resource[api.BackupPolicy] {
	return newResource[api.BackupPolicy](b.c, "/api/v1/backup-policies")
}

// List iterates backups.
func (b *BackupClient) List(ctx context.Context, opts ...ListOption) iter.Seq2[api.Backup, error] {
	return b.r.List(ctx, opts...)
}

// Get fetches a backup.
func (b *BackupClient) Get(ctx context.Context, name string) (api.Backup, error) {
	return b.r.Get(ctx, name)
}

// Delete requests deletion of a backup (needs backup-admin; the backup node
// may delay it).
func (b *BackupClient) Delete(ctx context.Context, name string) (*Operation[None], error) {
	op, _, err := sendOp[None](ctx, b.c, request{method: http.MethodDelete, path: b.r.item(name)}, nil)
	return op, err
}

// Preflight reports what a restore would need and change, and changes nothing.
func (b *BackupClient) Preflight(ctx context.Context, req api.RestoreRequest) (api.RestorePreflight, error) {
	if err := b.c.need("restore_preflight"); err != nil {
		return api.RestorePreflight{}, err
	}
	req.DryRun = true
	pf, _, err := send[api.RestorePreflight](ctx, b.c, request{method: http.MethodPost, path: "/api/v1/restores", body: req})
	return pf, err
}

// Restore restores a backup as a jail. Run Preflight first; the server
// refuses a restore whose preflight is not OK.
func (b *BackupClient) Restore(ctx context.Context, req api.RestoreRequest) (*Operation[api.Jail], error) {
	req.DryRun = false
	op, _, err := sendOp[api.Jail](ctx, b.c, request{method: http.MethodPost, path: "/api/v1/restores", body: req}, nil)
	return op, err
}

// RestoreVolume restores a volume backup as a new volume of the project (POST /api/v1/restores). Like Restore it
// does not run the preflight; Preflight does. The passphrase of an encrypted volume is req.Passphrase.
func (b *BackupClient) RestoreVolume(ctx context.Context, req api.RestoreRequest) (*Operation[api.Volume], error) {
	req.DryRun = false
	op, _, err := sendOp[api.Volume](ctx, b.c, request{method: http.MethodPost, path: "/api/v1/restores", body: req}, nil)
	return op, err
}

// Run starts a backup policy now, outside its schedule, for every jail it
// selects (POST /api/v1/backups/run, admin only). The result lists one run per
// jail and target; a failed job is a run with OK false. It needs the
// "backup_run" extension, which a server advertises when it has a backup
// backend.
func (b *BackupClient) Run(ctx context.Context, policy string) (*Operation[[]api.BackupRun], error) {
	return b.RunWith(ctx, api.BackupRunRequest{Policy: policy})
}

// RunWith is Run with the options of the request (NoVolumes leaves the volumes out of this run).
func (b *BackupClient) RunWith(ctx context.Context, req api.BackupRunRequest) (*Operation[[]api.BackupRun], error) {
	if err := b.c.need("backup_run"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[[]api.BackupRun](ctx, b.c, request{method: http.MethodPost, path: "/api/v1/backups/run", body: req}, nil)
	return op, err
}

// Verify checks a backup by reading it back deeply (POST
// /api/v1/backups/<id>/verify); the result is the run. It needs the
// "backup_verify" extension.
func (b *BackupClient) Verify(ctx context.Context, name string) (*Operation[api.BackupRun], error) {
	return b.VerifyDepth(ctx, name, "")
}

// VerifyDepth is Verify with a depth: "deep" (default), "extract" or "full".
func (b *BackupClient) VerifyDepth(ctx context.Context, name, depth string) (*Operation[api.BackupRun], error) {
	if err := b.c.need("backup_verify"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[api.BackupRun](ctx, b.c, request{method: http.MethodPost, path: b.r.item(name) + "/verify", body: api.BackupVerifyRequest{Depth: depth}}, nil)
	return op, err
}

// KeyStatus reports whether this host has a backup key and whether it is
// escrowed (GET /api/v1/backup/key, admin only).
func (b *BackupClient) KeyStatus(ctx context.Context) (api.BackupKeyStatus, error) {
	if err := b.c.need("backup_key"); err != nil {
		return api.BackupKeyStatus{}, err
	}
	v, _, err := send[api.BackupKeyStatus](ctx, b.c, request{method: http.MethodGet, path: "/api/v1/backup/key"})
	return v, err
}

// CreateKey creates the host's backup key (POST /api/v1/backup/key, admin
// only). The reply carries the recovery key; it is shown once, so the caller
// must show it to the operator now and store it nowhere else. recipients are
// age public keys to escrow to; empty uses the daemon's configuration.
func (b *BackupClient) CreateKey(ctx context.Context, recipients ...string) (api.BackupKeyCreated, error) {
	if err := b.c.need("backup_key"); err != nil {
		return api.BackupKeyCreated{}, err
	}
	v, _, err := send[api.BackupKeyCreated](ctx, b.c, request{method: http.MethodPost, path: "/api/v1/backup/key", body: api.BackupKeyCreate{Recipients: recipients}})
	return v, err
}

// EscrowKey wraps the key to the recovery recipients and uploads it to the
// node (POST /api/v1/backup/key/escrow, admin only).
func (b *BackupClient) EscrowKey(ctx context.Context, recipients ...string) (api.BackupKeyStatus, error) {
	if err := b.c.need("backup_key"); err != nil {
		return api.BackupKeyStatus{}, err
	}
	v, _, err := send[api.BackupKeyStatus](ctx, b.c, request{method: http.MethodPost, path: "/api/v1/backup/key/escrow", body: api.BackupKeyEscrow{Recipients: recipients}})
	return v, err
}
