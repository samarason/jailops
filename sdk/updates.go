package sdk

import (
	"context"
	"net/http"

	"jailops.net/jailops/sdk/api"
)

// UpdateClient accesses managed updates (design 8.4): /api/v1/updates and the
// per-jail history. It needs the "updates" extension.
type UpdateClient struct{ c *Client }

// Updates returns the updates client.
func (c *Client) Updates() *UpdateClient { return &UpdateClient{c} }

// List returns the latest check result of every jail that has one.
func (u *UpdateClient) List(ctx context.Context) ([]api.UpdateReport, error) {
	if err := u.c.need("updates"); err != nil {
		return nil, err
	}
	v, _, err := get[[]api.UpdateReport](ctx, u.c, "/api/v1/updates", nil)
	return v, err
}

// Check asks jails what could be updated; the operation's result is the
// reports. Nothing is applied. With no names it checks every jail of the
// project.
func (u *UpdateClient) Check(ctx context.Context, jails ...string) (*Operation[[]api.UpdateReport], error) {
	if err := u.c.need("updates"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[[]api.UpdateReport](ctx, u.c, request{method: http.MethodPost, path: "/api/v1/updates/check",
		body: api.UpdateCheckRequest{Jails: jails, All: len(jails) == 0}}, nil)
	return op, err
}

// Apply applies updates; the result is the history records written. With no
// names it applies to every jail of the project. Package restricts to package
// updates, OS to image generations; neither means what each jail's policy
// allows.
func (u *UpdateClient) Apply(ctx context.Context, req api.UpdateApplyRequest) (*Operation[[]api.UpdateRecord], error) {
	if err := u.c.need("updates"); err != nil {
		return nil, err
	}
	if len(req.Jails) == 0 {
		req.All = true
	}
	op, _, err := sendOp[[]api.UpdateRecord](ctx, u.c, request{method: http.MethodPost, path: "/api/v1/updates/apply", body: req}, nil)
	return op, err
}

// UpdateHistory returns a jail's update history, newest first.
func (j *JailClient) UpdateHistory(ctx context.Context, name string) ([]api.UpdateRecord, error) {
	if err := j.c.need("updates"); err != nil {
		return nil, err
	}
	v, _, err := get[[]api.UpdateRecord](ctx, j.c, j.r.item(name)+"/updates", nil)
	return v, err
}

// Provision runs the jail's provisioning (design 8.5). It refuses when
// provisioning completed before, unless again is set.
func (j *JailClient) Provision(ctx context.Context, name string, again bool) (*Operation[api.ProvisionResult], error) {
	if err := j.c.need("provisioning"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[api.ProvisionResult](ctx, j.c, request{method: http.MethodPost, path: j.r.item(name) + "/provision", body: api.ProvisionRequest{Again: again}}, nil)
	return op, err
}

// ShellSetup gives a FreeBSD jail the shell and prompt a new jail gets (docs/shell.md): bash installed when it is
// the jail's shell and missing, and the prompt written. The jail must run.
func (j *JailClient) ShellSetup(ctx context.Context, name string) (*Operation[api.ShellSetupResult], error) {
	if err := j.c.need("jail_shell_setup"); err != nil {
		return nil, err
	}
	op, _, err := sendOp[api.ShellSetupResult](ctx, j.c, request{method: http.MethodPost, path: j.r.item(name) + "/shell-setup", body: api.ShellSetupRequest{}}, nil)
	return op, err
}
