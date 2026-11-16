package sdk

import (
	"context"
	"net/url"

	"jailops.net/jailops/sdk/api"
)

// BootPlan returns what the daemon starts after a boot of the host, in order, and the jails with autostart it does
// not start (GET /api/v1/boot). The order is that of the host. It shows the jails of the client's project, or with
// allProjects those of every project the identity may use.
func (c *Client) BootPlan(ctx context.Context, allProjects bool) (api.BootPlan, error) {
	if err := c.need("boot_plan"); err != nil {
		return api.BootPlan{}, err
	}
	var q url.Values
	if allProjects {
		q = url.Values{"all_projects": {"true"}}
	}
	r, _, err := get[api.BootPlan](ctx, c, "/api/v1/boot", q)
	return r, err
}
