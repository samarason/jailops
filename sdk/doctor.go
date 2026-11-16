package sdk

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Doctor runs the server's diagnostics (GET /api/v1/doctor).
func (c *Client) Doctor(ctx context.Context) (api.DoctorReport, error) {
	if err := c.need("doctor"); err != nil {
		return api.DoctorReport{}, err
	}
	r, _, err := get[api.DoctorReport](ctx, c, "/api/v1/doctor", nil)
	return r, err
}

// DoctorFix performs the safe cleanups the diagnostics report (POST /api/v1/doctor/fix): stale mounts below the root of
// stopped jails and what an earlier network layout left. With dryRun it only lists them.
func (c *Client) DoctorFix(ctx context.Context, dryRun bool) (api.DoctorFixResult, error) {
	if err := c.need("doctor"); err != nil {
		return api.DoctorFixResult{}, err
	}
	r, _, err := send[api.DoctorFixResult](ctx, c, request{method: http.MethodPost, path: "/api/v1/doctor/fix", body: api.DoctorFixRequest{DryRun: dryRun}})
	return r, err
}

// Audit returns the newest audit entries, newest first (GET /api/v1/audit?limit=).
func (c *Client) Audit(ctx context.Context, limit int) ([]api.AuditEntry, error) {
	return c.AuditFiltered(ctx, AuditFilter{Limit: limit})
}

// AuditFilter narrows the audit entries the server returns. Zero fields match everything.
type AuditFilter struct {
	// Limit is the number of entries, at most (the server's default is 200, its maximum 1000).
	Limit int
	// Actor keeps the entries of one requestor: a user, a token name or a certificate fingerprint.
	Actor string
	// Since keeps the entries from this time on.
	Since time.Time
}

// AuditFiltered returns the newest audit entries that match f, newest first (GET /api/v1/audit?limit=&actor=&since=).
func (c *Client) AuditFiltered(ctx context.Context, f AuditFilter) ([]api.AuditEntry, error) {
	q := url.Values{}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Actor != "" {
		q.Set("actor", f.Actor)
	}
	if !f.Since.IsZero() {
		q.Set("since", f.Since.UTC().Format(time.RFC3339))
	}
	r, _, err := get[[]api.AuditEntry](ctx, c, "/api/v1/audit", q)
	return r, err
}
