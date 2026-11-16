package api

import "time"

// DoctorStatus is the verdict of one check or of the whole report.
type DoctorStatus string

const (
	DoctorOK      DoctorStatus = "ok"
	DoctorWarn    DoctorStatus = "warn"
	DoctorFail    DoctorStatus = "fail"
	DoctorUnknown DoctorStatus = "unknown" // could not be determined, for example without FreeBSD
	// DoctorInfo is a fact the administrator should know that is not a fault (a setting that is stored and
	// not enforced yet); it counts like ok for the status of the report.
	DoctorInfo DoctorStatus = "info"
)

// DoctorCheck is one diagnostic of GET /api/v1/doctor.
type DoctorCheck struct {
	// Name is a stable identifier such as "kernel.module.if_epair".
	Name    string       `json:"name"`
	Status  DoctorStatus `json:"status"`
	Message string       `json:"message,omitempty"`
	// Hint tells the administrator how to fix a failing check.
	Hint   string            `json:"hint,omitempty"`
	Detail map[string]string `json:"detail,omitempty"`
}

// DoctorReport is the reply of GET /api/v1/doctor. Status is the worst status of
// its checks (fail, warn, unknown, ok in that order).
type DoctorReport struct {
	Time   time.Time     `json:"time"`
	Host   string        `json:"host,omitempty"`
	Status DoctorStatus  `json:"status"`
	Checks []DoctorCheck `json:"checks"`
}

// AuditEntry is one row of GET /api/v1/audit.
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	// Requestor is the user, token name or certificate fingerprint.
	Requestor string `json:"requestor"`
	// Action is "<METHOD> <route pattern>".
	Action   string `json:"action"`
	Resource string `json:"resource,omitempty"`
	// Project is the project of the request; empty for host-level requests.
	Project  string `json:"project,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
	// Result is "ok", "denied" or "error".
	Result string `json:"result,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// PoolUsage is the reply of GET /api/v1/resources: the capacity of the pool that
// holds JailOps's datasets.
type PoolUsage struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Allocated uint64 `json:"allocated"`
	Free      uint64 `json:"free"`
	Health    string `json:"health,omitempty"`
}

// DoctorFixRequest is the body of POST /api/v1/doctor/fix: the safe cleanups the diagnostics report, with DryRun only
// listing them.
type DoctorFixRequest struct {
	DryRun bool `json:"dry_run,omitempty"`
}

// DoctorFixAction is one cleanup of POST /api/v1/doctor/fix: what it is for (the check), what it does, and whether it
// was done.
type DoctorFixAction struct {
	Check string `json:"check"`
	What  string `json:"what"`
	Done  bool   `json:"done,omitempty"`
	Error string `json:"error,omitempty"`
}

// DoctorFixResult is the reply of POST /api/v1/doctor/fix.
type DoctorFixResult struct {
	DryRun  bool              `json:"dry_run,omitempty"`
	Actions []DoctorFixAction `json:"actions"`
}
