package backupd

// The management API of the backup node, for its web UI and for scripts. It is
// served on the one listener (Config.Listen, TLS, tokens and sessions) under /api/v1 next to the UI
// files, and every answer is the envelope of sdk/api (api.Response): the payload
// is in "metadata", an error in "error" with a stable code.
//
// Authentication: POST /api/v1/auth/login {username, password} sets a session cookie
// and returns {user, role, csrf}; browser sessions send the csrf value in
// X-CSRF-Token on every request that is not GET. Scripts send
// "Authorization: Bearer jot_...". Roles: readonly < backup-admin < admin.
//
//	GET    /api/v1                                  server info, api.ServerInfo with role "backup" (public)
//	POST   /api/v1/auth/login                       public; 429 rate_limited after repeated failures
//	POST   /api/v1/auth/logout | GET /api/v1/auth/session | POST /api/v1/auth/password {current, new}
//	GET    /api/v1/repository                       readonly. node.RepositoryStatus plus "status" (api.RepositoryStatus) and "next_runs"
//	GET    /api/v1/certificate                      readonly. {fingerprint}: the node's certificate, which hosts pin
//	GET    /api/v1/hosts                            readonly. []ctl.Host {id, name, fingerprint, scopes, note, created_at, revoked_at, last_seen_at}
//	POST   /api/v1/hosts                            admin. {name, fingerprint | certificate (PEM), scopes?, note?}
//	PUT    /api/v1/hosts/{name}                     admin. {scopes}
//	DELETE /api/v1/hosts/{name}                     admin. revokes; open sessions are aborted
//	GET    /api/v1/groups                           readonly. one row per jail group with snapshot, failed, protected and pending counts
//	GET    /api/v1/groups/{group}/snapshots         readonly. []wire.Snapshot {snapshot_id, committed_at, chunk_count, protected,
//	                                             verify_state "", "ok" or "failed", verified_at, verify_problems,
//	                                             pending_deletion_requested_at/_after/_by}
//	GET    /api/v1/groups/{group}/snapshots/{snap}  readonly
//	PUT    /api/v1/groups/{group}/snapshots/{snap}/protected         backup-admin. {protected: bool}
//	POST   /api/v1/groups/{group}/snapshots/{snap}/deletion          backup-admin. {delay?: "72h"} step one; returns {requested_at, execute_after, requested_by}
//	DELETE /api/v1/groups/{group}/snapshots/{snap}/deletion          backup-admin. cancel
//	POST   /api/v1/groups/{group}/snapshots/{snap}/deletion/execute  backup-admin. step two; 409 busy before execute_after
//	GET    /api/v1/sessions                         readonly. open backup sessions (leases)
//	GET    /api/v1/jobs?kind=&limit=                readonly. ctl.Job {id, kind gc|verify|retention|reconcile|restore-test, state, params, result, error, ...}
//	GET    /api/v1/jobs/{id}                        readonly
//	POST   /api/v1/jobs/{id}/cancel                 backup-admin
//	POST   /api/v1/jobs/gc {grace?, dry_run?}       backup-admin. 202 with the job; 409 busy if another repository-wide job runs
//	POST   /api/v1/jobs/verify {mode: all|new|stale, quarantine?, stale_days?}
//	POST   /api/v1/jobs/retention {dry_run?, group?}  the plan is in the job's result
//	POST   /api/v1/jobs/reconcile
//	GET    /api/v1/maintenance                      readonly. {mode: online|read-only|offline}
//	PUT    /api/v1/maintenance {mode}               backup-admin. hosts get 503 "maintenance" while it is not online
//	GET    /api/v1/quarantine                       readonly. []node.QuarantinedChunk {id, size, since, healed}
//	POST   /api/v1/quarantine/purge                 backup-admin
//	POST   /api/v1/quarantine/{id}                  backup-admin. moves a chunk a host reported as undecryptable aside: {moved}
//	GET    /api/v1/escrow                           readonly. {domains: []} key domains with an escrow blob
//	DELETE /api/v1/escrow/{domain}                  backup-admin. deletes a damaged escrow blob; a host then stores a new one
//	GET    /api/v1/retention-policies               readonly. {scope: "default" | group id, policy, timezone}
//	PUT    /api/v1/retention-policies/{scope}       backup-admin. {policy: api.RetentionPolicy, timezone?}
//	DELETE /api/v1/retention-policies/{scope}       backup-admin
//	GET    /api/v1/audit?action=&limit=&before=     admin. []ctl.AuditEntry, newest first
//	GET|POST /api/v1/users, PUT|DELETE /api/v1/users/{name}   admin. {name, password, role, disabled}
//	GET|POST /api/v1/tokens, DELETE /api/v1/tokens/{name}     admin. POST {name, role, allow_from?, expires_at?} returns the secret once
//
// Error codes the UI should handle: unauthorized, forbidden, not_found, invalid, already_exists, busy
// (another job or a protected snapshot), rate_limited, maintenance.
//
// The routes are listed with their permissions in Perms (perms.go).
