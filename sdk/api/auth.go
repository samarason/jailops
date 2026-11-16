package api

import "time"

// Permission is a role. Roles form a ladder for day-to-day use
// (readonly < operator < admin) plus narrow roles for backup transport.
type Permission string

const (
	PermReadonly Permission = "readonly"
	PermOperator Permission = "operator" // lifecycle, snapshots, exec
	PermAdmin    Permission = "admin"    // configuration, users, raw PF, hooks

	// Backup transport and recovery.
	PermBackupPush  Permission = "backup-push" // may only send streams
	PermBackupPull  Permission = "backup-pull" // may only read for pulling
	PermRestore     Permission = "restore"
	PermBackupAdmin Permission = "backup-admin" // may schedule deletion on a backup node
)

// Rank orders the ladder roles. Narrow roles return -1 and are checked by
// exact match.
func (p Permission) Rank() int {
	switch p {
	case PermReadonly:
		return 0
	case PermOperator:
		return 1
	case PermAdmin:
		return 2
	}
	return -1
}

// Satisfies reports whether a holder of p may do something that requires need.
func (p Permission) Satisfies(need Permission) bool {
	if p == need {
		return true
	}
	if p.Rank() >= 0 && need.Rank() >= 0 {
		return p.Rank() >= need.Rank()
	}
	// Admin also covers restore.
	return p == PermAdmin && need == PermRestore
}

// Token is an API token. The secret is shown once, when it is created.
type Token struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     TokenSpec  `json:"spec"`
	// Secret is set only in the response to creation.
	Secret string `json:"secret,omitempty"`
}

// TokenSpec describes a token.
type TokenSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment    string     `json:"comment,omitempty"`
	Permission Permission `json:"permission"`
	ExpiresAt  time.Time  `json:"expires_at,omitzero"`
	// Remote restricts a token to a source network, optional.
	AllowFrom []string `json:"allow_from,omitempty"`
	// Projects restricts the token to these projects. A token needs a
	// non-empty Projects list or Global; an empty list never means all.
	Projects []string `json:"projects,omitempty"`
	Global   bool     `json:"global,omitempty"`
}

// Certificate is a trusted client or host certificate.
type Certificate struct {
	Metadata ObjectMeta      `json:"metadata"`
	Spec     CertificateSpec `json:"spec"`
}

// CertificateSpec pins a certificate by fingerprint.
type CertificateSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment     string     `json:"comment,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	Permission  Permission `json:"permission"`
	// Kind is "client", "host", "hub" or "backup". A "hub" certificate is
	// never accepted on the unix socket and has no global rights unless
	// Global is set explicitly: it limits what a hub may claim on behalf of
	// its callers.
	Kind string `json:"kind"`
	// Projects restricts the certificate to these projects. A certificate
	// needs a non-empty Projects list or Global; an empty list never means
	// all projects, and a stored certificate with neither can do nothing.
	Projects []string `json:"projects,omitempty"`
	Global   bool     `json:"global,omitempty"`
	// ExpiresAt, when set, ends the trust at that time.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// User is a local human account with a password and optional second factors.
// Users are ScopeFleet objects.
type User struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     UserSpec   `json:"spec"`
}

// UserSpec describes a user. Password hashes are never serialised to clients.
type UserSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment    string     `json:"comment,omitempty"`
	Permission Permission `json:"permission"`
	Projects   []string   `json:"projects,omitempty"`
	Global     bool       `json:"global,omitempty"`
	Disabled   bool       `json:"disabled,omitempty"`
	TOTP       bool       `json:"totp,omitempty"`
}

// Remote is a host a hub can manage.
type Remote struct {
	Metadata ObjectMeta   `json:"metadata"`
	Spec     RemoteSpec   `json:"spec"`
	Status   RemoteStatus `json:"status"`
}

// RemoteSpec identifies a remote host.
type RemoteSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment     string `json:"comment,omitempty"`
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	HostUUID    string `json:"host_uuid,omitempty"`
}

// RemoteStatus is the hub's view of the remote.
type RemoteStatus struct {
	Online     bool      `json:"online"`
	LastSeen   time.Time `json:"last_seen,omitzero"`
	Version    string    `json:"version,omitempty"`
	Extensions int       `json:"extensions,omitempty"`
}

// UserCreate is the body of POST /api/v1/users. An empty Password asks the
// server to generate one.
type UserCreate struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     UserSpec   `json:"spec"`
	Password string     `json:"password,omitempty"`
}

// PasswordSet is the body and the reply of POST /api/v1/users/{name}/password. In the request, Password is the new
// password, or empty to ask for a generated one. In the reply it is set only when the server generated it, and shown once.
type PasswordSet struct {
	Password string `json:"password,omitempty"`
}

// UserCreated is the reply to POST /api/v1/users. Password is set only here and
// only when the server generated it.
type UserCreated struct {
	User     User   `json:"user"`
	Password string `json:"password,omitempty"`
}

// TrustTokenRequest is the body of POST /api/v1/trust/tokens. It creates a
// single-use token that lets a client add its certificate to the trust store.
type TrustTokenRequest struct {
	Name       string     `json:"name"`
	Permission Permission `json:"permission"`
	// Projects restricts the new identity. The request needs a non-empty
	// Projects list or Global; an empty list never means all projects.
	Projects []string `json:"projects,omitempty"`
	Global   bool     `json:"global,omitempty"`
	// TTLSeconds is the lifetime of the token; it defaults to 3600.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// ExpiresAt, when set, is the expiry of the certificate trust that the
	// token creates (not of the token).
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// TrustToken is returned once, on creation. Token carries the server
// certificate fingerprint and a secret, so the client pins the server without
// trust on first use.
type TrustToken struct {
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TrustClientRequest is the body of POST /api/v1/trust/clients (unauthenticated,
// authorised by the token): the client presents its certificate.
type TrustClientRequest struct {
	Token string `json:"token"`
	// Certificate is the client's PEM certificate.
	Certificate string `json:"certificate"`
}

// Identity describes the caller as the server sees it
// (GET /api/v1/auth/session).
type Identity struct {
	// User is the user name, token name, "cert:<name>" or unix account.
	User string `json:"user"`
	// Kind is "user", "token", "certificate", "unix" or "hub".
	Kind       string     `json:"kind"`
	Permission Permission `json:"permission"`
	TOTP       bool       `json:"totp,omitempty"`
	Projects   []string   `json:"projects,omitempty"`
	Global     bool       `json:"global,omitempty"`
}

// Session is a web session as listed by GET /api/v1/sessions. The session cookie
// value is never returned; ID is a reference that DELETE /api/v1/sessions/<id>
// accepts.
type Session struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Remote    string    `json:"remote,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
	// Current marks the session that made the request.
	Current bool `json:"current,omitempty"`
}
