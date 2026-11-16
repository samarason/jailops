package api

import (
	"errors"
	"fmt"
	"net/http"
)

// Code is a stable machine-readable error code. Codes are part of the API
// contract: they appear in the CLI, the UI, `jailops explain <code>` and the
// SDK, and are never renamed.
type Code string

const (
	CodeInvalid         Code = "invalid" // request failed validation
	CodeNotFound        Code = "not_found"
	CodeAlreadyExists   Code = "already_exists"
	CodeConflict        Code = "conflict" // stale generation (HTTP 412)
	CodeUnauthorized    Code = "unauthorized"
	CodeForbidden       Code = "forbidden"
	CodeUnsupported     Code = "unsupported" // missing API extension
	CodeBusy            Code = "busy"        // resource is locked by another operation
	CodeInternal        Code = "internal"
	CodeIPConflict      Code = "ip_conflict"
	CodePoolExhausted   Code = "pool_exhausted"
	CodeImageInUse      Code = "image_in_use"
	CodeDataLoss        Code = "data_loss_unconfirmed"
	CodeVersionSkew     Code = "version_skew"
	CodeNotLeader       Code = "not_leader"
	CodeNoQuorum        Code = "no_quorum"
	CodeUnverified      Code = "unverified_platform" // needs FreeBSD or a missing kernel feature
	CodeZFSIncompatible Code = "zfs_incompatible"
	CodeChainBroken     Code = "chain_broken"
	CodeMergeConflict   Code = "merge_conflict"   // /etc merge needs a human; the jail stays on the old generation
	CodeQuotaExceeded   Code = "quota_exceeded"   // a project quota would be exceeded
	CodeRateLimited     Code = "rate_limited"     // too many failed attempts (HTTP 429)
	CodeKeyNotEscrowed  Code = "key_not_escrowed" // raw backup refused: no recoverable key escrow
	CodePlaintextDenied Code = "plaintext_denied" // node target needs encrypted data or allow_plaintext
	CodeMaintenance     Code = "maintenance"      // the backup node is read-only or offline (HTTP 503); retry later
	CodeMissingChunks   Code = "missing_chunks"   // a commit references chunks the repository lacks (HTTP 409); upload them and retry
	CodeLeaseExpired    Code = "lease_expired"    // the backup session timed out or was closed (HTTP 410)
	CodeNotManaged      Code = "not_managed"      // a host management module is not enabled (HTTP 403); the hint names the lines to add
	CodeLocked          Code = "locked"           // an encrypted volume waits for its passphrase (HTTP 409); unlock the jail first
	CodeBadPassphrase   Code = "bad_passphrase"   // the passphrase of an encrypted volume is wrong (HTTP 403); nothing else is said
	CodeStopForced      Code = "stop_forced"      // a stop that did not finish within its budget was forced: the jail is gone (a warning to the daemon, not an error)
)

// Error is the error body of the API and the error type of the SDK.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	// Hint tells the user how to fix the problem.
	Hint string `json:"hint,omitempty"`
	// Detail carries structured context such as the conflicting address.
	Detail map[string]string `json:"detail,omitempty"`
}

// Error implements error.
func (e *Error) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Hint)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Is matches on the code so that errors.Is(err, &api.Error{Code: ...}) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Errorf builds an Error.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithHint returns a copy with a hint.
func (e *Error) WithHint(h string) *Error { c := *e; c.Hint = h; return &c }

// WithDetail returns a copy with one detail entry.
func (e *Error) WithDetail(k, v string) *Error {
	c := *e
	c.Detail = make(map[string]string, len(e.Detail)+1)
	for dk, dv := range e.Detail {
		c.Detail[dk] = dv
	}
	c.Detail[k] = v
	return &c
}

// HTTPStatus maps a code to its HTTP status.
func (c Code) HTTPStatus() int {
	switch c {
	case CodeInvalid, CodeDataLoss:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeQuotaExceeded:
		return http.StatusConflict
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeKeyNotEscrowed, CodePlaintextDenied:
		return http.StatusUnprocessableEntity
	case CodeMergeConflict:
		return http.StatusConflict
	case CodeAlreadyExists, CodeIPConflict, CodeImageInUse, CodeChainBroken:
		return http.StatusConflict
	case CodeConflict:
		return http.StatusPreconditionFailed
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden, CodeNotManaged:
		return http.StatusForbidden
	case CodeUnsupported, CodeUnverified:
		return http.StatusNotImplemented
	case CodeBusy, CodePoolExhausted:
		return http.StatusConflict
	case CodeNotLeader, CodeNoQuorum, CodeVersionSkew, CodeMaintenance:
		return http.StatusServiceUnavailable
	case CodeMissingChunks, CodeLocked:
		return http.StatusConflict
	case CodeBadPassphrase:
		return http.StatusForbidden
	case CodeLeaseExpired:
		return http.StatusGone
	}
	return http.StatusInternalServerError
}

// IsCode reports whether err is or wraps an *Error with the given code.
func IsCode(err error, code Code) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
