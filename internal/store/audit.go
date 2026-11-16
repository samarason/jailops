package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"jailops.net/jailops/sdk/api"
)

// AuditEntry records one state-changing request: who, when, which route, which
// object and the result. Entries never contain secrets.
type AuditEntry struct {
	ID        int64
	Time      time.Time
	Actor     string // user name, token name or certificate fingerprint
	ActorKind string // "user", "token", "certificate", "unix"
	Method    string
	Route     string
	Object    string
	Result    string // "ok", "denied", "error"
	Status    int
	Remote    string
	Detail    string
	// Project is the project of the request; empty for host-level requests.
	Project string
}

// Audit is the audit log. There is no update method, and the only delete is Prune (retention), which database
// triggers limit: no row is ever changed, and none of the newest AuditKeep is deleted.
type Audit struct{ s *Store }

// Bounds of the free fields of an entry. An anonymous caller's entry is the smallest: it costs the caller nothing.
const (
	MaxAuditObject          = 256
	MaxAuditDetail          = 4096
	MaxAuditDetailAnonymous = 256
)

// AuditText makes a value safe to store in an audit entry: control and invisible characters (escape sequences, line
// breaks, bidirectional controls) and bytes that are not UTF-8 become Go escapes such as \x1b, \n and \u202e, and
// the result is cut at max bytes (with "..."). Every entry passes through it when it is appended.
func AuditText(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if b.Len() >= max {
			b.WriteString("...")
			break
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case api.UnsafeRune(r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// Append adds an entry and returns its id. A zero Time is replaced by now.
func (r *Audit) Append(ctx context.Context, e AuditEntry) (int64, error) {
	if e.Actor == "" || e.Method == "" || e.Route == "" || e.Result == "" {
		return 0, api.Errorf(api.CodeInvalid, "audit entry needs actor, method, route and result")
	}
	maxDetail := MaxAuditDetail
	if e.ActorKind == "anonymous" {
		maxDetail = MaxAuditDetailAnonymous
	}
	e.Actor, e.Object = AuditText(e.Actor, MaxAuditObject), AuditText(e.Object, MaxAuditObject)
	e.Detail, e.Remote = AuditText(e.Detail, maxDetail), AuditText(e.Remote, MaxAuditObject)
	if e.Time.IsZero() {
		e.Time = r.s.now()
	}
	var id int64
	err := r.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "INSERT INTO audit (ts, actor, actor_kind, method, route, object, result, status, remote, detail, project) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
			ts(e.Time), e.Actor, e.ActorKind, e.Method, e.Route, e.Object, e.Result, e.Status, e.Remote, e.Detail, e.Project)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// AuditFilter narrows List. Zero fields match everything.
type AuditFilter struct {
	Actor    string
	Since    time.Time
	BeforeID int64 // pagination: only entries with a smaller id
	Limit    int
	// ProjectFilter limits the result to entries of Projects; an empty list
	// then returns nothing.
	ProjectFilter bool
	Projects      []string

	// AfterID keeps the entries with a larger id and returns them oldest first (the log forwarder's cursor).
	AfterID int64
}

// List returns entries newest first.
func (r *Audit) List(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 100
	}
	q := "SELECT id, ts, actor, actor_kind, method, route, object, result, status, remote, detail, project FROM audit WHERE 1=1"
	var args []any
	if f.Actor != "" {
		q += " AND actor = ?"
		args = append(args, f.Actor)
	}
	if !f.Since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, ts(f.Since))
	}
	if f.BeforeID > 0 {
		q += " AND id < ?"
		args = append(args, f.BeforeID)
	}
	if f.AfterID > 0 {
		q += " AND id > ?"
		args = append(args, f.AfterID)
	}
	if f.ProjectFilter {
		if len(f.Projects) == 0 {
			return nil, nil
		}
		q += " AND project IN (?" + strings.Repeat(",?", len(f.Projects)-1) + ")"
		for _, p := range f.Projects {
			args = append(args, p)
		}
	}
	if f.AfterID > 0 {
		q += " ORDER BY id ASC LIMIT ?"
	} else {
		q += " ORDER BY id DESC LIMIT ?"
	}
	args = append(args, f.Limit)
	rows, err := r.s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var t int64
		if err := rows.Scan(&e.ID, &t, &e.Actor, &e.ActorKind, &e.Method, &e.Route, &e.Object, &e.Result, &e.Status, &e.Remote, &e.Detail, &e.Project); err != nil {
			return nil, err
		}
		e.Time = fromTS(t)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditKeep is the number of newest entries that pruning never removes (a database trigger enforces it as well).
const AuditKeep = 1000

// Prune deletes the entries older than before and the oldest beyond maxRows (0: no row limit), except the newest
// AuditKeep, and returns how many it deleted. It deletes in batches so the writer is never held long.
func (r *Audit) Prune(ctx context.Context, before time.Time, maxRows int) (int64, error) {
	var total int64
	for {
		var n int64
		err := r.s.write(ctx, func(tx *sql.Tx) error {
			var top sql.NullInt64
			if err := tx.QueryRowContext(ctx, "SELECT MAX(id) FROM audit").Scan(&top); err != nil {
				return err
			}
			if !top.Valid {
				return nil
			}
			keepFrom := top.Int64 - AuditKeep // ids above this are kept
			rowFrom := int64(-1)              // ids at or below this are beyond maxRows
			if maxRows > 0 {
				rowFrom = top.Int64 - int64(max(maxRows, AuditKeep))
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE id <= ? AND (ts < ? OR id <= ?) ORDER BY id LIMIT 5000)`,
				keepFrom, ts(before), rowFrom)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < 5000 {
			return total, nil
		}
	}
}
