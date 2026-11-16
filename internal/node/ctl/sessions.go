package ctl

import (
	"context"
	"fmt"
	"time"
)

// Session states.
const (
	SessionOpen      = "open"
	SessionCommitted = "committed"
	SessionAborted   = "aborted"
	SessionExpired   = "expired"
)

// Session is a lease on a group: the writer of the next snapshot.
type Session struct {
	ID         string     `json:"id"`
	GroupID    string     `json:"group_id"`
	HostID     string     `json:"host_id"`
	SnapshotID string     `json:"snapshot_id"`
	PreviousID string     `json:"previous_id,omitempty"`
	State      string     `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
	LeaseUntil time.Time  `json:"lease_expires_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	ChunksPut  int64      `json:"chunks_put"`
	BytesPut   int64      `json:"bytes_put"`
}

const sessionCols = `id::text, group_id, host_id::text, snapshot_id, previous_id, state, created_at, lease_expires_at, closed_at, chunks_put, bytes_put`

type scanner interface{ Scan(...any) error }

func scanSession(r scanner) (Session, error) {
	var s Session
	err := r.Scan(&s.ID, &s.GroupID, &s.HostID, &s.SnapshotID, &s.PreviousID, &s.State, &s.CreatedAt, &s.LeaseUntil, &s.ClosedAt, &s.ChunksPut, &s.BytesPut)
	return s, notFound(err)
}

// OpenSession creates the one open session of a group. A previous session
// whose lease ran out is expired first. Another live session is ErrConflict.
func (d *DB) OpenSession(ctx context.Context, group, hostID, snapshot, previous string, lease time.Duration) (Session, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return Session{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE sessions SET state='expired', closed_at=$2::timestamptz WHERE group_id=$1 AND state='open' AND lease_expires_at < $2::timestamptz`, group, d.now()); err != nil {
		return Session{}, err
	}
	s, err := scanSession(tx.QueryRow(ctx, `INSERT INTO sessions (group_id, host_id, snapshot_id, previous_id, state, lease_expires_at)
		VALUES ($1, $2::uuid, $3, $4, 'open', $6::timestamptz + $5 * interval '1 microsecond') RETURNING `+sessionCols,
		group, hostID, snapshot, previous, lease.Microseconds(), d.now()))
	if isUnique(err) {
		return Session{}, fmt.Errorf("%w: the group already has an open session", ErrConflict)
	}
	if err != nil {
		return Session{}, err
	}
	return s, tx.Commit(ctx)
}

// Session returns a session by id.
func (d *DB) Session(ctx context.Context, id string) (Session, error) {
	return scanSession(d.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = $1::uuid`, id))
}

// RenewSession extends the lease of an open session and counts uploaded
// chunks and bytes. It returns ErrNotFound when the session is not open or its
// lease has run out (the lease is then closed as expired).
func (d *DB) RenewSession(ctx context.Context, id string, lease time.Duration, chunks, bytes int64) (Session, error) {
	at := d.now()
	s, err := scanSession(d.pool.QueryRow(ctx, `UPDATE sessions SET lease_expires_at = $5::timestamptz + $2 * interval '1 microsecond',
			chunks_put = chunks_put + $3, bytes_put = bytes_put + $4
		WHERE id = $1::uuid AND state = 'open' AND lease_expires_at >= $5::timestamptz RETURNING `+sessionCols,
		id, lease.Microseconds(), chunks, bytes, at))
	if err == ErrNotFound {
		_, _ = d.pool.Exec(ctx, `UPDATE sessions SET state='expired', closed_at=$2::timestamptz WHERE id=$1::uuid AND state='open' AND lease_expires_at < $2::timestamptz`, id, at)
	}
	return s, err
}

// CloseSession ends an open session with the final state.
func (d *DB) CloseSession(ctx context.Context, id, state string) error {
	_, err := d.pool.Exec(ctx, `UPDATE sessions SET state=$2, closed_at=$3::timestamptz WHERE id=$1::uuid AND state='open'`, id, state, d.now())
	return err
}

// ExpireSessions closes every open session whose lease ran out and returns their ids.
func (d *DB) ExpireSessions(ctx context.Context) ([]string, error) {
	rows, err := d.pool.Query(ctx, `UPDATE sessions SET state='expired', closed_at=$1::timestamptz WHERE state='open' AND lease_expires_at < $1::timestamptz RETURNING id::text`, d.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// OpenSessions lists the sessions that are open now.
func (d *DB) OpenSessions(ctx context.Context) ([]Session, error) {
	rows, err := d.pool.Query(ctx, `SELECT `+sessionCols+` FROM sessions WHERE state='open' AND lease_expires_at >= $1::timestamptz ORDER BY created_at`, d.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SessionOpenFor returns the open session of a group, if any.
func (d *DB) SessionOpenFor(ctx context.Context, group string) (Session, error) {
	return scanSession(d.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE group_id=$1 AND state='open' AND lease_expires_at >= $2::timestamptz`, group, d.now()))
}

// PinnedSnapshots returns the (group, snapshot) pairs that open sessions use
// as their previous snapshot: retention must keep them.
func (d *DB) PinnedSnapshots(ctx context.Context) (map[[2]string]bool, error) {
	rows, err := d.pool.Query(ctx, `SELECT group_id, previous_id FROM sessions WHERE state='open' AND lease_expires_at >= $1::timestamptz AND previous_id <> ''`, d.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[[2]string]bool{}
	for rows.Next() {
		var g, s string
		if err := rows.Scan(&g, &s); err != nil {
			return nil, err
		}
		out[[2]string{g, s}] = true
	}
	return out, rows.Err()
}
